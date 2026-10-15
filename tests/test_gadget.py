import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge
import forge_android
import forge_apktool
import forge_flows
import forge_gadget
import forge_network
import forge_pcapdroid
import forge_tasks


SERIAL = "b519558f"
PACKAGE = "ai.x.grok"
COMPONENT = "ai.x.grok/.MainActivity"
DUMP_BYTES = b"]" + b"0:1,2:~}#" * 6
MARKER_TEXT = "".join(f"send: {marker}\n" for marker in ("forge-trust-bypass-loaded", "ssl-context-init-replaced",
                                                        "certificate-pinner-check$okhttp", "certificate-pinner-check",
                                                        "conscrypt-verify-chain", "conscrypt-engine-verify"))
REJECTION_ACTION = "fixture required action: fix the reported condition and rerun"
HOST_PATHS = ("https://api.ai.x.grok/v1/one?token=secret", "https://api.ai.x.grok/v1/two",
              "https://cdn.other.example/v1/one")


def call(stdout="", code=0, stderr="", expired=False, omitted_out=0, omitted_err=0):
    return {"returncode": None if expired else code, "timed_out": expired, "launch_error": None, "stdout": stdout,
            "stderr": stderr, "stdout_omitted_bytes": omitted_out, "stderr_omitted_bytes": omitted_err}


class Runner:
    """Fake host side for the adb/frida subprocesses the pipeline runs itself."""

    def __init__(self, *, absent=True, uninstall_code=1, uninstall_output=None, path_output="", pid=True,
                 gadget=True, pull=True, pull_empty=False, pull_error="adb: error: failed to stat remote object"):
        self.absent = absent
        self.uninstall_code = uninstall_code
        self.uninstall_output = uninstall_output
        self.path_output = path_output
        self.pid = pid
        self.gadget = gadget
        self.pull = pull
        self.pull_empty = pull_empty
        self.pull_error = pull_error
        self.commands = []

    # -- assertions helpers ------------------------------------------------
    def uninstalls(self):
        return [command for command in self.commands if command[-2:] == ["uninstall", PACKAGE]]

    def forwards(self):
        return [command[1:] for command in self.commands if "forward" in command]

    def attach_commands(self):
        return [command for command in self.commands if Path(command[0]).name in {"frida", "frida.exe"}]

    def __call__(self, command, timeout, binary=False):
        argv = [str(item) for item in command]
        self.commands.append(argv)
        tail = argv[1:]
        if tail[:1] == ["-s"]:
            tail = tail[2:]
        if tail[:3] == ["shell", "pm", "uninstall"]:
            if self.uninstall_output is not None:
                return call(self.uninstall_output, self.uninstall_code)
            if self.absent:
                return call("Failure [not installed for 0]\n", 1, "Failure [not installed for 0]\n")
        if tail[:3] == ["shell", "pm", "path"]:
            return call(self.path_output, 0 if self.path_output else 1, "")
        if tail[:3] == ["shell", "rm", "-f"]:
            return call("")
        if tail[:3] == ["shell", "pidof", PACKAGE]:
            return call(f"4126\n" if self.pid else "", 0 if self.pid else 1)
        if tail[:1] == ["forward"]:
            return call("" if tail[1:2] == ["--remove"] else "27042\n")
        if tail[:1] == ["pull"]:
            if not self.pull:
                return call("", 1, self.pull_error)
            Path(tail[2]).write_bytes(b"" if self.pull_empty else DUMP_BYTES)
            return call(f"{tail[1]}: 1 file pulled, 0 skipped.\n")
        name = Path(argv[0]).name
        if name.startswith("frida-ps"):
            if not self.gadget:
                return call("", 1, "unable to connect to remote frida-server\n")
            return call("  PID  Name\n-----  -----------------\n 4126  Gadget\n")
        if name.startswith("frida"):
            return call(MARKER_TEXT)
        raise AssertionError(f"unexpected command: {argv}")


class Fake:
    """Faked library boundary: every stage function the pipeline invokes."""

    def __init__(self, store):
        self.store = store
        self.gadget_calls, self.sign_calls, self.install_calls = [], [], []
        self.preflight_calls, self.capture_calls = [], []
        self.flows_calls, self.import_calls = [], []
        self.environ_seen = []
        self.fail = {}
        self.preflight_success = True
        self.preflight_status = "ready"
        self.mitm_installed = True
        self.capture_running = False
        self.flows = 3
        self.flows_skipped = 0
        self.bodies_truncated = 1
        self.reader = "builtin"
        self.urls = list(HOST_PATHS)
        self.capture_record = None
        self.rejection_id = None
        self.session_id = None

    def _reject(self, action, message, data):
        record = self.store.add("runtime", {"schema": "forge.fixture/v1", "action": action, "success": False,
                                            "error": message, "required_action": REJECTION_ACTION, **data})
        self.rejection_id = record["id"]
        raise ForgeError(f"{message}; rejection evidence {record['id']}")

    def gadget(self, args, store):
        self.gadget_calls.append(args)
        if "gadget" in self.fail:
            self._reject("apk-gadget", self.fail["gadget"], {"failure": self.fail["gadget"]})
        return store.add("analysis", {"schema": "forge.apk/v1", "tool": "frida-apk", "action": "apk-gadget",
                                      "success": True, "extract_native_libs_enabled": True, "gadget_abi": "arm64-v8a",
                                      "config_keys": [item.split("=")[0] for item in args.gadget_config],
                                      "output_path": "run/base-gadget.apk", "sha256": "a" * 64})

    def sign(self, args, store):
        self.sign_calls.append(args)
        self.environ_seen.append((args.store_pass_env, os.environ.get(args.store_pass_env)))
        if "sign" in self.fail:
            self._reject("apk-sign", self.fail["sign"], {"failure": self.fail["sign"]})
        return store.add("analysis", {"schema": "forge.apk/v1", "tool": "apksigner", "action": "sign", "success": True,
                                      "sha256": hashlib.sha256(str(args.output).encode("utf-8")).hexdigest()})

    def install(self, args, store):
        self.install_calls.append(args)
        if "install" in self.fail:
            self._reject("install-splits-rejected", self.fail["install"], {"error": self.fail["install"]})
        return store.add("runtime", {"schema": "forge.android.v1", "action": "install-splits", "success": True,
                                     "installer_action": "install-multiple"})

    def preflight(self, args, store):
        self.preflight_calls.append(args)
        return store.add("runtime", {"schema": "forge.pcapdroid/v1", "tool": "pcapdroid", "action": "preflight",
                                     "success": self.preflight_success, "status": self.preflight_status,
                                     "precondition": None if self.preflight_success else "fixture precondition: fix it",
                                     "capture_running": self.capture_running,
                                     "mitm_addon": {"installed": self.mitm_installed},
                                     "device": {"serial": SERIAL, "api": 34, "abis": ["arm64-v8a"]}})

    def capture(self, args, store):
        self.capture_calls.append(args)
        if "capture" in self.fail:
            message = self.fail["capture"]
            rejection = self.store.add("runtime", {"schema": "forge.pcapdroid/v1", "action": "capture-rejected",
                                                   "success": False, "error": message,
                                                   "required_action": REJECTION_ACTION})
            session = self.store.add("runtime", {"schema": "forge.pcapdroid/v1", "action": "capture-session",
                                                 "success": False})
            self.rejection_id, self.session_id = rejection["id"], session["id"]
            raise ForgeError(f"{message}; window rejection evidence {rejection['id']}; capture-session evidence "
                             f"{session['id']}")
        self.capture_record = store.add("runtime", {"schema": "forge.pcapdroid/v1", "tool": "pcapdroid",
                                                   "action": "capture-session", "success": True,
                                                   "attempted_windows": 1, "completed_windows": 1})
        return self.capture_record

    def flow_to_har(self, args, store):
        self.flows_calls.append(args)
        if "flows" in self.fail:
            self._reject("flow-to-har", self.fail["flows"], {"success": False})
        return store.add("analysis", {"schema": "forge.flows/v1", "tool": "mitmproxy", "action": "flow-to-har",
                                      "success": True, "flows": self.flows, "flows_skipped": self.flows_skipped,
                                      "bodies_truncated": self.bodies_truncated, "reader": self.reader,
                                      "limit": args.limit, "max_body_bytes": args.max_body_bytes})

    def har_import(self, args, store):
        self.import_calls.append(args)
        if "import" in self.fail:
            self._reject("har-import", self.fail["import"], {"success": False})
        records = [store.add("har_exchange", {"source": "har_import", "request": {"method": "POST", "url": url},
                                              "response": {"status": 200, "truncated": False}, "bucket": "HIT",
                                              "replayable": False}) for url in self.urls]
        return {"exchanges": records, "imported": len(records), "available": len(records), "omitted": 0}


class GadgetCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.session = self.root / "run"
        self.session.mkdir()
        self.base = self.root / "base.apk"
        self.base.write_bytes(b"base-apk")
        self.splits = []
        for name in ("config.arm64_v8a.apk", "config.xxhdpi.apk"):
            path = self.root / name
            path.write_bytes(f"split-{name}".encode("utf-8"))
            self.splits.append(path)
        self.gadget = self.root / "frida-gadget-arm64.so"
        self.gadget.write_bytes(b"\x7fELF" + b"\0" * 60)
        self.custom = self.root / "custom.js"
        self.custom.write_text("// custom hook\n", encoding="utf-8")
        self.keystore = self.root / "release.jks"
        self.keystore.write_bytes(b"keystore")
        self.notes = self.root / "notes.txt"
        self.notes.write_text("not an apk\n", encoding="utf-8")
        self.environment = patch.dict(os.environ, {"FORGE_KEYSTORE_PASS": "fixture-password"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    # -- fixtures ---------------------------------------------------------
    def args(self, **changes):
        values = dict(package=PACKAGE, component=COMPONENT, apk=[str(self.base), *[str(path) for path in self.splits]],
                      gadget=str(self.gadget), gadget_config=None, path=str(self.session), script="builtin",
                      seconds=15, serial=None, mitm=False, keystore=str(self.keystore), alias="forge",
                      store_pass_env="FORGE_KEYSTORE_PASS", key_pass_env="FORGE_KEY_PASS", debug_keystore=False,
                      max_bytes=33554432, poll_seconds=10, timeout=120, budget=1800)
        values.update(changes)
        return argparse.Namespace(**values)

    def harness(self, runner=None, fake=None):
        runner = runner or Runner()
        fake = fake or Fake(self.store)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(forge_gadget, "_run", runner))
        stack.enter_context(patch.object(forge_gadget, "_sleep", lambda seconds: time.sleep(min(seconds, 0.02))))
        stack.enter_context(patch.object(forge_gadget, "executable",
                                        lambda name: f"fixture-{name}" if name == "adb" else "frida"))
        stack.enter_context(patch.object(forge_apktool, "gadget", fake.gadget))
        stack.enter_context(patch.object(forge_apktool, "sign", fake.sign))
        stack.enter_context(patch.object(forge_android, "adb_install_splits", fake.install))
        stack.enter_context(patch.object(forge_pcapdroid, "pcapdroid_preflight", fake.preflight))
        stack.enter_context(patch.object(forge_pcapdroid, "pcapdroid_capture", fake.capture))
        stack.enter_context(patch.object(forge_flows, "flow_to_har", fake.flow_to_har))
        stack.enter_context(patch.object(forge_network, "handle_har_import", fake.har_import))
        return fake, runner

    def run_capture(self, args):
        return forge_gadget.gadget_capture(args, self.store)

    def stage_records(self):
        records = self.store.list("analysis", 200) + self.store.list("runtime", 200)
        return [record for record in records if record["data"].get("action") == forge_gadget.ACTION]

    def stage_record(self, stage):
        matches = [record for record in self.stage_records() if record["data"]["stage"] == stage]
        self.assertTrue(matches, f"no evidence record for stage {stage}")
        return matches[0]

    def session_dir(self, name):
        directory = self.root / name
        directory.mkdir()
        return str(directory)

    # -- happy path -------------------------------------------------------
    def test_happy_path_summary_reports_every_stage(self):
        fake, runner = self.harness()
        summary = self.run_capture(self.args())
        data = summary["data"]
        self.assertEqual(summary["kind"], "analysis")
        self.assertEqual(data["schema"], forge_gadget.SCHEMA)
        self.assertIs(data["installed"], True)
        self.assertEqual(data["capture_id"], fake.capture_record["id"])
        self.assertEqual(data["flows"], 3)
        self.assertEqual(data["har_imported"], 3)
        self.assertEqual(data["endpoints_hint"], 3)
        self.assertEqual(data["hosts"], ["api.ai.x.grok", "cdn.other.example"])
        self.assertEqual(data["hosts_omitted"], 0)
        self.assertEqual(data["exchanges_omitted"], 0)
        self.assertEqual(data["bodies_truncated"], 1)
        self.assertIsNone(data["required_action"])
        self.assertIs(data["gadget_observed"], True)
        self.assertIn("forge-trust-bypass-loaded", data["hooks_observed"])
        self.assertIn("ssl-context-init-replaced", data["hooks_observed"])
        self.assertEqual(set(data["stage_evidence"]), set(forge_gadget.STAGES) - {"summary"})
        for stage, identifiers in data["stage_evidence"].items():
            with self.subTest(stage=stage):
                self.assertTrue(identifiers[0].startswith("ev_"))
                self.assertTrue(all(identifier.startswith("ev_") for identifier in identifiers))
        for identifier in data["evidence_ids"]:
            with self.subTest(identifier=identifier):
                self.store.get(identifier)
        for record in self.stage_records():
            if record["data"]["stage"] != "summary":
                self.assertIn(record["id"], data["evidence_ids"] + [summary["id"]])
        self.assertIn(fake.capture_record["id"], data["evidence_ids"])
        # no URL, path or token from the imported record is echoed anywhere in the summary
        text = json.dumps(summary["data"], ensure_ascii=False)
        for secret in ("secret", "/v1/one", "/v1/two", "token="):
            self.assertNotIn(secret, text)

    def test_happy_path_uses_one_identity_no_wait_launch_and_the_builtin_script(self):
        fake, runner = self.harness()
        self.run_capture(self.args())
        gadget = fake.gadget_calls[0]
        self.assertEqual(gadget.path, str(self.base))
        self.assertEqual(gadget.gadget, str(self.gadget))
        self.assertEqual(gadget.output, str(self.session / "base-gadget.apk"))
        self.assertEqual(gadget.gadget_config, ["on_load=resume"])
        expected_outputs = [self.session / "base-signed.apk", self.session / "split-01-signed.apk",
                            self.session / "split-02-signed.apk"]
        self.assertEqual(len(fake.sign_calls), 3)
        self.assertEqual([call.output for call in fake.sign_calls], [str(path) for path in expected_outputs])
        self.assertEqual([Path(call.keystore) for call in fake.sign_calls], [self.keystore] * 3)
        self.assertEqual({call.alias for call in fake.sign_calls}, {"forge"})
        self.assertEqual({call.debug_keystore for call in fake.sign_calls}, {False})
        self.assertEqual(fake.install_calls[0].installer, "com.android.vending")
        self.assertEqual(fake.install_calls[0].apk, [str(path) for path in expected_outputs])
        self.assertIsNone(fake.install_calls[0].archive)
        capture = fake.capture_calls[0]
        self.assertIs(capture.launch_no_wait, True)
        self.assertIs(capture.force_stop, True)
        self.assertIs(capture.tls_decryption, True)
        self.assertEqual(capture.launch, COMPONENT)
        self.assertEqual(capture.repeat, 1)
        self.assertEqual(capture.mitmproxy_opts, "-w /sdcard/Download/PCAPdroid/flows.dump")
        self.assertEqual(capture.path, str(self.session / "capture.pcap"))
        self.assertEqual(capture.serial, SERIAL)
        self.assertEqual(fake.flows_calls[0].reader, "builtin")
        self.assertEqual(fake.flows_calls[0].path, str(self.session / "flows.dump"))
        self.assertEqual(fake.flows_calls[0].output, str(self.session / "capture.har"))
        self.assertEqual(fake.import_calls[0].har, str(self.session / "capture.har"))
        attach = runner.attach_commands()[0]
        script, expected_script = attach[attach.index("-l") + 1], forge_gadget._builtin_script()[0]
        self.assertEqual(Path(script).resolve(), expected_script)
        self.assertEqual(attach[attach.index("-n") + 1], forge_gadget.GADGET_PROCESS)
        self.assertEqual(attach[attach.index("-H") + 1], forge_gadget.FRIDA_HOST)
        seconds = int(attach[attach.index("-t") + 1])
        self.assertGreater(seconds, 0)
        self.assertLessEqual(seconds, 15)
        self.assertIn(["-s", SERIAL, "forward", "tcp:27042", "tcp:27042"], runner.forwards())
        self.assertIn(["-s", SERIAL, "forward", "--remove", "tcp:27042"], runner.forwards())

    def test_hook_evidence_records_the_attach_and_markers(self):
        fake, runner = self.harness()
        summary = self.run_capture(self.args())
        hook = self.stage_record("hook")
        self.assertIs(hook["data"]["success"], True)
        self.assertEqual(hook["data"]["script_source"], "builtin")
        self.assertEqual(hook["data"]["script_sha256"], forge_gadget._hash_file(forge_gadget._builtin_script()[0]))
        self.assertIs(hook["data"]["gadget_observed"], True)
        self.assertGreaterEqual(hook["data"]["gadget_polls"], 1)
        self.assertGreater(hook["data"]["attach_seconds"], 0)
        self.assertEqual(hook["data"]["window_seconds"], 15)
        self.assertIn("conscrypt-verify-chain", hook["data"]["markers"] or [])
        self.assertEqual(hook["data"]["markers"], summary["data"]["hooks_observed"])
        self.assertIsNone(hook["data"]["required_action"])

    def test_custom_script_is_honoured_and_hashed(self):
        fake, runner = self.harness()
        summary = self.run_capture(self.args(script=str(self.custom)))
        hook = self.stage_record("hook")
        self.assertEqual(hook["data"]["script_source"], "caller")
        self.assertEqual(hook["data"]["script_sha256"], forge_gadget._hash_file(self.custom))
        attach = runner.attach_commands()[0]
        self.assertEqual(Path(attach[attach.index("-l") + 1]).resolve(), self.custom)
        self.assertIs(summary["data"]["installed"], True)

    # -- failures ---------------------------------------------------------
    def test_stage_failure_preserves_prior_evidence_and_names_the_action(self):
        cases = {
            "gadget": ("gadget",),
            "sign": ("gadget", "sign"),
            "install": ("gadget", "sign", "uninstall", "install"),
            "capture": ("gadget", "sign", "uninstall", "install", "preflight"),
        }
        for stage in cases:
            with self.subTest(stage=stage):
                fake, runner = self.harness()
                fake.fail[stage] = f"fixture {stage} failure"
                with self.assertRaises(ForgeError) as caught:
                    self.run_capture(self.args(path=self.session_dir(f"fail-{stage}")))
                message = str(caught.exception)
                self.assertIn(f"stopped at the {stage} stage", message)
                self.assertIn("Next: ", message)
                self.assertIn(REJECTION_ACTION, message)
                self.assertIn(f"fixture {stage} failure", message)
                record = self.stage_record(stage)
                self.assertIs(record["data"]["success"], False)
                self.assertEqual(record["data"]["required_action"], REJECTION_ACTION)
                self.assertIn(f"fixture {stage} failure", record["data"]["error"])
                self.assertIn(fake.rejection_id, record["data"]["evidence"])
                self.assertEqual([entry["data"]["stage"] for entry in self.stage_records()].count(stage), 1)
                for prior in cases[stage]:
                    if prior == stage:
                        continue
                    earlier = [entry for entry in self.stage_records()
                               if entry["data"]["stage"] == prior and entry["data"]["success"]]
                    self.assertTrue(earlier, f"{prior} evidence was not preserved for a failed {stage}")

    def test_capture_failure_cites_the_rejection_and_the_session(self):
        fake, runner = self.harness()
        fake.fail["capture"] = "Capture prerequisite missing: mitm-addon-absent"
        with self.assertRaises(ForgeError) as caught:
            self.run_capture(self.args())
        record = self.stage_record("capture")
        self.assertIn(fake.rejection_id, record["data"]["evidence"])
        self.assertIn(fake.session_id, record["data"]["evidence"])
        self.assertIn(fake.rejection_id, str(caught.exception))
        hook = self.stage_record("hook")
        self.assertIn(hook["id"], record["data"]["evidence"])
        self.assertEqual(fake.flows_calls, [])
        self.assertEqual(fake.import_calls, [])

    def test_hook_failure_stops_before_the_harvest(self):
        fake, runner = self.harness(runner=Runner(gadget=False))
        with self.assertRaises(ForgeError) as caught:
            self.run_capture(self.args(poll_seconds=1))
        message = str(caught.exception)
        self.assertIn("stopped at the hook stage", message)
        self.assertIn("force-stop", message)
        hook = self.stage_record("hook")
        self.assertIs(hook["data"]["gadget_observed"], False)
        self.assertEqual(hook["data"]["markers"], [])
        self.assertEqual(hook["data"]["required_action"], forge_gadget.HOOK_ACTION)
        self.assertIs(self.stage_record("capture")["data"]["success"], True)
        self.assertEqual(fake.flows_calls, [])

    def test_uninstall_absent_is_tolerated(self):
        fake, runner = self.harness()
        summary = self.run_capture(self.args())
        absent = self.stage_record("uninstall")
        self.assertIs(absent["data"]["absent"], True)
        self.assertIs(absent["data"]["success"], True)
        self.assertIs(absent["data"]["pm_uninstall"]["returncode"], 1)
        self.assertEqual(len(runner.uninstalls()), 1)
        self.assertEqual(len(fake.install_calls), 1)
        self.assertIs(summary["data"]["installed"], True)

    def test_uninstall_failure_stops_before_installing(self):
        fake, runner = self.harness(runner=Runner(uninstall_output="Failure [DELETE_FAILED_INTERNAL_ERROR]\n",
                                                  uninstall_code=1, path_output=f"package:/data/app/x/{PACKAGE}-y/base.apk\n"))
        with self.assertRaises(ForgeError) as caught:
            self.run_capture(self.args(path=self.session_dir("fail-uninstall")))
        self.assertIn("DELETE_FAILED_INTERNAL_ERROR", str(caught.exception))
        self.assertIn("Next: ", str(caught.exception))
        record = self.stage_record("uninstall")
        self.assertIs(record["data"]["success"], False)
        self.assertIn("--serial", record["data"]["required_action"])
        self.assertEqual(fake.install_calls, [])

    def test_preflight_prerequisites_stop_the_run(self):
        fake, runner = self.harness()
        fake.preflight_success = False
        fake.preflight_status = "capture-app-absent"
        with self.assertRaises(ForgeError) as caught:
            self.run_capture(self.args())
        self.assertIn("capture-app-absent", str(caught.exception))
        record = self.stage_record("preflight")
        self.assertEqual(record["data"]["required_action"], "fixture precondition: fix it")
        self.assertEqual(fake.capture_calls, [])

        fake, runner = self.harness()
        fake.capture_running = True
        with self.assertRaises(ForgeError) as caught:
            self.run_capture(self.args(path=self.session_dir("active-capture")))
        self.assertIn("already running", str(caught.exception))
        self.assertIn("Stop the running PCAPdroid capture", self.stage_record("preflight")["data"]["required_action"])
        self.assertEqual(fake.capture_calls, [])

    def test_mitm_refuses_without_the_addon_and_runs_without_the_flag(self):
        fake, runner = self.harness()
        fake.mitm_installed = False
        with self.assertRaises(ForgeError) as caught:
            self.run_capture(self.args(mitm=True))
        self.assertIn(forge_pcapdroid.MITM_PACKAGE, str(caught.exception))
        self.assertIn("Install the PCAPdroid mitm addon", self.stage_record("preflight")["data"]["required_action"])
        self.assertEqual(fake.capture_calls, [])

        fake, runner = self.harness()
        fake.mitm_installed = False
        summary = self.run_capture(self.args(mitm=False, path=self.session_dir("no-mitm-flag")))
        self.assertEqual(len(fake.capture_calls), 1)
        self.assertIs(self.stage_record("preflight")["data"]["mitm_addon_installed"], False)
        self.assertEqual(summary["data"]["flows"], 3)

    def test_flows_stage_failures_name_the_next_action(self):
        with self.subTest(case="pull"):
            fake, runner = self.harness(runner=Runner(pull=False))
            with self.assertRaises(ForgeError) as caught:
                self.run_capture(self.args())
            self.assertIn("could not pull", str(caught.exception))
            self.assertEqual(self.stage_record("flows")["data"]["required_action"], forge_gadget.FLOWS_ACTION)
            self.assertEqual(fake.flows_calls, [])
        with self.subTest(case="empty-dump"):
            fake, runner = self.harness(runner=Runner(pull_empty=True))
            with self.assertRaises(ForgeError) as caught:
                self.run_capture(self.args(path=self.session_dir("empty-dump")))
            self.assertIn("empty", str(caught.exception))
            self.assertEqual(self.stage_record("flows")["data"]["dump_size"], 0)
            self.assertEqual(fake.flows_calls, [])
        with self.subTest(case="flow-to-har"):
            fake, runner = self.harness()
            fake.fail["flows"] = "flow-to-har rejected the dump"
            with self.assertRaises(ForgeError) as caught:
                self.run_capture(self.args(path=self.session_dir("bad-dump")))
            record = self.stage_record("flows")
            self.assertIn(fake.rejection_id, record["data"]["evidence"])
            self.assertEqual(record["data"]["required_action"], REJECTION_ACTION)
            self.assertEqual(fake.import_calls, [])
        with self.subTest(case="har-import"):
            fake, runner = self.harness()
            fake.fail["import"] = "har-import rejected the document"
            with self.assertRaises(ForgeError) as caught:
                self.run_capture(self.args(path=self.session_dir("bad-har")))
            self.assertIn("har-import rejected the document", str(caught.exception))
            self.assertEqual(fake.flows_calls[0].reader, "builtin")

    def test_zero_flows_summary_names_the_next_action(self):
        fake, runner = self.harness(fake=Fake(self.store))
        fake.flows, fake.urls = 0, []
        summary = self.run_capture(self.args())
        data = summary["data"]
        self.assertEqual(data["flows"], 0)
        self.assertEqual(data["har_imported"], 0)
        self.assertEqual(data["endpoints_hint"], 0)
        self.assertIn("--seconds", data["required_action"])
        self.assertEqual(data["required_action"], self.stage_record("summary")["data"]["required_action"])

    def test_budget_stop_keeps_earlier_evidence(self):
        class DriftClock:
            def __init__(self, step):
                self.step, self.value = step, 0.0

            def monotonic(self):
                self.value += self.step
                return self.value

            def sleep(self, seconds):
                self.value += seconds

        fake, runner = self.harness()
        with patch.object(forge_gadget, "time", DriftClock(20)):
            with self.assertRaises(ForgeError) as caught:
                self.run_capture(self.args(budget=60))
        message = str(caught.exception)
        self.assertIn("budget", message)
        self.assertIn("--budget", self.stage_record("uninstall")["data"]["required_action"])
        self.assertTrue([record for record in self.stage_records()
                         if record["data"]["stage"] == "gadget" and record["data"]["success"]])
        self.assertEqual(fake.capture_calls, [])

    # -- keys and script --------------------------------------------------
    def test_debug_keystore_materialises_one_identity_for_the_run(self):
        fake, runner = self.harness()
        keystore = self.session / "forge-debug.keystore"
        identity = (keystore, "androiddebugkey", forge_apktool.DEBUG_PASSWORD, forge_apktool.DEBUG_PASSWORD, True)
        with patch.object(forge_gadget, "_debug_identity", return_value=identity) as creation:
            summary = self.run_capture(self.args(keystore=None, alias=None, debug_keystore=True))
        self.assertEqual(creation.call_count, 1)
        self.assertEqual([Path(call.keystore) for call in fake.sign_calls], [keystore] * 3)
        self.assertEqual({call.alias for call in fake.sign_calls}, {"androiddebugkey"})
        self.assertEqual({call.store_pass_env for call in fake.sign_calls}, {forge_gadget.STORE_ENV})
        self.assertEqual({password for _, password in fake.environ_seen}, {forge_apktool.DEBUG_PASSWORD})
        self.assertNotIn(forge_gadget.STORE_ENV, os.environ)
        self.assertNotIn(forge_gadget.KEY_ENV, os.environ)
        self.assertIs(self.stage_record("sign")["data"]["identity_generated"], True)
        self.assertIs(summary["data"]["installed"], True)

    def test_keystore_inputs_are_validated_before_any_stage(self):
        fake, runner = self.harness()
        with self.assertRaisesRegex(ForgeError, "not both"):
            self.run_capture(self.args(debug_keystore=True))
        with self.assertRaisesRegex(ForgeError, "Provide --keystore"):
            self.run_capture(self.args(keystore=None, debug_keystore=False))
        with self.assertRaisesRegex(ForgeError, "does not hold the keystore password"):
            with patch.dict(os.environ, {"FORGE_KEYSTORE_PASS": ""}):
                self.run_capture(self.args())
        with self.assertRaisesRegex(ForgeError, "--alias"):
            self.run_capture(self.args(alias=None))
        with self.assertRaisesRegex(ForgeError, "must stay inside the project"):
            self.run_capture(self.args(keystore=str(self.root.parent / "outside.jks")))
        self.assertEqual(fake.sign_calls, [])
        self.assertEqual(fake.gadget_calls, [])
        self.assertEqual(runner.commands, [])

    def test_invalid_inputs_never_reach_a_stage(self):
        cases = [
            {"apk": []},
            {"apk": [str(self.base), str(self.notes)]},
            {"apk": [str(self.base), str(self.root.parent / "outside.apk")]},
            {"apk": ["missing.apk"]},
            {"gadget": str(self.custom)},
            {"gadget": "missing.so"},
            {"path": str(self.root / "missing-directory")},
            {"path": "../outside"},
            {"path": str(self.base)},
            {"script": "missing.js"},
            {"script": str(self.notes)},
            {"package": "invalid"},
            {"package": "other.pkg", "component": COMPONENT},
            {"component": "not-a-component"},
            {"component": "ai.x.grok/"},
            {"serial": "bad serial"},
            {"seconds": 0},
            {"seconds": 301},
            {"poll_seconds": 0},
            {"poll_seconds": 11},
            {"budget": 10},
            {"budget": 100000},
            {"timeout": 0},
            {"max_bytes": 10},
            {"gadget_config": ["on_load"]},
            {"gadget_config": ["=wait"]},
            {"mitm": "yes"},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                fake, runner = self.harness()
                with self.assertRaises(ForgeError):
                    self.run_capture(self.args(**changes))
                self.assertEqual(fake.gadget_calls, [])
                self.assertEqual(runner.commands, [])

    def test_existing_run_outputs_are_refused(self):
        (self.session / "capture.pcap").write_bytes(b"old")
        fake, runner = self.harness()
        with self.assertRaisesRegex(ForgeError, "already exists"):
            self.run_capture(self.args())
        self.assertEqual(fake.gadget_calls, [])

    def test_offline_task_scope_refuses_before_any_stage(self):
        forge_tasks.initialize(argparse.Namespace(target="https://example.test/app", goal="fixture goal",
                                                 authorization="granted", basis="own_system",
                                                 network_profile="offline", in_scope=None, out_of_scope=None),
                               self.store, ["mobile_graphql"])
        fake, runner = self.harness()
        with self.assertRaisesRegex(ForgeError, "offline"):
            self.run_capture(self.args())
        self.assertEqual(fake.gadget_calls, [])
        self.assertEqual(runner.commands, [])

    def test_missing_host_tools_are_named_before_any_stage(self):
        fake, runner = self.harness()
        def missing(name):
            if name == "frida":
                raise ForgeError("Missing frida (FORGE/tools): Install frida-tools in FORGE/tools/frida venv")
            return f"fixture-{name}"

        with patch.object(forge_gadget, "executable", missing):
            with self.assertRaisesRegex(ForgeError, "frida-tools"):
                self.run_capture(self.args())
        self.assertEqual(fake.gadget_calls, [])

    def test_shipped_trust_bypass_script_exists_and_is_loadable(self):
        path, candidates = forge_gadget._builtin_script()
        self.assertIsNotNone(path, f"candidates: {candidates}")
        self.assertEqual(path.name, forge_gadget.SCRIPT_NAME)
        self.assertIn("scripts", path.parts)
        content = path.read_text(encoding="utf-8")
        for needle in ("Java.perform", "Java.registerClass", "javax.net.ssl.X509TrustManager",
                       "javax.net.ssl.SSLContext", "SSLContext.init.overload", "okhttp3.CertificatePinner",
                       "check$okhttp", "com.android.org.conscrypt.TrustManagerImpl", "verifyChain",
                       "com.android.org.conscrypt.ConscryptEngineSocket", "verifyCertificateChain",
                       "return arguments[0]", "send('", "forge-trust-bypass-loaded"):
            with self.subTest(needle=needle):
                self.assertIn(needle, content)
        self.assertNotIn("checkTrustedRecursive.overloads", content,
                         "the docstring may name it, the hook must not exist")
        for marker in ("ssl-context-init-replaced", "forge-trust-bypass-loaded", "conscrypt-verify-chain",
                       "conscrypt-engine-verify", "certificate-pinner-"):
            with self.subTest(marker=marker):
                self.assertIn(marker, content)
        self.assertIs(forge_gadget._script(self.store, forge_gadget.BUILTIN)[1], forge_gadget.BUILTIN)

    def test_stage_namespaces_cover_every_registered_flag(self):
        fake, runner = self.harness()
        self.run_capture(self.args())
        subparsers = next(action for action in forge.parser()._actions
                          if isinstance(action, argparse._SubParsersAction))
        observed = {"apk-gadget": fake.gadget_calls[0], "apk-sign": fake.sign_calls[0],
                    "adb-install-splits": fake.install_calls[0], "pcapdroid-preflight": fake.preflight_calls[0],
                    "pcapdroid-capture": fake.capture_calls[0], "flow-to-har": fake.flows_calls[0],
                    "har-import": fake.import_calls[0]}
        for command, namespace in observed.items():
            with self.subTest(command=command):
                registered = {action.dest for action in subparsers.choices[command]._actions if action.dest != "help"}
                self.assertTrue(registered.issubset(set(vars(namespace))),
                                f"{command} reads {sorted(registered - set(vars(namespace)))}")


if __name__ == "__main__":
    unittest.main()
