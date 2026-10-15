import argparse
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_runtime
import forge_android


def result(stdout=b"", code=0, stderr=b"", expired=False):
    return code, stdout if isinstance(stdout, bytes) else stdout.encode(), \
        stderr if isinstance(stderr, bytes) else stderr.encode(), expired


class RuntimeActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_runtime.register(self.parser.add_subparsers())
        self.serial = "owned-fixture"
        self.adb = self.root / "adb"

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def run_with(self, handler):
        def run(command, timeout):
            if command[1:] == ["devices", "-l"]:
                return result(f"List of devices attached\n{self.serial} device product:fixture\n")
            return handler(command, timeout)
        return run

    def invoke(self, handler, *argv):
        with patch.object(forge_runtime, "executable", return_value=str(self.adb)), \
                patch.object(forge_runtime, "_run", side_effect=self.run_with(handler)):
            return self.command(*argv)

    def last_record(self, action):
        return next(record["data"] for record in self.store.list()
                    if record["data"].get("action") == action)

    def test_devices_records_the_same_shape_as_other_actions(self):
        record = self.invoke(lambda command, timeout: result(), "adb", "devices", "--serial", self.serial)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertEqual(data["serial"], self.serial)
        self.assertEqual(data["devices"][0]["serial"], self.serial)
        self.assertEqual(data["returncode"], 0)

    def test_pull_writes_one_new_project_file_and_records_hash(self):
        payload = b"owned-pulled-bytes" * 64
        handler = lambda command, timeout: (Path(command[-1]).write_bytes(payload), result(b"1 file pulled"))[1]
        record = self.invoke(handler, "adb", "pull", "--serial", self.serial,
                             "--remote", "/data/local/tmp/sample.bin", "--path", "sample.bin")
        destination = self.root / "sample.bin"
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(record["data"]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(record["data"]["size"], len(payload))
        self.assertEqual(record["data"]["path"], "sample.bin")

    def test_pull_refuses_overwrite_traversal_and_missing_remote(self):
        (self.root / "taken.bin").write_bytes(b"existing")
        handler = lambda command, timeout: result(b"1 file pulled")
        for path, message in (("taken.bin", "already exists"), ("../escape.bin", "inside the project")):
            with self.assertRaisesRegex(ForgeError, message):
                self.invoke(handler, "adb", "pull", "--serial", self.serial,
                            "--remote", "/data/local/tmp/sample.bin", "--path", path)
        with self.assertRaisesRegex(ForgeError, "must be absolute"):
            self.invoke(handler, "adb", "pull", "--serial", self.serial,
                        "--remote", "relative/path", "--path", "new.bin")
        with self.assertRaisesRegex(ForgeError, "must not contain"):
            self.invoke(handler, "adb", "pull", "--serial", self.serial,
                        "--remote", "/data/../etc/passwd", "--path", "new.bin")
        self.assertFalse((self.root / "escape.bin").exists())

    def test_pull_rejects_directories_caps_and_leaves_no_partial_file(self):
        def directory(command, timeout):
            Path(command[-1]).mkdir()
            return result(b"0 files pulled")
        with self.assertRaisesRegex(ForgeError, "directories are not supported"):
            self.invoke(directory, "adb", "pull", "--serial", self.serial,
                        "--remote", "/data/local/tmp/dir", "--path", "dir.bin")
        self.assertFalse((self.root / "dir.bin").exists())

        def oversized(command, timeout):
            Path(command[-1]).write_bytes(b"A" * 4096)
            return result(b"1 file pulled")
        with self.assertRaisesRegex(ForgeError, "exceeds --max-bytes"):
            self.invoke(oversized, "adb", "pull", "--serial", self.serial,
                        "--remote", "/data/local/tmp/big.bin", "--path", "big.bin", "--max-bytes", "1024")
        self.assertFalse((self.root / "big.bin").exists())

    def test_pull_failure_is_recorded_with_remote_and_no_file(self):
        def failing(command, timeout):
            return result(b"", code=1, stderr=b"adb: error: failed to stat remote object")
        with self.assertRaisesRegex(ForgeError, "ADB pull failed"):
            self.invoke(failing, "adb", "pull", "--serial", self.serial,
                        "--remote", "/data/local/tmp/absent.bin", "--path", "absent.bin")
        record = self.last_record("pull")
        self.assertFalse(record["success"])
        self.assertEqual(record["remote"], "/data/local/tmp/absent.bin")
        self.assertFalse((self.root / "absent.bin").exists())

    def test_push_requires_one_project_file(self):
        with self.assertRaisesRegex(ForgeError, "regular project-local file"):
            self.invoke(lambda command, timeout: result(), "adb", "push", "--serial", self.serial,
                        "--path", "missing.js", "--remote", "/data/local/tmp/hook.js")
        (self.root / "hook.js").write_text("Java.perform(function () {});")
        calls = []

        def pushing(command, timeout):
            calls.append(command)
            return result(b"1 file pushed")
        self.invoke(pushing, "adb", "push", "--serial", self.serial,
                    "--path", "hook.js", "--remote", "/data/local/tmp/hook.js")
        self.assertEqual(calls[-1][3:], ["push", str(self.root / "hook.js"), "/data/local/tmp/hook.js"])

    def test_packages_lists_filters_and_reports_names(self):
        listing = "package:com.example.alpha\npackage:com.example.beta\npackage:com.android.settings\n"

        def listing_run(command, timeout):
            self.assertIn("pm", command)
            return result(listing)
        record = self.invoke(listing_run, "adb", "packages", "--serial", self.serial, "--third-party")
        self.assertEqual(record["data"]["stdout"].splitlines(),
                         ["com.example.alpha", "com.example.beta", "com.android.settings"])
        record = self.invoke(listing_run, "adb", "packages", "--serial", self.serial, "--filter", "ALPHA")
        self.assertEqual(record["data"]["stdout"], "com.example.alpha")

    def test_package_reports_observed_paths_and_facts(self):
        def inspecting(command, timeout):
            if "path" in command:
                return result(b"package:/data/app/~~abc==/com.example.app-xyz==/base.apk\n"
                              b"package:/data/app/~~abc==/com.example.app-xyz==/split_config.en.apk\n")
            return result(b"    versionCode=280 minSdk=32 targetSdk=34\n"
                          b"    versionName=2.6.1\n    primaryCpuAbi=arm64-v8a\n"
                          b"    splitNames=[config.en]\n")
        record = self.invoke(inspecting, "adb", "package", "--serial", self.serial, "--package", "com.example.app")
        facts = record["data"]["facts"]
        self.assertEqual(facts["version_name"], "2.6.1")
        self.assertEqual(facts["version_code"], "280")
        self.assertEqual(facts["primary_cpu_abi"], "arm64-v8a")
        self.assertEqual(facts["split_names"], ["config.en"])
        self.assertEqual(len(facts["code_paths"]), 2)
        self.assertFalse(facts["truncated"])

    def test_pull_package_copies_the_installed_base_and_splits_with_hashes(self):
        (self.root / "installed").mkdir()
        payloads = {"base.apk": b"base-apk-fixture", "split_config.en.apk": b"split-apk-fixture"}
        paths = ("/data/app/pkg/base.apk", "/data/app/pkg/split_config.en.apk")

        def pulling(command, timeout):
            if command[3:] == ["shell", "pm", "path", "com.example.app"]:
                return result("".join(f"package:{path}\n" for path in paths))
            if command[3:6] == ["shell", "dumpsys", "package"]:
                return result("versionCode=280 versionName=2.6.1 primaryCpuAbi=arm64-v8a splitNames=[config.en]")
            if "pull" in command:
                Path(command[-1]).write_bytes(payloads[Path(command[-2]).name])
                return result("1 file pulled")
            return result(code=1, stderr="unexpected command")

        manifests = [{"package": "com.example.app", "split": None},
                     {"package": "com.example.app", "split": "config.en"}]
        with patch.object(forge_android, "inspect_apk", side_effect=manifests):
            record = self.invoke(pulling, "adb", "pull-package", "--serial", self.serial,
                                 "--package", "com.example.app", "--path", "installed/grok")
        data = record["data"]
        output = self.root / "installed" / "grok"
        self.assertTrue(data["success"])
        self.assertEqual(data["package_facts"]["version_name"], "2.6.1")
        self.assertEqual([row["filename"] for row in data["files"]], list(payloads))
        self.assertEqual((output / "base.apk").read_bytes(), payloads["base.apk"])
        self.assertEqual(data["files"][1]["sha256"], hashlib.sha256(payloads["split_config.en.apk"]).hexdigest())
        self.assertEqual(data["bytes_pulled"], sum(map(len, payloads.values())))

    def test_pull_package_failure_publishes_no_partial_directory(self):
        (self.root / "installed").mkdir()
        calls = 0

        def failing(command, timeout):
            nonlocal calls
            if command[3:] == ["shell", "pm", "path", "com.example.app"]:
                return result("package:/data/app/pkg/base.apk\npackage:/data/app/pkg/split.apk\n")
            if command[3:6] == ["shell", "dumpsys", "package"]:
                return result("versionName=1 versionCode=1")
            if "pull" in command:
                calls += 1
                if calls == 1:
                    Path(command[-1]).write_bytes(b"base")
                    return result("1 file pulled")
                return result(code=1, stderr="permission denied")
            return result(code=1, stderr="unexpected command")

        with self.assertRaisesRegex(ForgeError, "ADB pull failed for installed split"):
            self.invoke(failing, "adb", "pull-package", "--serial", self.serial,
                        "--package", "com.example.app", "--path", "installed/grok")
        self.assertFalse((self.root / "installed" / "grok").exists())
        self.assertFalse(self.last_record("pull-package")["success"])

    def test_pull_package_rejects_manifest_package_mismatch_without_publishing(self):
        (self.root / "installed").mkdir()

        def pulling(command, timeout):
            if command[3:] == ["shell", "pm", "path", "com.example.app"]:
                return result("package:/data/app/pkg/base.apk\n")
            if command[3:6] == ["shell", "dumpsys", "package"]:
                return result("versionName=1 versionCode=1")
            if "pull" in command:
                Path(command[-1]).write_bytes(b"fixture-apk")
                return result("1 file pulled")
            return result()

        with patch.object(forge_android, "inspect_apk", return_value={"package": "com.other.app"}):
            with self.assertRaisesRegex(ForgeError, "declares package com.other.app"):
                self.invoke(pulling, "adb", "pull-package", "--serial", self.serial,
                            "--package", "com.example.app", "--path", "installed/example")
        self.assertFalse((self.root / "installed" / "example").exists())
        self.assertFalse(self.last_record("pull-package")["success"])

    def test_observe_captures_only_target_pids_in_a_bounded_time_window(self):
        dates = iter(("1700000000\n", "1700000010\n"))
        log = ("1700000001.100  123  456 I Grok: observed request host api.example.test\n"
               "1700000001.200  999  999 I Other: unrelated\n"
               "1700000011.100  123  456 I Grok: after session\n")

        def observing(command, timeout):
            if command[3:7] == ["shell", "ps", "-A", "-o"]:
                return result("PID NAME\n123 com.example.app\n")
            if command[3:6] == ["shell", "date", "+%s"]:
                return result(next(dates))
            if "logcat" in command:
                return result(log)
            return result(code=1, stderr="unexpected command")

        with patch.object(forge_runtime.time, "sleep") as sleep:
            record = self.invoke(observing, "adb", "observe", "--serial", self.serial,
                                 "--package", "com.example.app", "--seconds", "10", "--lines", "20")
        data = record["data"]
        self.assertEqual(sleep.call_args.args, (10,))
        self.assertEqual(data["device_epoch_start"], 1700000000)
        self.assertEqual(data["device_epoch_end"], 1700000010)
        self.assertEqual(data["logcat_line_count"], 1)
        self.assertEqual(data["logcat_line_cap_per_pid"], 20)
        self.assertIn("api.example.test", data["logcat_lines"][0])
        self.assertTrue(data["success"])
        self.assertIn("does not capture or decrypt HTTP traffic", data["scope"])

    def test_observe_requires_the_app_to_be_running(self):
        def no_process(command, timeout):
            if command[3:7] == ["shell", "ps", "-A", "-o"]:
                return result("PID NAME\n")
            return result("1700000000\n")

        with self.assertRaisesRegex(ForgeError, "Target app is not running"):
            self.invoke(no_process, "adb", "observe", "--serial", self.serial,
                        "--package", "com.example.app", "--seconds", "2")
        self.assertFalse(self.last_record("observe")["success"])

    def test_observe_ui_snapshots_are_opt_in_and_remote_files_are_removed(self):
        dates = iter(("1700000000\n", "1700000002\n"))
        commands = []

        def observing(command, timeout):
            commands.append(command)
            if command[3:7] == ["shell", "ps", "-A", "-o"]:
                return result("PID NAME\n123 com.example.app\n")
            if command[3:6] == ["shell", "date", "+%s"]:
                return result(next(dates))
            if "uiautomator" in command:
                return result("UI hierarchy dumped")
            if command[3:5] == ["exec-out", "cat"]:
                return result('<hierarchy text="Settings"/>')
            if "logcat" in command:
                return result("1700000001.000 123 456 I App: tap\n")
            return result()

        with patch.object(forge_runtime.time, "sleep"):
            record = self.invoke(observing, "adb", "observe", "--serial", self.serial,
                                 "--package", "com.example.app", "--seconds", "2", "--ui-snapshots")
        ui = record["data"]["ui_snapshots"]
        self.assertEqual(ui["before"]["xml"], '<hierarchy text="Settings"/>')
        self.assertEqual(ui["after"]["xml"], '<hierarchy text="Settings"/>')
        self.assertEqual(sum(1 for command in commands if command[3:5] == ["shell", "rm"]), 2)


    def test_observe_logcat_failure_is_not_reported_as_a_successful_session(self):
        dates = iter(("1700000000\n", "1700000002\n"))

        def failing(command, timeout):
            if command[3:7] == ["shell", "ps", "-A", "-o"]:
                return result("PID NAME\n123 com.example.app\n")
            if command[3:6] == ["shell", "date", "+%s"]:
                return result(next(dates))
            if "logcat" in command:
                return result(code=1, stderr="logcat permission denied")
            return result()

        with patch.object(forge_runtime.time, "sleep"):
            with self.assertRaisesRegex(ForgeError, "logcat observation failed"):
                self.invoke(failing, "adb", "observe", "--serial", self.serial,
                            "--package", "com.example.app", "--seconds", "2")
        self.assertFalse(self.last_record("observe")["success"])
    def test_ui_tree_retries_after_a_non_idle_window(self):
        attempts = []

        def dumping(command, timeout):
            if "KEYCODE_WAKEUP" in command:
                return result()
            if "uiautomator" in command:
                attempts.append(1)
                if len(attempts) == 1:
                    return result(code=0, stderr=b"ERROR: could not get idle state.")
                return result(b"UI hierchary dumped to: /data/local/tmp/forge-ui.xml")
            return result(b"<hierarchy/>")
        record = self.invoke(dumping, "adb", "ui-tree", "--serial", self.serial)
        self.assertEqual(len(attempts), 2)
        self.assertTrue(record["data"]["success"])
        self.assertEqual(record["data"]["stdout"], "<hierarchy/>")

    def test_ui_tree_failure_names_the_window_limitation(self):
        def dumping(command, timeout):
            if "KEYCODE_WAKEUP" in command:
                return result()
            return result(code=0, stderr=b"ERROR: could not get idle state.")
        with self.assertRaisesRegex(ForgeError, "failed after retry"):
            self.invoke(dumping, "adb", "ui-tree", "--serial", self.serial)
        record = self.last_record("ui-tree")
        self.assertFalse(record["success"])
        self.assertIn("quiescent", record["limitation"])


class FridaPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_runtime.register(self.parser.add_subparsers())
        suffix = ".exe" if os.name == "nt" else ""
        self.launcher = self.root / f"frida{suffix}"
        self.launcher.write_bytes(b"")
        (self.root / f"frida-ps{suffix}").write_bytes(b"")
        (self.root / "hook.js").write_text("Java.perform(function () {});")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def invoke(self, listing_result, hook_result):
        def run(command, timeout):
            return listing_result if "frida-ps" in command[0] else hook_result
        with patch.object(forge_runtime, "executable", return_value=str(self.launcher)), \
                patch.object(forge_runtime, "_run", side_effect=run):
            args = self.parser.parse_args(["frida", "--package", "com.example.app", "--script", "hook.js",
                                           "--duration", "5"])
            return args.handler(args, self.store)

    def test_unreachable_device_fails_before_the_hook_runs(self):
        def run(command, timeout):
            self.assertNotIn("-l", command)
            return result(code=1, stderr=b"Failed to connect to remote frida-server")
        with patch.object(forge_runtime, "executable", return_value=str(self.launcher)), \
                patch.object(forge_runtime, "_run", side_effect=run):
            args = self.parser.parse_args(["frida", "--package", "com.example.app", "--script", "hook.js",
                                           "--duration", "5"])
            with self.assertRaisesRegex(ForgeError, "prerequisite missing"):
                args.handler(args, self.store)
        record = next(record["data"] for record in self.store.list()
                      if record["data"].get("action") == "frida-prerequisite")
        self.assertFalse(record["success"])

    def test_jailed_android_spawn_is_named_as_the_blocker(self):
        with self.assertRaisesRegex(ForgeError, "jailed Android cannot be spawned"):
            self.invoke(result(b"  PID  Name\n1234  system_server\n"),
                        result(code=1, stdout=b"Failed to spawn: need Gadget to attach on jailed Android\n"))

    def test_unreachable_server_at_spawn_is_named_as_the_blocker(self):
        with self.assertRaisesRegex(ForgeError, "no reachable hook transport"):
            self.invoke(result(b"  PID  Name\n1234  system_server\n"),
                        result(code=1, stderr=b"frida: unable to connect to remote frida-server"))

    def gadget_args(self, extra=()):
        return self.parser.parse_args(["frida", "--package", "Gadget", "--script", "hook.js", "--duration", "5", *extra])

    def test_gadget_host_attaches_over_the_forwarded_port_and_removes_it(self):
        calls = []

        def run(command, timeout):
            calls.append(list(command))
            if "frida-ps" in command[0]:
                return result(b"  PID  Name\n16320  Gadget\n")
            if "forward" in command:
                return result(b"27042\n")
            return result(code=0, stdout=b"[FORGE] java=true\n")

        args = self.gadget_args(["--host", "127.0.0.1:27042", "--forward", "27042", "--attach"])
        with patch.object(forge_runtime, "executable", return_value=str(self.launcher)), \
                patch.object(forge_runtime, "_run", side_effect=run):
            record = args.handler(args, self.store)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertEqual(data["transport"]["mode"], "gadget-host")
        self.assertEqual(data["transport"]["forwarded_port"], 27042)
        self.assertEqual(data["transport"]["forward"]["returncode"], 0)
        hook = [call for call in calls if "-l" in call][0]
        self.assertEqual(hook[1:5], ["-H", "127.0.0.1:27042", "-n", "Gadget"])
        self.assertNotIn("-U", hook)
        self.assertIn(["forward", "--remove", "tcp:27042"], [call[1:] for call in calls])

    def test_gadget_host_requires_attach_and_a_well_formed_host(self):
        cases = ((["--host", "127.0.0.1", "--attach"], "--host must be HOST:PORT"),
                 (["--host", "127.0.0.1:27042"], "requires --attach"),
                 (["--host", "127.0.0.1:27042", "--attach", "--forward", "70000"], "between 1 and 65535"),
                 (["--forward", "27042", "--attach"], "--forward needs --host"))
        for extra, message in cases:
            with self.subTest(extra=extra), self.assertRaisesRegex(ForgeError, message):
                args = self.gadget_args(extra)
                args.handler(args, self.store)

    def test_failed_forward_is_recorded_and_never_runs_the_hook(self):
        def run(command, timeout):
            if "forward" in command:
                return result(code=1, stderr=b"error: cannot bind listener")
            return result(b"  PID  Name\n")

        args = self.gadget_args(["--host", "127.0.0.1:27042", "--forward", "27042", "--attach"])
        with patch.object(forge_runtime, "executable", return_value=str(self.launcher)), \
                patch.object(forge_runtime, "_run", side_effect=run) as mocked:
            with self.assertRaisesRegex(ForgeError, "port forward failed"):
                args.handler(args, self.store)
        self.assertFalse(any("-l" in call.args[0] for call in mocked.call_args_list))
        actions = [record["data"].get("action") for record in self.store.list()]
        self.assertIn("frida-forward", actions)

    def test_unclassified_failure_stays_a_generic_session_error(self):
        with self.assertRaisesRegex(ForgeError, "did not complete"):
            self.invoke(result(b"  PID  Name\n1234  system_server\n"),
                        result(code=1, stderr=b"TypeError: cannot read property 'x' of undefined"))


if __name__ == "__main__":
    unittest.main()
