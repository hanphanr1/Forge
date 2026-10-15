import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import forge_pcapdroid as pcapdroid
from forge_core import EvidenceStore, ForgeError


SERIAL = "b519558f"
PACKAGE = "ai.x.grok"
LAUNCH = "ai.x.grok/.MainActivity"
SESSION_PATH = "captures/session"
PCAP_HEADER = b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00" + b"\x00" * 8 + b"\x00\x08\x00\x00" + b"\x01\x00\x00\x00"
# Synthesized addon logcat tail in the shape the device produces: two rejections for one host
# (one of them upper-cased with a trailing dot), one wrapped onto a second line, one without a
# host at all, plus an unrelated request line whose URL must never reach evidence.
LOGCAT_TAIL = (
    "10-15 21:04:01.010  4211  4310 D mitmproxy: [127.0.0.1:43036] Client TLS handshake failed. The client does not "
    "trust the proxy's certificate for grok.com (OpenSSL Error([('SSL routines', '', 'sslv3 alert certificate "
    "unknown')]))\n"
    "10-15 21:04:01.220  4211  4310 I mitmproxy: GET https://grok.com/_data/v1/app_config HTTP/2.0 200\n"
    "10-15 21:04:02.010  4211  4311 D mitmproxy: [127.0.0.1:43044] Client TLS handshake failed. The client does not "
    "trust the proxy's certificate for Grok.com. (OpenSSL Error(...))\n"
    "10-15 21:04:02.510  4211  4312 D mitmproxy: [127.0.0.1:43050] Client TLS handshake failed. The client does not "
    "trust the proxy's\ncertificate for api.x.ai (OpenSSL Error(...))\n"
    "10-15 21:04:03.010  4211  4313 W mitmproxy: Client TLS handshake failed. The client does not trust the proxy's "
    "certificate (no SNI)\n"
    "10-15 21:04:03.500  3102  3102 I ActivityManager: unrelated line\n")
REJECTION_HOSTS = {"grok.com": 2, "api.x.ai": 1, pcapdroid.UNATTRIBUTED_HOST: 1}


def pcap_bytes(payload=b""):
    return PCAP_HEADER + payload


def call_result(stdout="", code=0, stderr="", expired=False, omitted_out=0, omitted_err=0, binary=False):
    return {"returncode": None if expired else code, "timed_out": expired, "launch_error": None,
            "stdout": b"" if binary and not isinstance(stdout, bytes) else stdout, "stderr": stderr,
            "stdout_omitted_bytes": omitted_out, "stderr_omitted_bytes": omitted_err}


class FakeClock:
    """Deterministic clock: sleeps advance fake time instead of blocking."""

    def __init__(self, start=1000.0):
        self.value = start

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += max(float(seconds), 0.25)


class Device:
    """Fake ADB backend holding the observed PCAPdroid service/file state machine."""

    def __init__(self, *, installed=True, target_installed=True, capture_running=False, consent=True,
                 stop_works=True, header_valid=True, payload=b"", truncate_service=False, start_error=False,
                 device_size=None, create_file=True, defer_data=False, truncate_package=False, am_echo="",
                 devices=None, adb="configured-adb", launch_error=False, force_stop_error=False,
                 mitm_installed=False, logcat="", logcat_error=None, logcat_omitted=0):
        self.adb = adb
        self.mitm_installed = mitm_installed
        self.installed = installed
        self.target_installed = target_installed
        self.capture_running = capture_running
        self.consent = consent
        self.stop_works = stop_works
        self.header_valid = header_valid
        self.payload = payload
        self.truncate_service = truncate_service
        self.start_error = start_error
        self.truncate_package = truncate_package
        self.device_size = device_size
        self.create_file = create_file
        self.defer_data = defer_data
        self.am_echo = am_echo
        self.launch_error = launch_error
        self.force_stop_error = force_stop_error
        self.logcat_text = logcat
        self.logcat_error = logcat_error
        self.logcat_omitted = logcat_omitted
        self.devices = [{"serial": SERIAL, "state": "device"}] if devices is None else devices
        self.file = None
        self.remote_path = None
        self.commands = []
        self.launched = []
        self.force_stopped = []

    # -- command dispatch -------------------------------------------------
    def __call__(self, command, timeout, binary=False):
        argv = [str(item) for item in command]
        self.commands.append(argv)
        tail = argv[1:]
        if tail == ["version"]:
            return call_result("Android Debug Bridge version 1.0.41\n")
        if tail == ["devices", "-l"]:
            return call_result("List of devices attached\n"
                               + "".join(f"{item['serial']}\t{item['state']}\n" for item in self.devices))
        if tail[:2] == ["-s", SERIAL]:
            rest = tail[2:]
            if rest[:1] == ["shell"]:
                return self.shell(rest[1:])
            if rest[:1] == ["exec-out"]:
                return self.exec_out(rest[1:], binary)
            if rest[:1] == ["pull"]:
                return self.pull(rest[1], rest[2])
            if rest[:1] == ["logcat"]:
                return self.logcat(rest)
        raise AssertionError(f"unexpected ADB command: {argv}")

    def am_commands(self):
        return [command for command in self.commands if "am" in command]

    def launch_rest(self):
        """The scripted launch argv after `am`, one entry per launch dispatch."""
        return [command[command.index("am") + 1:] for command in self.am_commands()
                if command[command.index("am") + 1] == "start" and "-e" not in command]

    def logcat_commands(self):
        return [command for command in self.commands if "logcat" in command]

    def stop_commands(self):
        return [command for command in self.am_commands() if "stop" in command]

    def start_commands(self):
        return [command for command in self.am_commands()
                if "action" in command and command[command.index("action") + 1] == "start"]

    def shell(self, rest):
        if rest[:2] == ["pm", "path"]:
            package = rest[2]
            if package == pcapdroid.CAPTURE_PACKAGE and self.installed:
                return call_result(f"package:/data/app/{pcapdroid.CAPTURE_PACKAGE}/base.apk\n")
            if package == PACKAGE and self.target_installed:
                return call_result(f"package:/data/app/{PACKAGE}/base.apk\n")
            return call_result("", code=1, stderr=f"Error: package {package} not found\n")
        if rest[:3] == ["pm", "list", "packages"]:
            package = rest[-1]
            if package == pcapdroid.CAPTURE_PACKAGE and self.installed:
                return call_result(f"package:{package} uid:10234\n")
            if package == PACKAGE and self.target_installed:
                return call_result(f"package:{package} uid:10345\n")
            return call_result("")
        if rest[:2] == ["dumpsys", "package"]:
            return self.package_detail(rest[2])
        if rest[:2] == ["dumpsys", "activity"]:
            return self.service_listing()
        if rest[:1] == ["am"]:
            return self.am(rest[1:])
        if rest[:3] == ["stat", "-c", "%s"]:
            return self.stat(rest[3])
        if rest[:2] == ["ls", "-ln"]:
            return self.stat(rest[2])
        raise AssertionError(f"unexpected shell command: {rest}")

    def exec_out(self, rest, binary):
        path = rest[-1]
        if rest[:2] == ["head", "-c"] or rest[:3] == ["toybox", "head", "-c"]:
            if self.file is None or path != self.remote_path:
                return call_result(b"", code=1, stderr="head: no such file\n", binary=True)
            head = self.file[:24]
            return call_result(head if binary else head.decode("latin-1"), binary=binary)
        raise AssertionError(f"unexpected exec-out command: {rest}")

    def pull(self, remote, local):
        if self.file is None or remote != self.remote_path:
            return call_result("", code=1, stderr="adb: error: failed to stat remote object\n")
        target = Path(local)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.file)
        return call_result(f"{remote}: 1 file pulled\n")

    def package_detail(self, package):
        if self.truncate_package:
            return call_result(f"Package [{package}] (8f0f2c4):\n  userId=10234\n", omitted_out=8192)
        if package == pcapdroid.MITM_PACKAGE and self.mitm_installed:
            return call_result(f"Package [{package}] (mitm1):\n  userId=10100\n  versionName=2.4\n"
                               f"  versionCode=26 minSdk=24 targetSdk=34\n")
        if package == pcapdroid.CAPTURE_PACKAGE and self.installed:
            return call_result(f"Package [{pcapdroid.CAPTURE_PACKAGE}] (8f0f2c4):\n"
                               f"  userId=10234\n  versionName=2.0.2\n  versionCode=95 minSdk=21 targetSdk=34\n")
        if package == PACKAGE and self.target_installed:
            return call_result(f"Package [{PACKAGE}] (1a2b3c4):\n"
                               f"  userId=10345\n  versionName=1.0.0\n  versionCode=12\n")
        return call_result(f"Unable to find package: {package}\n")

    def service_listing(self):
        if self.truncate_service:
            return call_result("ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
                               "  * ServiceRecord{1 u0 com.emanuelef.remote_capture/.CaptureService}\n",
                               omitted_out=4096)
        if self.capture_running:
            return call_result("ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
                               "  User 0 active services:\n"
                               f"  * ServiceRecord{{6f2c1e u0 {pcapdroid.CAPTURE_PACKAGE}/.CaptureService}}\n"
                               f"    packageName={pcapdroid.CAPTURE_PACKAGE}\n")
        return call_result("(nothing)\n")

    def am(self, rest):
        if rest[:1] == ["force-stop"]:
            if len(rest) != 2:
                raise AssertionError(f"unexpected force-stop command: {rest}")
            self.force_stopped.append(rest[1])
            if self.force_stop_error:
                return call_result("Error: Force-stop of package failed\n", code=1, stderr="Error type 3\n")
            return call_result("")
        if rest[:1] == ["start"] and "-e" not in rest:
            if rest == ["start", "-n", rest[-1]]:
                pass  # --launch-no-wait: a plain `am start -n`, no Activity-result wait
            elif rest != ["start", "-W", "-n", rest[-1]]:
                raise AssertionError(f"unexpected launch command: {rest}")
            self.launched.append(rest[-1])
            if self.launch_error:
                return call_result("Error: Activity not started, unable to resolve Intent { cmp=... }\n", code=1,
                                   stderr="Error type 3\n")
            return call_result(f"Starting: Intent {{ cmp={rest[-1]} }}\nStatus: ok\n")
        if rest[:1] != ["start"]:
            raise AssertionError(f"unexpected am command: {rest}")
        extras, index = {}, 1
        while index < len(rest):
            if rest[index] == "-e":
                extras[rest[index + 1]] = rest[index + 2]
                index += 3
            elif rest[index] == "-n":
                extras["component"] = rest[index + 1]
                index += 2
            else:
                raise AssertionError(f"unexpected am argument: {rest[index]}")
        if self.start_error:
            return call_result("Error: Activity not started, unable to resolve Intent { cmp=... }\n", code=1,
                               stderr="Error type 3\n")
        if extras["action"] == "start":
            if self.consent and self.installed:
                self.capture_running = True
                self.remote_path = f"{pcapdroid.DEVICE_DIRECTORY}/{extras['pcap_name']}"
                if self.create_file:
                    self.file = b"" if self.defer_data else self.dump()
            return call_result("Starting: Intent { act=android.intent.action.VIEW cmp=... }" + self.am_echo + "\n")
        if extras["action"] == "stop":
            if self.stop_works:
                self.capture_running = False
                if self.create_file and self.defer_data:
                    self.file = self.dump()
            return call_result("Starting: Intent { act=android.intent.action.VIEW cmp=... }\n")
        raise AssertionError(f"unexpected am action: {extras['action']}")

    def dump(self):
        return pcap_bytes(self.payload) if self.header_valid else b"\x00\x01\x02\x03" + self.payload

    def stat(self, remote):
        if self.file is None or remote != self.remote_path:
            return call_result("", code=1, stderr=f"stat: '{remote}': No such file or directory\n")
        size = len(self.file) if self.device_size is None else self.device_size
        return call_result(f"{size}\n")

    def logcat(self, rest):
        """Only the scoped addon tail may be read, and only with the documented bound."""
        if rest != ["logcat", "-d", "-t", str(pcapdroid.LOGCAT_TAIL_LINES), "-s", pcapdroid.LOGCAT_TAG + ":*"]:
            raise AssertionError(f"unexpected logcat command: {rest}")
        if self.logcat_error is not None:
            return self.logcat_error
        return call_result(self.logcat_text, omitted_out=self.logcat_omitted)


def capture_args(**overrides):
    values = {"package": PACKAGE, "path": "captures/run.pcap", "serial": SERIAL, "seconds": 2, "consent_timeout": 1,
              "timeout": 2, "api_key_env": None, "max_bytes": 33554432, "repeat": 1, "gap": 0, "launch": None,
              "force_stop": False, "tls_decryption": False, "launch_no_wait": False}
    values.update(overrides)
    return SimpleNamespace(**values)


def extras_from(command):
    start = command.index("am") + 2
    extras, index = {}, start
    while index < len(command):
        if command[index] == "-e":
            extras[command[index + 1]] = command[index + 2]
            index += 3
        elif command[index] == "-n":
            extras["component"] = command[index + 1]
            index += 2
        else:
            raise AssertionError(f"unexpected argument: {command[index]}")
    return extras


class FlakyAdb:
    """Device proxy that answers matching calls with a dead-server result before delegating.

    `restarts` records the server restarts the code under test asked for, `forwarded` the
    calls that were answered with the failure instead of reaching the device, and `calls`
    every invocation in order.
    """

    def __init__(self, device, *, error=None, failures=1, match=None):
        self.device = device
        self.adb = device.adb
        self.error = f"error: device '{SERIAL}' not found\n" if error is None else error
        self.remaining = failures
        self.match = match if match is not None else (lambda argv: True)
        self.restarts = []
        self.forwarded = []
        self.calls = []

    def __call__(self, command, timeout, binary=False):
        argv = [str(item) for item in command]
        self.calls.append(argv)
        if argv[0] == self.adb and argv[1:] in (["kill-server"], ["start-server"]):
            self.restarts.append(argv[1])
            return call_result("", stderr="* daemon started successfully *\n" if argv[1] == "start-server" else "")
        if self.remaining and self.match(argv):
            self.remaining -= 1
            self.forwarded.append(argv)
            return call_result("", code=1, stderr=self.error)
        return self.device(command, timeout, binary=binary)


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        (self.root / "captures").mkdir()
        self.clock = FakeClock()
        self.stderr = ""

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def run_command(self, function, args, device=None, tool=None):
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            if device is not None:
                stack.enter_context(patch.object(pcapdroid, "_run", side_effect=device))
                tool = {"return_value": device.adb} if tool is None else tool
            if tool is not None:
                stack.enter_context(patch.object(pcapdroid, "executable", **tool))
            stack.enter_context(patch.object(pcapdroid.time, "monotonic", self.clock.monotonic))
            stack.enter_context(patch.object(pcapdroid.time, "sleep", self.clock.sleep))
            with contextlib.redirect_stderr(stderr):
                try:
                    result = function(args, self.store)
                finally:
                    self.stderr = stderr.getvalue()
        return result, self.stderr

    def capture(self, device=None, tool=None, **overrides):
        return self.run_command(pcapdroid.pcapdroid_capture, capture_args(**overrides), device=device, tool=tool)

    def session_directory(self):
        directory = self.root / "captures" / "session"
        directory.mkdir()
        return directory

    def am_sequence(self, device):
        """Session commands in dispatch order, named by their observed shape."""
        kinds = []
        for command in device.commands:
            if "am" not in command:
                continue
            rest = command[command.index("am") + 1:]
            if rest[:1] == ["force-stop"]:
                kinds.append("force-stop")
            elif "action" not in rest:
                kinds.append("launch")
            else:
                kinds.append(f"capture-{rest[rest.index('action') + 1]}")
        return kinds

    def preflight(self, device=None, tool=None, package=None, serial=SERIAL):
        return self.run_command(pcapdroid.pcapdroid_preflight, SimpleNamespace(serial=serial, package=package),
                                device=device, tool=tool)

    def records(self, action=None):
        return [record for record in self.store.list(limit=50) if action is None or record["data"].get("action") == action]

    def rejection(self):
        found = self.records("capture-rejected")
        self.assertEqual(len(found), 1, [record["data"].get("error") for record in found])
        return found[0]

    def stored_text(self):
        return json.dumps([record["data"] for record in self.store.list(limit=50)], ensure_ascii=False)


class PreflightTests(BaseCase):
    def test_missing_tool_and_failed_adb_are_distinguished(self):
        record, _ = self.preflight(tool={"side_effect": ForgeError("Missing adb")})
        self.assertEqual((record["data"]["status"], record["data"]["success"]), ("missing-tool", False))
        self.assertIn("Missing adb", record["data"]["precondition"])

        record, _ = self.preflight(Device(devices=[]))
        self.assertEqual(record["data"]["status"], "absent")

        device = Device(devices=[{"serial": SERIAL, "state": "unauthorized"}])
        record, _ = self.preflight(device)
        self.assertEqual(record["data"]["status"], "unauthorized")
        self.assertEqual(len(device.commands), 2, "an unauthorized device is never probed further")

        record, _ = self.preflight(Device(devices=[{"serial": "a", "state": "device"},
                                                  {"serial": "b", "state": "device"}]), serial=None)
        self.assertEqual(record["data"]["status"], "multiple")

    def test_installed_facts_uid_and_service_state_are_observed(self):
        device = Device()
        record, _ = self.preflight(device, package=PACKAGE)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "ready")
        self.assertFalse(data["capture_running"])
        self.assertEqual(data["service"]["records"], [])
        self.assertTrue(data["service"]["known"])
        self.assertEqual(data["capture_package"]["version_name"], "2.0.2")
        self.assertEqual(data["capture_package"]["version_code"], 95)
        self.assertEqual(data["capture_package"]["uid"], 10234)
        self.assertEqual(data["target_package"]["uid"], 10345)
        self.assertEqual(data["device"]["serial"], SERIAL)
        self.assertFalse(any("su" in command for command in device.commands))

    def test_running_capture_and_missing_apps_are_separate_states(self):
        record, _ = self.preflight(Device(capture_running=True))
        self.assertEqual(record["data"]["status"], "capture-active")
        self.assertTrue(record["data"]["capture_running"])
        self.assertTrue(record["data"]["success"])

        record, _ = self.preflight(Device(installed=False))
        self.assertEqual((record["data"]["status"], record["data"]["success"]), ("capture-app-absent", False))

        record, _ = self.preflight(Device(target_installed=False), package=PACKAGE)
        self.assertEqual(record["data"]["status"], "target-app-absent")

        record, _ = self.preflight(Device(truncate_package=True))
        self.assertEqual((record["data"]["status"], record["data"]["success"]), ("capture-app-unknown", False))
        self.assertFalse(record["data"]["capture_package"]["observed"])
        self.assertIn("observed completely", record["data"]["precondition"])

    def test_truncated_or_unparseable_service_output_is_unknown(self):
        record, _ = self.preflight(Device(truncate_service=True))
        self.assertEqual((record["data"]["status"], record["data"]["success"]), ("service-unknown", False))
        self.assertIsNone(record["data"]["capture_running"])
        device = Device()
        device.service_listing = lambda: call_result("ACTIVITY MANAGER SERVICES\n  unparsable junk\n")
        record, _ = self.preflight(device)
        self.assertEqual(record["data"]["status"], "service-unknown")

    def test_denied_or_offline_scope_blocks_device_work_before_any_adb_call(self):
        self.scope(authorization="denied")
        device = Device()
        with self.assertRaisesRegex(ForgeError, "denies active work"):
            self.preflight(device)
        self.assertEqual(device.commands, [])

        self.scope(authorization="granted", basis="own_system", network_profile="offline")
        device = Device()
        with self.assertRaisesRegex(ForgeError, "network profile is offline"):
            self.capture(device)
        self.assertEqual(device.commands, [])

    def scope(self, authorization="granted", basis="own_system", network_profile="unspecified"):
        import forge_tasks
        return forge_tasks.initialize(SimpleNamespace(target="https://example.invalid/", goal="g",
                                                     authorization=authorization, basis=basis,
                                                     network_profile=network_profile, in_scope=[],
                                                     out_of_scope=[]), self.store, ["web"])


class ArgumentSafetyTests(BaseCase):
    def assert_refused(self, message, **overrides):
        device = Device()
        with self.assertRaises(ForgeError, msg=message):
            self.capture(device, **overrides)
        self.assertEqual(device.commands, [], "no ADB call may happen before validation")
        return device

    def test_bounded_arguments_are_enforced_before_dispatch(self):
        for field, value, message in (("seconds", 0, "seconds must be an integer between 1 and 300"),
                                      ("seconds", 301, "seconds must be an integer between 1 and 300"),
                                      ("consent_timeout", 0, "consent-timeout"),
                                      ("consent_timeout", 121, "consent-timeout"),
                                      ("timeout", 0, "timeout must be an integer"),
                                      ("timeout", 121, "timeout must be an integer"),
                                      ("max_bytes", 1023, "max-bytes must be an integer between 1024 and"),
                                      ("max_bytes", 134217729, "max-bytes must be an integer between 1024 and"),
                                      ("package", "ai x grok", "valid --package"),
                                      ("package", "ai.x.grok;id", "valid --package"),
                                      ("serial", "-s", "serial without spaces"),
                                      ("serial", "b519558f rm", "serial without spaces"),
                                      ("serial", "..", "serial without spaces")):
            with self.subTest(field=field, value=value):
                self.assert_refused(message, **{field: value})

    def test_unsafe_destination_paths_are_refused_before_dispatch(self):
        (self.root / "existing.pcap").write_bytes(b"x")
        (self.root / "plain.txt").write_bytes(b"x")
        for path, message in ((str(self.root / "existing.pcap"), "already exists"),
                              ("captures/../../escape.pcap", "traversal is not allowed"),
                              ("\\\\server\\share\\run.pcap", "not a device, UNC or alternate-stream path"),
                              ("captures/run.pcap:ads", "UNC or alternate-stream path"),
                              ("captures/run.txt", "must name a new .pcap file"),
                              ("captures/missing/run.pcap", "Destination directory does not exist"),
                              ("plain.txt/run.pcap", "Destination directory does not exist"),
                              ("captures/ru|n.pcap", "plain file name")):
            with self.subTest(path=path):
                self.assert_refused(message, path=path)

    def test_absolute_destination_outside_project_is_refused_before_device_access(self):
        device = Device()
        with tempfile.TemporaryDirectory() as outside:
            destination = Path(outside) / "run.pcap"
            with self.assertRaises(ForgeError):
                self.capture(device, path=str(destination))
            self.assertFalse(destination.exists())
        self.assertEqual(device.commands, [])

    def test_symlinked_destination_directory_is_refused(self):
        target = self.root / "real"
        target.mkdir()
        link = self.root / "link"
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        self.assert_refused("Symlink/reparse destination paths are not allowed", path="link/run.pcap")

    def test_multi_window_paths_are_validated_before_dispatch(self):
        directory = self.session_directory()
        self.assert_refused("existing project directory", repeat=3, path="captures/run.pcap")
        self.assert_refused("existing project directory", repeat=3, path="captures/absent")
        self.assert_refused("UNC or alternate-stream path", repeat=2, path="captures/run.pcap:ads")
        self.assert_refused("must name a new .pcap file", path=SESSION_PATH)
        self.assert_refused("traversal", repeat=3, path="captures/session/../../escape")
        self.assert_refused("not a device, UNC or alternate-stream path", repeat=3, path="\\\\server\\share\\run")
        (directory / "window-01.pcap").write_bytes(b"previous session")
        self.assert_refused("already exists", repeat=3, path=SESSION_PATH)
        self.assert_refused("already exists", repeat=2, path=SESSION_PATH)
        (directory / "window-01.pcap").unlink()
        for path in (f"{SESSION_PATH}/window-02.pcap", f"{SESSION_PATH}/window-03.pcap"):
            with self.subTest(path=path):
                (self.root / path).write_bytes(b"previous session")
                self.assert_refused("already exists", repeat=3, path=SESSION_PATH)
                (self.root / path).unlink()
        self.assertEqual(sorted(item.name for item in directory.iterdir()), [])

    def test_symlinked_session_directory_is_refused(self):
        target = self.root / "real"
        target.mkdir()
        link = self.root / "link"
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        self.assert_refused("Symlink/reparse destination paths are not allowed", repeat=3, path="link")

    def test_api_key_environment_failures_are_refused_before_dispatch(self):
        self.assert_refused("must name an environment variable", api_key_env="1BAD NAME")
        self.assert_refused("does not provide a PCAPdroid API key", api_key_env="FORGE_TEST_ABSENT_KEY")
        with patch.dict(os.environ, {"FORGE_TEST_BLANK_KEY": "   "}):
            self.assert_refused("does not provide a PCAPdroid API key", api_key_env="FORGE_TEST_BLANK_KEY")
        with patch.dict(os.environ, {"FORGE_TEST_LONG_KEY": "k" * 513}):
            self.assert_refused("plausible PCAPdroid API key", api_key_env="FORGE_TEST_LONG_KEY")

    def test_scripted_session_arguments_are_enforced_before_dispatch(self):
        for field, value, message in (("repeat", 0, "repeat must be an integer between 1 and 20"),
                                      ("repeat", 21, "repeat must be an integer between 1 and 20"),
                                      ("repeat", "3", "repeat must be an integer between 1 and 20"),
                                      ("repeat", True, "repeat must be an integer between 1 and 20"),
                                      ("gap", -1, "gap must be a number of seconds between 0 and 60"),
                                      ("gap", 61, "gap must be a number of seconds between 0 and 60"),
                                      ("gap", True, "gap must be a number of seconds between 0 and 60"),
                                      ("gap", "1", "gap must be a number of seconds between 0 and 60"),
                                      ("launch", "ai.x.grok", "PACKAGE/COMPONENT"),
                                      ("launch", ";id", "PACKAGE/COMPONENT"),
                                      ("launch", "-W", "PACKAGE/COMPONENT"),
                                      ("launch", "ai.x.grok/.Main Activity", "PACKAGE/COMPONENT"),
                                      ("launch", "/.MainActivity", "PACKAGE/COMPONENT"),
                                      ("force_stop", 1, "is a flag and takes no value"),
                                      ("tls_decryption", "yes", "is a flag and takes no value"),
                                      ("launch_no_wait", "yes", "is a flag and takes no value")):
            with self.subTest(field=field, value=value):
                self.assert_refused(message, **{field: value})

    def test_launch_no_wait_requires_the_scripted_launch_it_shortens(self):
        self.assert_refused("--launch-no-wait only applies with --launch", launch_no_wait=True)

    def test_gap_and_repeat_bounds_accept_their_limits(self):
        device = Device(payload=b"\x21" * 8)
        self.session_directory()
        record, stderr = self.capture(device, path=SESSION_PATH, repeat=20, gap=60, seconds=1)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertEqual(data["repeats"], 20)
        self.assertEqual(data["gap_seconds"], 60)
        self.assertEqual(len(data["windows"]), 20)
        self.assertTrue(all(entry["success"] for entry in data["windows"]))
        self.assertEqual(len(self.records("capture")), 20)
        self.assertEqual(len(device.start_commands()), 20)
        self.assertFalse(device.capture_running)

    def test_required_prerequisites_never_reach_the_device(self):
        device = Device(installed=False)
        with self.assertRaisesRegex(ForgeError, "prerequisite missing: capture-app-absent"):
            self.capture(device)
        self.assertEqual(device.am_commands(), [])
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertEqual(len(self.records("capture-rejected")), 1)

        device = Device()
        with patch.object(pcapdroid, "_run") as calls, \
                patch.object(pcapdroid, "executable", side_effect=ForgeError("Missing configured ADB")):
            with self.assertRaisesRegex(ForgeError, "prerequisite missing: missing-tool"):
                pcapdroid.pcapdroid_capture(capture_args(), self.store)
        calls.assert_not_called()
        self.assertEqual(device.commands, [])


class CapturePolicyTests(BaseCase):

    def test_successful_session_publishes_hash_and_observed_lifecycle(self):
        payload = bytes(range(256)) * 4
        device = Device(payload=payload)
        record, stderr = self.capture(device)
        data = record["data"]
        destination = self.root / "captures" / "run.pcap"
        self.assertEqual(data["action"], "capture")
        self.assertTrue(data["success"])
        self.assertEqual(data["capture"]["path"], "captures/run.pcap")
        self.assertEqual(data["capture"]["sha256"], hashlib.sha256(pcap_bytes(payload)).hexdigest())
        self.assertEqual(data["capture"]["size"], len(pcap_bytes(payload)))
        self.assertEqual(destination.read_bytes(), pcap_bytes(payload))
        self.assertFalse(data["empty"])
        self.assertEqual(data["pcap_header"], {"magic": "d4c3b2a1", "byte_order": "little", "version": "2.4",
                                              "snaplen": 2048, "link_type": 1, "ethernet_link_type": True,
                                              "nanosecond_timestamps": False})
        self.assertEqual(data["target_uid"], 10345)
        self.assertEqual(data["package"], PACKAGE)
        self.assertFalse(data["max_dump_size_reached"])
        self.assertNotIn("truncated", data)
        self.assertRegex(data["settings"]["pcap_name"], pcapdroid.CAPTURE_NAME)
        self.assertEqual(data["device"]["device_path"],
                         f"{pcapdroid.DEVICE_DIRECTORY}/{data['settings']['pcap_name']}")
        self.assertRegex(data["device"]["device_path"], pcapdroid.DEVICE_PATH)
        self.assertTrue(data["device"]["size_stable_after_stop"])
        self.assertTrue(data["dispatch"]["accepted"] and data["dispatch"]["marked_starting"])
        proof = data["proof"]
        self.assertTrue(proof["dispatch_observed"])
        self.assertTrue(proof["service_running_observed"] and proof["file_header_observed"])
        self.assertTrue(proof["complete_start_signals"] and proof["stop_requested"])
        self.assertTrue(proof["service_stopped_observed"])
        self.assertFalse(proof["activity_result_available"])
        self.assertFalse(proof["get_status_extras_used"])
        self.assertTrue(proof["target_uid_observed"])
        self.assertTrue(proof["retrieved_header_valid"])
        self.assertEqual(data["stop"]["state"], "stopped")
        self.assertEqual(data["evidence_ids"], [data["preflight_evidence_id"]])
        self.assertEqual(self.store.get(data["preflight_evidence_id"])["data"]["status"], "ready")
        self.assertFalse(device.capture_running, "the bounded session must end with no running capture")
        self.assertIn("approve it on the device", stderr, "the operator must be told the stop may need consent")
        self.assertEqual(len(self.records("capture")), 1)

    def test_header_only_capture_is_retrieved_but_reported_empty(self):
        record, _ = self.capture(Device())
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertTrue(data["empty"])
        self.assertTrue(data["proof"]["empty_capture"])
        self.assertEqual(data["capture"]["size"], 24)
        self.assertEqual((self.root / "captures" / "run.pcap").read_bytes(), PCAP_HEADER)

    def test_created_but_empty_dump_does_not_block_readiness_or_count_as_data(self):
        payload = b"\x09" * 64
        device = Device(payload=payload, defer_data=True)
        record, stderr = self.capture(device)
        data = record["data"]
        self.assertTrue(data["start"]["complete"])
        self.assertTrue(data["start"]["file_created"])
        self.assertEqual(data["start"]["file_size"], 0)
        self.assertFalse(data["start"]["file_header_observed"])
        self.assertTrue(data["proof"]["file_created_observed"])
        self.assertFalse(data["empty"])
        self.assertEqual(data["capture"]["sha256"], hashlib.sha256(pcap_bytes(payload)).hexdigest())
        self.assertEqual(data["pcap_header"]["snaplen"], 2048)
        self.assertTrue(data["dump_size_stable_after_stop"])

    def test_device_dump_over_requested_cap_is_not_pulled_or_published(self):
        device = Device(payload=b"\x07" * 2000)
        with self.assertRaises(ForgeError):
            self.capture(device, max_bytes=1024)
        data = self.rejection()["data"]
        self.assertFalse(data["success"])
        self.assertTrue(data["stop"]["observed_stopped"])
        self.assertFalse(device.capture_running)
        self.assertFalse(any("pull" in command for command in device.commands))
        self.assertFalse((self.root / "captures" / "run.pcap").exists())


    def test_pre_existing_capture_is_refused_without_start_or_stop(self):
        device = Device(capture_running=True)
        with self.assertRaisesRegex(ForgeError, "prerequisite missing: capture-active"):
            self.capture(device)
        self.assertEqual(device.am_commands(), [])
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        data = self.rejection()["data"]
        self.assertFalse(data["success"])
        self.assertIsNone(data["dispatch"])
        self.assertIsNone(data["stop"])
        self.assertFalse(data["destination_published"])
        self.assertTrue(device.capture_running, "the existing capture must keep running")


class CaptureFailureTests(BaseCase):
    def test_dispatched_but_never_started_keeps_evidence_and_sends_no_stop(self):
        device = Device(consent=False)
        with self.assertRaises(ForgeError):
            self.capture(device, consent_timeout=2)
        data = self.rejection()["data"]
        self.assertTrue(data["dispatch"]["accepted"])
        self.assertFalse(data["start"]["observed"])
        self.assertTrue(data["start"]["consent_pending"])
        self.assertFalse(data["start"]["service_running"])
        self.assertFalse(data["start"]["file_header_observed"])
        self.assertGreaterEqual(data["start"]["polls"], 2)
        self.assertFalse(data["stop"]["requested"])
        self.assertIn("approve", data["required_action"])
        self.assertFalse(data["retrieval"]["pulled"])
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertEqual(device.stop_commands(), [], "no stop without an observed own start")
        self.assertNotIn("stop consent", self.stderr)
        self.assertEqual(self.records("capture"), [])

    def test_running_service_without_this_sessions_file_is_not_claimed_or_stopped(self):
        device = Device(create_file=False)
        with self.assertRaises(ForgeError):
            self.capture(device)
        data = self.rejection()["data"]
        self.assertTrue(data["start"]["service_running"])
        self.assertFalse(data["start"]["file_created"])
        self.assertFalse(data["start"]["observed"])
        self.assertFalse(data["stop"]["requested"])
        self.assertEqual(device.stop_commands(), [])
        self.assertTrue(device.capture_running)
        self.assertFalse(any("pull" in command for command in device.commands))
        self.assertFalse((self.root / "captures" / "run.pcap").exists())


    def test_file_without_running_service_does_not_establish_ownership(self):
        device = Device()
        original_start = device.am

        def dispatch_without_service(arguments):
            result = original_start(arguments)
            device.capture_running = False
            return result

        device.am = dispatch_without_service
        with self.assertRaises(ForgeError):
            self.capture(device)
        data = self.rejection()["data"]
        self.assertTrue(data["start"]["file_created"])
        self.assertFalse(data["start"]["service_running"])
        self.assertFalse(data["start"]["observed"])
        self.assertFalse(data["stop"]["requested"])
        self.assertEqual(device.stop_commands(), [])
        self.assertFalse((self.root / "captures" / "run.pcap").exists())

    def test_unreadable_dump_header_is_never_pulled_or_claimed(self):
        device = Device(header_valid=False)
        with self.assertRaisesRegex(ForgeError, "No readable dump file named"):
            self.capture(device)
        data = self.rejection()["data"]
        self.assertTrue(data["start"]["service_running"])
        self.assertFalse(data["start"]["file_header_observed"])
        self.assertFalse(any("pull" in command for command in device.commands))
        self.assertFalse((self.root / "captures" / "run.pcap").exists())

    def test_unobserved_stop_state_is_never_reported_as_success(self):
        device = Device(stop_works=False)
        with self.assertRaisesRegex(ForgeError, "still observed as running"):
            self.capture(device)
        data = self.rejection()["data"]
        self.assertFalse(data["success"])
        self.assertTrue(data["stop"]["requested"])
        self.assertFalse(data["stop"]["observed_stopped"])
        self.assertEqual(data["stop"]["state"], "stop-not-observed")
        self.assertTrue(data["stop"]["service"]["running"])
        self.assertIn("stop the capture manually", data["required_action"])
        self.assertFalse(any("pull" in command for command in device.commands))
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertTrue(device.capture_running)
        self.assertEqual(self.records("capture"), [])

    def test_failed_dispatch_is_not_capture_success(self):
        device = Device(start_error=True)
        with self.assertRaisesRegex(ForgeError, "Capture start was not dispatched"):
            self.capture(device)
        data = self.rejection()["data"]
        self.assertFalse(data["dispatch"]["accepted"])
        self.assertIn("unable to resolve", data["dispatch"]["error_line"])
        self.assertIsNone(data["start"])
        self.assertFalse(data["stop"]["requested"])
        self.assertIn("No own capture start was observed", data["stop"]["reason"])
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertEqual(device.stop_commands(), [])

    def test_truncated_dispatch_output_is_not_accepted(self):
        device = Device()
        original = device.am
        device.am = lambda rest: dict(original(rest), stdout_omitted_bytes=2048)
        with self.assertRaisesRegex(ForgeError, "output was truncated"):
            self.capture(device)
        self.assertEqual(self.rejection()["data"]["dispatch"]["accepted"], False)

    def test_oversized_device_dump_is_never_pulled(self):
        device = Device(device_size=200 * 1024 * 1024)
        with self.assertRaises(ForgeError):
            self.capture(device)
        self.assertFalse(any("pull" in command for command in device.commands))
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertEqual(self.rejection()["data"]["retrieval"], {"pulled": False, "published": False})

    def test_failed_pull_publishes_nothing(self):
        device = Device()
        device.pull = lambda remote, local: call_result("", code=1, stderr="adb: error: remote object missing\n")
        with self.assertRaisesRegex(ForgeError, "could not pull the capture file"):
            self.capture(device)
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertEqual([item.name for item in (self.root / "captures").iterdir()], [])

    def test_dump_changed_during_pull_is_not_published(self):
        device = Device(payload=b"packet-data")
        original_pull = device.pull

        def growing_pull(remote, local):
            result = original_pull(remote, local)
            destination = Path(local)
            destination.write_bytes(destination.read_bytes() + b"later")
            return result

        device.pull = growing_pull
        with self.assertRaises(ForgeError):
            self.capture(device)
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertFalse(self.rejection()["data"]["success"])


class DecryptionTests(BaseCase):
    RULES = json.dumps([{"type": "APP", "value": PACKAGE}], separators=(",", ":"))

    def test_preflight_reports_the_addon_as_its_own_scoped_fact(self):
        record, _ = self.preflight(Device())
        addon = record["data"]["mitm_addon"]
        self.assertFalse(addon["installed"])
        self.assertEqual(addon["package"], pcapdroid.MITM_PACKAGE)
        self.assertIsNone(addon["version_name"])
        record, _ = self.preflight(Device(mitm_installed=True))
        addon = record["data"]["mitm_addon"]
        self.assertTrue(addon["installed"])
        self.assertEqual((addon["version_name"], addon["version_code"]), ("2.4", 26))

    def test_decryption_refuses_before_dispatch_when_the_addon_is_absent(self):
        device = Device(payload=b"\x05" * 8)
        with self.assertRaisesRegex(ForgeError, "mitm-addon-absent"):
            self.capture(device, tls_decryption=True)
        self.assertEqual(device.am_commands(), [], "no capture Intent may be sent without the addon")
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        data = self.rejection()["data"]
        self.assertFalse(data["dispatch"])
        self.assertIn(pcapdroid.MITM_REPOSITORY, data["error"])

    def test_decryption_proceeds_when_the_addon_is_installed(self):
        record, _ = self.capture(Device(mitm_installed=True, payload=b"\x06" * 8), tls_decryption=True)
        self.assertTrue(record["data"]["success"])
        self.assertTrue(record["data"]["decryption_requested"])

    def test_decryption_stays_off_unless_the_operator_opts_in(self):
        device = Device(payload=b"\x05" * 16)
        record, _ = self.capture(device)
        data = record["data"]
        settings = data["settings"]
        self.assertFalse(settings["tls_decryption"])
        self.assertEqual(settings["block_quic"], "never")
        self.assertNotIn("decryption_rules", settings)
        extras = extras_from(device.am_commands()[0])
        self.assertEqual(extras["tls_decryption"], "false")
        self.assertEqual(extras["block_quic"], "never")
        self.assertNotIn("decryption_rules", extras)
        self.assertFalse(data["decryption_requested"])
        self.assertFalse(data["operator_approved_tls_decryption"])
        self.assertIsNone(data["decryption_scope"])
        self.assertFalse(any("request, not decryption" in item for item in data["limits"]))
        session = self.records("capture-session")[0]["data"]
        self.assertFalse(session["decryption_requested"])
        self.assertNotIn("decryption_rules", session["settings"])

    def test_tls_decryption_opt_in_sends_settings_and_records_consent(self):
        device = Device(mitm_installed=True, payload=b"\x06" * 16)
        record, _ = self.capture(device, tls_decryption=True)
        data = record["data"]
        settings = data["settings"]
        self.assertTrue(settings["tls_decryption"])
        self.assertEqual(settings["block_quic"], "to_decrypt")
        self.assertEqual(json.loads(settings["decryption_rules"]), json.loads(self.RULES),
                         "the stored setting is redaction-normalized JSON; compare parsed rules")
        extras = extras_from(device.am_commands()[0])
        self.assertEqual(extras["tls_decryption"], "true")
        self.assertEqual(extras["block_quic"], "to_decrypt")
        self.assertEqual(shlex.split(extras["decryption_rules"]), [self.RULES],
                         "the device shell must receive the JSON value intact")
        self.assertTrue(data["decryption_requested"])
        self.assertTrue(data["operator_approved_tls_decryption"])
        self.assertIn("installs no CA", data["decryption_scope"])
        self.assertIn("pinning", data["decryption_scope"])
        self.assertIn("never evidence that a given flow was decrypted", data["decryption_scope"])
        self.assertTrue(any("request, not decryption" in item for item in data["limits"]))
        self.assertTrue(data["settings"]["full_payload"])

    def test_decryption_is_independent_of_the_api_key(self):
        device = Device(mitm_installed=True, payload=b"\x07" * 16)
        with patch.dict(os.environ, {"FORGE_TEST_API_KEY": "decryption-key-123"}):
            record, stderr = self.capture(device, tls_decryption=True, api_key_env="FORGE_TEST_API_KEY")
        data = record["data"]
        self.assertTrue(data["settings"]["tls_decryption"])
        self.assertTrue(data["settings"]["key_supplied"])
        self.assertEqual(json.loads(data["settings"]["decryption_rules"]), json.loads(self.RULES))
        self.assertEqual(data["dispatch_command"][data["dispatch_command"].index("api_key") + 1],
                         pcapdroid.API_KEY_PLACEHOLDER)
        self.assertNotIn("decryption-key-123", json.dumps(data))
        self.assertNotIn("decryption-key-123", stderr)

    def test_decryption_consent_survives_a_failed_window(self):
        device = Device(mitm_installed=True, stop_works=False)
        with self.assertRaisesRegex(ForgeError, "still observed as running"):
            self.capture(device, tls_decryption=True)
        data = self.rejection()["data"]
        self.assertTrue(data["decryption_requested"])
        self.assertTrue(data["operator_approved_tls_decryption"])
        self.assertIn("installs no CA", data["decryption_scope"])
        self.assertEqual(json.loads(data["settings"]["decryption_rules"]), json.loads(self.RULES))
        session = self.records("capture-session")[0]["data"]
        self.assertFalse(session["success"])
        self.assertTrue(session["decryption_requested"])
        self.assertIn("trusted by the target app", session["decryption_scope"])
        self.assertEqual(session["failures"][0]["index"], 1)
        self.assertEqual(session["windows"][0]["evidence_id"], self.rejection()["id"])


class SessionTests(BaseCase):
    def test_single_window_run_records_a_session_and_keeps_the_capture_result(self):
        device = Device(payload=b"\x14" * 8)
        record, _ = self.capture(device)
        self.assertEqual(record["data"]["action"], "capture")
        self.assertEqual((record["data"]["window_index"], record["data"]["window_count"]), (1, 1))
        session = self.records("capture-session")[0]["data"]
        self.assertTrue(session["success"])
        self.assertEqual(session["repeats"], 1)
        self.assertEqual(session["attempted_windows"], 1)
        self.assertEqual([entry["path"] for entry in session["windows"]], ["captures/run.pcap"])
        self.assertEqual(session["windows"][0]["evidence_id"], record["id"])
        self.assertEqual(session["windows"][0]["stop_state"], "stopped")
        self.assertEqual(session["evidence_ids"], [record["data"]["preflight_evidence_id"], record["id"]])
        self.assertEqual(session["destination"], "captures/run.pcap")
        self.assertFalse(session["force_stop"])
        self.assertIsNone(session["launch"])
        self.assertEqual(session["failures"], [])
        self.assertEqual((session["attempted_windows"], session["completed_windows"]), (1, 1))
        self.assertFalse(session["capture_running_after_session"])
        self.assertIsNone(session["settings"]["pcap_name"],
                          "per-window dump names are listed in windows[]")
        self.assertEqual(session["settings"]["app_filter"], PACKAGE)
        self.assertIsNone(session["required_action"])

    def test_three_window_session_records_every_window_and_a_session_record(self):
        device = Device()
        original_am = device.am
        starts = []

        def am_with_window_payload(rest):
            # Only the CaptureCtrl start carries pcap_dump_mode; the scripted `am start -W`
            # launch must not advance the per-window payload.
            if rest[:1] == ["start"] and "pcap_dump_mode" in rest:
                starts.append(1)
                device.payload = bytes([0x40 + len(starts)]) * 8
            return original_am(rest)
        device.am = am_with_window_payload
        directory = self.session_directory()
        record, stderr = self.capture(device, path=SESSION_PATH, repeat=3, gap=1, launch=LAUNCH, force_stop=True)
        data = record["data"]
        self.assertEqual(data["action"], "capture-session")
        self.assertTrue(data["success"])
        self.assertEqual((data["repeats"], data["attempted_windows"], data["completed_windows"]), (3, 3, 3))
        self.assertEqual((data["gap_seconds"], data["seconds"]), (1, 2))
        self.assertTrue(data["force_stop"])
        self.assertEqual(data["launch"], LAUNCH)
        self.assertEqual(data["destination"], SESSION_PATH)
        self.assertEqual(data["failures"], [])
        self.assertEqual(data["target_uid"], 10345)
        self.assertEqual(data["evidence_ids"][0], data["preflight_evidence_id"])
        self.assertEqual(len(data["windows"]), 3)
        self.assertFalse(data["capture_running_after_session"])
        self.assertFalse(data["service_after_session"]["running"])
        self.assertEqual(data["service_after_session"]["records"], [])
        self.assertIsNone(data["required_action"])

        names = set()
        for position, entry in enumerate(data["windows"], start=1):
            expected = pcap_bytes(bytes([0x40 + position]) * 8)
            self.assertEqual((directory / f"window-{position:02d}.pcap").read_bytes(), expected)
            self.assertEqual(entry["index"], position)
            self.assertEqual(entry["path"], f"{SESSION_PATH}/window-{position:02d}.pcap")
            self.assertTrue(entry["attempted"] and entry["success"])
            self.assertFalse(entry["empty"])
            self.assertEqual(entry["sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(entry["size"], len(expected))
            self.assertEqual(entry["stop_state"], "stopped")
            self.assertIsNone(entry["error"])
            window = self.store.get(entry["evidence_id"])["data"]
            self.assertEqual((window["action"], window["success"]), ("capture", True))
            self.assertEqual((window["window_index"], window["window_count"]), (position, 3))
            self.assertEqual(window["capture"]["sha256"], entry["sha256"])
            self.assertEqual(window["capture"]["path"], entry["path"])
            self.assertEqual(window["settings"]["pcap_name"], entry["pcap_name"])
            self.assertEqual(window["device"]["device_size"], len(expected))
            self.assertEqual(window["force_stop_action"]["command"][-2:], ["force-stop", PACKAGE])
            self.assertEqual(window["launch_action"]["command"][-3:], ["-W", "-n", LAUNCH])
            self.assertTrue(window["force_stop_action"]["accepted"] and window["launch_action"]["accepted"])
            names.add(entry["pcap_name"])
        self.assertEqual(len(names), 3, "every window needs its own dump name")
        self.assertEqual(sorted(record["data"]["window_index"] for record in self.records("capture")), [1, 2, 3])
        self.assertEqual(len(self.records("capture")), 3)

        self.assertEqual(device.force_stopped, [PACKAGE, PACKAGE, PACKAGE])
        self.assertEqual(device.launched, [LAUNCH, LAUNCH, LAUNCH])
        self.assertEqual(self.am_sequence(device),
                         ["capture-start", "force-stop", "launch", "capture-stop"] * 3,
                         "force-stop and launch run inside every window, before that window's stop")
        self.assertEqual(stderr.count("approve it on the device"), 3, "each window keeps its own stop notice")
        self.assertEqual(stderr.count("starting forge-"), 3)
        self.assertIn("window 2/3", stderr)
        self.assertFalse(device.capture_running)

    def test_mid_session_failure_stops_later_windows_and_keeps_completed_ones(self):
        device = Device(payload=b"\x11" * 32)
        directory = self.session_directory()
        original_pull = device.pull
        pulls = []

        def fail_second_pull(remote, local):
            pulls.append(remote)
            if len(pulls) == 2:
                return call_result("", code=1, stderr="adb: error: failed to stat remote object\n")
            return original_pull(remote, local)

        device.pull = fail_second_pull
        with self.assertRaisesRegex(ForgeError, "window 2/3") as raised:
            self.capture(device, path=SESSION_PATH, repeat=3)
        self.assertIn("could not pull the capture file", str(raised.exception))
        self.assertIn("capture-session evidence", str(raised.exception))
        session = self.records("capture-session")[0]["data"]
        self.assertFalse(session["success"])
        self.assertEqual((session["repeats"], session["attempted_windows"], session["completed_windows"]), (3, 2, 1))
        self.assertEqual([entry["attempted"] for entry in session["windows"]], [True, True, False])
        self.assertEqual([entry["success"] for entry in session["windows"]], [True, False, False])
        self.assertEqual(session["windows"][2]["path"], f"{SESSION_PATH}/window-03.pcap")
        self.assertIsNone(session["windows"][2]["evidence_id"])
        self.assertIsNone(session["windows"][2]["pcap_name"])
        self.assertEqual(len(session["failures"]), 1)
        self.assertEqual(session["failures"][0]["index"], 2)
        self.assertEqual(session["failures"][0]["evidence_id"], session["windows"][1]["evidence_id"])
        self.assertIn("could not pull the capture file", session["failures"][0]["error"])
        self.assertFalse(session["capture_running_after_session"])
        self.assertTrue(session["windows"][0]["sha256"], "the completed window keeps its hash")
        self.assertTrue((directory / "window-01.pcap").is_file())
        self.assertFalse((directory / "window-02.pcap").exists())
        self.assertFalse((directory / "window-03.pcap").exists())
        self.assertFalse(device.capture_running)
        self.assertEqual(len(device.start_commands()), 2, "no further window may start after a failure")
        rejection = self.rejection()["data"]
        self.assertEqual(rejection["window_index"], 2)
        self.assertEqual(rejection["window_count"], 3)
        self.assertFalse(rejection["destination_published"])
        self.assertEqual(rejection["retrieval"], {"pulled": False, "published": False})
        self.assertEqual(rejection["stop"]["state"], "stopped")
        self.assertEqual(rejection["limits"], self.records("capture-session")[0]["data"]["limits"])

    def test_continue_on_error_runs_later_windows_and_reports_success_false(self):
        device = Device(payload=b"\x13" * 32)
        self.session_directory()
        original_pull = device.pull
        pulls = []

        def fail_second_pull(remote, local):
            pulls.append(remote)
            if len(pulls) == 2:
                return call_result("", code=1, stderr="adb: error: failed to stat remote object\n")
            return original_pull(remote, local)

        device.pull = fail_second_pull
        record, _ = self.capture(device, path=SESSION_PATH, repeat=3, continue_on_error=True)
        session = record["data"]
        self.assertEqual(session["action"], "capture-session")
        self.assertFalse(session["success"])
        self.assertEqual((session["attempted_windows"], session["completed_windows"]), (3, 2))
        self.assertEqual([entry["success"] for entry in session["windows"]], [True, False, True])
        self.assertEqual([entry["index"] for entry in session["failures"]], [2])
        self.assertEqual(len(device.start_commands()), 3, "later windows must still run")
        self.assertTrue((Path(self.root) / SESSION_PATH / "window-01.pcap").is_file())
        self.assertTrue((Path(self.root) / SESSION_PATH / "window-03.pcap").is_file())
        self.assertFalse((Path(self.root) / SESSION_PATH / "window-02.pcap").exists())
        self.assertFalse(device.capture_running)


    def test_window_precheck_refuses_to_start_when_a_foreign_capture_runs(self):
        device = Device(payload=b"\x12" * 32)
        self.session_directory()
        original_pull = device.pull

        def pull_then_foreign_capture(remote, local):
            result = original_pull(remote, local)
            device.capture_running = True
            return result

        device.pull = pull_then_foreign_capture
        with self.assertRaisesRegex(ForgeError, "window 2/3") as raised:
            self.capture(device, path=SESSION_PATH, repeat=3)
        self.assertIn("prerequisite missing: capture-active", str(raised.exception))
        rejection = self.rejection()["data"]
        self.assertEqual(rejection["window_index"], 2)
        self.assertIsNone(rejection["dispatch"])
        self.assertIsNone(rejection["stop"], "a foreign capture is never stopped")
        self.assertTrue(rejection["service_precheck"]["known"])
        self.assertTrue(rejection["service_precheck"]["running"])
        self.assertIn("Resolve the reported prerequisite", rejection["required_action"])
        session = self.records("capture-session")[0]["data"]
        self.assertEqual([entry["attempted"] for entry in session["windows"]], [True, True, False])
        self.assertTrue(session["windows"][0]["success"])
        self.assertFalse(session["windows"][1]["success"])
        self.assertTrue(session["capture_running_after_session"], "a foreign capture is reported, not adopted")
        self.assertEqual(len(device.start_commands()), 1)
        self.assertEqual(len(device.stop_commands()), 1, "only this session's own capture was stopped")

    def test_window_stop_failure_keeps_evidence_and_asks_the_operator(self):
        device = Device(payload=b"\x13" * 32)
        self.session_directory()
        original_pull = device.pull

        def stop_after_first_window(remote, local):
            result = original_pull(remote, local)
            device.stop_works = False
            return result

        device.pull = stop_after_first_window
        with self.assertRaisesRegex(ForgeError, "window 2/3") as raised:
            self.capture(device, path=SESSION_PATH, repeat=3)
        self.assertIn("still observed as running", str(raised.exception))
        rejection = self.rejection()["data"]
        self.assertEqual(rejection["window_index"], 2)
        self.assertTrue(rejection["stop"]["requested"])
        self.assertEqual(rejection["stop"]["state"], "stop-not-observed")
        self.assertIn("stop the capture manually", rejection["required_action"])
        session = self.records("capture-session")[0]["data"]
        self.assertFalse(session["success"])
        self.assertEqual(session["windows"][1]["stop_state"], "stop-not-observed")
        self.assertFalse(session["windows"][2]["attempted"])
        self.assertTrue(session["capture_running_after_session"])
        self.assertEqual(len(device.start_commands()), 2)
        self.assertTrue(device.capture_running,
                        "the fake device keeps the capture the operator must stop by hand")

    def test_undispatched_force_stop_fails_the_window_after_stopping_our_capture(self):
        device = Device(payload=b"\x15" * 8, force_stop_error=True)
        with self.assertRaisesRegex(ForgeError, "scripted force-stop action was not dispatched"):
            self.capture(device, launch=LAUNCH, force_stop=True)
        data = self.rejection()["data"]
        self.assertFalse(data["force_stop_action"]["accepted"])
        self.assertTrue(data["launch_action"]["accepted"])
        self.assertEqual(data["force_stop_action"]["command"][-2:], ["force-stop", PACKAGE])
        self.assertEqual(data["launch_action"]["command"][-3:], ["-W", "-n", LAUNCH])
        self.assertEqual(len(device.stop_commands()), 1, "our own capture is always stopped")
        self.assertFalse(device.capture_running)
        self.assertFalse(any("pull" in command for command in device.commands))
        self.assertFalse((self.root / "captures" / "run.pcap").exists())
        self.assertFalse(self.records("capture-session")[0]["data"]["success"])

    def test_undispatched_launch_fails_the_window_after_stopping_our_capture(self):
        device = Device(payload=b"\x16" * 8, launch_error=True)
        with self.assertRaisesRegex(ForgeError, "scripted launch action was not dispatched"):
            self.capture(device, launch=LAUNCH, force_stop=True)
        data = self.rejection()["data"]
        self.assertTrue(data["force_stop_action"]["accepted"])
        self.assertFalse(data["launch_action"]["accepted"])
        self.assertIn("unable to resolve", data["launch_action"]["error_line"])
        self.assertEqual(len(device.stop_commands()), 1)
        self.assertFalse(device.capture_running)
        self.assertFalse((self.root / "captures" / "run.pcap").exists())

    def test_scripted_actions_are_optional_and_absent_by_default(self):
        device = Device(payload=b"\x17" * 8)
        record, _ = self.capture(device)
        data = record["data"]
        self.assertIsNone(data["launch_action"])
        self.assertIsNone(data["force_stop_action"])
        self.assertEqual(device.launched, [])
        self.assertEqual(device.force_stopped, [])
        self.assertEqual(self.am_sequence(device), ["capture-start", "capture-stop"])


class LaunchNoWaitTests(BaseCase):
    """`--launch-no-wait` dispatches a plain `am start -n` and records that it did not wait."""

    def test_no_wait_launch_is_a_plain_am_start_with_recorded_evidence(self):
        device = Device(payload=b"\x18" * 8)
        record, _ = self.capture(device, launch=LAUNCH, launch_no_wait=True)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertEqual(device.launch_rest(), [["start", "-n", LAUNCH]])
        self.assertEqual(data["launch_action"]["command"][-2:], ["-n", LAUNCH])
        self.assertNotIn("-W", data["launch_action"]["command"])
        self.assertFalse(data["launch_action"]["wait_for_launch"])
        self.assertTrue(data["launch_action"]["accepted"])
        self.assertEqual(device.launched, [LAUNCH])
        self.assertEqual(self.am_sequence(device), ["capture-start", "launch", "capture-stop"])
        self.assertTrue((self.root / "captures" / "run.pcap").is_file())

    def test_the_default_launch_still_waits_and_says_so(self):
        device = Device(payload=b"\x19" * 8)
        record, _ = self.capture(device, launch=LAUNCH, force_stop=True)
        data = record["data"]
        self.assertEqual(device.launch_rest(), [["start", "-W", "-n", LAUNCH]])
        self.assertEqual(data["launch_action"]["command"][-3:], ["-W", "-n", LAUNCH])
        self.assertTrue(data["launch_action"]["wait_for_launch"])
        self.assertFalse(self.records("capture-session")[0]["data"]["launch_no_wait"])

    def test_every_window_of_a_no_wait_session_launches_without_waiting(self):
        device = Device(payload=b"\x1a" * 8)
        self.session_directory()
        record, _ = self.capture(device, path=SESSION_PATH, repeat=2, launch=LAUNCH, force_stop=True,
                                 launch_no_wait=True)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertTrue(data["launch_no_wait"])
        self.assertEqual([entry["success"] for entry in data["windows"]], [True, True])
        self.assertEqual(device.launch_rest(), [["start", "-n", LAUNCH]] * 2)
        self.assertEqual(self.am_sequence(device),
                         ["capture-start", "force-stop", "launch", "capture-stop"] * 2)
        for entry in data["windows"]:
            window = self.store.get(entry["evidence_id"])["data"]
            self.assertFalse(window["launch_action"]["wait_for_launch"])


class AdbRestartTests(BaseCase):
    """A dead ADB server is restarted once and that call retried; nothing else is ever retried."""

    def test_a_dead_server_during_a_window_is_restarted_once_and_recorded(self):
        device = Device(payload=b"\x1b" * 8)
        proxy = FlakyAdb(device, match=lambda argv: "am" in argv and "action" in argv)
        record, stderr = self.capture(proxy)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertEqual(proxy.restarts, ["kill-server", "start-server"])
        self.assertTrue(data["adb_server_restarted"])
        restart = data["adb_server_restart"]
        self.assertTrue(restart["retried_once"], "the retry is the whole point of the restart")
        self.assertEqual(restart["trigger"], f"error: device '{SERIAL}' not found")
        self.assertEqual([restart["kill_server"]["returncode"], restart["start_server"]["returncode"]], [0, 0])
        self.assertFalse(restart["kill_server"]["output_truncated"])
        self.assertIn("daemon started successfully", restart["start_server"]["stderr"])
        self.assertEqual(len(device.start_commands()), 1, "the dispatch that died is retried exactly once")
        self.assertTrue(self.records("capture-session")[0]["data"]["adb_server_restarted"])
        self.assertIn("restarted it once", stderr)
        self.assertTrue((self.root / "captures" / "run.pcap").is_file())

    def test_other_device_failures_are_never_restarted_or_retried(self):
        cases = (f"error: device '{SERIAL}' unauthorized\n", "error: closed\n",
                 "error: more than one device/emulator\n", "adb: error: failed to stat remote object\n")
        for error in cases:
            with self.subTest(error=error):
                device = Device()
                proxy = FlakyAdb(device, error=error)
                with self.assertRaises(ForgeError):
                    self.capture(proxy)
                self.assertEqual(proxy.restarts, [])
                self.assertEqual(len(proxy.forwarded), 1, "a non-server failure must be answered once")
                self.assertFalse(any("kill-server" in command for command in proxy.calls))
                self.assertFalse(self.records("capture-session")[0]["data"]["adb_server_restarted"])
                self.assertIsNone(self.records("capture-session")[0]["data"]["adb_server_restart"])

    def test_the_restart_is_one_shot_even_when_the_server_dies_again(self):
        device = Device()
        proxy = FlakyAdb(device, failures=2)
        with self.assertRaises(ForgeError):
            self.capture(proxy)
        self.assertEqual(proxy.restarts, ["kill-server", "start-server"])
        self.assertEqual(len([command for command in proxy.calls if command[1:2] == ["kill-server"]]), 1)
        self.assertEqual(len(proxy.forwarded), 2, "the retry itself is not retried again")

    def test_the_restart_flag_is_per_window_while_the_session_records_the_whole_run(self):
        device = Device(payload=b"\x1c" * 8)
        directory = self.session_directory()
        starts = []

        def second_capture_start(argv):
            if "action" in argv and argv[argv.index("action") + 1] == "start":
                starts.append(1)
                return len(starts) == 2
            return False

        proxy = FlakyAdb(device, match=second_capture_start)
        record, _ = self.capture(proxy, path=SESSION_PATH, repeat=2)
        data = record["data"]
        self.assertTrue(data["success"])
        first, second = (self.store.get(entry["evidence_id"])["data"] for entry in data["windows"])
        self.assertFalse(first["adb_server_restarted"])
        self.assertIsNone(first["adb_server_restart"])
        self.assertTrue(second["adb_server_restarted"])
        self.assertTrue(second["adb_server_restart"]["retried_once"])
        self.assertTrue(data["adb_server_restarted"])
        self.assertEqual(proxy.restarts, ["kill-server", "start-server"])
        self.assertEqual(sorted(item.name for item in directory.iterdir()), ["window-01.pcap", "window-02.pcap"])

    def test_restart_evidence_never_carries_the_api_key(self):
        secret = "pcapdroid-restart-secret-77"
        device = Device(payload=b"\x1d" * 8)

        def failing(command, timeout, binary=False):
            argv = [str(item) for item in command]
            if argv[1:] in (["kill-server"], ["start-server"]):
                return call_result("")
            if "am" in argv and "action" in argv and not failing.answered:
                failing.answered = True
                return call_result("", code=1, stderr=f"error: device '{SERIAL}' not found; argv {argv}\n")
            return device(command, timeout, binary=binary)

        failing.answered = False

        with patch.dict(os.environ, {"FORGE_TEST_RESTART_KEY": secret}):
            record, stderr = self.capture(failing, api_key_env="FORGE_TEST_RESTART_KEY",
                                          tool={"return_value": device.adb})
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertTrue(data["adb_server_restarted"])
        self.assertEqual(data["dispatch_command"][data["dispatch_command"].index("api_key") + 1],
                         pcapdroid.API_KEY_PLACEHOLDER)
        self.assertIn("[REDACTED]", data["adb_server_restart"]["trigger"])
        self.assertNotIn(secret, json.dumps(data["adb_server_restart"]))
        self.assertNotIn(secret, self.stored_text())
        self.assertNotIn(secret, stderr)


class TlsRejectionTests(BaseCase):
    """Post-window diagnostics: per-host client TLS rejections from the scoped addon logcat tail."""

    def test_rejections_are_counted_per_host_with_no_log_value_in_evidence(self):
        device = Device(mitm_installed=True, logcat=LOGCAT_TAIL)
        record, _ = self.capture(device, tls_decryption=True)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertTrue(data["empty"], "the fixture holds no packet data: the rejections explain why")
        self.assertEqual(data["tls_client_rejections"], REJECTION_HOSTS)
        self.assertEqual(data["tls_client_rejection_total"], sum(REJECTION_HOSTS.values()))
        self.assertEqual(device.logcat_commands()[0][-2:], ["-s", "mitmproxy:*"], "only the addon tag is read")
        self.assertEqual(len(device.logcat_commands()), 1, "one bounded tail per window")
        logcat = data["tls_logcat"]
        self.assertEqual((logcat["tag"], logcat["tail_lines"]), ("mitmproxy", pcapdroid.LOGCAT_TAIL_LINES))
        self.assertEqual((logcat["lines_read"], logcat["observed"], logcat["output_truncated"], logcat["reason"]),
                         (LOGCAT_TAIL.count("\n"), True, False, None))
        self.assertFalse(data["no_flows_and_no_rejections"])
        self.assertIn("trust bypass", data["tls_client_rejection_scope"])
        self.assertIn("host names only", data["tls_client_rejection_scope"])
        stored = self.stored_text()
        self.assertNotIn("/_data/v1/app_config", stored, "addon request values never reach evidence")
        self.assertNotIn("OpenSSL", stored)
        self.assertNotIn("ActivityManager", stored)

    def test_zero_rejections_with_an_empty_dump_are_reported_together(self):
        device = Device(mitm_installed=True, logcat="10-15 21:00:00.000  4211  4310 I mitmproxy: listening\n")
        record, _ = self.capture(device, tls_decryption=True)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertTrue(data["empty"])
        self.assertEqual(data["tls_client_rejections"], {})
        self.assertEqual(data["tls_client_rejection_total"], 0)
        self.assertTrue(data["no_flows_and_no_rejections"])
        self.assertEqual(data["tls_logcat"]["lines_read"], 1)

    def test_packet_data_never_claims_that_no_flows_were_captured(self):
        device = Device(mitm_installed=True, payload=b"\x2b" * 32)
        record, _ = self.capture(device, tls_decryption=True)
        data = record["data"]
        self.assertFalse(data["empty"])
        self.assertEqual(data["tls_client_rejection_total"], 0)
        self.assertFalse(data["no_flows_and_no_rejections"])

    def test_an_incomplete_tail_leaves_the_counts_unknown_and_names_the_next_action(self):
        cases = ((call_result("", code=1, stderr="error: closed\n"), False),
                 (call_result("mitmproxy: nothing", omitted_out=4096), True))
        for result, truncated in cases:
            with self.subTest(truncated=truncated):
                device = Device(mitm_installed=True, logcat=LOGCAT_TAIL, logcat_error=result)
                record, _ = self.capture(device, tls_decryption=True,
                                         path=f"captures/tail-{int(truncated)}.pcap")
                data = record["data"]
                self.assertTrue(data["success"], "a diagnostics miss never fails an observed capture")
                self.assertIsNone(data["tls_client_rejections"])
                self.assertIsNone(data["tls_client_rejection_total"])
                self.assertIsNone(data["no_flows_and_no_rejections"])
                self.assertFalse(data["tls_logcat"]["observed"])
                self.assertEqual(data["tls_logcat"]["output_truncated"], truncated)
                self.assertIn("logcat -d -t 2000", data["tls_logcat"]["reason"])
                self.assertFalse(any("kill-server" in command for command in device.commands))
                self.assertNotIn("/_data/v1/app_config", self.stored_text())

    def test_no_logcat_is_read_and_no_rejection_key_is_claimed_without_decryption(self):
        device = Device(payload=b"\x2c" * 8, logcat=LOGCAT_TAIL)
        record, _ = self.capture(device)
        data = record["data"]
        self.assertEqual(device.logcat_commands(), [])
        for key in ("tls_client_rejections", "tls_client_rejection_total", "tls_client_rejection_scope",
                    "tls_logcat", "no_flows_and_no_rejections"):
            self.assertIsNone(data[key])
        self.assertNotIn("trust the proxy", self.stored_text())
        self.assertNotIn("trust the proxy", json.dumps(self.records("capture-session")[0]["data"]))

    def test_a_rejected_window_still_records_the_rejections_it_observed(self):
        device = Device(mitm_installed=True, header_valid=False, logcat=LOGCAT_TAIL)
        with self.assertRaisesRegex(ForgeError, "No readable dump file named"):
            self.capture(device, tls_decryption=True)
        data = self.rejection()["data"]
        self.assertEqual(data["tls_client_rejections"], REJECTION_HOSTS)
        self.assertEqual(data["tls_client_rejection_total"], 4)
        self.assertEqual(data["tls_logcat"]["lines_read"], LOGCAT_TAIL.count("\n"))
        self.assertFalse(data["destination_published"])
        self.assertFalse(data["no_flows_and_no_rejections"], "the tail did name rejections")
        self.assertFalse(self.records("capture-session")[0]["data"]["success"])
        self.assertNotIn("/_data/v1/app_config", self.stored_text())

    def test_a_window_that_failed_before_its_stop_claims_no_rejection_count(self):
        device = Device(mitm_installed=True, consent=False, logcat=LOGCAT_TAIL)
        with self.assertRaises(ForgeError):
            self.capture(device, tls_decryption=True, consent_timeout=2)
        data = self.rejection()["data"]
        self.assertEqual(device.logcat_commands(), [], "the tail is read only after an observed stop")
        for key in ("tls_client_rejections", "tls_client_rejection_total", "tls_client_rejection_scope",
                    "tls_logcat", "no_flows_and_no_rejections"):
            self.assertIsNone(data[key], key)


class PrivacyTests(BaseCase):
    SECRET = "pcapdroid-secret-key-9f2c"

    def test_api_key_never_reaches_evidence_files_or_stderr(self):
        device = Device(payload=b"\x01" * 40, am_echo=f" api_key={self.SECRET}\n")
        with patch.dict(os.environ, {"FORGE_TEST_API_KEY": self.SECRET}):
            record, stderr = self.capture(device, api_key_env="FORGE_TEST_API_KEY")
        data = record["data"]
        command = data["dispatch_command"]
        self.assertEqual(command[command.index("api_key") + 1], pcapdroid.API_KEY_PLACEHOLDER)
        self.assertNotIn(self.SECRET, self.stored_text())
        self.assertNotIn(self.SECRET, stderr)
        self.assertNotIn(self.SECRET, json.dumps(data))
        self.assertTrue(data["settings"]["key_supplied"])
        self.assertEqual(data["settings"]["api_env_variable"], "FORGE_TEST_API_KEY")
        self.assertNotIn("pcapdroid-secret", data["dispatch"]["stdout"])
        self.assertIn("[REDACTED]", data["dispatch"]["stdout"])
        self.assertTrue((self.root / "captures" / "run.pcap").is_file())

    def test_shell_quoted_api_key_echo_is_redacted(self):
        secret = "private-control-key'quoted;$(not-a-command)"
        device = Device(am_echo="api_key=" + shlex.quote(secret))
        with patch.dict(os.environ, {"FORGE_TEST_QUOTED_KEY": secret}):
            _, stderr = self.capture(device, api_key_env="FORGE_TEST_QUOTED_KEY")
        for representation in (secret, shlex.quote(secret), "private-control-key"):
            self.assertNotIn(representation, self.stored_text())
            self.assertNotIn(representation, stderr)

    def test_api_key_is_absent_from_failure_evidence(self):
        device = Device(stop_works=False, am_echo=f" api_key={self.SECRET}\n")
        with patch.dict(os.environ, {"FORGE_TEST_API_KEY": self.SECRET}):
            with self.assertRaises(ForgeError) as raised:
                self.capture(device, api_key_env="FORGE_TEST_API_KEY")
        self.assertNotIn(self.SECRET, str(raised.exception))
        self.assertNotIn(self.SECRET, self.stored_text())
        data = self.rejection()["data"]
        self.assertIn(pcapdroid.API_KEY_PLACEHOLDER, data["stop"]["command"])
        self.assertNotIn(self.SECRET, json.dumps(data))
        self.assertTrue(data["settings"]["key_supplied"])

    def test_arbitrary_api_key_is_posix_quoted_exactly_once(self):
        for index, key in enumerate(("plain-key-123", "key;id", "$(id)", "a b'c\"d", "x&&y|z", "k\nk", "-e")):
            with self.subTest(key=key):
                device = Device(payload=b"\x03" * 8)
                path = f"captures/key-{index}.pcap"
                with patch.dict(os.environ, {"FORGE_TEST_API_KEY": key}):
                    record, _ = self.capture(device, path=path, api_key_env="FORGE_TEST_API_KEY")
                start = device.am_commands()[0]
                element = start[start.index("api_key") + 1]
                self.assertEqual(element, shlex.quote(key), "the device shell must see one quoted argument")
                self.assertEqual(start.count("api_key"), 1)
                self.assertEqual(record["data"]["dispatch_command"][
                    record["data"]["dispatch_command"].index("api_key") + 1], pcapdroid.API_KEY_PLACEHOLDER)
                if shlex.quote(key) != key:
                    self.assertNotIn(key, start, "a metacharacter key must never appear unquoted")
                    self.assertNotIn(key, self.stored_text())
                stop = device.stop_commands()[0]
                self.assertEqual(stop[stop.index("api_key") + 1], shlex.quote(key))
                self.assertTrue((self.root / path).is_file())





if __name__ == "__main__":
    unittest.main()
