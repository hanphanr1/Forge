import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import forge_ios as ios
import forge_toolchain
from forge_core import EvidenceStore, ForgeError


UDID_ONE = "00008110-001A2B3C4E5F001E"
UDID_TWO = "00008120-001B2C3D4E5F60AB"


def run_result(stdout="", code=0, stderr="", expired=False, omitted=0, launch_error=None):
    return {"returncode": code, "timed_out": expired, "launch_error": launch_error, "stdout": stdout,
            "stderr": stderr, "stdout_omitted_bytes": omitted, "stderr_omitted_bytes": 0}


class IosBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        self.commands = self.parser.add_subparsers(dest="command", required=True)
        ios.register(self.commands)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def tool(self, name, path="configured-tool"):
        return {"available": True, "path": path, "source": "PATH", "setup": forge_toolchain.TOOLS[name]["setup"]}

    def missing(self, name):
        return {"available": False, "path": None, "source": "PATH", "setup": forge_toolchain.TOOLS[name]["setup"]}

    def devices_record(self, stdout, **kwargs):
        with patch.object(ios, "find_tool", return_value=self.tool("idevice_id", "idevice-id-fixture")), \
                patch.object(ios, "_run", return_value=run_result(stdout, **kwargs)):
            return self.command("ios-devices")

    # --- device enumeration -------------------------------------------------------------------

    def test_device_listing_records_only_observed_udids(self):
        record = self.devices_record(f"{UDID_ONE}\nnot-a-udid\n\n{UDID_TWO}\n")
        data = record["data"]
        self.assertEqual(data["devices"], [UDID_ONE, UDID_TWO])
        self.assertEqual(data["devices_omitted"], 0)
        self.assertEqual(data["malformed_lines"], 1)
        self.assertEqual(data["status"], "observed")
        self.assertTrue(data["success"])
        self.assertEqual(data["invocation"]["argv"], ["idevice-id-fixture", "-l"])
        self.assertEqual(self.store.get(record["id"]), record)

    def test_device_listing_is_bounded_and_absent_is_an_observation(self):
        absent = self.devices_record("")
        self.assertEqual(absent["data"]["status"], "absent")
        self.assertTrue(absent["data"]["success"])
        self.assertEqual(absent["data"]["devices"], [])

        flooded = self.devices_record("\n".join(f"{index:040x}" for index in range(ios.MAX_DEVICES + 5)) + "\n")
        self.assertEqual(len(flooded["data"]["devices"]), ios.MAX_DEVICES)
        self.assertEqual(flooded["data"]["devices_omitted"], 5)

    def test_device_listing_never_calls_the_tool_without_configuration(self):
        with patch.object(ios, "find_tool", return_value=self.missing("idevice_id")), \
                patch.object(ios, "_run") as calls:
            with self.assertRaisesRegex(ForgeError, "idevice_id.*FORGE_IDEVICE_ID"):
                self.command("ios-devices")
        calls.assert_not_called()
        record = self.store.list()[0]
        self.assertEqual((record["kind"], record["data"]["status"], record["data"]["success"]),
                         ("runtime", "missing-tool", False))

    def test_device_tool_failure_is_refused_with_evidence_id(self):
        with patch.object(ios, "find_tool", return_value=self.tool("idevice_id", "idevice-id-fixture")), \
                patch.object(ios, "_run", return_value=run_result("", code=1, stderr="boom")):
            with self.assertRaisesRegex(ForgeError, r"tool-failed.*evidence ev_") as raised:
                self.command("ios-devices")
        record = self.store.list()[0]
        self.assertEqual(record["data"]["status"], "tool-failed")
        self.assertFalse(record["data"]["success"])
        self.assertIn(record["id"], str(raised.exception))

    # --- pairing ------------------------------------------------------------------------------

    def test_pairing_verdicts_are_parsed_from_tool_output(self):
        self.assertEqual(ios.parse_pairing(f"SUCCESS: Valid pairing with device {UDID_ONE}\n"), "paired")
        self.assertEqual(ios.parse_pairing("ERROR: Invalid pairing with device %s\n" % UDID_ONE), "not-paired")
        self.assertEqual(ios.parse_pairing("ERROR: Device is not paired with this host\n"), "not-paired")
        self.assertEqual(ios.parse_pairing("noise\n"), "unknown")

        with patch.object(ios, "_run", return_value=run_result(f"SUCCESS: Valid pairing with device {UDID_ONE}\n")):
            paired = ios._pair(self.tool("idevicepair"), UDID_ONE)
        self.assertEqual((paired["status"], paired["pairing_state"], paired["success"]), ("paired", "paired", True))

    def test_pair_command_reports_states_and_records_argv(self):
        with patch.object(ios, "find_tool", return_value=self.tool("idevicepair", "idevicepair-fixture")), \
                patch.object(ios, "_run", return_value=run_result(f"SUCCESS: Valid pairing with device {UDID_ONE}\n")):
            record = self.command("ios-pair", "--udid", UDID_ONE)
        self.assertEqual(record["data"]["status"], "paired")
        self.assertEqual(record["data"]["udid"], UDID_ONE)
        self.assertEqual(record["data"]["invocation"]["argv"], ["idevicepair-fixture", "validate", "-u", UDID_ONE])

        with patch.object(ios, "find_tool", return_value=self.tool("idevicepair", "idevicepair-fixture")), \
                patch.object(ios, "_run", return_value=run_result(f"ERROR: Invalid pairing with device {UDID_ONE}\n", code=1)):
            unpaired = self.command("ios-pair", "--udid", UDID_ONE)
        self.assertEqual(unpaired["data"]["status"], "not-paired")
        self.assertTrue(unpaired["data"]["success"])
        self.assertFalse(unpaired["data"]["tool_ok"])

    def test_unknown_and_failed_pairing_are_refused(self):
        for result, expected in ((run_result("noise\n"), "unknown"), (run_result("SUCCESS: Valid pairing\n", omitted=5), "tool-failed")):
            with self.subTest(expected=expected), \
                    patch.object(ios, "find_tool", return_value=self.tool("idevicepair", "idevicepair-fixture")), \
                    patch.object(ios, "_run", return_value=result):
                with self.assertRaisesRegex(ForgeError, expected):
                    self.command("ios-pair", "--udid", UDID_ONE)

    def test_missing_pair_tool_and_unobserved_udid_never_run_the_tool(self):
        with patch.object(ios, "find_tool", return_value=self.missing("idevicepair")), patch.object(ios, "_run") as calls:
            with self.assertRaisesRegex(ForgeError, "idevicepair.*FORGE_IDEVICEPAIR"):
                self.command("ios-pair", "--udid", UDID_ONE)
        calls.assert_not_called()
        self.assertEqual(self.store.list()[0]["data"]["status"], "missing-tool")

        with patch.object(ios, "_run") as calls, self.assertRaisesRegex(ForgeError, "observed iOS UDID"):
            self.command("ios-pair", "--udid=--bind")
        calls.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parser.parse_args(["ios-pair"])

    # --- boundary claims ----------------------------------------------------------------------

    def test_scope_states_boundary_and_no_capability_is_claimed(self):
        data = self.devices_record(f"{UDID_ONE}\n")["data"]
        self.assertIn("no iOS runtime adapter", data["scope"])
        self.assertIn("jailed", data["scope"])
        self.assertIn("cannot be instrumented", data["scope"])
        self.assertIn("ADB does not apply to iOS", data["scope"])
        self.assertIn("not offered or implied", "\n".join(data["limits"]))
        self.assertTrue(data["read_only"])
        self.assertFalse(data["network_action"])
        self.assertFalse(data["device_write"])
        serialized = json.dumps(data)
        for claim in ("captured", "hooked", "injected", "installed certificate", "bound socket"):
            self.assertNotIn(claim, serialized)

        with patch.object(ios, "_run", return_value=run_result("noise\n")):
            pair = ios._pair(self.tool("idevicepair"), UDID_ONE)
        self.assertEqual(pair["scope"], ios.SCOPE)
        self.assertFalse(pair["network_action"])

    # --- tool discovery -----------------------------------------------------------------------

    def test_tool_discovery_is_the_shared_toolchain_finder(self):
        self.assertIs(ios.find_tool, forge_toolchain.find_tool)

        def which(value):
            return "/opt/" + value if value == "custom-idevice-id" else None
        with patch.dict(os.environ, {"FORGE_IDEVICE_ID": "custom-idevice-id"}), \
                patch.object(forge_toolchain.shutil, "which", side_effect=which):
            found = ios.find_tool("idevice_id")
        self.assertEqual((found["available"], found["path"], found["source"]),
                         (True, "/opt/custom-idevice-id", "FORGE_IDEVICE_ID"))

        with patch.dict(os.environ, {"FORGE_IDEVICE_ID": ""}), patch.object(forge_toolchain.shutil, "which", side_effect=which):
            self.assertFalse(ios.find_tool("idevice_id")["available"])

        with patch.dict(os.environ, {}, clear=True), \
                patch.object(forge_toolchain.shutil, "which", side_effect=lambda value: "/usr/bin/" + value):
            found = ios.find_tool("idevicepair")
        self.assertEqual((found["available"], found["path"], found["source"]), (True, "/usr/bin/idevicepair", "PATH"))
        with self.assertRaises(ForgeError):
            ios.find_tool("not-a-tool")


if __name__ == "__main__":
    unittest.main()
