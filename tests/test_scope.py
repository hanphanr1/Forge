import argparse
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge
import forge_tasks


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.cli = forge.parser()

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def init(self, *extra):
        args = self.cli.parse_args(["--project", str(self.root), "init", "--target", "https://example.com", *extra])
        return args.handler(args, self.store)

    def test_declared_scope_is_stored_and_surfaced_unmasked(self):
        record = self.init("--authorization", "granted", "--basis", "own_system",
                           "--network-profile", "authorized_target_only", "--in-scope", "example.com",
                           "--out-of-scope", "third-party hosts")
        stored = record["task"]["data"]["scope"]
        self.assertEqual(stored["scope_status"], "granted")
        self.assertEqual(stored["scope_basis"], "own_system")
        self.assertEqual(stored["in_scope"], ["example.com"])
        self.assertEqual(stored["out_of_scope"], ["third-party hosts"])
        progress = forge_tasks.task_status(self.store)
        self.assertEqual(progress["scope"]["scope_status"], "granted")

    def test_granted_requires_a_declared_basis(self):
        with self.assertRaisesRegex(ForgeError, "needs a --basis"):
            self.init("--authorization", "granted")
        with self.assertRaises(SystemExit):
            self.init("--authorization", "granted", "--basis", "own_system", "--network-profile", "bogus")
        with self.assertRaises(SystemExit):
            self.init("--authorization", "bogus")

    def test_unspecified_scope_never_gates(self):
        self.init()
        self.assertIsInstance(forge_tasks.check_scope(self.store, "probe", network=True), dict)
        self.assertIsInstance(forge_tasks.check_scope(self.store, "adb devices", device=True), dict)

    def test_denied_scope_blocks_active_work_but_not_local_analysis(self):
        self.init("--authorization", "denied")
        with self.assertRaisesRegex(ForgeError, "authorization status is denied"):
            forge_tasks.check_scope(self.store, "probe", network=True)
        with self.assertRaisesRegex(ForgeError, "authorization status is denied"):
            forge_tasks.check_scope(self.store, "adb devices", device=True)
        self.assertFalse(forge_tasks.check_scope(self.store, "native imports")["active"])

    def test_offline_profile_blocks_network_and_device_only(self):
        self.init("--authorization", "granted", "--basis", "lab_only", "--network-profile", "offline")
        with self.assertRaisesRegex(ForgeError, "network activity"):
            forge_tasks.check_scope(self.store, "probe", network=True)
        with self.assertRaisesRegex(ForgeError, "device activity"):
            forge_tasks.check_scope(self.store, "frida", device=True)
        self.assertIsInstance(forge_tasks.check_scope(self.store, "protocol-map"), dict)

    def test_gate_messages_are_not_masked_by_redaction(self):
        self.init("--authorization", "denied")
        with self.assertRaises(ForgeError) as caught:
            forge_tasks.check_scope(self.store, "probe", network=True)
        self.assertNotIn("[REDACTED]", str(caught.exception))
        self.assertIn("denied", str(caught.exception))

    def test_scope_gate_prefers_the_newest_task(self):
        self.init("--authorization", "denied")
        self.init("--authorization", "granted", "--basis", "own_system", "--network-profile", "unrestricted_lab")
        self.assertEqual(forge_tasks.check_scope(self.store, "probe", network=True)["scope_status"], "granted")


class HookEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.cli = forge.parser()

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def run_cli(self, *argv):
        args = self.cli.parse_args(["--project", str(self.root), *argv])
        return args.handler(args, self.store)

    def claim(self, text):
        return self.run_cli("claim", text, "--scope", "fixture 1.0")["id"]

    def test_triple_is_stored_with_its_own_citation_per_part(self):
        static, dynamic, state = self.claim("static"), self.claim("dynamic"), self.claim("state")
        record = self.run_cli("hook-evidence", "signer boundary", "--package", "com.example.app",
                              "--static-location", "com.example.Signer.sign", "--static-evidence", static,
                              "--dynamic-proof", "returned a 32-byte value", "--dynamic-evidence", dynamic,
                              "--state-dependency", "needs a stored nonce row", "--state-evidence", state,
                              "--scope", "fixture 1.0")
        triple = record["data"]["hook"]
        self.assertEqual(triple["static_location"], {"text": "com.example.Signer.sign", "evidence": static})
        self.assertEqual(triple["dynamic_proof"], {"text": "returned a 32-byte value", "evidence": dynamic})
        self.assertEqual(triple["state_dependency"], {"text": "needs a stored nonce row", "evidence": state})
        self.assertEqual(record["data"]["evidence"], [static, dynamic, state])
        self.assertEqual(record["kind"], "claim")

    def test_missing_state_dependency_is_recorded_as_not_established(self):
        static, dynamic = self.claim("static"), self.claim("dynamic")
        record = self.run_cli("hook-evidence", "signer boundary", "--package", "com.example.app",
                              "--static-location", "com.example.Signer.sign", "--static-evidence", static,
                              "--dynamic-proof", "returned a 32-byte value", "--dynamic-evidence", dynamic,
                              "--scope", "fixture 1.0")
        state = record["data"]["hook"]["state_dependency"]
        self.assertIsNone(state["text"])
        self.assertEqual(state["state"], "not-established")

    def test_partial_state_pair_and_unknown_citations_are_rejected(self):
        static, dynamic = self.claim("static"), self.claim("dynamic")
        base = ["hook-evidence", "signer boundary", "--package", "com.example.app",
                "--static-location", "com.example.Signer.sign", "--static-evidence", static,
                "--dynamic-proof", "returned a 32-byte value", "--dynamic-evidence", dynamic,
                "--scope", "fixture 1.0"]
        with self.assertRaisesRegex(ForgeError, "supplied together"):
            self.run_cli(*base, "--state-dependency", "a pref row")
        with self.assertRaisesRegex(ForgeError, "Unknown evidence ID"):
            self.run_cli("hook-evidence", "signer boundary", "--package", "com.example.app",
                         "--static-location", "com.example.Signer.sign", "--static-evidence", "ev_missing",
                         "--dynamic-proof", "returned a 32-byte value", "--dynamic-evidence", dynamic,
                         "--scope", "fixture 1.0")


if __name__ == "__main__":
    unittest.main()
