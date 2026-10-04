import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError, redact, scrub_text
from forge import verify


class EvidencePrivacyTests(unittest.TestCase):
    def test_nested_json_and_source_snippets_redact_secrets(self):
        value = {"url": "https://user:proxy-secret@example.com/login?access_token=query-secret&mode=normal",
                 "body": '{"password":"body-secret","nested":{"api_key":"key-secret","plan":"pro"}}',
                 "source": 'const cfg = {"token":"source-secret"};',
                 "headers": {"Authorization": "Bearer header-secret", "Content-Type": "application/json"}}
        safe = json.dumps(redact(value))
        for secret in ("proxy-secret", "query-secret", "body-secret", "key-secret", "source-secret", "header-secret"):
            self.assertNotIn(secret, safe)
        self.assertIn("normal", safe)
        self.assertIn("pro", safe)

    def test_explicit_secret_redaction_in_opaque_body(self):
        self.assertEqual(scrub_text("echo:opaque-value", secrets=["opaque-value"]), "echo:[REDACTED]")

    def test_large_opaque_response_retains_body_and_redacts_adjacent_credentials(self):
        body = "x" * (1024 * 1024) + ' access_token="private-long-body-token"'
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore(directory)
            try:
                record = store.add("http_probe", {"response": {"body": body}})
                retained = store.get(record["id"])["data"]["response"]["body"]
                self.assertEqual(retained, "x" * (1024 * 1024) + " access_token=[REDACTED]")
                self.assertNotIn("private-long-body-token", json.dumps(record))
            finally:
                store.close()

    def test_database_does_not_retain_original_json_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore(directory)
            try:
                record = store.add("http_probe", {"response": {"body": '{"refresh_token":"never-persist-this","plan":"pro"}'}})
                stored = store.connection.execute("SELECT data FROM evidence WHERE id=?", (record["id"],)).fetchone()[0]
                self.assertNotIn("never-persist-this", stored)
                self.assertEqual(json.loads(store.get(record["id"])["data"]["response"]["body"])["plan"], "pro")
            finally:
                store.close()


class ControlGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(self.temp.name)
        self.positive = self.exchange("HIT")
        self.negative = self.exchange("FAIL")
        self.protocol = Path(self.temp.name) / "protocol.json"
        self.protocol.write_text(json.dumps({"endpoint": "https://example.com/login", "evidence": [self.positive["id"]]}))

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def exchange(self, bucket, **changes):
        data = {"source": "live_probe", "bucket": bucket,
                "request": {"method": "POST", "url": "https://example.com/login"},
                "response": {"status": 403, "body": {"message": bucket}, "truncated": False},
                "context": {"client": "fixture-client", "egress": "fixture-ip"},
                "transport": {"name": "urllib"}}
        data.update(changes)
        return self.store.add("http_probe", data)

    def run_gate(self, negative=None, positive=None):
        return verify(SimpleNamespace(positive=(positive or self.positive)["id"],
                                      negative=(negative or self.negative)["id"], protocol=str(self.protocol)), self.store)

    def test_protocol_is_resolved_in_target_not_current_directory(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as unrelated:
            (Path(unrelated) / "protocol.json").write_text('{"evidence":["wrong-project-id"]}')
            try:
                os.chdir(unrelated)
                result = verify(SimpleNamespace(positive=self.positive["id"], negative=self.negative["id"],
                                                protocol="protocol.json"), self.store)
            finally:
                os.chdir(previous)
        self.assertEqual(result["data"]["protocol"]["endpoint"], "https://example.com/login")

    def test_status_does_not_override_body_classification(self):
        result = self.run_gate()
        self.assertTrue(result["data"]["passed"])
        self.assertEqual(result["data"]["negative"], self.negative["id"])

    def test_different_egress_cannot_pass_control_gate(self):
        negative = self.exchange("FAIL", context={"client": "fixture-client", "egress": "different-ip"})
        with self.assertRaisesRegex(ForgeError, "differ in egress"):
            self.run_gate(negative=negative)

    def test_different_transport_cannot_pass_control_gate(self):
        negative = self.exchange("FAIL", transport={"name": "curl_cffi"})
        with self.assertRaisesRegex(ForgeError, "same HTTP transport"):
            self.run_gate(negative=negative)

    def test_imported_or_truncated_response_is_not_live_control(self):
        for changes in ({"source": "har_import"}, {"response": {"status": 403, "truncated": True}}):
            with self.subTest(changes=changes):
                with self.assertRaises(ForgeError):
                    self.run_gate(negative=self.exchange("FAIL", **changes))

    def test_unknown_cannot_be_labeled_negative(self):
        with self.assertRaisesRegex(ForgeError, "body-classified FAIL"):
            self.run_gate(negative=self.exchange("UNKNOWN"))


if __name__ == "__main__":
    unittest.main()
