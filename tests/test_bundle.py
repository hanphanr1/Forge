import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_bundle import bundle
from forge_core import EvidenceStore, ForgeError


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.store = EvidenceStore(self.root)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.store.close)

    def export(self, ids, name="handoff.zip", **kwargs):
        options = {"evidence": ids, "output": name, "limit": 100, "max_bytes": 8 * 1024 * 1024,
                   "max_record_bytes": 16 * 1024 * 1024, "include_findings": False}
        options.update(kwargs)
        return bundle(SimpleNamespace(**options), self.store)

    def read_members(self, name="handoff.zip"):
        with zipfile.ZipFile(self.root / name) as archive:
            self.assertEqual(set(archive.namelist()), {"manifest.json", "evidence.json", "report.md"})
            return {member: archive.read(member) for member in archive.namelist()}

    def test_raw_capture_streams_paths_blobs_and_claim_prose_are_not_shared(self):
        opaque = "privateOpaqueSessionMaterial7391"
        capture = self.store.add("http_probe", {
            "source": "live_probe", "bucket": "HIT", "request": {"method": "POST", "url": "https://private-internal.example/login",
            "headers": {"X-Payload": opaque}, "body": {"opaque": opaque}},
            "response": {"status": 200, "body": {"opaque_echo": opaque}},
            "stdout": opaque, "source_path": "C:/Users/PrivateOwner/private-source.py"})
        self.assertIn(opaque, json.dumps(capture))
        blob = self.store.put_bytes(("raw private binary " + opaque).encode())
        self.store.add("artifact", {**blob, "filename": "private-original.exe"})
        finding = self.store.add("claim", {"text": opaque, "state": "OBSERVED", "evidence": [capture["id"]], "scope": "private-target"})
        result = self.export([finding["id"]])
        members = self.read_members()
        packed = b"\n".join(members.values()).decode()
        for forbidden in [opaque, "private-internal.example", "PrivateOwner", "private-source.py", "private-original.exe", "raw private binary"]:
            self.assertNotIn(forbidden, packed)
        evidence = json.loads(members["evidence.json"])
        shared_capture = next(r for r in evidence["records"] if r["id"] == capture["id"])
        self.assertEqual(shared_capture["facts"]["response"]["status"], 200)
        self.assertEqual(shared_capture["facts"]["bucket"], "HIT")
        self.assertEqual(shared_capture["facts"]["source"], "live_probe")
        self.assertTrue(shared_capture["facts"]["request"]["url"]["identity_withheld"])
        self.assertFalse(result["manifest"]["raw_materials_included"])
        self.assertTrue(result["manifest"]["closure_complete"])

    def test_transitive_controls_are_cited_and_archive_content_hashes_match(self):
        positive = self.store.add("target_run", {"control": "positive", "bucket": "FREE", "success": True, "runtime_before": {"sha256": "a" * 64, "size": 123}})
        negative = self.store.add("target_run", {"control": "negative", "bucket": "FAIL", "success": True})
        gate = self.store.add("target_verification", {"passed": True, "positive": positive["id"], "negative": negative["id"]})
        result = self.export([gate["id"], gate["id"]])
        members = self.read_members()
        manifest = json.loads(members["manifest.json"])
        self.assertEqual(set(manifest["included_ids"]), {gate["id"], positive["id"], negative["id"]})
        self.assertEqual(manifest["selected_ids"], [gate["id"]])
        for fact in manifest["members"]:
            self.assertEqual(hashlib.sha256(members[fact["name"]]).hexdigest(), fact["sha256"])
            self.assertEqual(len(members[fact["name"]]), fact["size"])
        self.assertEqual(hashlib.sha256((self.root / "handoff.zip").read_bytes()).hexdigest(), result["record"]["data"]["sha256"])
        exported = json.loads(members["evidence.json"])["records"]
        self.assertEqual(next(r for r in exported if r["id"] == positive["id"])["facts"]["runtime_before"]["sha256"], "a" * 64)

    def test_missing_and_capped_citations_do_not_claim_complete_handoff(self):
        missing = "ev_" + "f" * 32
        first = self.store.add("claim", {"text": "known local finding", "state": "INFERRED", "evidence": [missing]})
        complete = self.export([first["id"]])
        self.assertFalse(complete["manifest"]["closure_complete"])
        self.assertEqual(complete["manifest"]["missing_reference_ids"], [missing])
        second = self.store.add("target_run", {"control": "negative", "bucket": "FAIL"})
        gate = self.store.add("target_verification", {"passed": False, "positive": first["id"], "negative": second["id"]})
        limited = self.export([gate["id"]], "limited.zip", limit=1)
        self.assertFalse(limited["manifest"]["closure_complete"])
        self.assertEqual(set(limited["manifest"]["omitted_reference_ids"]), {first["id"], second["id"]})

    def test_findings_need_explicit_opt_in_and_tagged_secrets_remain_scrubbed(self):
        finding = self.store.add("claim", {"text": "Observed profile plan; password=private-pass", "state": "OBSERVED", "evidence": []})
        self.export([finding["id"]], include_findings=True)
        members = self.read_members()
        self.assertIn("Observed profile plan", members["report.md"].decode())
        self.assertNotIn("private-pass", b"\n".join(members.values()).decode())
        self.assertTrue(json.loads(members["manifest.json"])["free_text_findings_included"])

    def test_collision_traversal_invalid_ids_and_size_limits_publish_nothing(self):
        finding = self.store.add("claim", {"text": "x" * 10000, "evidence": []})
        for name, options in [("too-small.zip", {"max_bytes": 10}), ("large-record.zip", {"max_record_bytes": 10}),
                              ("../outside.zip", {}), (".forge/private.zip", {})]:
            with self.subTest(name=name):
                before = self.store.connection.execute("SELECT count(*) FROM evidence").fetchone()[0]
                with self.assertRaises(ForgeError):
                    self.export([finding["id"]], name, **options)
                self.assertEqual(self.store.connection.execute("SELECT count(*) FROM evidence").fetchone()[0], before)
                if ".." not in name:
                    self.assertFalse((self.root / name).exists())
        with self.assertRaises(ForgeError):
            self.export(["not-a-canonical-evidence-id"])
        self.export([finding["id"]])
        original = (self.root / "handoff.zip").read_bytes()
        with self.assertRaises(ForgeError):
            self.export([finding["id"]])
        self.assertEqual((self.root / "handoff.zip").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
