import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_retention


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_retention.register(self.parser.add_subparsers())
        self.blobs = self.store.directory / "blobs"

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def backdate(self, evidence_id, days):
        moment = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="milliseconds")
        with self.store.connection:
            self.store.connection.execute("UPDATE evidence SET created_at=? WHERE id=?", (moment, evidence_id))

    def record_ids(self):
        return {record["id"] for record in self.store.list(limit=1000)}

    def test_storage_report_inventories_kinds_blobs_and_database(self):
        probe = self.store.add("http_probe", {"bucket": "HIT", "source": "live_probe"})
        self.store.add("claim", {"text": "observed", "state": "OBSERVED", "evidence": [probe["id"]]})
        orphan = self.store.put_bytes(b"orphan-inventory-payload")
        result = self.command("storage-report")
        kinds = {entry["kind"]: entry for entry in result["records"]["kinds"]}
        self.assertEqual(result["records"]["total"], 2)
        self.assertEqual(kinds["http_probe"]["records"], 1)
        self.assertGreater(kinds["http_probe"]["bytes"], 0)
        self.assertLessEqual(kinds["claim"]["oldest_created_at"], kinds["claim"]["newest_created_at"])
        self.assertEqual(result["blobs"]["total"]["count"], 1)
        self.assertEqual(result["blobs"]["total"]["bytes"], len(b"orphan-inventory-payload"))
        self.assertEqual(result["blobs"]["unreferenced"]["count"], 1)
        self.assertEqual(result["blobs"]["unreferenced"]["sha256"], [orphan["sha256"]])
        self.assertEqual(result["blobs"]["referenced"]["count"], 0)
        self.assertGreater(result["database"]["bytes"], 0)
        self.assertFalse(result["scan"]["truncated"])
        self.assertEqual(len(self.store.list(limit=1000)), 2, "storage-report must not append evidence")

    def test_dry_run_deletes_nothing(self):
        probe = self.store.add("http_probe", {"bucket": "HIT", "source": "live_probe"})
        blob = self.store.put_bytes(b"orphan-dry-run-payload")
        self.backdate(probe["id"], 30)
        before = self.record_ids()
        result = self.command("evidence-prune", "--unreferenced-blobs", "--older-than", "1")
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["apply"])
        self.assertEqual(result["deleted"]["records"], 0)
        self.assertEqual(result["deleted"]["blobs"], 0)
        self.assertEqual(result["deleted"]["bytes_freed"], 0)
        self.assertEqual(result["planned"]["records"], [probe["id"]])
        self.assertEqual(result["planned"]["blobs"], [blob["sha256"]])
        self.assertTrue((self.blobs / blob["sha256"]).is_file())
        after = self.record_ids()
        self.assertTrue(before <= after)
        self.assertEqual(after - before, {result["audit"]["id"]}, "only the mandated audit row is appended")

    def test_prior_audit_rows_do_not_shield_orphan_blobs(self):
        orphan = self.store.put_bytes(b"orphan-after-audit-payload")
        self.command("evidence-prune", "--unreferenced-blobs")
        result = self.command("evidence-prune", "--unreferenced-blobs", "--apply")
        self.assertEqual(result["planned"]["blobs"], [orphan["sha256"]])
        self.assertEqual(result["deleted"]["blobs"], 1)
        self.assertFalse((self.blobs / orphan["sha256"]).exists())

    def test_apply_removes_only_unreferenced_blobs(self):
        referenced = self.store.put_bytes(b"referenced-payload")
        orphan = self.store.put_bytes(b"orphan-payload")
        record = self.store.add("runtime", {"tool": "adb", "action": "screenshot", "blob": referenced})
        result = self.command("evidence-prune", "--unreferenced-blobs", "--apply")
        self.assertEqual(result["deleted"]["blobs"], 1)
        self.assertEqual(result["deleted"]["blob_bytes"], len(b"orphan-payload"))
        self.assertTrue((self.blobs / referenced["sha256"]).is_file())
        self.assertFalse((self.blobs / orphan["sha256"]).exists())
        self.assertEqual(self.store.get(record["id"])["kind"], "runtime")

    def test_cited_evidence_is_protected_without_force(self):
        probe = self.store.add("http_probe", {"bucket": "HIT", "source": "live_probe"})
        claim = self.store.add("claim", {"text": "observed", "state": "OBSERVED", "evidence": [probe["id"]]})
        self.backdate(probe["id"], 30)
        self.backdate(claim["id"], 30)
        result = self.command("evidence-prune", "--older-than", "1", "--apply")
        self.assertEqual(result["deleted"]["records"], 0)
        self.assertEqual(result["skipped"]["cited"], 1)
        self.assertEqual(result["skipped"]["citation_source"], 1)
        self.assertEqual(self.store.get(probe["id"])["id"], probe["id"])
        self.assertEqual(self.store.get(claim["id"])["id"], claim["id"])
        forced = self.command("evidence-prune", "--older-than", "1", "--apply", "--force")
        self.assertIn(probe["id"], forced["planned"]["records"])
        with self.assertRaises(ForgeError):
            self.store.get(probe["id"])

    def test_active_task_protection(self):
        task = self.store.add("task", {"target": "https://example.invalid", "state": "active", "phase": "discover"})
        checkpoint = self.store.add("task_checkpoint", {"task_id": task["id"], "revision": 1,
                                                        "phase": "probe", "state": "active"})
        probe = self.store.add("http_probe", {"bucket": "HIT", "source": "live_probe"})
        self.backdate(task["id"], 40)
        self.backdate(checkpoint["id"], 10)
        self.backdate(probe["id"], 5)
        with self.assertRaisesRegex(ForgeError, "active task"):
            self.command("evidence-prune", "--older-than", "1", "--apply")
        self.assertEqual(self.store.get(probe["id"])["id"], probe["id"])
        audits = [record for record in self.store.list("maintenance", 10)]
        self.assertTrue(audits, "refused runs still append an audit record")
        self.assertIn("active task", audits[0]["data"]["refused"])

    def test_maintenance_audit_is_written_and_never_pruned(self):
        result = self.command("evidence-prune", "--unreferenced-blobs")
        audit = self.store.get(result["audit"]["id"])
        self.assertEqual(audit["kind"], "maintenance")
        self.assertTrue(audit["data"]["append_only_violation"])
        self.assertIn("no longer resolve", audit["data"]["citation_warning"])
        self.assertEqual(audit["data"]["filters"], {"older_than_days": None, "kinds": []})
        self.backdate(audit["id"], 400)
        pruned = self.command("evidence-prune", "--older-than", "1", "--kind", "maintenance", "--apply", "--force")
        self.assertEqual(pruned["deleted"]["records"], 0)
        self.assertEqual(pruned["skipped"]["maintenance"], 1)
        self.assertEqual(self.store.get(audit["id"])["kind"], "maintenance")

    def test_invalid_arguments_are_rejected(self):
        for argv in (("evidence-prune",),
                     ("evidence-prune", "--apply", "--dry-run", "--older-than", "1"),
                     ("evidence-prune", "--older-than", "0"),
                     ("evidence-prune", "--older-than", "36501"),
                     ("evidence-prune", "--unreferenced-blobs", "--kind", "http_probe"),
                     ("evidence-prune", "--kind", "http_probe")):
            with self.subTest(argv=argv), self.assertRaises(ForgeError):
                self.command(*argv)
        self.assertEqual(self.store.list(limit=1000), [], "rejected arguments write no evidence")

    def test_older_than_kind_filter_narrows_deletion(self):
        probe = self.store.add("http_probe", {"bucket": "HIT", "source": "live_probe"})
        analysis = self.store.add("analysis", {"tool": "jadx", "success": True})
        self.backdate(probe["id"], 30)
        self.backdate(analysis["id"], 30)
        result = self.command("evidence-prune", "--older-than", "1", "--kind", "analysis", "--apply")
        self.assertEqual(result["planned"]["records"], [analysis["id"]])
        self.assertEqual(result["deleted"]["records"], 1)
        self.assertEqual(self.store.get(probe["id"])["kind"], "http_probe")
        with self.assertRaises(ForgeError):
            self.store.get(analysis["id"])


if __name__ == "__main__":
    unittest.main()
