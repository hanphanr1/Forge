from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from threading import Barrier
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_tasks
from forge_tasks import checkpoint, initialize, resume, task_status


class TaskCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.task = self.new_task()

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def new_task(self, goal="Identify the official client protocol"):
        return initialize(SimpleNamespace(target="https://example.com/login", goal=goal),
                          self.store, ["desktop", "web"])["task"]

    def args(self, **changes):
        values = dict(task=self.task["id"], phase="analyze", state="active", summary="Observed request fields",
                      next_action="Inspect the client request builder", blocker=None,
                      evidence=None, file=None, expect_revision=0)
        values.update(changes)
        return SimpleNamespace(**values)

    def read(self, task=None, snapshot=None):
        return resume(SimpleNamespace(task=task or self.task["id"], checkpoint=snapshot), self.store)

    def count(self):
        return self.store.connection.execute("SELECT count(*) FROM evidence WHERE kind='task_checkpoint'").fetchone()[0]

    def assert_rejected(self, **changes):
        before = self.count()
        with self.assertRaises((ForgeError, OSError)):
            checkpoint(self.args(**changes), self.store)
        self.assertEqual(self.count(), before)
        self.assertFalse(self.store.connection.in_transaction)


    def test_initialize_uses_official_workflow_when_package_has_no_local_file(self):
        with patch.object(forge_tasks, "__file__", str(self.root / "forge_tasks.py")):
            result = initialize(SimpleNamespace(target="https://example.com", goal="Inspect protocol"), self.store, [])
        self.assertEqual(result["workflow"], "https://github.com/hanphanr1/Forge/blob/main/WORKFLOW.md")

    def test_initialize_preserves_local_workflow_path(self):
        workflow = self.root / "WORKFLOW.md"
        workflow.write_text("Agent workflow", encoding="utf-8")
        with patch.object(forge_tasks, "__file__", str(self.root / "forge_tasks.py")):
            result = initialize(SimpleNamespace(target="https://example.com", goal="Inspect protocol"), self.store, [])
        self.assertEqual(result["workflow"], str(workflow))

    def test_invalid_target_does_not_create_a_task(self):
        before = len(self.store.list("task"))
        for target in ("file:///tmp/source", "https://", "https://[invalid"):
            with self.subTest(target=target), self.assertRaises(ForgeError):
                initialize(SimpleNamespace(target=target, goal="Inspect protocol"), self.store, [])
        self.assertEqual(len(self.store.list("task")), before)

    def test_blocked_checkpoint_survives_store_reopen_exactly(self):
        source = self.root / "client.py"
        content = b"def build_request():\n    return {}\n"
        source.write_bytes(content)
        citation = self.store.add("artifact", {"description": "Official client source"})
        saved = checkpoint(self.args(phase="probe", state="blocked", summary="Client requires a device response",
                                     next_action="Obtain the authorized device response",
                                     blocker=["No connected authorized device"], evidence=[citation["id"]],
                                     file=["client.py"]), self.store)
        self.store.close()
        self.store = EvidenceStore(self.root)
        result = self.read()
        self.assertEqual(result["checkpoint"], saved)
        self.assertEqual(result["revision"], 1)
        self.assertEqual(result["current_revision"], 1)
        self.assertTrue(result["is_current"])
        for field in ("phase", "state", "summary", "next_action", "blockers", "evidence", "files"):
            self.assertEqual(result[field], saved["data"][field])
        fact = result["files"][0]
        self.assertEqual(fact, {"path": "client.py", "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        self.assertEqual(result["file_integrity"][0]["status"], "unchanged")
        self.assertEqual(self.count(), 1)

    def test_changed_and_missing_files_are_facts_without_resetting_progress(self):
        (self.root / "changed.py").write_text("before", encoding="utf-8")
        missing = self.root / "missing.py"
        missing.write_text("original", encoding="utf-8")
        checkpoint(self.args(state="blocked", blocker=["Need target access"], file=["missing.py", "changed.py"]), self.store)
        (self.root / "changed.py").write_text("after", encoding="utf-8")
        missing.unlink()
        result = self.read()
        facts = {item["path"]: item for item in result["file_integrity"]}
        self.assertEqual(facts["changed.py"]["status"], "changed")
        self.assertNotEqual(facts["changed.py"]["expected"]["sha256"], facts["changed.py"]["observed"]["sha256"])
        self.assertEqual(facts["missing.py"]["status"], "missing")
        self.assertIsNone(facts["missing.py"]["observed"])
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["blockers"], ["Need target access"])
        self.assertEqual(result["revision"], 1)
        self.assertEqual(self.count(), 1)

    def test_status_never_rehashes_files(self):
        (self.root / "source.py").write_text("source", encoding="utf-8")
        checkpoint(self.args(file=["source.py"]), self.store)
        with patch.object(forge_tasks, "_file_fact", side_effect=AssertionError("status must not hash")):
            result = task_status(self.store, self.task["id"])
        self.assertEqual(result["files"][0]["path"], "source.py")

    def test_tasks_have_independent_revisions_and_default_selects_newest_task(self):
        first = checkpoint(self.args(state="blocked", blocker=["Task one blocker"]), self.store)
        second_task = self.new_task("Different target investigation")
        second = checkpoint(self.args(task=None, summary="Task two observed source", phase="implement"), self.store)
        self.assertEqual(second["data"]["task_id"], second_task["id"])
        self.assertEqual(second["data"]["revision"], 1)
        self.assertEqual(task_status(self.store)["checkpoint_id"], second["id"])
        self.assertEqual(task_status(self.store, self.task["id"])["checkpoint_id"], first["id"])
        self.assertEqual(self.read()["blockers"], ["Task one blocker"])
        default = resume(SimpleNamespace(task=None, checkpoint=None), self.store)
        self.assertEqual(default["task"]["id"], second_task["id"])
        self.assertEqual(default["blockers"], [])

    def test_task_snapshot_query_is_not_limited_to_recent_evidence(self):
        saved = checkpoint(self.args(), self.store)
        for index in range(105):
            task = self.new_task(f"Unrelated task {index}")
            checkpoint(self.args(task=task["id"]), self.store)
        self.assertEqual(task_status(self.store, self.task["id"])["checkpoint_id"], saved["id"])

    def test_legacy_task_resumes_at_revision_zero_then_accepts_checkpoint(self):
        legacy = self.store.add("task", {"target": "https://example.com", "goal": "Legacy discovery", "phase": "discover"})
        result = self.read(task=legacy["id"])
        self.assertEqual(result["revision"], 0)
        self.assertEqual(result["state"], "active")
        self.assertEqual(result["blockers"], [])
        self.assertTrue(result["next_action"])
        saved = checkpoint(self.args(task=legacy["id"]), self.store)
        self.assertEqual(saved["data"]["revision"], 1)

    def test_stale_revision_is_rejected_before_file_access_and_without_writes(self):
        checkpoint(self.args(), self.store)
        with patch.object(forge_tasks, "_file_fact", side_effect=AssertionError("stale write must not hash")):
            self.assert_rejected(file=["not-present.py"], expect_revision=0)
        self.assertEqual(task_status(self.store)["revision"], 1)
        saved = checkpoint(self.args(expect_revision=1), self.store)
        self.assertEqual(saved["data"]["revision"], 2)

    def test_historical_resume_cannot_replace_current_or_clear_blockers(self):
        old = checkpoint(self.args(state="blocked", blocker=["Missing observation"]), self.store)
        new = checkpoint(self.args(expect_revision=1, phase="discover", summary="Investigating another client"), self.store)
        result = self.read(snapshot=old["id"])
        self.assertEqual(result["revision"], 1)
        self.assertEqual(result["current_revision"], 2)
        self.assertFalse(result["is_current"])
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["blockers"], ["Missing observation"])
        self.assertEqual(task_status(self.store)["checkpoint_id"], new["id"])
        self.assert_rejected(expect_revision=result["revision"])
        self.assertEqual(self.count(), 2)

    def test_historical_file_integrity_uses_selected_snapshot_not_current(self):
        source = self.root / "source.py"
        source.write_text("original", encoding="utf-8")
        old = checkpoint(self.args(file=["source.py"]), self.store)
        source.write_text("updated", encoding="utf-8")
        checkpoint(self.args(expect_revision=1, file=["source.py"]), self.store)
        self.assertEqual(self.read(snapshot=old["id"])["file_integrity"][0]["status"], "changed")
        self.assertEqual(self.read()["file_integrity"][0]["status"], "unchanged")

    def test_cross_task_and_noncheckpoint_resume_ids_are_rejected(self):
        first = checkpoint(self.args(), self.store)
        second_task = self.new_task()
        for record_id in (first["id"], self.task["id"]):
            with self.subTest(record_id=record_id), self.assertRaises(ForgeError):
                self.read(task=second_task["id"], snapshot=record_id)
        self.assertEqual(self.count(), 1)
        self.assertFalse(self.store.connection.in_transaction)

    def test_unknown_and_nontask_ids_fail_without_checkpoint_writes(self):
        unrelated = self.store.add("artifact", {"description": "Not a task"})
        for task_id in ("ev_missing", unrelated["id"]):
            self.assert_rejected(task=task_id)
            with self.assertRaises(ForgeError):
                task_status(self.store, task_id)
        self.assert_rejected(evidence=["ev_missing"])

    def test_cross_task_citations_are_rejected_but_unscoped_evidence_is_allowed(self):
        other = self.new_task()
        other_checkpoint = checkpoint(self.args(task=other["id"]), self.store)
        scoped = self.store.add("artifact", {"task_id": other["id"], "description": "Other task source"})
        for record in (other, other_checkpoint, scoped):
            self.assert_rejected(evidence=[record["id"]])
        unscoped = self.store.add("artifact", "Description without task assignment")
        saved = checkpoint(self.args(evidence=[unscoped["id"], self.task["id"], unscoped["id"]]), self.store)
        self.assertEqual(saved["data"]["evidence"], [unscoped["id"], self.task["id"]])

    def test_completed_and_blocked_lifecycle_invariants(self):
        for changes in (dict(next_action=None), dict(next_action=" "), dict(summary=" "),
                        dict(state="blocked"), dict(state="blocked", blocker=["Need source"], next_action=None),
                        dict(state="blocked", blocker=[" "]), dict(state="completed"),
                        dict(state="completed", next_action=None, blocker=["Unresolved"]),
                        dict(phase="unknown"), dict(state="unknown")):
            with self.subTest(changes=changes):
                self.assert_rejected(**changes)
        saved = checkpoint(self.args(state="completed", phase="verify", next_action=None), self.store)
        self.assertEqual(saved["data"]["state"], "completed")
        self.assertIsNone(saved["data"]["next_action"])
        self.assertEqual(saved["data"]["blockers"], [])
        self.assertNotIn("passed", saved["data"])
        self.assertIn("do not prove", saved["data"]["meaning"])
        resumed = checkpoint(self.args(expect_revision=1, phase="discover"), self.store)
        self.assertEqual(resumed["data"]["phase"], "discover")
        self.assertEqual(resumed["data"]["state"], "active")

    def test_invalid_revisions_are_rejected_without_writes(self):
        for value in (None, -1, True, 1.0, "0"):
            with self.subTest(value=value):
                self.assert_rejected(expect_revision=value)

    def test_excluded_paths_traversal_directories_and_external_files_are_rejected(self):
        outside = self.root.parent / "outside.py"
        candidates = ["../outside.py", "nested/../../outside.py", "nested\\..\\source.py", str(outside),
                      ".forge/evidence.sqlite3", ".git/config", "node_modules/package/index.js", ".venv/lib/source.py",
                      "results/result.json", "__pycache__/source.pyc", "accounts.txt", "proxies.txt", "keys.txt",
                      ".env", ".env.production", "secrets/api.txt", "credentials/password.txt", "data/account-list.csv",
                      "private.pem", "source.py:alternate", "C:relative.py"]
        for candidate in candidates:
            with self.subTest(path=candidate):
                self.assert_rejected(file=[candidate])
        folder = self.root / "folder"
        folder.mkdir()
        self.assert_rejected(file=["folder"])
        self.assert_rejected(file=["missing.py"])

    def test_absolute_project_files_are_saved_as_relative_and_sorted_without_duplicates(self):
        for name in ("a.py", "z.py"):
            (self.root / name).write_text(name, encoding="utf-8")
        result = checkpoint(self.args(file=["z.py", str(self.root / "a.py"), "./a.py"]), self.store)
        self.assertEqual([fact["path"] for fact in result["data"]["files"]], ["a.py", "z.py"])
        self.assertTrue(all(set(fact) == {"path", "sha256", "size"} for fact in result["data"]["files"]))

    def test_unsafe_file_in_batch_rolls_back_entire_checkpoint(self):
        (self.root / "safe.py").write_text("source", encoding="utf-8")
        self.assert_rejected(file=["safe.py", "accounts.txt"])
        self.assertEqual(task_status(self.store)["revision"], 0)

    def test_symlink_files_and_ancestor_directories_are_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "source.py"
            target.write_text("external", encoding="utf-8")
            try:
                (self.root / "alias.py").symlink_to(target)
                (self.root / "linked").symlink_to(Path(outside), target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Platform does not permit symlinks: {exc}")
            self.assert_rejected(file=["alias.py"])
            self.assert_rejected(file=["linked/source.py"])
            (self.root / "local.py").write_text("source", encoding="utf-8")
            (self.root / "local_alias.py").symlink_to(self.root / "local.py")
            self.assert_rejected(file=["local_alias.py"])

    def test_resume_reports_file_replaced_by_symlink_as_unsafe_without_following_it(self):
        source = self.root / "source.py"
        source.write_text("original", encoding="utf-8")
        checkpoint(self.args(file=["source.py"]), self.store)
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "external.py"
            target.write_text("must not be read", encoding="utf-8")
            source.unlink()
            try:
                source.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Platform does not permit symlinks: {exc}")
            result = self.read()
        fact = result["file_integrity"][0]
        self.assertEqual(fact["status"], "unsafe")
        self.assertIsNone(fact["observed"])
        self.assertEqual(self.count(), 1)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Requires POSIX FIFOs")
    def test_special_file_is_rejected_without_blocking(self):
        os.mkfifo(self.root / "pipe")
        self.assert_rejected(file=["pipe"])

    def test_redaction_applies_before_return_and_persistence(self):
        saved = checkpoint(self.args(state="blocked", summary="password=summary-secret",
                                     blocker=["Authorization: Bearer blocker-secret"], next_action="token=next-secret"), self.store)
        output = json.dumps(saved) + json.dumps(self.read())
        rows = self.store.connection.execute("SELECT data FROM evidence").fetchall()
        persisted = "".join(row[0] for row in rows)
        for secret in ("summary-secret", "blocker-secret", "next-secret"):
            self.assertNotIn(secret, output)
            self.assertNotIn(secret, persisted)
        self.assertIn("[REDACTED]", output)
        database_bytes = b"".join(path.read_bytes() for path in self.store.directory.glob("evidence.sqlite3*"))
        for secret in (b"summary-secret", b"blocker-secret", b"next-secret"):
            self.assertNotIn(secret, database_bytes)

    def test_initialize_redacts_target_userinfo_query_and_goal(self):
        result = initialize(SimpleNamespace(target="https://user:target-secret@example.com/login?token=query-secret",
                                            goal="password=goal-secret"), self.store, [])
        serialized = json.dumps(result)
        for secret in ("target-secret", "query-secret", "goal-secret"):
            self.assertNotIn(secret, serialized)

    def test_failed_insert_rolls_back_lock_and_keeps_revision(self):
        self.store.connection.execute("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON evidence "
                                      "WHEN NEW.kind='task_checkpoint' BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
        self.store.connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            checkpoint(self.args(), self.store)
        self.assertEqual(self.count(), 0)
        self.assertFalse(self.store.connection.in_transaction)
        self.store.connection.execute("DROP TRIGGER reject_checkpoint")
        self.store.connection.commit()
        self.assertEqual(checkpoint(self.args(), self.store)["data"]["revision"], 1)

    def test_concurrent_writers_cannot_both_append_same_revision(self):
        barrier = Barrier(2)

        def write_snapshot():
            store = EvidenceStore(self.root)
            try:
                barrier.wait(timeout=10)
                try:
                    return checkpoint(self.args(), store)["data"]["revision"]
                except ForgeError as exc:
                    return str(exc)
            finally:
                store.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: write_snapshot(), range(2)))
        self.assertEqual(results.count(1), 1)
        self.assertEqual(sum(isinstance(value, str) and "Stale revision" in value for value in results), 1)
        self.assertEqual(self.count(), 1)

    def test_no_task_status_and_commands_have_explicit_behavior(self):
        with tempfile.TemporaryDirectory() as empty:
            store = EvidenceStore(empty)
            try:
                self.assertIsNone(task_status(store))
                with self.assertRaisesRegex(ForgeError, "No task"):
                    checkpoint(self.args(task=None), store)
                with self.assertRaisesRegex(ForgeError, "No task"):
                    resume(SimpleNamespace(task=None, checkpoint=None), store)
                self.assertFalse(store.connection.in_transaction)
                self.assertEqual(store.list("task_checkpoint"), [])
            finally:
                store.close()



    def test_history_pages_stay_task_scoped_and_ordered(self):
        first = checkpoint(self.args(state="blocked", blocker=["Missing capture"]), self.store)
        other = self.new_task("Independent client")
        unrelated = checkpoint(self.args(task=other["id"], summary="Other findings"), self.store)
        second = checkpoint(self.args(expect_revision=1, phase="probe", summary="Capture obtained"), self.store)
        page = forge_tasks.history(SimpleNamespace(task=self.task["id"], after_revision=0, limit=1), self.store)
        self.assertEqual([record["id"] for record in page["checkpoints"]], [first["id"]])
        self.assertEqual(page["checkpoints"][0]["data"]["blockers"], ["Missing capture"])
        self.assertTrue(page["has_more"])
        self.assertEqual(page["next_revision"], 1)
        next_page = forge_tasks.history(
            SimpleNamespace(task=self.task["id"], after_revision=page["next_revision"], limit=1), self.store)
        self.assertEqual([record["id"] for record in next_page["checkpoints"]], [second["id"]])
        self.assertFalse(next_page["has_more"])
        self.assertIsNone(next_page["next_revision"])
        newest = forge_tasks.history(SimpleNamespace(task=None, after_revision=0, limit=20), self.store)
        self.assertEqual(newest["task"]["id"], other["id"])
        self.assertEqual([record["id"] for record in newest["checkpoints"]], [unrelated["id"]])

    def test_history_rejects_invalid_cursor_limit_and_task(self):
        args = {"task": self.task["id"], "after_revision": 0, "limit": 20}
        for changes in ({"limit": 0}, {"limit": 1001}, {"after_revision": -1},
                        {"task": "ev_missing"}, {"task": self.store.add("artifact", {})["id"]}):
            with self.subTest(changes=changes), self.assertRaises(ForgeError):
                forge_tasks.history(SimpleNamespace(**(args | changes)), self.store)
        self.assertEqual(self.count(), 0)


if __name__ == "__main__":
    unittest.main()
