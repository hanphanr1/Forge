import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_artifacts


class AndroidApiMapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_artifacts.register(self.parser.add_subparsers())
        self.index_path = self.store.directory / "indexes" / "fixture" / "index.jsonl"
        self.index_path.parent.mkdir(parents=True)
        rows = [
            {"source": "installed/base.apk", "member": "classes.dex", "byte_offset": 42,
             "kind": "binary_string", "text": "https://api.example.test/v1/login"},
            {"source": "installed/base.apk", "member": "classes2.dex", "byte_offset": 90,
             "kind": "binary_string", "text": "wss://api.example.test/ws/events"},
        ]
        content = "".join(json.dumps(row) + "\n" for row in rows).encode()
        self.index_path.write_bytes(content)
        self.index = self.store.add("analysis", {"tool": "static_index", "path": self.index_path.relative_to(self.root).as_posix(),
                                                   "index_sha256": hashlib.sha256(content).hexdigest(),
                                                   "index_size": len(content), "truncated": False})
        self.source_root = self.store.directory / "analysis" / "jadx-fixture" / "output"
        sources = self.source_root / "sources" / "e5"
        sources.mkdir(parents=True)
        (sources / "c.java").write_text(
            'package e5;\nclass c {\n  String login = "https://api.example.test/v1/login";\n'
            '  String socket = "wss://api.example.test/ws/events";\n}\n', encoding="utf-8")
        other = self.source_root / "sources" / "other"
        other.mkdir()
        (other / "Client.java").write_text("package other; class Client {}\n", encoding="utf-8")
        self.jadx = self.store.add("analysis", {"tool": "jadx", "status": "partial",
                                                 "output_path": self.source_root.relative_to(self.root).as_posix(),
                                                 "java_files": 2})

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def run_map(self, *extra):
        args = self.parser.parse_args(["android-api-map", "--index-evidence", self.index["id"],
                                       "--jadx-evidence", self.jadx["id"], *extra])
        return args.handler(args, self.store)

    def test_maps_dex_literals_to_source_classes_and_lines_without_claiming_calls(self):
        record = self.run_map("--class-filter", "e5.c")
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertEqual(data["index_records_scanned"], 2)
        self.assertEqual(data["candidate_count"], 2)
        self.assertEqual(data["source_files_scanned"], 1)
        login = next(item for item in data["api_candidates"] if "/v1/login" in item["url"])
        self.assertEqual(login["category"], "static_candidate")
        self.assertEqual(login["dex_locations"][0]["dex_member"], "classes.dex")
        self.assertEqual(login["dex_locations"][0]["byte_offset"], 42)
        self.assertEqual(login["source_occurrences"][0]["class_name"], "e5.c")
        self.assertEqual(login["source_occurrences"][0]["line"], 3)
        self.assertEqual(len(login["source_occurrences"][0]["source_sha256"]), 64)
        self.assertIn(self.index["id"], data["evidence_ids"])
        self.assertIn(self.jadx["id"], data["evidence_ids"])
        self.assertIn("do not prove", data["scope"])

    def test_changed_static_index_is_rejected(self):
        self.index_path.write_text('{"text":"changed"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ForgeError, "changed after their cited evidence"):
            self.run_map()

    def test_class_filter_limits_the_source_walk(self):
        record = self.run_map("--class-filter", "e5.c")
        data = record["data"]
        self.assertEqual(data["source_files_scanned"], 1)
        self.assertTrue(all(item["class_name"] == "e5.c"
                            for candidate in data["api_candidates"]
                            for item in candidate["source_occurrences"]))


    def test_candidate_source_file_and_occurrence_caps_are_reported(self):
        candidate_limited = self.run_map("--max-candidates", "1")["data"]
        self.assertEqual(candidate_limited["candidate_count"], 1)
        self.assertEqual(candidate_limited["candidate_omitted"], 1)
        self.assertTrue(candidate_limited["truncated"])

        file_limited = self.run_map("--max-source-files", "1")["data"]
        self.assertEqual(file_limited["source_files_scanned"], 1)
        self.assertEqual(file_limited["source_files_omitted"], 1)
        self.assertTrue(file_limited["truncated"])

        occurrence_limited = self.run_map("--class-filter", "e5.c", "--max-occurrences", "1")["data"]
        self.assertEqual(occurrence_limited["source_occurrence_count"], 1)
        self.assertEqual(occurrence_limited["source_occurrences_omitted"], 1)
        self.assertTrue(occurrence_limited["truncated"])

    def test_trace_budget_is_shared_across_source_files(self):
        second = self.source_root / "sources" / "other" / "Client.java"
        second.write_text(
            'package other; class Client { String endpoint = "https://api.example.test/v1/login"; }',
            encoding="utf-8")
        data = self.run_map("--max-trace-items", "1")["data"]
        traces = [trace for candidate in data["api_candidates"] for trace in candidate["source_traces"]]
        self.assertEqual(data["source_occurrence_count"], 3)
        self.assertEqual(len(traces), 1)
        self.assertEqual(data["trace_items"], 1)
        self.assertGreaterEqual(data["trace_items_omitted"], 2)
        self.assertTrue(data["trace_truncated"])
        self.assertTrue(data["truncated"])

    def test_kotlin_literals_remain_cited_without_java_resolution(self):
        source = self.source_root / "sources" / "other" / "Client.kt"
        source.write_text('fun login() = "https://api.example.test/v1/login"\n', encoding="utf-8")
        data = self.run_map("--class-filter", "other.Client")["data"]
        login = next(candidate for candidate in data["api_candidates"] if "/v1/login" in candidate["url"])
        self.assertEqual(login["source_traces"][0]["context_kind"], "unsupported")
        self.assertEqual(login["source_traces"][0]["literal_line"], 1)
        self.assertEqual(login["source_traces"][0]["source_sha256"],
                         hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertNotIn("method_name", login["source_traces"][0])
        self.assertFalse(data["trace_truncated"])

    def test_wrong_evidence_kinds_are_refused(self):
        claim = self.store.add("claim", {"text": "not an index"})
        args = self.parser.parse_args(["android-api-map", "--index-evidence", claim["id"],
                                       "--jadx-evidence", self.jadx["id"]])
        with self.assertRaisesRegex(ForgeError, "static_index analysis record"):
            args.handler(args, self.store)


if __name__ == "__main__":
    unittest.main()
