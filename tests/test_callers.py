import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_callers

CANDIDATE_KEYS = {"file", "class_name", "line", "receiver_kind", "receiver", "possible_owners",
                  "possible_owners_omitted", "declaration_ambiguous", "source_sha256"}

CLIENT_SOURCE = """package com.example.app;

import com.example.net.Transport;

class Client {
    Transport helper = new Transport();

    void send() {
        query(1);
    }

    void decorated() {
        // query(2);
        /* query(3); */
        String doc = "query(4);";
        char open = '(';
        char quote = '"';
        this.query(5);
        Client.query(6);
        helper.query(7);
        build().query(8);
    }

    void query(int flag) {
    }

    Runnable task = new Runnable() {
        public void query(int flag) {
        }
    };

    java.util.Map<String, java.util.List<String>> query(int flag) {
        return null;
    }
}
"""

AMBIGUOUS_SOURCE = """package com.example.app;

class Ambiguous {
    @query(value = "probe")
    void run() {
        // Lexical probe: no generic run closes before the statement boundary.
        Object pick = total > query(1);
    }
}
"""

WORKER_SOURCE = """package com.example.app;

class Worker {
    void run() {
        new Transport(1);
    }
}
"""

TRANSPORT_SOURCE = """package com.example.net;

class Transport {
    void relay() {
        query(1);
        this.query(2);
        helper.query(3);
        super.query(4);
    }
}
"""

DETACHED_SOURCE = """package com.example.other;

class Detached {
    void run() {
        query(1);
    }
}
"""

KOTLIN_SOURCE = """package com.example.app

class Api {
    fun send() {
        query(1)
    }
}
"""

WILDCARD_SOURCE = """package com.example.wild;

import com.example.net.*;

class Wild {
    void run() {
        query(1);
    }
}
"""


def line_of(text, needle):
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    raise AssertionError(f"missing line: {needle}")


class _CallerMapFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_callers.register(self.parser.add_subparsers())
        self.output = self.store.directory / "analysis" / "jadx-fixture" / "output"
        self.paths = {}
        self.write("com/example/app/Ambiguous.java", AMBIGUOUS_SOURCE)
        self.write("com/example/app/Api.kt", KOTLIN_SOURCE)
        self.write("com/example/app/Client.java", CLIENT_SOURCE)
        self.write("com/example/app/Worker.java", WORKER_SOURCE)
        self.write("com/example/net/Transport.java", TRANSPORT_SOURCE)
        self.write("com/example/other/Detached.java", DETACHED_SOURCE)
        self.jadx = self.store.add("analysis", {
            "tool": "jadx", "status": "partial", "java_files": 5,
            "output_path": self.output.relative_to(self.root).as_posix()})

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def write(self, relative, text):
        path = self.output / "sources" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.paths[relative] = path
        return path

    def run_map(self, *extra, method="query"):
        args = self.parser.parse_args(["android-caller-map", "--jadx-evidence", self.jadx["id"],
                                       "--method", method, *extra])
        return args.handler(args, self.store)["data"]

    def run_raw(self, *extra):
        args = self.parser.parse_args(["android-caller-map", *extra])
        return args.handler(args, self.store)

    def in_file(self, data, name):
        return [candidate for candidate in data["candidates"] if candidate["file"].endswith(name)]

    def receiver(self, data, name, kind):
        found = [candidate for candidate in self.in_file(data, name) if candidate["receiver_kind"] == kind]
        self.assertEqual(len(found), 1, f"expected one {kind} candidate in {name}")
        return found[0]


class AndroidCallerMapTests(_CallerMapFixture):
    def test_evidence_validation_matches_android_api_map(self):
        claim = self.store.add("claim", {"text": "not jadx"})
        wrong_tool = self.store.add("analysis", {"tool": "static_index", "path": ".forge/index.jsonl"})
        failed = self.store.add("analysis", {"tool": "jadx", "status": "failed", "output_path": "missing"})
        for record in (claim, wrong_tool, failed):
            with self.assertRaisesRegex(ForgeError, "successful or partial JADX analysis record"):
                self.run_raw("--jadx-evidence", record["id"], "--method", "query")
        with self.assertRaisesRegex(ForgeError, "Unknown evidence ID"):
            self.run_raw("--jadx-evidence", "ev_missing", "--method", "query")

    def test_unavailable_output_directory_is_refused(self):
        gone = self.store.add("analysis", {"tool": "jadx", "status": "success",
                                           "output_path": ".forge/analysis/absent/output"})
        with self.assertRaisesRegex(ForgeError, "Artifact path does not exist"):
            self.run_raw("--jadx-evidence", gone["id"], "--method", "query")
        loose = self.store.directory / "loose.java"
        loose.write_text("class Loose {}\n", encoding="utf-8")
        file_record = self.store.add("analysis", {
            "tool": "jadx", "status": "success", "output_path": loose.relative_to(self.root).as_posix()})
        with self.assertRaisesRegex(ForgeError, "output directory is unavailable"):
            self.run_raw("--jadx-evidence", file_record["id"], "--method", "query")

    def test_names_and_caps_are_validated(self):
        for method in ("no space", "1bad", "", "class.method"):
            with self.assertRaisesRegex(ForgeError, "one Java identifier"):
                self.run_raw("--jadx-evidence", self.jadx["id"], "--method", method)
        for owner in ("bad name", "1bad", "a..b"):
            with self.assertRaisesRegex(ForgeError, "dotted Java class name"):
                self.run_map("--class", owner)
        for extra in (("--max-items", "100001"), ("--max-files", "500001"),
                      ("--max-file-bytes", str(128 * 1024 * 1024 + 1)),
                      ("--max-total-bytes", str(2 * 1024 * 1024 * 1024 + 1))):
            with self.assertRaisesRegex(ForgeError, "must be an integer from 1 to"):
                self.run_map(*extra)


    def test_path_filter_scopes_the_walk_and_the_owner_tree(self):
        data = self.run_map("--path-filter", "com/example/net")
        self.assertEqual(data["path_filter"], ["com/example/net"])
        self.assertEqual({candidate["class_name"] for candidate in data["candidates"]}, {"com.example.net.Transport"})
        self.assertLess(data["files_enumerated"], 6)
        scoped = self.run_map("--path-filter", "com/example/app/Client.java")
        self.assertEqual({candidate["class_name"] for candidate in scoped["candidates"]}, {"com.example.app.Client"})
        dotted = self.run_map("--path-filter", "example.other")
        self.assertEqual({candidate["class_name"] for candidate in dotted["candidates"]}, {"com.example.other.Detached"})
        for value in ("", "   ", "/" * 600):
            with self.assertRaisesRegex(ForgeError, "path/class substring"):
                self.run_map("--path-filter", value)

    def test_record_schema_and_scope_make_no_resolution_claim(self):
        data = self.run_map()
        self.assertEqual(data["schema"], "forge.android-caller-map/v1")
        self.assertEqual(data["tool"], "android")
        self.assertEqual(data["action"], "caller-map")
        self.assertIs(data["success"], True)
        self.assertEqual(data["method_name"], "query")
        self.assertEqual(data["owner_class"], "")
        self.assertEqual(data["evidence_ids"], [self.jadx["id"]])
        self.assertEqual(data["jadx_evidence_id"], self.jadx["id"])
        self.assertEqual(data["resolution"], "cross_file_name_candidate")
        self.assertIs(data["overload_aware"], False)
        self.assertEqual(data["candidate_count"], len(data["candidates"]))
        self.assertTrue(data["source_root"].endswith("jadx-fixture/output/sources"))
        for phrase in ("not a resolved call graph", "Overloads", "generics", "inheritance", "reflection"):
            self.assertIn(phrase, data["scope"])
        for candidate in data["candidates"]:
            self.assertEqual(set(candidate), CANDIDATE_KEYS)
            self.assertIn(candidate["receiver_kind"], forge_callers.RECEIVER_KINDS)
            self.assertIn("declaration_ambiguous", candidate)
            self.assertEqual(len(candidate["source_sha256"]), 64)

    def test_candidates_are_cited_per_file_with_lines_and_hashes(self):
        data = self.run_map()
        self.assertEqual(data["files_enumerated"], 6)
        self.assertEqual(data["files_scanned"], 5)
        self.assertEqual(data["files_skipped_kt"], 1)
        self.assertEqual(data["files_omitted"], 0)
        self.assertFalse(data["truncated"])
        self.assertEqual(data["candidate_count"], 11)
        self.assertEqual(data["candidates_omitted"], 0)
        self.assertEqual(data["candidates_filtered"], 0)
        self.assertEqual(data["caps"], {"max_items": 500, "max_files": 50000,
                                       "max_file_bytes": 16 * 1024 * 1024,
                                       "max_total_bytes": 128 * 1024 * 1024,
                                       "max_possible_owners": 8})
        client = self.receiver(data, "Client.java", "bare")
        self.assertEqual(client["class_name"], "com.example.app.Client")
        self.assertEqual(client["line"], line_of(CLIENT_SOURCE, "query(1);"))
        self.assertEqual(client["source_sha256"],
                         hashlib.sha256(self.paths["com/example/app/Client.java"].read_bytes()).hexdigest())
        self.assertEqual([candidate["line"] for candidate in self.in_file(data, "Client.java")],
                         [line_of(CLIENT_SOURCE, needle) for needle in
                          ("query(1);", "this.query(5);", "Client.query(6);", "helper.query(7);",
                           "build().query(8);")])
        self.assertEqual([], self.in_file(data, "Api.kt"))

    def test_bare_calls_offer_imported_and_same_package_owners(self):
        data = self.run_map()
        client = self.receiver(data, "Client.java", "bare")
        self.assertEqual(client["possible_owners"], ["com.example.app.Ambiguous", "com.example.app.Api",
                                                     "com.example.app.Client", "com.example.app.Worker",
                                                     "com.example.net.Transport"])
        self.assertFalse(client["possible_owners_omitted"])
        self.assertIsNone(client["receiver"])
        self.assertEqual(self.receiver(data, "Transport.java", "bare")["possible_owners"],
                         ["com.example.net.Transport"])
        self.assertEqual(self.receiver(data, "Detached.java", "bare")["possible_owners"],
                         ["com.example.other.Detached"])
        for candidate in data["candidates"]:
            if candidate["receiver_kind"] != "bare":
                self.assertEqual(candidate["possible_owners"], [])

    def test_wildcard_import_adds_package_owners(self):
        self.write("com/example/wild/Wild.java", WILDCARD_SOURCE)
        wild = self.receiver(self.run_map(), "Wild.java", "bare")
        self.assertEqual(wild["possible_owners"], ["com.example.net.Transport", "com.example.wild.Wild"])

    def test_receiver_shapes_come_from_the_preceding_tokens(self):
        data = self.run_map()
        self.assertEqual([(candidate["line"], candidate["receiver_kind"], candidate["receiver"])
                          for candidate in self.in_file(data, "Client.java")],
                         [(line_of(CLIENT_SOURCE, "query(1);"), "bare", None),
                          (line_of(CLIENT_SOURCE, "this.query(5);"), "this", "this"),
                          (line_of(CLIENT_SOURCE, "Client.query(6);"), "owner_class", "Client"),
                          (line_of(CLIENT_SOURCE, "helper.query(7);"), "named_receiver", "helper"),
                          (line_of(CLIENT_SOURCE, "build().query(8);"), "expression", None)])
        self.assertEqual([(candidate["line"], candidate["receiver_kind"], candidate["receiver"])
                          for candidate in self.in_file(data, "Transport.java")],
                         [(line_of(TRANSPORT_SOURCE, "query(1);"), "bare", None),
                          (line_of(TRANSPORT_SOURCE, "this.query(2);"), "this", "this"),
                          (line_of(TRANSPORT_SOURCE, "helper.query(3);"), "named_receiver", "helper"),
                          (line_of(TRANSPORT_SOURCE, "super.query(4);"), "this", "super")])
        constructs = self.run_map(method="Transport")
        self.assertEqual([(candidate["receiver_kind"], candidate["file"].rsplit("/", 1)[-1])
                          for candidate in constructs["candidates"]],
                         [("constructor", "Client.java"), ("constructor", "Worker.java")])
        self.assertEqual(constructs["candidates"][1]["line"], line_of(WORKER_SOURCE, "new Transport(1);"))
        self.assertIsNone(constructs["candidates"][1]["receiver"])

    def test_declarations_are_excluded_and_ambiguous_sites_are_kept(self):
        data = self.run_map()
        self.assertEqual(data["declarations_skipped"], 3)
        self.assertEqual(data["annotation_uses_skipped"], 1)
        client_lines = {candidate["line"] for candidate in self.in_file(data, "Client.java")}
        for declaration in ("void query(int flag) {", "public void query(int flag) {",
                            "java.util.List<String>> query(int flag) {"):
            self.assertNotIn(line_of(CLIENT_SOURCE, declaration), client_lines)
        for inert in ("// query(2);", "/* query(3); */", 'String doc = "query(4);"',
                      "char open = '(';", "char quote = '\"';"):
            self.assertNotIn(line_of(CLIENT_SOURCE, inert), client_lines)
        ambiguous = self.receiver(data, "Ambiguous.java", "bare")
        self.assertTrue(ambiguous["declaration_ambiguous"])
        self.assertEqual(ambiguous["line"], line_of(AMBIGUOUS_SOURCE, "total > query(1);"))
        self.assertEqual(ambiguous["possible_owners"], ["com.example.app.Ambiguous", "com.example.app.Api",
                                                        "com.example.app.Client", "com.example.app.Worker"])
        for candidate in data["candidates"]:
            if (candidate["file"], candidate["line"]) != (ambiguous["file"], ambiguous["line"]):
                self.assertFalse(candidate["declaration_ambiguous"])
        self.assertEqual(sum(1 for candidate in data["candidates"] if candidate["declaration_ambiguous"]), 1)

    def test_owner_candidates_are_bounded_and_flagged(self):
        for index in range(12):
            self.write(f"com/example/many/C{index:02d}.java",
                       f"package com.example.many;\n\nclass C{index:02d} {{\n}}\n")
        self.write("com/example/many/Caller.java",
                   "package com.example.many;\n\nclass Caller {\n    void run() {\n        query(1);\n    }\n}\n")
        caller = self.receiver(self.run_map(), "Caller.java", "bare")
        self.assertEqual(caller["possible_owners"], [f"com.example.many.C{index:02d}" for index in range(8)])
        self.assertTrue(caller["possible_owners_omitted"])

    def test_item_cap_reports_truncation_and_walk_order(self):
        full = self.run_map("--no-cache")
        capped = self.run_map("--no-cache", "--max-items", "1")
        self.assertEqual(capped["candidate_count"], 1)
        self.assertEqual(capped["candidates_omitted"], full["candidate_count"] - 1)
        self.assertTrue(capped["truncated"])
        self.assertTrue(capped["candidates"][0]["file"].endswith("Ambiguous.java"))
        self.assertEqual((capped["files_scanned"], capped["files_omitted"]), (5, 0))

    def test_file_and_byte_caps_report_omissions(self):
        limited = self.run_map("--no-cache", "--max-files", "1")
        self.assertEqual(limited["files_scanned"], 1)
        self.assertEqual(limited["files_omitted"], 1)
        self.assertEqual(limited["files_skipped_kt"], 1)
        self.assertTrue(limited["truncated"])
        tiny = self.run_map("--no-cache", "--max-file-bytes", "1")
        self.assertEqual((tiny["files_scanned"], tiny["files_omitted"], tiny["candidate_count"]), (0, 5, 0))
        self.assertGreater(tiny["bytes_omitted"], 0)
        self.assertTrue(tiny["truncated"])
        first_size = self.paths["com/example/app/Ambiguous.java"].stat().st_size
        total = self.run_map("--no-cache", "--max-total-bytes", str(first_size))
        self.assertEqual((total["files_scanned"], total["bytes_scanned"]), (1, first_size))
        self.assertEqual(total["files_omitted"], 1)
        self.assertTrue(total["truncated"])

    def test_class_filter_keeps_only_attributable_candidates(self):
        data = self.run_map("--class", "com.example.net.Transport")
        self.assertEqual(data["owner_class"], "com.example.net.Transport")
        self.assertEqual([(candidate["file"].rsplit("/", 1)[-1], candidate["line"], candidate["receiver"])
                          for candidate in data["candidates"]],
                         [("Client.java", line_of(CLIENT_SOURCE, "query(1);"), None),
                          ("Transport.java", line_of(TRANSPORT_SOURCE, "query(1);"), None),
                          ("Transport.java", line_of(TRANSPORT_SOURCE, "this.query(2);"), "this"),
                          ("Transport.java", line_of(TRANSPORT_SOURCE, "super.query(4);"), "super")])
        self.assertEqual(data["candidates_filtered"], 7)
        self.assertEqual(data["candidate_count"], 4)
        self.assertFalse(data["truncated"])
        slashed = self.run_map("--class", "com/example/net/Transport.java")
        self.assertEqual(slashed["candidates"], data["candidates"])
        constructed = self.run_map("--class", "Transport", method="Transport")
        self.assertEqual([candidate["receiver_kind"] for candidate in constructed["candidates"]],
                         ["constructor", "constructor"])


class CallerMapCacheTests(_CallerMapFixture):
    JAVA_SOURCES = ("com/example/app/Ambiguous.java", "com/example/app/Client.java",
                    "com/example/app/Worker.java", "com/example/net/Transport.java",
                    "com/example/other/Detached.java")

    def cache_directory(self):
        return self.store.directory / "cache" / "callers"

    def cache_entries(self):
        directory = self.cache_directory()
        if not directory.is_dir():
            return []
        return sorted(path for path in directory.iterdir() if path.name != forge_callers.CACHE_INDEX_NAME)

    def entry_for(self, relative):
        digest = hashlib.sha256(self.paths[relative].read_bytes()).hexdigest()
        return self.cache_directory() / (digest + ".json")

    def test_first_run_writes_one_entry_per_source_and_reports_counts(self):
        data = self.run_map()
        self.assertIs(data["cache_enabled"], True)
        self.assertEqual(data["cache_dir"], ".forge/cache/callers")
        self.assertEqual((data["cache_hits"], data["cache_misses"]), (0, 5))
        self.assertEqual(data["cache_writes"], 5)
        self.assertEqual(data["cache_invalid"], 0)
        self.assertEqual((data["cache_evicted"], data["cache_evicted_bytes"]), (0, 0))
        self.assertEqual(data["cache_bytes_reused"], 0)
        self.assertEqual(data["cache_cap_bytes"], forge_callers.CACHE_CAP_BYTES)
        entries = self.cache_entries()
        self.assertEqual(len(entries), 5)
        index = self.cache_directory() / forge_callers.CACHE_INDEX_NAME
        self.assertEqual(data["cache_bytes"], sum(path.stat().st_size for path in entries) + index.stat().st_size)
        source = self.paths["com/example/app/Client.java"]
        entry = json.loads(self.entry_for("com/example/app/Client.java").read_text(encoding="utf-8"))
        self.assertEqual(set(entry), {"schema", "sha256", "size", "candidates", "digests", "imports",
                                      "skipped", "method"})
        self.assertEqual(entry["schema"], forge_callers.CACHE_SCHEMA)
        self.assertEqual(entry["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(entry["size"], source.stat().st_size)
        self.assertEqual(entry["method"], "query")
        self.assertEqual(entry["digests"]["source_sha256"], entry["sha256"])
        self.assertEqual(len(entry["digests"]["payload_sha256"]), 64)
        self.assertEqual(entry["imports"], {"exact": ["com.example.net.Transport"], "simple": ["Transport"],
                                            "wildcard": []})
        self.assertEqual(entry["skipped"], {"declarations": 3, "annotations": 0})
        self.assertEqual([fragment["line"] for fragment in entry["candidates"]],
                         [candidate["line"] for candidate in self.in_file(data, "Client.java")])
        for fragment in entry["candidates"]:
            self.assertEqual(set(fragment), {"line", "receiver_kind", "receiver", "declaration_ambiguous"})

    def test_identical_rerun_reads_no_source_and_yields_identical_candidates(self):
        first = self.run_map()
        with patch.object(Path, "read_bytes", side_effect=AssertionError("a source was read again")):
            second = self.run_map()
        self.assertEqual(second["candidates"], first["candidates"])
        self.assertEqual(json.dumps(second["candidates"]), json.dumps(first["candidates"]))
        self.assertEqual((second["cache_hits"], second["cache_misses"]), (5, 0))
        self.assertEqual((second["cache_writes"], second["cache_invalid"]), (0, 0))
        self.assertEqual((second["files_scanned"], second["bytes_scanned"]), (0, 0))
        self.assertEqual((second["candidate_count"], second["declarations_skipped"],
                          second["annotation_uses_skipped"]),
                         (first["candidate_count"], first["declarations_skipped"], first["annotation_uses_skipped"]))
        self.assertEqual(second["cache_bytes_reused"],
                         sum(self.paths[name].stat().st_size for name in self.JAVA_SOURCES))

    def test_changed_file_is_reparsed_and_sibling_entries_are_reused(self):
        first = self.run_map()
        edited = CLIENT_SOURCE.replace("query(1);", "query(1);\n        query(9);")
        self.write("com/example/app/Client.java", edited)
        data = self.run_map()
        self.assertEqual((data["cache_hits"], data["cache_misses"]), (4, 1))
        self.assertEqual((data["files_scanned"], data["cache_writes"]), (1, 1))
        self.assertEqual(data["bytes_scanned"],
                         self.paths["com/example/app/Client.java"].stat().st_size,
                         "the scanner counts raw disk bytes, including platform newlines")
        self.assertEqual(data["candidate_count"], first["candidate_count"] + 1)
        lines = [candidate["line"] for candidate in self.in_file(data, "Client.java")]
        self.assertIn(line_of(edited, "query(9);"), lines)
        self.assertEqual(self.in_file(data, "Transport.java"), self.in_file(first, "Transport.java"))
        entry = json.loads(self.entry_for("com/example/app/Client.java").read_text(encoding="utf-8"))
        self.assertEqual([fragment["line"] for fragment in entry["candidates"]], lines)
        self.assertEqual(len(self.cache_entries()), 6)

    def test_no_cache_reruns_every_source_and_writes_nothing(self):
        first = self.run_map("--no-cache")
        second = self.run_map("--no-cache")
        for data in (first, second):
            self.assertIs(data["cache_enabled"], False)
            self.assertEqual((data["cache_hits"], data["cache_misses"], data["cache_writes"]), (0, 0, 0))
            self.assertEqual(data["files_scanned"], 5)
            self.assertEqual(data["bytes_scanned"],
                             sum(self.paths[name].stat().st_size for name in self.JAVA_SOURCES))
            self.assertEqual((data["cache_bytes"], data["cache_bytes_reused"]), (0, 0))
        self.assertEqual(second["candidates"], first["candidates"])
        self.assertFalse((self.store.directory / "cache").exists())
        self.assertIs(self.run_map("--cache")["cache_enabled"], True)

    def test_missing_index_reparses_every_source_without_rewriting_entries(self):
        first = self.run_map()
        (self.cache_directory() / forge_callers.CACHE_INDEX_NAME).unlink()
        data = self.run_map()
        self.assertEqual((data["cache_hits"], data["cache_misses"]), (0, 5))
        self.assertEqual((data["files_scanned"], data["cache_writes"]), (5, 0))
        self.assertEqual(data["candidates"], first["candidates"])

    def test_unreadable_entries_are_reported_and_reparsed(self):
        first = self.run_map()
        self.entry_for("com/example/app/Worker.java").write_text("{not json", encoding="utf-8")
        padding = json.dumps({"sha256": "0" * 64, "pad": "x" * (forge_callers.CACHE_ENTRY_FLOOR + 1)})
        self.entry_for("com/example/other/Detached.java").write_text(padding, encoding="utf-8")
        data = self.run_map()
        self.assertEqual(data["cache_invalid"], 2)
        self.assertEqual((data["cache_hits"], data["cache_misses"]), (3, 2))
        self.assertEqual(data["cache_writes"], 2)
        self.assertEqual(data["candidates"], first["candidates"])

    def test_identical_content_shares_one_entry_and_keeps_its_own_class_name(self):
        self.write("com/example/other/Worker.java", WORKER_SOURCE)
        data = self.run_map(method="Transport")
        self.assertEqual((data["cache_hits"], data["cache_misses"]), (0, 6))
        self.assertEqual(data["cache_writes"], 5)
        self.assertEqual(len(self.cache_entries()), 5)
        self.assertEqual(sorted(candidate["class_name"] for candidate in data["candidates"]
                                if candidate["file"].endswith("/Worker.java")),
                         ["com.example.app.Worker", "com.example.other.Worker"])

    def test_method_name_is_part_of_the_cache_key(self):
        constructors = self.run_map(method="Transport")
        self.assertEqual((constructors["cache_hits"], constructors["cache_misses"]), (0, 5))
        queries = self.run_map()
        self.assertEqual((queries["cache_hits"], queries["cache_misses"]), (0, 5))
        replayed = self.run_map(method="Transport")
        self.assertEqual((replayed["cache_hits"], replayed["cache_misses"]), (0, 5))
        self.assertEqual(replayed["candidates"], constructors["candidates"])
        self.assertEqual(self.run_map(method="Transport")["cache_hits"], 5)

    def test_cached_receiver_is_promoted_against_the_live_tree(self):
        first = self.receiver(self.run_map(), "Transport.java", "named_receiver")
        self.assertEqual(first["receiver"], "helper")
        self.write("com/example/net/helper.java", "package com.example.net;\n\nclass helper {\n}\n")
        data = self.run_map()
        self.assertEqual((data["cache_hits"], data["cache_misses"]), (5, 1))
        promoted = self.receiver(data, "Transport.java", "owner_class")
        self.assertEqual(promoted["receiver"], "helper")
        self.assertEqual(promoted["source_sha256"], first["source_sha256"])
        self.assertEqual(promoted["line"], first["line"])

    def test_bounded_walk_stays_identical_across_cached_reruns(self):
        first = self.run_map("--max-files", "1")
        second = self.run_map("--max-files", "1")
        self.assertEqual((first["files_scanned"], first["files_omitted"]), (1, 1))
        self.assertEqual((second["files_scanned"], second["cache_hits"], second["files_omitted"]), (0, 1, 1))
        self.assertEqual(second["candidates"], first["candidates"])
        self.assertIs(first["truncated"], True)
        self.assertIs(second["truncated"], True)

    def test_eviction_keeps_the_newest_entries_and_is_reported(self):
        self.run_map()
        entries = self.cache_entries()
        self.assertEqual(len(entries), 5)
        for index, path in enumerate(entries):
            stamp = (index + 1) * 1_000_000_000
            os.utime(path, ns=(stamp, stamp))
        sizes = [path.stat().st_size for path in entries]
        index = self.cache_directory() / forge_callers.CACHE_INDEX_NAME
        cap = index.stat().st_size + sizes[-1] + sizes[-2]
        with patch.object(forge_callers, "CACHE_CAP_BYTES", cap):
            data = self.run_map()
        self.assertEqual((data["cache_hits"], data["cache_misses"]), (5, 0))
        self.assertEqual(data["cache_evicted"], 3)
        self.assertEqual(data["cache_evicted_bytes"], sum(sizes[:3]))
        self.assertEqual(data["cache_cap_bytes"], cap)
        self.assertLessEqual(data["cache_bytes"], cap)
        self.assertGreater(data["cache_bytes"], 0)
        self.assertEqual({path.name for path in self.cache_entries()}, {path.name for path in entries[-2:]})
        follow = self.run_map()
        self.assertEqual((follow["cache_hits"], follow["cache_misses"]), (2, 3))
        self.assertEqual(follow["cache_writes"], 3)
        self.assertEqual((follow["cache_evicted"], follow["cache_evicted_bytes"]), (0, 0))

    def test_cache_files_never_contain_absolute_paths(self):
        self.run_map()
        directory = self.cache_directory()
        for path in sorted(directory.iterdir()):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(str(self.root), text)
            self.assertNotIn(self.root.as_posix(), text)
            self.assertIsNone(re.search(r"[A-Za-z]:[\\/]", text), path.name)
        index = json.loads((directory / forge_callers.CACHE_INDEX_NAME).read_text(encoding="utf-8"))
        keys = sorted(index["entries"])
        self.assertEqual(len(keys), 5)
        for key in keys:
            self.assertFalse(Path(key).is_absolute())
            self.assertFalse(key.startswith("/"))
            self.assertNotIn(":", key)
            self.assertTrue(key.startswith(".forge/analysis/"))
            self.assertTrue(key.endswith(".java"))
        self.assertEqual({value["method"] for value in index["entries"].values()}, {"query"})
        self.assertEqual({len(value["sha256"]) for value in index["entries"].values()}, {64})


if __name__ == "__main__":
    unittest.main()
