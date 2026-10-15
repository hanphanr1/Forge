import argparse
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

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


class AndroidCallerMapTests(unittest.TestCase):
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
        full = self.run_map()
        capped = self.run_map("--max-items", "1")
        self.assertEqual(capped["candidate_count"], 1)
        self.assertEqual(capped["candidates_omitted"], full["candidate_count"] - 1)
        self.assertTrue(capped["truncated"])
        self.assertTrue(capped["candidates"][0]["file"].endswith("Ambiguous.java"))
        self.assertEqual((capped["files_scanned"], capped["files_omitted"]), (5, 0))

    def test_file_and_byte_caps_report_omissions(self):
        limited = self.run_map("--max-files", "1")
        self.assertEqual(limited["files_scanned"], 1)
        self.assertEqual(limited["files_omitted"], 1)
        self.assertEqual(limited["files_skipped_kt"], 1)
        self.assertTrue(limited["truncated"])
        tiny = self.run_map("--max-file-bytes", "1")
        self.assertEqual((tiny["files_scanned"], tiny["files_omitted"], tiny["candidate_count"]), (0, 5, 0))
        self.assertGreater(tiny["bytes_omitted"], 0)
        self.assertTrue(tiny["truncated"])
        first_size = self.paths["com/example/app/Ambiguous.java"].stat().st_size
        total = self.run_map("--max-total-bytes", str(first_size))
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


if __name__ == "__main__":
    unittest.main()
