import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_artifacts
import forge_comparisons
import forge_network


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        commands = self.parser.add_subparsers()
        for module in (forge_artifacts, forge_network, forge_comparisons):
            module.register(commands)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def save_json(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def archive(self, name, members, version=None, index=True):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as output:
            for member, content in members.items():
                output.writestr(member, content)
        arguments = ("--version", version) if version else ()
        artifact = self.command("artifact-add", str(path), *arguments)
        analysis = self.command("artifact-index", artifact["data"]["path"]) if index else None
        return path, artifact, analysis

    def compare(self, before, after, left_index=None, right_index=None, *options):
        arguments = ["client-diff", "--before", before["id"], "--after", after["id"]]
        if left_index:
            arguments.extend(("--before-index", left_index["id"]))
        if right_index:
            arguments.extend(("--after-index", right_index["id"]))
        return self.command(*arguments, *options)

    def capture(self, url, status=200, body=None):
        result = self.command("har-import", self.save_json("capture.har", {"log": {"entries": [{
            "request": {"url": url, "method": "POST", "headers": [
                {"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                {"name": "X-Before", "value": "private-request-header"}],
                "postData": {"text": "choice=private-form-value"}},
            "response": {"status": status, "headers": [
                {"name": "Content-Type", "value": "application/json"},
                {"name": "X-Old", "value": "private-response-header"}],
                "content": {"text": json.dumps(body or {"old": {"value": "private-body"}})}}}]}}))
        return result["exchanges"][0]

    def snapshot(self, record, *options):
        return self.command("protocol-snapshot", "--evidence", record["id"], *options)

    def test_actual_har_and_live_snapshot_dimensions_provenance_and_citations(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-New", "private-live-header")
                self.end_headers()
                self.wfile.write(b'{"new":{"value":"private-extracted"}}')

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/api/profile"
        try:
            captured = self.capture(url + "?before=owned")
            before = self.snapshot(captured)
            live = self.command("probe", self.save_json("request.json", {
                "url": url + "?after=owned", "method": "POST", "headers": {"X-After": "private-live-request"},
                "json": {"new_choice": "private-json-value"}, "extract": {"binding": {"json_path": "$.new.value"}}}))
            after = self.snapshot(live)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        original = self.store.get(before["id"])
        comparison = self.command("protocol-diff", "--before", before["id"], "--after", after["id"])
        data = comparison["data"]
        self.assertEqual(comparison["kind"], "protocol_diff")
        self.assertEqual(data["added"], [])
        self.assertEqual(data["removed"], [])
        changed = data["changed"][0]
        self.assertEqual(changed["identity"], {"url": url, "method": "POST"})
        dimensions = changed["changes"]
        self.assertEqual(dimensions["response_status"], {"before": [200], "after": [201]})
        self.assertEqual(dimensions["category"], {"before": ["captured_http"], "after": ["live_http"]})
        self.assertEqual(dimensions["query_field_names"], {"before": ["before"], "after": ["after"]})
        for field in ("request_header_names", "response_header_names", "request_body.form_field_names",
                      "request_body.json_field_paths", "response_body.json_field_paths", "extraction_selectors", "provenance"):
            self.assertIn(field, dimensions)
        self.assertEqual(changed["before_observations"][0]["citations"][0]["evidence_id"], captured["id"])
        self.assertEqual(changed["after_observations"][0]["citations"][0]["evidence_id"], live["id"])
        self.assertFalse(data["authentication_verified"])
        self.assertEqual(self.store.get(before["id"]), original)
        self.assertEqual(before["data"]["options"]["evidence"], [captured["id"]])
        for private in ("private-form-value", "private-body", "private-extracted", "private-live-header", "private-json-value"):
            self.assertNotIn(private, json.dumps(data))
        again = self.command("protocol-diff", "--before", before["id"], "--after", after["id"])
        self.assertEqual(again["data"], data)

    def test_protocol_endpoint_add_remove_and_static_method_unknown(self):
        source = self.root / "client.js"
        source.write_text('fetch("/api/old");', encoding="utf-8")
        old = self.command("artifact-index", str(source))
        before = self.snapshot(old)
        source.write_text('fetch("/api/new");', encoding="utf-8")
        new = self.command("artifact-index", str(source))
        after = self.snapshot(new)
        source.unlink()
        (self.root / old["data"]["path"]).unlink()
        (self.root / new["data"]["path"]).unlink()
        data = self.command("protocol-diff", "--before", before["id"], "--after", after["id"])["data"]
        self.assertEqual(data["removed"][0]["identity"], {"url": "/api/old"})
        self.assertEqual(data["added"][0]["identity"], {"url": "/api/new"})
        self.assertFalse(data["added"][0]["observations"][0]["proven_live"])

    def test_protocol_omissions_query_collapse_and_redacted_identity_are_explicit(self):
        first = self.capture("https://owned.example/api/profile?token=private-one")
        second = self.capture("https://owned.example/api/profile?token=private-two&mode=owned")
        before = self.command("protocol-snapshot", "--evidence", first["id"], "--evidence", second["id"])
        after = self.snapshot(first, "--max-endpoints", "1")
        data = self.command("protocol-diff", "--before", before["id"], "--after", after["id"])["data"]
        self.assertFalse(data["complete"])
        self.assertTrue(data["ambiguities"]["before"][0]["redacted_identity"])
        self.assertEqual(data["ambiguities"]["before"][0]["query_variants"], 2)
        self.assertIn("max_endpoints", data["selection_options"]["after"])
        source = self.root / "many.js"
        source.write_text('fetch("/api/a"); fetch("/api/b");', encoding="utf-8")
        index = self.command("artifact-index", str(source))
        limited = self.snapshot(index, "--max-endpoints", "1")
        result = self.command("protocol-diff", "--before", limited["id"], "--after", limited["id"])["data"]
        self.assertIn("output_truncated", result["limitations"]["omission_flags"])
        self.assertFalse(result["complete"])

    def test_wrong_snapshot_kind_rejected(self):
        record = self.capture("https://owned.example/api/profile")
        with self.assertRaisesRegex(ForgeError, "supported protocol snapshot"):
            self.command("protocol-diff", "--before", record["id"], "--after", record["id"])

    def test_stored_archive_bytes_endpoints_and_hashes_survive_original_deletion(self):
        left_path, left, left_index = self.archive("old.zip", {
            "client.js": 'fetch("https://owned.example/api/old"); password="private-before";',
            "removed.bin": b"old bytes", "same.bin": b"stable"}, "1.0")
        right_path, right, right_index = self.archive("new.zip", {
            "client.js": 'fetch("https://owned.example/api/new"); password="private-after";',
            "added.bin": b"new bytes", "same.bin": b"stable"}, "2.0")
        left_path.unlink()
        right_path.unlink()
        original = self.store.get(left["id"])
        result = self.compare(left, right, left_index, right_index)
        data = result["data"]
        self.assertEqual(result["kind"], "client_diff")
        self.assertEqual([item["file"] for item in data["files"]["added"]], ["added.bin"])
        self.assertEqual([item["file"] for item in data["files"]["removed"]], ["removed.bin"])
        self.assertEqual([item["file"] for item in data["files"]["changed"]], ["client.js"])
        changed = data["files"]["changed"][0]
        self.assertEqual(changed["before"]["hash_basis"], "member_bytes")
        self.assertEqual(changed["before"]["citations"][0]["evidence_id"], left["id"])
        self.assertTrue(data["before"]["metadata"]["artifact"]["hash_verified"])
        self.assertEqual(data["after"]["metadata"]["artifact"]["version"], "2.0")
        self.assertEqual(data["metadata_changes"]["version"], {"before": "1.0", "after": "2.0"})
        self.assertIn("sha256", data["metadata_changes"])
        self.assertEqual(data["endpoint_candidates"]["added"][0]["url"], "https://owned.example/api/new")
        self.assertEqual(data["endpoint_candidates"]["removed"][0]["url"], "https://owned.example/api/old")
        self.assertEqual(data["endpoint_candidates"]["added"][0]["citations"][0]["evidence_id"], right_index["id"])
        self.assertTrue(data["source_strings"]["added"])
        self.assertFalse(data["server_changes_verified"])
        self.assertTrue(data["file_inventory_complete"])
        self.assertTrue(data["complete"])
        self.assertFalse(data["limitations"]["legacy_index_creation_hash_unavailable"])
        self.assertTrue(data["before"]["metadata"]["index"]["hash_verified"])
        self.assertEqual(self.store.get(left["id"]), original)
        for private in ("private-before", "private-after", 'fetch("'):
            self.assertNotIn(private, json.dumps(data))
        self.assertEqual(self.compare(left, right, left_index, right_index)["data"], data)
        paired = self.command("client-diff", "--before", left_index["id"], "--after", right_index["id"],
                              "--before-artifact", left["id"], "--after-artifact", right["id"])["data"]
        self.assertEqual(paired["files"], data["files"])

    def test_source_versions_use_saved_index_projections_not_changed_or_deleted_sources(self):
        indexes = []
        for name, members in (("old-src", {"client.js": 'fetch("/api/old");', "removed.js": "old name"}),
                              ("new-src", {"client.js": 'fetch("/api/new");', "added.js": "new name"})):
            directory = self.root / name
            directory.mkdir()
            for filename, text in members.items():
                (directory / filename).write_text(text, encoding="utf-8")
            indexes.append(self.command("artifact-index", str(directory)))
            for file in directory.iterdir():
                file.unlink()
            directory.rmdir()
        data = self.compare(*indexes)["data"]
        self.assertEqual([item["file"] for item in data["files"]["added"]], ["added.js"])
        self.assertEqual([item["file"] for item in data["files"]["removed"]], ["removed.js"])
        self.assertEqual(data["files"]["changed"][0]["file"], "client.js")
        self.assertEqual(data["files"]["changed"][0]["after"]["hash_basis"], "redacted_index_projection")
        self.assertFalse(data["file_inventory_complete"])
        self.assertFalse(data["complete"])
        self.assertEqual(data["endpoint_candidates"]["added"][0]["url"], "/api/new")

    def test_unindexed_regular_artifacts_compare_metadata_and_content_hash(self):
        records = []
        for name, content, version in (("one.js", b"first bytes", "one"), ("two.js", b"second bytes", "two")):
            path = self.root / name
            path.write_bytes(content)
            records.append(self.command("artifact-add", str(path), "--version", version))
            path.unlink()
        data = self.compare(*records)["data"]
        self.assertEqual(data["files"]["changed"][0]["file"], "artifact")
        self.assertEqual(data["files"]["changed"][0]["after"]["sha256"], hashlib.sha256(b"second bytes").hexdigest())
        self.assertEqual(data["endpoint_candidates"], {"added": [], "removed": []})
        self.assertFalse(data["complete"])
        self.assertTrue(any("No explicit static index" in item["reason"] for item in data["before"]["omissions"]))

    def test_archive_traversal_duplicates_symlinks_nonregular_and_bombs_are_omitted(self):
        path = self.root / "unsafe.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as output:
                output.writestr("safe.js", 'fetch("/api/safe");')
                output.writestr("../escape.js", 'fetch("/api/escape");')
                output.writestr("duplicate.js", 'fetch("/api/first");')
                output.writestr("duplicate.js", 'fetch("/api/second");')
                for name, mode in (("link.js", stat.S_IFLNK), ("pipe.js", stat.S_IFIFO)):
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (mode | 0o644) << 16
                    output.writestr(info, 'fetch("/api/nonregular");')
                output.writestr("bomb.bin", b"A" * 100000, compress_type=zipfile.ZIP_DEFLATED)
        artifact = self.command("artifact-add", str(path))
        index = self.command("artifact-index", artifact["data"]["path"])
        data = self.compare(artifact, artifact, index, index)["data"]
        self.assertEqual([item["file"] for item in data["before"]["files"]], ["safe.js"])
        reasons = {item["reason"] for item in data["before"]["omissions"]}
        for reason in ("unsafe member path", "duplicate/aliased member identity", "nonregular member (including symlink)",
                       "compression ratio exceeds 200:1"):
            self.assertIn(reason, reasons)
        self.assertFalse(data["complete"])
        self.assertFalse(data["file_inventory_complete"])
        self.assertFalse((self.root / "escape.js").exists())
        _, empty, empty_index = self.archive("empty.zip", {})
        removed = self.compare(artifact, empty, index, empty_index)["data"]["endpoint_candidates"]["removed"]
        self.assertEqual([item["url"] for item in removed], ["/api/safe"])

    def test_member_byte_caps_record_incomplete_inventory(self):
        _, artifact, index = self.archive("capped.zip", {"safe.js": 'fetch("/api/safe");', "large.bin": b"B" * 512})
        data = self.compare(artifact, artifact, index, index, "--max-file-bytes", "64")["data"]
        self.assertFalse(data["file_inventory_complete"])
        self.assertIn("member exceeds --max-file-bytes", {item["reason"] for item in data["before"]["omissions"]})
        data = self.compare(artifact, artifact, index, index, "--max-total-bytes", "64")["data"]
        self.assertIn("member exceeds --max-total-bytes", {item["reason"] for item in data["before"]["omissions"]})
        with self.assertRaisesRegex(ForgeError, "exceeding --max-entries"):
            self.compare(artifact, artifact, None, None, "--max-entries", "1")

    def test_index_caps_and_original_index_truncation_are_disclosed(self):
        source = self.root / "many.js"
        source.write_text('fetch("/api/a");\nfetch("/api/b");\nfetch("/api/c");', encoding="utf-8")
        complete = self.command("artifact-index", str(source))
        truncated = self.command("artifact-index", str(source), "--max-records", "1")
        data = self.compare(complete, truncated)["data"]
        self.assertTrue(any("original static indexing" in item["reason"] for item in data["after"]["omissions"]))
        limited = self.compare(complete, complete, None, None, "--max-records", "1")["data"]
        self.assertFalse(limited["complete"])
        self.assertTrue(any("cap reached" in item["reason"] for item in limited["before"]["omissions"]))

    def test_corrupt_blob_and_mismatched_index_are_not_published(self):
        _, first, first_index = self.archive("first.zip", {"client.js": 'fetch("/api/first");'})
        _, second, second_index = self.archive("second.zip", {"client.js": 'fetch("/api/second");'})
        with self.assertRaisesRegex(ForgeError, "corresponding stored artifact blob"):
            self.compare(first, second, second_index, first_index)
        before_count = len(self.store.list("client_diff"))
        (self.root / first["data"]["path"]).write_bytes(b"corrupt")
        with self.assertRaisesRegex(ForgeError, "hash/size mismatch"):
            self.compare(first, second)
        self.assertEqual(len(self.store.list("client_diff")), before_count)

    def test_stored_inputs_outside_forge_and_nonregular_inputs_are_rejected(self):
        path = self.root / "local.js"
        path.write_bytes(b"owned bytes")
        artifact = self.command("artifact-add", str(path))
        outside = self.store.add("artifact", {**artifact["data"], "path": "local.js"})
        traversal = self.store.add("artifact", {**artifact["data"], "path": ".forge/../local.js"})
        directory = self.store.add("artifact", {**artifact["data"], "path": ".forge/blobs"})
        for invalid in (outside, traversal, directory):
            with self.subTest(invalid=invalid["id"]), self.assertRaisesRegex(ForgeError, "inside .forge"):
                self.compare(invalid, artifact)
        link = self.store.directory / "linked"
        try:
            link.symlink_to(self.root / artifact["data"]["path"])
        except (OSError, NotImplementedError):
            return
        linked = self.store.add("artifact", {**artifact["data"], "path": ".forge/linked"})
        with self.assertRaisesRegex(ForgeError, "nonlinked"):
            self.compare(linked, artifact)

    def test_index_record_count_mismatch_and_input_size_cap_rejected(self):
        path = self.root / "client.js"
        path.write_text('fetch("/api/one");', encoding="utf-8")
        index = self.command("artifact-index", str(path))
        with self.assertRaisesRegex(ForgeError, "max-input-bytes"):
            self.compare(index, index, None, None, "--max-input-bytes", "8")
        stored = self.root / index["data"]["path"]
        with stored.open("a", encoding="utf-8") as output:
            output.write(json.dumps({"text": "extra", "source": "client.js", "line": 2}) + "\n")
        with self.assertRaisesRegex(ForgeError, "index hash/size mismatch"):
            self.compare(index, index)
        legacy = self.store.add("analysis", {key: value for key, value in index["data"].items()
                                            if key not in {"index_sha256", "index_size"}})
        with self.assertRaisesRegex(ForgeError, "record count"):
            self.compare(legacy, legacy)

    def test_legacy_indexes_pin_observed_hash_but_do_not_claim_creation_integrity(self):
        _, artifact, index = self.archive("legacy.zip", {"client.js": 'fetch("/api/legacy");'})
        legacy = self.store.add("analysis", {key: value for key, value in index["data"].items()
                                            if key not in {"index_sha256", "index_size"}})
        data = self.compare(artifact, artifact, legacy, legacy)["data"]
        self.assertTrue(data["file_inventory_complete"])
        self.assertFalse(data["complete"])
        self.assertFalse(data["before"]["metadata"]["index"]["hash_verified"])
        self.assertTrue(data["limitations"]["legacy_index_creation_hash_unavailable"])
        self.assertEqual(data["before"]["metadata"]["index"]["sha256"], index["data"]["index_sha256"])

    def test_index_same_count_tampering_fails_creation_hash_validation(self):
        source = self.root / "client.js"
        source.write_text('fetch("/api/old");', encoding="utf-8")
        index = self.command("artifact-index", str(source))
        stored = self.root / index["data"]["path"]
        stored.write_bytes(stored.read_bytes().replace(b"/api/old", b"/api/new"))
        with self.assertRaisesRegex(ForgeError, "index hash/size mismatch"):
            self.compare(index, index)

    def test_raw_and_projection_hash_bases_cannot_be_silently_mixed(self):
        path = self.root / "client.js"
        path.write_text('fetch("/api/one");', encoding="utf-8")
        artifact = self.command("artifact-add", str(path))
        index = self.command("artifact-index", str(path))
        with self.assertRaisesRegex(ForgeError, "raw artifact inventories against index projections"):
            self.compare(artifact, index)


if __name__ == "__main__":
    unittest.main()
