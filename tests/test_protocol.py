import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_artifacts
import forge_network
import forge_protocol


class ProtocolMapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        commands = self.parser.add_subparsers()
        forge_protocol.register(commands)
        forge_network.register(commands)
        forge_artifacts.register(commands)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def save(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")
        return name

    def http(self, url="https://fixture.example/api/login", method="POST", status=200, **changes):
        data = {"source": "live_probe", "request": {"url": url, "method": method, "headers": {}, "body": None},
                "response": {"status": status, "headers": {}, "body": None, "truncated": False}}
        data.update(changes)
        return self.store.add("http_probe", data)

    def test_mixed_actual_index_search_har_and_live_observations_are_read_only(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                body = b'{"result":{"plan":"private-plan-value"},"binding":"opaque-bound-value"}'
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Request-Id", "private-header-value")
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/api/login?mode=owned&token=query-private"
        try:
            live = self.command("probe", self.save("request.json", {
                "url": url, "method": "POST", "headers": {"Authorization": "Bearer request-private"},
                "json": {"password": "body-private", "profile": {"name": "private-name"}},
                "extract": {"binding": {"json_path": "$.binding"}}}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        har = self.command("har-import", self.save("capture.har", {"log": {"entries": [{
            "request": {"url": url, "method": "POST", "headers": [
                {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                "postData": {"text": "username=har-private&choice=opaque-form-value"}},
            "response": {"status": 401, "headers": [{"name": "Content-Type", "value": "application/json"}],
                         "content": {"text": '{"failure":{"reason":"opaque-response-value"}}'}}}]}}))
        archive = self.root / "owned.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("client.js", 'fetch("https://fixture.example/api/login");\nfetch("/api/profile");')
        index = self.command("artifact-index", str(archive))
        search = self.command("search", "api/", str(archive))
        before = self.store.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        # Published metadata suffices even when every original input/index is unavailable.
        archive.unlink()
        (self.root / index["data"]["path"]).unlink()
        with patch.object(Path, "open", side_effect=AssertionError("protocol-map must not open sources")):
            result = self.command("protocol-map")
        after = self.store.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        self.assertEqual(before, after)
        self.assertEqual(set(result["evidence_ids"]), {live["id"], har["exchanges"][0]["id"], index["id"], search["id"]})
        live_endpoint = next(endpoint for endpoint in result["endpoints"] if endpoint.get("method") == "POST")
        self.assertTrue(live_endpoint["proven_live"])
        observations = {item["category"]: item for item in live_endpoint["observations"]}
        self.assertEqual(set(observations), {"live_http", "captured_http"})
        actual = observations["live_http"]
        self.assertEqual(actual["response_status"], 202)
        self.assertEqual(actual["query_field_names"], ["mode", "token"])
        self.assertIn("Authorization", actual["request_header_names"])
        self.assertIn("x-request-id", [name.lower() for name in actual["response_header_names"]])
        self.assertIn("/password", actual["request_body"]["json_field_paths"])
        self.assertIn("/profile/name", actual["request_body"]["json_field_paths"])
        self.assertIn("/result/plan", actual["response_body"]["json_field_paths"])
        self.assertEqual(actual["extraction_selectors"][0]["json_path"], "$.binding")
        self.assertNotIn("value", actual["extraction_selectors"][0])
        captured = observations["captured_http"]
        self.assertFalse(captured["proven_live"])
        self.assertEqual(captured["request_body"]["form_field_names"], ["choice", "username"])
        self.assertEqual(captured["response_status"], 401)
        static = [endpoint for endpoint in result["endpoints"] if "method" not in endpoint]
        self.assertTrue(static)
        self.assertTrue(any(endpoint["url"] == "/api/profile" for endpoint in static))
        for endpoint in static:
            self.assertFalse(endpoint["proven_live"])
            self.assertNotIn("host", endpoint)
            self.assertEqual(len(endpoint["observations"]), 1)
            citations = endpoint["observations"][0]["citations"]
            self.assertEqual({citation["evidence_id"] for citation in citations}, {index["id"], search["id"]})
            self.assertTrue(all(citation["location"]["member"] == "client.js" for citation in citations))
            self.assertTrue(all("line" in citation["location"] for citation in citations))
        self.assertFalse(result["authentication_verified"])
        serialized = json.dumps(result)
        for value in ("query-private", "request-private", "body-private", "private-name", "har-private",
                      "opaque-form-value", "opaque-response-value", "private-plan-value", "private-header-value", "opaque-bound-value"):
            self.assertNotIn(value, serialized)

    def test_failed_actual_live_transport_is_not_endpoint_proof(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with self.assertRaisesRegex(ForgeError, "transport error"):
            self.command("probe", self.save("failed.json", {"url": f"http://127.0.0.1:{port}/api/login"}),
                         "--timeout", "0.2")
        result = self.command("protocol-map")
        endpoint = result["endpoints"][0]
        observation = endpoint["observations"][0]
        self.assertEqual(observation["category"], "live_http")
        self.assertFalse(endpoint["proven_live"])
        self.assertFalse(observation["response_observed"])
        self.assertIsNone(observation["response_status"])
        self.assertTrue(observation["response_error"])

    def test_kind_cannot_promote_imported_or_unknown_source_to_live(self):
        for source in ("har_import", None, "manual"):
            record = self.http(source=source)
            with self.subTest(source=source), self.assertRaisesRegex(ForgeError, "provenance"):
                self.command("protocol-map", "--evidence", record["id"])

    def test_exact_identity_unique_observations_and_distinct_citations(self):
        first = self.http(url="https://fixture.example/api/item?view=a")
        same = self.http(url="https://fixture.example/api/item?view=a")
        changed = self.http(url="https://fixture.example/api/item?view=a", status=403)
        self.http(url="https://fixture.example/api/item?view=b")
        self.http(url="https://fixture.example/api/item?view=a", method="GET")
        record = self.store.add("analysis", {"tool": "static_index", "endpoint_candidates": [
            {"value": "/api/item", "location": {"source": "owned.dex", "offset": 10}},
            {"value": "/api/item", "location": {"source": "owned.dex", "offset": 10}},
            {"value": "/api/item", "location": {"source": "owned.dex", "offset": 30}}]})
        result = self.command("protocol-map", "--evidence", first["id"], "--evidence", first["id"],
                              "--evidence", same["id"], "--evidence", changed["id"], "--evidence", record["id"])
        self.assertEqual(result["evidence_ids"].count(first["id"]), 1)
        endpoint = next(item for item in result["endpoints"] if item.get("method") == "POST")
        self.assertEqual(len(endpoint["observations"]), 2)
        self.assertEqual({item["response_status"] for item in endpoint["observations"]}, {200, 403})
        observed = next(item for item in endpoint["observations"] if item["response_status"] == 200)
        self.assertEqual({citation["evidence_id"] for citation in observed["citations"]}, {first["id"], same["id"]})
        static = next(item for item in result["endpoints"] if "method" not in item)
        self.assertEqual(len(static["observations"][0]["citations"]), 2)
        all_records = self.command("protocol-map")
        self.assertEqual(len(all_records["endpoints"]), 4)

    def test_relevant_window_explicit_precedence_bounds_and_empty(self):
        empty = self.command("protocol-map")
        self.assertTrue(empty["empty"])
        self.assertEqual(empty["endpoints"], [])
        older = self.http(url="https://fixture.example/api/older")
        latest = self.http(url="https://fixture.example/api/latest")
        for index in range(110):
            self.store.add("checkpoint", {"index": index})
        irrelevant = self.store.add("analysis", {"tool": "jadx"})
        result = self.command("protocol-map", "--limit", "1")
        self.assertEqual(result["evidence_ids"], [latest["id"]])
        self.assertTrue(result["window_truncated"])
        explicit = self.command("protocol-map", "--limit", "1", "--evidence", older["id"], "--evidence", latest["id"])
        self.assertEqual(explicit["evidence_ids"], [older["id"], latest["id"]])
        self.assertFalse(explicit["window_truncated"])
        limited = self.command("protocol-map", "--max-endpoints", "1")
        self.assertEqual(len(limited["endpoints"]), 1)
        self.assertTrue(limited["output_truncated"])
        for option, value in (("--limit", "0"), ("--limit", "1001"), ("--max-endpoints", "0"), ("--max-endpoints", "5001")):
            with self.assertRaises(ForgeError):
                self.command("protocol-map", option, value)
        for evidence_id in (irrelevant["id"], "ev_missing"):
            with self.assertRaises(ForgeError):
                self.command("protocol-map", "--evidence", evidence_id)
        self.assertEqual(len(self.command("protocol-map", "--limit", "1000", "--max-endpoints", "5000")["endpoints"]), 2)

    def test_static_sampling_and_input_truncation_are_visible_without_index_reads(self):
        source = self.root / "owned.js"
        source.write_text("\n".join(f'fetch("https://fixture.example/api/item/{index}");' for index in range(105)), encoding="utf-8")
        record = self.command("artifact-index", str(source))
        source.unlink()
        (self.root / record["data"]["path"]).unlink()
        result = self.command("protocol-map")
        self.assertEqual(len(result["endpoints"]), 100)
        self.assertTrue(result["static_candidate_sampling"][0]["sampling_possible"])
        self.assertEqual(result["static_candidate_sampling"][0]["metadata_candidate_limit"], 100)
        record = self.store.add("search", {"truncated": True, "matches": []})
        result = self.command("protocol-map", "--evidence", record["id"])
        self.assertTrue(result["input_truncated"])
        self.assertTrue(result["empty"])

    def test_binary_index_citations_preserve_observed_byte_offsets(self):
        archive = self.root / "owned.apk"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("classes.dex", b"dex\n035\x00\x00https://fixture.example/api/login\x00")
        record = self.command("artifact-index", str(archive))
        candidate = record["data"]["endpoint_candidates"][0]
        result = self.command("protocol-map", "--evidence", record["id"])
        location = result["endpoints"][0]["observations"][0]["citations"][0]["location"]
        self.assertEqual(location["byte_offset"], candidate["location"]["byte_offset"])
        self.assertEqual(location["member"], "classes.dex")
        self.assertEqual(location["source"], candidate["location"]["source"])
        self.assertFalse(result["endpoints"][0]["proven_live"])

    def test_nested_body_form_attestation_and_omission_flags(self):
        nested = {"leaf": "never-output-value"}
        for _ in range(20):
            nested = {"nested": nested}
        record = self.http(response={"status": 200, "headers": {"Content-Type": "application/json"},
                                    "body": nested, "truncated": True},
                           request={"url": "https://fixture.example/api/nested", "method": "POST",
                                    "headers": {}, "body": "field=opaque-unattested-form-value"})
        result = self.command("protocol-map", "--evidence", record["id"])
        self.assertTrue(result["fields_omitted"])
        self.assertTrue(result["input_truncated"])
        observation = result["endpoints"][0]["observations"][0]
        self.assertEqual(observation["request_body"]["form_field_names"], [])
        self.assertTrue(observation["request_body"]["body_unparsed"])
        self.assertNotIn("never-output-value", json.dumps(result))
        self.assertNotIn("opaque-unattested-form-value", json.dumps(result))
        form = self.http(request={"url": "https://fixture.example/api/form", "method": "POST",
                         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                         "body": {"username": "opaque-user", "selected": "opaque-selection"}})
        observation = self.command("protocol-map", "--evidence", form["id"])["endpoints"][0]["observations"][0]
        self.assertEqual(observation["request_body"]["form_field_names"], ["selected", "username"])
        self.assertEqual(observation["request_body"]["json_field_paths"], [])

    def test_parse_limits_do_not_discard_other_side_and_pointer_names_are_escaped(self):
        record = self.http(request={"url": "https://fixture.example/api/form", "method": "POST",
                           "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                           "body": "&".join(f"field{index}=opaque-form-secret" for index in range(2050))},
                           response={"status": 200, "headers": {},
                                     "body": {"a/b": [{"~name": "opaque-json-secret"}]}, "truncated": False})
        result = self.command("protocol-map", "--evidence", record["id"])
        observation = result["endpoints"][0]["observations"][0]
        self.assertTrue(result["fields_omitted"])
        self.assertTrue(observation["request_body"]["fields_omitted"])
        self.assertIn("/a~1b/0/~0name", observation["response_body"]["json_field_paths"])
        self.assertNotIn("opaque-form-secret", json.dumps(result))
        self.assertNotIn("opaque-json-secret", json.dumps(result))
        oversized = self.http(response={"status": 200, "headers": {},
                              "body": "x" * (1048576 + 1), "truncated": False})
        result = self.command("protocol-map", "--evidence", oversized["id"])
        self.assertTrue(result["fields_omitted"])
        self.assertTrue(result["endpoints"][0]["observations"][0]["response_body"]["body_unparsed"])
        many_fields = self.http(response={"status": 200, "headers": {},
                                "body": {f"field{index}": "opaque" for index in range(300)}, "truncated": False})
        result = self.command("protocol-map", "--evidence", many_fields["id"])
        paths = result["endpoints"][0]["observations"][0]["response_body"]["json_field_paths"]
        self.assertEqual(len(paths), 256)
        self.assertTrue(result["fields_omitted"])

    def test_observation_and_citation_caps_report_omissions(self):
        self.store.add("search", {"matches": [{"endpoint_candidates": [
            {"value": "/api/repeated", "location": {"source": "owned.js", "line": line}}
        ]} for line in range(110)]})
        result = self.command("protocol-map")
        self.assertTrue(result["citations_omitted"])
        self.assertEqual(len(result["endpoints"][0]["observations"][0]["citations"]), 100)
        for index in range(110):
            self.http(status=200 + index)
        result = self.command("protocol-map", "--limit", "1000")
        self.assertTrue(result["observations_omitted"])
        endpoint = next(item for item in result["endpoints"] if item.get("method") == "POST")
        self.assertEqual(len(endpoint["observations"]), 100)


if __name__ == "__main__":
    unittest.main()
