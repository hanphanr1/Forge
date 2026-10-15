import argparse
import base64
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from demo_server import DemoServer
from forge_core import EvidenceStore, ForgeError
import forge_flows
import forge_har
import forge_network


class HarFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        commands = self.parser.add_subparsers()
        forge_har.register(commands)
        forge_network.register(commands)
        forge_flows.register(commands)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *arguments):
        args = self.parser.parse_args(arguments)
        return args.handler(args, self.store)

    def capture(self, requests):
        har = {"log": {"entries": [{"request": request, "response": {"status": 200,
                    "content": {"text": "opaque-response-not-exported"}}} for request in requests]}}
        (self.root / "owned.har").write_text(json.dumps(har), encoding="utf-8")
        return har

    def environment(self, har, variables):
        values = {}
        for binding in variables:
            pointer, separator, nested = binding["pointer"].partition("#")
            value = har
            for component in forge_network._path_parts(pointer):
                value = value[int(component)] if isinstance(value, list) else value[component]
            if separator:
                value = json.loads(value)
                for component in forge_network._path_parts(nested or "$"):
                    value = value[int(component)] if isinstance(value, list) else value[component]
            if binding["format"] == "form_urlencoded":
                value = urlencode([(item["name"], item["value"]) for item in value])
            if binding["format"] == "cookie_header":
                value = "; ".join(item["name"] + "=" + item["value"] for item in value)
            values[binding["variable"]] = value
        return values

    def test_export_sends_nothing_and_explicitly_materialized_flow_runs_real_http(self):
        with DemoServer(0) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                har = self.capture([
                    {"url": base + "/login", "method": "POST", "headers": [
                     {"name": "Content-Type", "value": "application/json"},
                     {"name": "Host", "value": "private-captured-host"}],
                     "postData": {"mimeType": "application/json", "text": json.dumps({"login": "demo", "password": "demo-password"})}},
                    {"url": base + "/profile", "method": "GET", "headers": []}])
                exported = self.command("har-to-flow", "owned.har", "--output", "flow.json")
                self.assertEqual(server.sessions, {})
                flow = json.loads((self.root / "flow.json").read_text(encoding="utf-8"))
                self.assertEqual([item["method"] for item in flow], ["POST", "GET"])
                self.assertNotIn("Host", flow[0]["headers"])
                flow[0]["extract"] = {"AUTH": {"json_path": "/data/opaque"}}
                flow[1]["headers"]["Authorization"] = "Bearer ${flow.AUTH}"
                for item in flow:
                    item["rules"] = [{"bucket": "HIT", "contains": "SIGNED_IN"}, {"bucket": "HIT", "contains": "PROFILE_READY"}]
                (self.root / "reviewed.json").write_text(json.dumps(flow), encoding="utf-8")
                with patch.dict("os.environ", self.environment(har, exported["variables"])):
                    live = self.command("probe-run", "reviewed.json")
                self.assertEqual([item["data"]["bucket"] for item in live["exchanges"]], ["HIT", "HIT"])
                self.assertFalse(live["stopped"])
                self.assertEqual(live["exchanges"][1]["data"]["response"]["body"]["opaque_echo"], "[REDACTED]")
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_credentials_in_urls_headers_and_body_never_enter_template_or_evidence(self):
        secrets = ["private-path-opaque-123", "private-cookie-opaque-123", "private-body-opaque-123", "private-header-opaque-123"]
        har = self.capture([{"url": "https://owned.example/" + secrets[0] + "?opaque=" + secrets[0],
                             "method": "POST", "headers": [{"name": "X-Proof", "value": secrets[3]},
                               {"name": "Cookie", "value": "sid=" + secrets[1]}],
                             "postData": {"mimeType": "application/json", "text": json.dumps({"opaque": secrets[2]})}}])
        before = (self.root / "owned.har").read_bytes()
        result = self.command("har-to-flow", "owned.har", "--output", "flow.json")
        self.assertEqual(before, (self.root / "owned.har").read_bytes())
        exported = (self.root / "flow.json").read_text(encoding="utf-8") + json.dumps(result)
        stored = b"".join(path.read_bytes() for path in (self.root / ".forge").glob("evidence.sqlite3*"))
        for value in [*secrets, "opaque-response-not-exported"]:
            self.assertNotIn(value, exported)
            self.assertNotIn(value.encode(), stored)
        with patch.dict("os.environ", self.environment(har, result["variables"])):
            template = json.loads((self.root / "flow.json").read_text(encoding="utf-8"))[0]
            materialized = forge_network._substitute(template, set(), {}, {})
            self.assertEqual(materialized["url"], har["log"]["entries"][0]["request"]["url"])
            self.assertEqual(materialized["json"], {"opaque": secrets[2]})

    def test_numeric_opaque_credentials_preserve_type_through_whole_json_body(self):
        payload = {"code": 923781123845, "enabled": True, "opaque": "private-numeric-fixture"}
        har = self.capture([{"url": "https://owned.example/login", "method": "POST", "headers": [],
                            "postData": {"mimeType": "application/json", "text": json.dumps(payload)}}])
        result = self.command("har-to-flow", "owned.har", "--output", "flow.json")
        template = json.loads((self.root / "flow.json").read_text(encoding="utf-8"))[0]
        self.assertNotIn("json", template)
        self.assertNotIn("923781123845", json.dumps(template))
        with patch.dict("os.environ", self.environment(har, result["variables"])):
            resolved = forge_network._substitute(template, set(), {}, {})
        self.assertEqual(json.loads(resolved["body"]), payload)

    def test_forms_duplicate_fields_and_cookies_are_explicit_not_lossy(self):
        har = self.capture([{"url": "https://owned.example/form", "method": "POST", "headers": [],
                             "cookies": [{"name": "sid", "value": "private-form-cookie"}],
                             "postData": {"mimeType": "application/x-www-form-urlencoded", "params": [
                                {"name": "choice", "value": "a&b"}, {"name": "choice", "value": "c d"}]}}])
        result = self.command("har-to-flow", "owned.har", "--output", "flow.json")
        with patch.dict("os.environ", self.environment(har, result["variables"])):
            resolved = forge_network._substitute(json.loads((self.root / "flow.json").read_text())[0], set(), {}, {})
        self.assertEqual(resolved["body"], "choice=a%26b&choice=c+d")
        self.assertEqual(resolved["headers"]["Cookie"], "sid=private-form-cookie")

    def test_invalid_later_request_publishes_no_file_or_evidence(self):
        self.capture([{"url": "https://owned.example/login", "method": "GET"},
                      {"url": "https://owned.example/profile", "method": "GET", "headers": [
                          {"name": "X-Proof", "value": "first"}, {"name": "x-proof", "value": "second"}]}])
        with self.assertRaises(ForgeError):
            self.command("har-to-flow", "owned.har", "--output", "flow.json")
        self.assertFalse((self.root / "flow.json").exists())
        self.assertEqual(self.store.list(), [])

    def test_output_collision_traversal_limits_and_unsupported_payloads(self):
        self.capture([{"url": "https://owned.example/login", "method": "GET"}])
        (self.root / "keep.json").write_text("user-owned", encoding="utf-8")
        for arguments in [("--output", "keep.json"), ("--output", "../escape.json"),
                          ("--output", "limit.json", "--limit", "0"),
                          ("--output", "large.json", "--max-input-bytes", "5")]:
            with self.subTest(arguments=arguments), self.assertRaises(ForgeError):
                self.command("har-to-flow", "owned.har", *arguments)
        self.assertEqual((self.root / "keep.json").read_text(), "user-owned")
        for post in [{"mimeType": "multipart/form-data", "text": "private-body"},
                     {"mimeType": "application/json", "text": '{"code":NaN}'},
                     {"mimeType": "application/octet-stream", "text": "AAAA", "encoding": "base64"}]:
            self.capture([{"url": "https://owned.example/login", "method": "POST", "postData": post}])
            with self.subTest(post=post), self.assertRaises(ForgeError):
                self.command("har-to-flow", "owned.har", "--output", "bad.json")
        self.assertFalse((self.root / "bad.json").exists())

    def test_base64_grpc_body_keeps_the_exchange_without_the_body(self):
        body = b"\x00\x00\x00\x00\x08\x08\x06\x1a\x04\xff\xfeVN"
        self.capture([{"url": "https://grok.com/grok_api.Models/ListModes", "method": "POST",
                       "headers": [{"name": "Content-Type", "value": "application/grpc"}],
                       "postData": {"mimeType": "application/grpc", "text": base64.b64encode(body).decode(),
                                    "encoding": "base64"}},
                      {"url": "https://grok.com/_data/v1/app_config", "method": "GET", "headers": []}])
        result = self.command("har-to-flow", "owned.har", "--output", "flow.json")
        self.assertEqual((result["converted"], result["available"]), (2, 2))
        self.assertEqual([warning["type"] for warning in result["warnings"]], ["binary_body_omitted"])
        self.assertIn(str(len(body)), result["warnings"][0]["message"])
        template = json.loads((self.root / "flow.json").read_text(encoding="utf-8"))
        self.assertEqual(template[0]["method"], "POST")
        self.assertTrue(template[0]["url"].startswith("${HAR_1_URL_"))
        self.assertTrue(template[0]["headers"]["Content-Type"].startswith("${HAR_1_HEADER_"))
        for absent in ("body", "json", "params"):
            self.assertNotIn(absent, template[0])
        self.assertEqual(template[1]["method"], "GET")
        stored = b"".join(path.read_bytes() for path in (self.root / ".forge").glob("evidence.sqlite3*"))
        self.assertNotIn(base64.b64encode(body), stored)

    def test_base64_body_that_is_not_grpc_or_not_base64_still_fails(self):
        for post in [{"mimeType": "application/octet-stream", "text": "AAAA", "encoding": "base64"},
                     {"mimeType": "application/grpc", "text": "not base64!", "encoding": "base64"},
                     {"mimeType": "application/grpc", "text": "AAAA", "encoding": "gzip"}]:
            self.capture([{"url": "https://grok.com/grok_api.Models/ListModes", "method": "POST", "postData": post}])
            with self.subTest(post=post), self.assertRaisesRegex(ForgeError, "unsupported|not decodable"):
                self.command("har-to-flow", "owned.har", "--output", "rejected.json")
        self.assertFalse((self.root / "rejected.json").exists())

    def test_flow_to_har_output_imports_without_replaying_the_grpc_body(self):
        def pairs(rows):
            return [[name.encode(), value.encode()] for name, value in rows]

        def grpc_flow(path, request_body, response_body):
            return {"type": b"http", "version": 21, "websocket": None,
                    "request": {"method": b"POST", "scheme": b"https", "authority": b"grok.com",
                                "host": "203.0.113.9", "port": 443, "path": path.encode(),
                                "http_version": b"HTTP/2.0", "timestamp_start": 1700000000.5,
                                "timestamp_end": 1700000000.6,
                                "headers": pairs([("content-type", "application/grpc")]),
                                "content": request_body or None, "trailers": None},
                    "response": {"status_code": 200, "reason": b"OK", "http_version": b"HTTP/2.0",
                                 "timestamp_start": 1700000000.5, "timestamp_end": 1700000000.6,
                                 "headers": pairs([("content-type", "application/grpc")]),
                                 "content": response_body or None,
                                 "trailers": pairs([("grpc-status", "0")])}}

        (self.root / "flows.dump").write_bytes(b"".join(
            forge_flows.tns_dumps(grpc_flow("/grok_api.Models/ListModes", b"\x00\x00\x00\x00\x08\x08\x06\x1a\x04\xff\xfeVN",
                                            b"\x00\x00\x00\x00\x04\x0a\x02\xff\xfe"))
            for _ in range(2)))
        args = self.parser.parse_args(["flow-to-har", "flows.dump", "--output", "flows.har"])
        converted = args.handler(args, self.store)
        self.assertEqual(converted["data"]["flows"], 2)
        self.assertEqual(converted["data"]["bodies_encoded"], 4)
        result = self.command("har-to-flow", "flows.har", "--output", "flow.json")
        self.assertEqual((result["converted"], result["available"]), (2, 2))
        self.assertEqual([warning["type"] for warning in result["warnings"]], ["binary_body_omitted"] * 2)
        self.assertEqual(json.loads((self.root / "flow.json").read_text())[0]["method"], "POST")

    def test_limit_is_visible_and_http2_transport_headers_are_not_replayed(self):
        self.capture([{"url": "https://owned.example/login", "method": "GET", "headers": [
                        {"name": ":authority", "value": "private-origin"}]},
                      {"url": "https://owned.example/profile", "method": "GET"}])
        result = self.command("har-to-flow", "owned.har", "--output", "flow.json", "--limit", "1")
        self.assertEqual((result["converted"], result["available"], result["omitted"]), (1, 2, 1))
        self.assertEqual(json.loads((self.root / "flow.json").read_text())[0]["headers"], {})


if __name__ == "__main__":
    unittest.main()
