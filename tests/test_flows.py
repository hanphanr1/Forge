import argparse
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_network


class FlowHttpTests(unittest.TestCase):
    transport = "urllib"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.received = []
        self.first = "opaque-fixture-first-78ac"
        self.second = "opaque-fixture-second-f45b"
        self.cookie = "fixture-cookie-583b"
        self.login_body = {"data": {"opaque": self.first}, "echo": self.first}
        self.login_headers = []
        self.login_status = 200
        self.login_padding = ""
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.do_GET()

            def do_GET(self):
                content = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                fixture.received.append({"path": self.path, "headers": dict(self.headers),
                                         "body": content.decode("utf-8")})
                if self.path == "/disconnect":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                headers = []
                status = 200
                if self.path == "/login":
                    body = fixture.login_body
                    headers = [("Set-Cookie", "sid=" + fixture.cookie + "; Path=/")] + fixture.login_headers
                    status = fixture.login_status
                elif self.path == "/rotate":
                    body = {"data": {"opaque": fixture.second}, "old_echo": fixture.first}
                elif self.path == "/future-echo":
                    body = {"opaque_echo": fixture.second}
                elif self.path.startswith("/resource"):
                    supplied = self.headers.get("Authorization")
                    expected = "Bearer " + (fixture.second if "rotated" in self.path else fixture.first)
                    cookie_ok = "sid=" + fixture.cookie in self.headers.get("Cookie", "")
                    body = {"result": "HIT" if supplied == expected and cookie_ok else "FAIL",
                            "opaque_echo": supplied.removeprefix("Bearer ") if supplied else "none"}
                else:
                    body = {"result": "OK", "opaque_echo": fixture.first}
                raw = json.dumps(body, ensure_ascii=False).encode("utf-8") + fixture.login_padding.encode("utf-8") if self.path == "/login" else json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.parser = argparse.ArgumentParser()
        forge_network.register(self.parser.add_subparsers())

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.close()
        self.temp.cleanup()

    def save(self, name, data):
        (self.root / name).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return name

    def command(self, command, specs, *options):
        name = self.save("flow.json" if command == "probe-run" else "request.json", specs)
        args = self.parser.parse_args([command, name, "--transport", self.transport, *options])
        return args.handler(args, self.store)

    def login(self, **overrides):
        return {"url": self.base + "/login", "extract": {"AUTH": {"json_path": "/data/opaque"}}, **overrides}

    def resource(self, **overrides):
        return {"url": self.base + "/resource", "headers": {"Authorization": "Bearer ${flow.AUTH}"},
                "rules": [{"bucket": "HIT", "json_path": "$.result", "equals": "HIT"}], **overrides}

    def metadata(self, record, variable="AUTH"):
        return next(item for item in record["data"]["extraction"] if item["variable"] == variable)

    def assert_private(self, result, *secrets):
        serialized = json.dumps(result, ensure_ascii=False)
        persisted = json.dumps(self.store.list("http_probe", 1000), ensure_ascii=False)
        files = [path.read_bytes() for path in self.store.directory.iterdir() if path.is_file()]
        for secret in secrets:
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, persisted)
            for content in files:
                self.assertNotIn(secret.encode("utf-8"), content)
                self.assertNotIn(json.dumps(secret)[1:-1].encode("utf-8"), content)

    def test_login_extract_authorize_hit_and_cookie_carry(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = self.command("probe-run", [self.login(), self.resource()])
            print(json.dumps(result))
        self.assertEqual(result["completed"], 2)
        self.assertEqual(result["requested"], 2)
        self.assertTrue(result["session_reused"])
        self.assertFalse(result["stopped"])
        self.assertEqual(result["exchanges"][1]["data"]["bucket"], "HIT")
        self.assertEqual(self.received[1]["headers"]["Authorization"], "Bearer " + self.first)
        self.assertIn("sid=" + self.cookie, self.received[1]["headers"]["Cookie"])
        self.assertTrue(self.metadata(result["exchanges"][0])["succeeded"])
        self.assertEqual(result["exchanges"][0]["data"]["response"]["body"]["data"]["opaque"], "[REDACTED]")
        self.assertNotIn(self.first, output.getvalue())
        self.assert_private(result, self.first, self.cookie)

    def test_header_extraction_case_insensitive_and_sensitive_name_metadata(self):
        self.login_headers = [("X-Request-ID", self.first)]
        result = self.command("probe-run", [self.login(extract={"SESSION_TOKEN": {"header": "X-Request-ID"}}),
                              self.resource(headers={"Authorization": "Bearer ${flow.SESSION_TOKEN}"})])
        self.assertEqual(result["exchanges"][1]["data"]["bucket"], "HIT")
        self.assertTrue(self.metadata(result["exchanges"][0], "SESSION_TOKEN")["succeeded"])
        self.assert_private(result, self.first)

    def test_rotation_retains_all_previous_secrets(self):
        rotate = {"url": self.base + "/rotate", "headers": {"Authorization": "Bearer ${flow.AUTH}"},
                  "extract": {"AUTH": {"json_path": "data.opaque"}}}
        result = self.command("probe-run", [self.login(), rotate, self.resource(url=self.base + "/resource?rotated")])
        self.assertEqual(result["completed"], 3)
        self.assertEqual(self.received[1]["headers"]["Authorization"], "Bearer " + self.first)
        self.assertEqual(self.received[2]["headers"]["Authorization"], "Bearer " + self.second)
        self.assertEqual(result["exchanges"][-1]["data"]["bucket"], "HIT")
        self.assert_private(result, self.first, self.second)

    def test_later_extraction_redacts_earlier_echo_before_sqlite_wal(self):
        result = self.command("probe-run", [{"url": self.base + "/future-echo"}, self.login(),
                              {"url": self.base + "/rotate", "extract": {"AUTH": {"json_path": "/data/opaque"}}}])
        self.assertEqual(result["exchanges"][0]["data"]["response"]["body"]["opaque_echo"], "[REDACTED]")
        self.assert_private(result, self.first, self.second)

    def test_substitutes_path_query_json_and_body_as_strings(self):
        result = self.command("probe-run", [self.login(),
                              {"url": self.base + "/echo/${flow.AUTH}?id=${flow.AUTH}", "method": "POST",
                               "json": {"value": "${flow.AUTH}", "embedded": "before:${flow.AUTH}:after"}},
                              {"url": self.base + "/echo", "method": "POST", "body": "value=${flow.AUTH}"}])
        self.assertEqual(result["completed"], 3)
        self.assertEqual(self.received[1]["path"], "/echo/" + self.first + "?id=" + self.first)
        self.assertEqual(json.loads(self.received[1]["body"]), {"value": self.first, "embedded": "before:" + self.first + ":after"})
        self.assertEqual(self.received[2]["body"], "value=" + self.first)
        self.assert_private(result, self.first)

    def test_extracted_templates_are_not_recursively_interpreted(self):
        token = "literal-${flow.UNDECLARED}-${FORGE_TEST_ENV}-tail"
        self.login_body = {"data": {"opaque": token}}
        with patch.dict(os.environ, {"FORGE_TEST_ENV": "do-not-insert"}):
            result = self.command("probe-run", [self.login(),
                                  {"url": self.base + "/echo", "method": "POST", "body": "${flow.AUTH}"}])
        self.assertEqual(self.received[1]["body"], token)
        self.assertEqual(result["completed"], 2)
        self.assert_private(result, token)

    def test_environment_insertions_are_not_recursively_interpreted(self):
        value = "literal-${flow.UNDECLARED}-${FORGE_TEST_OTHER}"
        with patch.dict(os.environ, {"FORGE_TEST_ENV": value, "FORGE_TEST_OTHER": "do-not-insert"}):
            result = self.command("probe-run", [{"url": self.base + "/echo", "method": "POST", "body": "${FORGE_TEST_ENV}"}])
        self.assertEqual(self.received[0]["body"], value)
        self.assert_private(result, value)

    def test_flow_prefixed_environment_names_remain_environment_references(self):
        with patch.dict(os.environ, {"flow": self.first, "flow_fixture": self.second}):
            result = self.command("probe-run", [{"url": self.base + "/echo", "method": "POST",
                                  "body": "${flow}:${flow_fixture}"}])
        self.assertEqual(self.received[0]["body"], self.first + ":" + self.second)
        self.assert_private(result, self.first, self.second)

    def test_future_literal_secret_is_redacted_even_when_terminal_stops_first(self):
        private = "forge-flow-value-real-credential"
        self.login_body = {"message": "DOMAIN_NOT_ALLOWED", "opaque_echo": private}
        first = self.login(extract={}, rules=[{"bucket": "TERMINAL", "contains": "DOMAIN_NOT_ALLOWED"}])
        later = {"url": self.base + "/echo", "method": "POST", "json": {"password": private}}
        result = self.command("probe-run", [first, later])
        self.assertEqual(result["stop_reason"]["type"], "bucket")
        self.assertEqual(result["stop_reason"]["bucket"], "TERMINAL")
        self.assertEqual([request["path"] for request in self.received], ["/login"])
        self.assert_private(result, private)

    def test_extraction_reuses_pointer_escapes_and_numeric_indexes(self):
        self.login_body = {"a/b": {"c~d": [self.first]}, "items": [{"value": self.second}]}
        record = self.command("probe", self.login(extract={
            "FIRST": {"json_path": "/a~1b/c~0d/0"},
            "SECOND": {"json_path": "$.items[0].value"},
        }))
        self.assertTrue(self.metadata(record, "FIRST")["succeeded"])
        self.assertTrue(self.metadata(record, "SECOND")["succeeded"])
        self.assert_private(record, self.first, self.second)

    def test_forward_undefined_self_and_malformed_references_send_zero_requests(self):
        cases = [
            [self.resource(), self.login()],
            [self.login(), self.resource(headers={"Authorization": "${flow.OTHER}"})],
            [self.login(headers={"Authorization": "${flow.AUTH}"})],
            [self.login(), self.resource(body="${flow.AUTH")],
            [self.login(), self.resource(body="${flow.1AUTH}")],
            [self.login(), self.resource(body="${flow.AUTH.more}")],
        ]
        for specs in cases:
            with self.subTest(specs=specs):
                with self.assertRaises(ForgeError):
                    self.command("probe-run", specs)
                self.assertEqual(self.received, [])
        self.assertEqual(self.store.list("http_probe"), [])

    def test_references_in_forbidden_fields_send_zero_requests(self):
        cases = [
            {"method": "${flow.AUTH}"}, {"proxy": "http://${flow.AUTH}"},
            {"context": {"description": "${flow.AUTH}"}},
            {"rules": [{"bucket": "HIT", "contains": "${flow.AUTH}"}]},
            {"extract": {"NEXT": {"json_path": "/${flow.AUTH}"}}},
            {"url": "http://${flow.AUTH}/resource"},
            {"url": "${flow.AUTH}://127.0.0.1/resource"},
            {"url": self.base + "/resource#${flow.AUTH}"},
            {"headers": {"${flow.AUTH}": "value"}},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ForgeError):
                    self.command("probe-run", [self.login(), self.resource(**overrides)])
                self.assertEqual(self.received, [])

    def test_invalid_later_extractor_or_rule_sends_zero_requests(self):
        cases = [
            {"extract": []}, {"extract": {"1BAD": {"header": "x-id"}}},
            {"extract": {"NEXT": {"header": "bad\nname"}}},
            {"extract": {"NEXT": {"json_path": "/data/~2"}}},
            {"extract": {"NEXT": {"header": "x-id", "json_path": "/data"}}},
            {"extract": {"NEXT": {"unknown": "x"}}},
            {"rules": [{"bucket": "HIT", "status": 200}]},
            {"rules": [{"bucket": "HIT", "regex": "["}]},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ForgeError):
                    self.command("probe-run", [self.login(), self.resource(**overrides)])
                self.assertEqual(self.received, [])

    def test_default_rules_cannot_reference_flow(self):
        rules = self.save("rules.json", [{"bucket": "HIT", "contains": "${flow.AUTH}"}])
        with self.assertRaises(ForgeError):
            self.command("probe-run", [self.login(), self.resource()], "--rules", rules)
        self.assertEqual(self.received, [])

    def test_missing_null_object_empty_newline_and_redacted_extraction_stop(self):
        cases = [({}, "missing_value"), ({"opaque": None}, "expected_nonempty_string"),
                 ({"opaque": {"inner": self.first}}, "expected_nonempty_string"),
                 ({"opaque": []}, "expected_nonempty_string"),
                 ({"opaque": 123}, "expected_nonempty_string"),
                 ({"opaque": ""}, "expected_nonempty_string"),
                 ({"opaque": "unsafe\r\nvalue"}, "newline_or_ambiguous_value"),
                 ({"opaque": "[REDACTED]-" + self.first}, "redacted_value")]
        for data, expected in cases:
            with self.subTest(data=data):
                self.received.clear()
                self.login_body = {"data": data}
                result = self.command("probe-run", [self.login(), self.resource()])
                self.assertEqual(len(self.received), 1)
                self.assertEqual(result["completed"], 1)
                self.assertEqual(result["stop_reason"]["type"], "extraction_error")
                self.assertEqual(result["stop_reason"]["evidence_id"], result["exchanges"][0]["id"])
                self.assertEqual(result["exchanges"][0]["data"]["response"]["status"], 200)
                self.assertEqual(self.metadata(result["exchanges"][0])["error"], expected)

    def test_truncation_blocks_extraction_even_when_json_prefix_is_complete(self):
        self.login_padding = " " * 200
        limit = len(json.dumps(self.login_body).encode("utf-8"))
        result = self.command("probe-run", [self.login(), self.resource()], "--max-body", str(limit))
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["stop_reason"]["type"], "extraction_error")
        self.assertTrue(result["exchanges"][0]["data"]["response"]["truncated"])
        self.assertEqual(self.metadata(result["exchanges"][0])["error"], "truncated_response")
        self.assert_private(result, self.first)

    def test_partial_opaque_json_token_is_not_saved(self):
        prefix = self.first[:12]
        limit = len('{"data": {"opaque": "'.encode("utf-8")) + len(prefix)
        result = self.command("probe-run", [self.login(), self.resource()], "--max-body", str(limit))
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["stop_reason"]["type"], "extraction_error")
        self.assertEqual(result["exchanges"][0]["data"]["response"]["body"], '"[REDACTED]"')
        self.assert_private(result, prefix)

    def test_duplicate_headers_are_not_bindings(self):
        self.login_headers = [("X-Request-ID", self.first), ("x-request-id", self.second)]
        result = self.command("probe-run", [self.login(extract={"AUTH": {"header": "x-request-id"}}), self.resource()])
        self.assertEqual(result["completed"], 1)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(result["stop_reason"]["type"], "extraction_error")
        self.assertFalse(self.metadata(result["exchanges"][0])["succeeded"])
        self.assert_private(result, self.first)

    def test_materialized_url_is_revalidated_before_dispatch(self):
        self.login_body = {"data": {"opaque": "invalid space"}}
        result = self.command("probe-run", [self.login(), self.resource(url=self.base + "/resource/${flow.AUTH}")])
        self.assertEqual(len(self.received), 1)
        self.assertEqual(result["stop_reason"]["type"], "extraction_error")
        self.assertIn("Materialized request rejected", result["stop_reason"]["message"])
        self.assertEqual(result["stop_reason"]["evidence_id"], result["exchanges"][0]["id"])
        self.assert_private(result, "invalid space")

    def test_materialized_header_controls_are_rejected_before_dispatch(self):
        token = "opaque\x00invalid"
        self.login_body = {"data": {"opaque": token}}
        result = self.command("probe-run", [self.login(), self.resource(headers={"X-ID": "${flow.AUTH}"})])
        self.assertEqual(len(self.received), 1)
        self.assertTrue(self.metadata(result["exchanges"][0])["succeeded"])
        self.assertEqual(result["stop_reason"]["type"], "extraction_error")
        self.assertIn("Materialized request rejected", result["stop_reason"]["message"])
        self.assertEqual(result["stop_reason"]["evidence_id"], result["exchanges"][0]["id"])
        self.assert_private(result, token)

    def test_environment_header_crlf_is_rejected_before_dispatch(self):
        with patch.dict(os.environ, {"FORGE_TEST_HEADER": "invalid\r\nheader"}):
            with self.assertRaises(ForgeError):
                self.command("probe-run", [self.login(), self.resource(headers={"X-ID": "${FORGE_TEST_HEADER}"})])
        self.assertEqual(self.received, [])

    def test_terminal_bucket_precedes_missing_extractor(self):
        self.login_body = {"result": "REAUTH_REQUIRED"}
        self.login_status = 403
        rules = [{"bucket": "TERMINAL", "json_path": "/result", "equals": "REAUTH_REQUIRED"}]
        result = self.command("probe-run", [self.login(rules=rules), self.resource()])
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["stop_reason"]["type"], "bucket")
        self.assertEqual(result["stop_reason"]["bucket"], "TERMINAL")
        self.assertEqual(result["exchanges"][0]["data"]["response"]["status"], 403)
        self.assertFalse(self.metadata(result["exchanges"][0])["succeeded"])

    def test_custom_stop_bucket_precedes_missing_extractor(self):
        self.login_body = {"result": "BLOCKED"}
        result = self.command("probe-run", [self.login(rules=[{"bucket": "BLOCKED", "contains": "BLOCKED"}]),
                              self.resource()], "--stop-bucket", "BLOCKED")
        self.assertEqual(result["stop_reason"]["type"], "bucket")
        self.assertEqual(result["stop_reason"]["bucket"], "BLOCKED")
        self.assertEqual(len(self.received), 1)

    def test_transport_failure_keeps_transport_reason(self):
        result = self.command("probe-run", [self.login(url=self.base + "/disconnect"), self.resource()])
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["stop_reason"]["type"], "transport_error")
        self.assertEqual(result["stop_reason"]["evidence_id"], result["exchanges"][0]["id"])
        self.assertIsNone(result["exchanges"][0]["data"]["response"]["status"])
        self.assertEqual(self.metadata(result["exchanges"][0])["error"], "transport_error")

    def test_single_probe_extraction_is_private_and_not_replayable(self):
        record = self.command("probe", self.login())
        self.assertTrue(self.metadata(record)["succeeded"])
        self.assertFalse(record["data"]["redaction"]["replayable"])
        self.assert_private(record, self.first)

    def test_single_probe_missing_extraction_reports_saved_evidence(self):
        self.login_body = {"data": {}}
        with self.assertRaisesRegex(ForgeError, "extraction error.*evidence ev_") as caught:
            self.command("probe", self.login())
        record = self.store.list("http_probe", 1)[0]
        self.assertIn(record["id"], str(caught.exception))
        self.assertEqual(record["data"]["response"]["status"], 200)
        self.assertFalse(self.metadata(record)["succeeded"])

    def test_single_probe_terminal_keeps_bucket_precedence(self):
        self.login_body = {"result": "REAUTH_REQUIRED"}
        record = self.command("probe", self.login(rules=[
            {"bucket": "TERMINAL", "json_path": "/result", "equals": "REAUTH_REQUIRED"}
        ]))
        self.assertEqual(record["data"]["bucket"], "TERMINAL")
        self.assertFalse(self.metadata(record)["succeeded"])

    def test_legacy_request_arrays_keep_cookie_session_and_result_shape(self):
        result = self.command("probe-run", [{"url": self.base + "/login"},
                              self.resource(headers={"Authorization": "Bearer " + self.first})])
        self.assertEqual(set(result), {"exchanges", "completed", "requested", "stopped", "stop_reason", "session_reused"})
        self.assertEqual(result["completed"], 2)
        self.assertEqual(result["exchanges"][1]["data"]["bucket"], "HIT")
        self.assertNotIn("extraction", result["exchanges"][0]["data"])
        self.assert_private(result, self.first, self.cookie)

    def test_bindings_do_not_survive_into_another_command(self):
        self.command("probe", self.login())
        self.received.clear()
        with self.assertRaises(ForgeError):
            self.command("probe", self.resource())
        self.assertEqual(self.received, [])


@unittest.skipUnless(importlib.util.find_spec("curl_cffi"), "curl_cffi is not installed")
class CurlFlowHttpTests(FlowHttpTests):
    transport = "curl_cffi"


if __name__ == "__main__":
    unittest.main()
