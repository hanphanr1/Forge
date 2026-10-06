import argparse
import contextlib
import io
import json
from pathlib import Path
import re
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_capture
import forge_network


def har_entry(url, method="GET", status=200, content="{}", started="2026-01-01T00:00:00.000Z"):
    return {"startedDateTime": started, "time": 3.5,
            "request": {"method": method, "url": url, "headers": [], "cookies": []},
            "response": {"status": status, "headers": [], "content": {"text": content}, "cookies": []}}


def post(port, payload, path="/report", method="POST", headers=None):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body if method == "POST" else None,
                                     method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


class CaptureIngestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_capture.register(self.parser.add_subparsers())

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def listener(self, *argv):
        """Start the real single-threaded loop in-process; return (state, stop, thread)."""
        args = self.parser.parse_args(["capture-ingest", *argv])
        options = forge_capture._capture_options(args)
        state = {"ready": threading.Event(), "result": None}
        stop = threading.Event()

        def notify(listener):
            state["bound"] = listener
            state["ready"].set()

        def run():
            state["result"] = forge_capture._serve(options, self.store, stop=stop, notify=notify)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.assertTrue(state["ready"].wait(10), "listener did not report a bound port")
        return state, stop, thread

    def finish(self, state, stop, thread):
        stop.set()
        thread.join(10)
        self.assertFalse(thread.is_alive(), "listener did not stop")
        return state["result"]

    def save(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")
        return name

    def test_ephemeral_loopback_post_is_accepted_stored_and_announced(self):
        errors = io.StringIO()
        state = {"result": None}
        with contextlib.redirect_stderr(errors):
            args = self.parser.parse_args(["capture-ingest", "--port", "0", "--seconds", "1"])
            thread = threading.Thread(target=lambda: state.update(result=args.handler(args, self.store)))
            thread.start()
            match = None
            for _ in range(100):
                match = re.search(r"listening on 127\.0\.0\.1:(\d+)/report", errors.getvalue())
                if match:
                    break
                threading.Event().wait(0.05)
            self.assertIsNotNone(match, f"no announce line: {errors.getvalue()!r}")
            port = int(match.group(1))
            payload = {"log": {"entries": [har_entry("https://target.example/api/login", "POST", 200,
                                                     '{"token":"private-response-value"}')]}}
            status, response = post(port, payload)
            self.assertEqual((status, response["stored"]), (200, 1))
            thread.join(10)
        result = state["result"]
        self.assertEqual(result["listener"], {"host": "127.0.0.1", "port": port, "route": "/report",
                                              "loopback_only": True})
        self.assertGreater(port, 0)
        self.assertEqual((result["accepted_requests"], result["rejected_requests"]), (1, 0))
        self.assertEqual(result["stopped_reason"], "deadline")
        self.assertFalse(result["token_required"])
        self.assertEqual(len(result["evidence"]), 1)
        record = self.store.get(result["evidence"][0])
        self.assertEqual(record["kind"], "har_exchange")
        self.assertEqual(record["data"]["source"], "har_import")
        self.assertEqual(record["data"]["request"]["method"], "POST")
        self.assertFalse(record["data"]["redaction"]["replayable"])
        self.assertNotIn("private-response-value", json.dumps(record))

    def test_wrong_route_method_oversize_and_malformed_documents_are_counted(self):
        state, stop, thread = self.listener("--max-body", "512", "--seconds", "30")
        port = state["bound"]["port"]
        self.assertEqual(post(port, {"log": {"entries": []}}, path="/other")[0], 404)
        self.assertEqual(post(port, None, method="GET")[0], 405)
        self.assertEqual(post(port, b'{"pad":"' + b"x" * 2000 + b'"}')[0], 413)
        self.assertEqual(post(port, b"not json")[0], 400)
        self.assertEqual(post(port, {"hello": 1})[0], 400)
        self.assertEqual(post(port, [{"request": {}}])[0], 400)
        accepted = post(port, [har_entry("https://target.example/a")])
        self.assertEqual(accepted[0], 200)
        single = post(port, har_entry("https://target.example/b", "POST", 201))
        self.assertEqual(single[0], 200)
        result = self.finish(state, stop, thread)
        self.assertEqual(result["rejected_reasons"], {"invalid_entry": 1, "malformed_json": 1,
                                                      "oversized_body": 1, "unsupported_document": 1,
                                                      "wrong_method": 1, "wrong_route": 1})
        self.assertEqual((result["accepted_requests"], result["exchanges_stored"]), (2, 2))
        self.assertEqual(result["entries_available"], 2)
        self.assertEqual(result["records_omitted"], 0)
        self.assertEqual(len(result["evidence"]), 2)
        self.assertGreater(result["bytes_read"], 2000)

    def test_token_is_required_for_header_or_bearer_credentials(self):
        state, stop, thread = self.listener("--token", "private-shared-token", "--seconds", "30")
        port = state["bound"]["port"]
        payload = {"log": {"entries": [har_entry("https://target.example/token")]}}
        self.assertEqual(post(port, payload)[0], 401)
        self.assertEqual(post(port, payload, headers={"X-Forge-Token": "wrong"})[0], 401)
        self.assertEqual(post(port, payload, headers={"X-Forge-Token": "private-shared-token"})[0], 200)
        self.assertEqual(post(port, payload, headers={"Authorization": "Bearer private-shared-token"})[0], 200)
        result = self.finish(state, stop, thread)
        self.assertTrue(result["token_required"])
        self.assertEqual(result["rejected_reasons"], {"unauthorized": 2})
        self.assertNotIn("private-shared-token", json.dumps(result))

    def test_record_cap_omits_entries_and_stops_the_listener(self):
        state, stop, thread = self.listener("--max-records", "2", "--seconds", "30")
        port = state["bound"]["port"]
        document = {"log": {"entries": [har_entry(f"https://target.example/{index}") for index in range(5)]}}
        status, response = post(port, document)
        self.assertEqual(status, 200)
        self.assertEqual((response["stored"], response["omitted"]), (2, 3))
        thread.join(10)
        self.assertFalse(thread.is_alive())
        result = state["result"]
        self.assertEqual(result["stopped_reason"], "max_records")
        self.assertEqual((result["exchanges_stored"], result["records_omitted"]), (2, 3))

    def test_missing_content_length_non_loopback_and_bad_options_fail_closed(self):
        state, stop, thread = self.listener("--seconds", "30")
        port = state["bound"]["port"]
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            connection.sendall(b"POST /report HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            response = connection.recv(65536).decode("latin-1")
        self.assertIn("411", response.split("\r\n")[0])
        result = self.finish(state, stop, thread)
        self.assertEqual(result["rejected_reasons"], {"missing_length": 1})
        self.assertEqual(forge_capture._listen_host(), "127.0.0.1")
        with self.assertRaisesRegex(ForgeError, "loopback only"):
            forge_capture._listen_host("0.0.0.0")
        for arguments, message in ((["--seconds", "0"], "--seconds"), (["--port", "70000"], "--port"),
                                   (["--route", "report"], "--route"), (["--token", ""], "--token"),
                                   (["--max-body", "0"], "--max-body"), (["--max-records", "0"], "--max-records")):
            with self.assertRaisesRegex(ForgeError, message):
                self.command("capture-ingest", *arguments)

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def test_deadline_bounds_the_listener_lifetime(self):
        with contextlib.redirect_stderr(io.StringIO()):
            result = self.command("capture-ingest", "--port", "0", "--seconds", "1")
        self.assertEqual(result["stopped_reason"], "deadline")
        self.assertGreaterEqual(result["elapsed_seconds"], 1.0)
        self.assertEqual((result["accepted_requests"], result["rejected_requests"], result["bytes_read"]), (0, 0, 0))
        self.assertEqual(result["evidence"], [])
        self.assertFalse(result["truncated"])
        self.assertIn("not live proof", result["scope"])


class WebSocketAnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_capture.register(self.parser.add_subparsers())

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def save(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")
        return name

    def test_har_session_reports_directions_types_bytes_codes_and_field_names(self):
        first = '{"action":"sub","id":7}'
        second = '{"type":"tick","payload":{"price":"private-price-value"}}'
        har = {"log": {"entries": [
            har_entry("https://plain.example/index.js"),
            {**har_entry("wss://private-user:private-pass@stream.example/socket?token=private-query-value"),
             "_webSocketMessages": [
                 {"type": "send", "time": 1.5, "opcode": 1, "data": first},
                 {"type": "receive", "time": 1.6, "opcode": 1, "data": second},
                 {"type": "receive", "time": 1.7, "opcode": 8, "data": "", "code": 1000},
                 {"type": "receive", "time": 1.8, "opcode": 9, "data": "ping"}]}]}}
        result = self.command("websocket-analyze", self.save("capture.har", har))
        self.assertEqual((result["sources_observed"], result["sources_parsed"]), (1, 1))
        self.assertEqual(result["sources"][0]["format"], "har")
        self.assertEqual(result["sources"][0]["sessions_observed"], 1)
        self.assertEqual(result["frames_observed"], 4)
        session = result["sources"][0]["sessions"][0]
        self.assertEqual(session["url"], "wss://[REDACTED]@stream.example/socket?token=%5BREDACTED%5D")
        self.assertTrue(session["url_redacted"])
        self.assertEqual(session["frames_observed"], 4)
        self.assertEqual(session["directions"], {"request": 1, "response": 3, "unknown": 0})
        self.assertEqual(session["frame_types"], {"close": 1, "ping": 1, "text": 2})
        self.assertEqual(session["close_frames"], 1)
        self.assertEqual(session["close_codes"], [1000])
        total = sum(len(value.encode("utf-8")) for value in (first, second, "", "ping"))
        self.assertEqual(session["payload_bytes"], {"frames_measured": 4, "min": 0,
                                                    "max": max(len(value.encode("utf-8")) for value in (first, second, "", "ping")),
                                                    "total": total, "frames_without_payload": 0})
        shape = session["json_shape"]
        self.assertEqual((shape["json_frames"], shape["unparsed_frames"], shape["empty_frames"]),
                         (2, 1, 1))
        self.assertEqual(shape["root_kinds"], {"object": 2, "array": 0, "scalar": 0})
        self.assertEqual(shape["field_paths"], ["/action", "/id", "/payload", "/payload/price", "/type"])
        serialized = json.dumps(result)
        for secret in ("private-price-value", "private-pass", "private-query-value", "private-user"):
            self.assertNotIn(secret, serialized)

    def test_explicit_frames_documents_and_arrays_leave_direction_unknown(self):
        document = {"url": "wss://stream.example/live", "frames": [
            {"type": "text", "data": '{"a":{"b":1}}'},
            {"opcode": "2", "data": "AQID"},
            {"type": "close", "data": "", "code": 1001},
            {"data": '{"c":true}'},
            "not-an-object"]}
        result = self.command("websocket-analyze", self.save("frames.json", document))
        source = result["sources"][0]
        self.assertEqual(source["format"], "frames")
        session = source["sessions"][0]
        self.assertEqual(session["frames_observed"], 5)
        self.assertEqual(session["frames_parsed"], 4)
        self.assertEqual(session["invalid_frames"], 1)
        self.assertEqual(session["directions"], {"request": 0, "response": 0, "unknown": 4})
        self.assertEqual(session["frame_types"], {"binary": 1, "close": 1, "text": 1, "unknown": 1})
        self.assertEqual(session["close_codes"], [1001])
        self.assertEqual(session["json_shape"]["field_paths"], ["/a", "/a/b", "/c"])
        self.assertEqual(session["json_shape"]["root_kinds"], {"object": 2, "array": 0, "scalar": 0})
        array = [{"url": "wss://one.example/a", "frames": [{"opcode": 1, "data": '{"x":1}'}]},
                 {"url": "wss://two.example/b", "frames": [{"opcode": 1, "data": '{"y":2}'}]}]
        result = self.command("websocket-analyze", self.save("many.json", array))
        self.assertEqual(result["sources"][0]["sessions_observed"], 2)
        self.assertEqual([session["url"] for session in result["sources"][0]["sessions"]],
                         ["wss://one.example/a", "wss://two.example/b"])

    def test_caps_and_byte_limits_report_omissions(self):
        frames = [{"type": "send", "opcode": 1, "data": '{"field%s":%s}' % (index, index)} for index in range(6)]
        first = {"url": "wss://one.example/a", "frames": frames}
        second = {"url": "wss://two.example/b", "frames": frames}
        result = self.command("websocket-analyze", self.save("a.json", [first, second]), self.save("b.json", first),
                              "--max-sources", "1", "--max-sessions", "1", "--max-frames", "3",
                              "--max-fields", "1", "--max-frame-bytes", "8")
        self.assertEqual((result["sources_observed"], result["sources_parsed"], result["sources_omitted"]), (2, 1, 1))
        source = result["sources"][0]
        self.assertEqual((source["sessions_observed"], source["sessions_parsed"], source["sessions_omitted"]), (2, 1, 1))
        session = source["sessions"][0]
        self.assertEqual((session["frames_observed"], session["frames_parsed"], session["frames_omitted"]), (6, 3, 3))
        self.assertEqual(sum(session["frame_types"].values()), 3)
        shape = session["json_shape"]
        self.assertEqual(shape["frames_over_byte_limit"], 3)
        self.assertTrue(shape["field_paths_omitted"])
        self.assertEqual(shape["field_paths"], [])
        self.assertTrue(result["limits"]["max_frames_per_session"] == 3)
        wide = self.command("websocket-analyze", self.save("c.json", first), "--max-fields", "1")
        self.assertEqual(len(wide["sources"][0]["sessions"][0]["json_shape"]["field_paths"]), 1)
        self.assertTrue(wide["sources"][0]["sessions"][0]["json_shape"]["field_paths_omitted"])

    def test_unsupported_sources_are_rejected(self):
        with self.assertRaisesRegex(ForgeError, "WebSocket source"):
            self.command("websocket-analyze", self.save("bad.json", {"hello": 1}))
        with self.assertRaisesRegex(ForgeError, "WebSocket source"):
            self.command("websocket-analyze", self.save("bad.json", [1, 2]))
        with self.assertRaisesRegex(ForgeError, "Cannot read JSON file"):
            self.command("websocket-analyze", "missing.har")
        bare = self.command("websocket-analyze", self.save("bare.json", [
            {**har_entry("wss://bare.example/socket"), "_webSocketFrames": [{"opcode": 2, "data": "AA=="}]}]))
        self.assertEqual(bare["sources"][0]["format"], "har")
        self.assertEqual(bare["sources"][0]["sessions"][0]["frame_types"], {"binary": 1})


class ApiShapeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        commands = self.parser.add_subparsers()
        forge_capture.register(commands)
        forge_network.register(commands)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def save(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")
        return name

    def probe(self, url, method="POST", status=200, request_headers=None, request_body=None,
              response_headers=None, response_body=None):
        return self.store.add("http_probe", {
            "source": "live_probe",
            "request": {"url": url, "method": method, "headers": request_headers or {}, "body": request_body},
            "response": {"status": status, "headers": response_headers or {}, "body": response_body,
                         "truncated": False}})

    def fixtures(self):
        login = self.probe("https://api.example/login?token=private-query-value&q=private-query-plain", "POST", 401,
                           {"Authorization": "Bearer private-header-value", "Content-Type": "application/json"},
                           '{"username":"private-user-value","password":"private-pass-value",'
                           '"note":"private-body-plain"}',
                           {"Set-Cookie": "private-cookie-value", "Content-Type": "application/json"},
                           '{"error":{"code":1,"message":"private-message-value"}}')
        self.probe("https://api.example/login?token=private-query-value&q=private-query-plain", "POST", 200,
                   {"Authorization": "Bearer private-header-value"}, None, {"Content-Type": "application/json"}, "{}")
        form = self.probe("https://form.example/submit?sig=private-signature-value", "POST", 422,
                          {"Content-Type": "application/x-www-form-urlencoded"},
                          "field=private-form-value&otp=1", {"Content-Type": "text/html"}, "<html>")
        self.probe("https://cdn.example/asset/app.js", "GET", 200, None, None, {"Content-Length": "10"}, "body")
        imported = self.command("har-import", self.save("capture.har", {"log": {"entries": [
            har_entry("https://api.example/refresh", "POST", 500, '{"detail":{"reason":"private-reason-value"}}')]}}),
            "--limit", "5")
        return login, form, imported["exchanges"][0]

    def test_summary_reports_names_identities_and_statuses_without_values(self):
        self.fixtures()
        result = self.command("api-shape")
        self.assertEqual(result["selection"], "newest_window")
        self.assertTrue(result["values_withheld"])
        self.assertFalse(result["window_truncated"])
        domains = {domain["domain"]: domain for domain in result["domains"]}
        self.assertEqual(sorted(domains), ["api.example", "cdn.example", "form.example"])
        api = domains["api.example"]
        self.assertEqual(api["observations"], 3)
        self.assertEqual(len(api["evidence_ids"]), 3)
        self.assertEqual(api["method_paths"], [{"method": "POST", "path": "/login", "observations": 2},
                                               {"method": "POST", "path": "/refresh", "observations": 1}])
        self.assertEqual(api["statuses"], {"200": 1, "401": 1, "500": 1})
        self.assertEqual(api["response_status_unobserved"], 0)
        self.assertIn("Authorization", api["request_header_names"])
        self.assertIn("Set-Cookie", api["response_header_names"])
        self.assertEqual(api["request_json_field_paths"], ["/note", "/password", "/username"])
        self.assertEqual(api["response_json_field_paths"],
                         ["/detail", "/detail/reason", "/error", "/error/code", "/error/message"])
        self.assertEqual(api["query_field_names"], ["q", "token"])
        form = domains["form.example"]
        self.assertEqual(sorted(form["request_form_field_names"]), ["field", "otp"])
        self.assertEqual(form["query_field_names"], ["sig"])
        self.assertEqual(form["response_status_unobserved"], 0)
        self.assertNotIn("api.example:443", json.dumps(result))
        serialized = json.dumps(result)
        for secret in ("private-query-value", "private-query-plain", "private-header-value", "private-user-value",
                       "private-pass-value", "private-body-plain", "private-cookie-value", "private-message-value",
                       "private-form-value", "private-signature-value", "private-reason-value"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("/login?token", serialized)

    def test_domain_filter_explicit_ids_and_unknown_ids(self):
        login, _form, imported = self.fixtures()
        filtered = self.command("api-shape", "--domain", "form.example")
        self.assertEqual([domain["domain"] for domain in filtered["domains"]], ["form.example"])
        with_port = self.store.add("http_probe", {
            "source": "live_probe", "request": {"url": "https://api.example:8443/v2/login", "method": "POST",
                                                "headers": {}, "body": None},
            "response": {"status": 201, "headers": {}, "body": None, "truncated": False}})
        explicit = self.command("api-shape", "--evidence", imported["id"])
        self.assertEqual(explicit["selection"], "explicit")
        self.assertEqual(explicit["considered"], 1)
        self.assertEqual(explicit["evidence_ids"], [imported["id"]])
        self.assertEqual(explicit["domains"][0]["domain"], "api.example")
        self.assertEqual([domain["domain"] for domain in self.command("api-shape", "--domain", "api.example:8443")["domains"]],
                         ["api.example"])
        self.assertEqual(self.command("api-shape", "--domain", "api.example:8443")["considered"], 1)
        with self.assertRaisesRegex(ForgeError, "Unknown evidence ID"):
            self.command("api-shape", "--evidence", "ev_missing")
        analysis = self.store.add("analysis", {"tool": "static_index"})
        with self.assertRaisesRegex(ForgeError, "http_probe or har_exchange"):
            self.command("api-shape", "--evidence", analysis["id"])
        with self.assertRaisesRegex(ForgeError, "--domain"):
            self.command("api-shape", "--domain", "https://api.example")
        with self.assertRaisesRegex(ForgeError, "--limit"):
            self.command("api-shape", "--limit", "0")
        self.assertEqual(self.command("api-shape", "--domain", "nothing.example")["domains"], [])
        self.assertEqual(self.command("api-shape", "--limit", "1")["considered"], 1)
        self.assertTrue(self.command("api-shape", "--limit", "1")["window_truncated"])
        self.assertEqual(len(self.store.get(login["id"])["data"]["request"]["headers"]), 2)
        self.assertEqual(len(self.store.get(with_port["id"])["data"]["request"]["headers"]), 0)
        self.assertEqual(self.command("api-shape", "--evidence", login["id"])["domains"][0]["ports"], [])

    def test_caps_are_reported_and_inconsistent_provenance_is_rejected(self):
        records = [self.probe("https://host0.example/one?a=1&b=2", "POST", 200,
                              {"X-Trace": "1"}, '{"alpha":1,"beta":{"gamma":"value"}}', {"X-Reply": "y"}, '{"delta":2}'),
                   self.probe("https://host0.example/two?a=1", "POST", 201, None, {"alpha":1}, None, '{"epsilon":3}'),
                   self.probe("https://host1.example/one", "POST", 202)]
        evidence = []
        for record in records:
            evidence += ["--evidence", record["id"]]
        capped = self.command("api-shape", *evidence, "--max-domains", "1", "--max-paths", "1", "--max-names", "1",
                              "--max-statuses", "1", "--max-ids", "1")
        self.assertTrue(capped["domains_omitted"])
        self.assertEqual(len(capped["domains"]), 1)
        domain = capped["domains"][0]
        self.assertEqual(domain["domain"], "host0.example")
        self.assertEqual(domain["observations"], 2)
        self.assertEqual(len(domain["method_paths"]), 1)
        self.assertEqual(len(domain["evidence_ids"]), 1)
        self.assertEqual(len(domain["query_field_names"]), 1)
        self.assertEqual(len(domain["request_json_field_paths"]), 1)
        self.assertEqual(domain["statuses"], {"200": 1})
        self.assertTrue(domain["paths_omitted"])
        self.assertTrue(domain["names_omitted"])
        self.assertTrue(domain["statuses_omitted"])
        self.assertTrue(domain["ids_omitted"])
        self.assertEqual(domain["unparsed_bodies"], 0)
        self.assertEqual(domain["request_form_field_names"], [])
        self.assertEqual(capped["input_fields_omitted"], False)
        self.store.add("http_probe", {"source": "manual", "request": {"url": "https://host0.example/three",
                        "method": "GET", "headers": {}, "body": None},
                        "response": {"status": 200, "headers": {}, "body": None, "truncated": False}})
        with self.assertRaisesRegex(ForgeError, "inconsistent HTTP provenance"):
            self.command("api-shape")


if __name__ == "__main__":
    unittest.main()
