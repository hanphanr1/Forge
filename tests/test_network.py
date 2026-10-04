import argparse
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_network


class LiveHttpBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.received = []
        received = self.received

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                received.append(self.path)
                if self.path == "/opaque":
                    body, encoding = b"echo:fixture-private-value", None
                else:
                    body = gzip.compress(b'{"message":"INVALID_PASSWORD","plan":null}')
                    encoding = "gzip" if self.path == "/gzip" else "unsupported"
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if encoding:
                    self.send_header("Content-Encoding", encoding)
                self.end_headers()
                self.wfile.write(body)

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
        (self.root / name).write_text(json.dumps(data), encoding="utf-8")
        return name

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def test_gzip_http_error_classifies_decoded_body(self):
        request = self.save("request.json", {"url": self.base + "/gzip",
                            "rules": [{"bucket": "FAIL", "json_path": "$.message", "equals": "INVALID_PASSWORD"}]})
        record = self.command("probe", request)
        self.assertEqual(record["data"]["bucket"], "FAIL")
        self.assertEqual(record["data"]["response"]["status"], 403)
        self.assertEqual(record["data"]["response"]["body"]["message"], "INVALID_PASSWORD")

    def test_unsupported_encoding_is_recorded_error_not_false_fail(self):
        request = self.save("request.json", {"url": self.base + "/unsupported"})
        with self.assertRaisesRegex(ForgeError, "cannot decode Content-Encoding"):
            self.command("probe", request)
        record = self.store.list("http_probe", 1)[0]
        self.assertEqual(record["data"]["bucket"], "UNKNOWN")
        self.assertIsNone(record["data"]["response"]["status"])
        self.assertEqual(self.received, ["/unsupported"])

    def test_invalid_later_rule_sends_no_earlier_request(self):
        flow = self.save("flow.json", [{"url": self.base + "/gzip"},
                        {"url": self.base + "/gzip", "rules": [{"bucket": "FAIL", "status": 403}]}])
        with self.assertRaisesRegex(ForgeError, "body predicate|exactly one"):
            self.command("probe-run", flow)
        self.assertEqual(self.received, [])

    def test_opaque_echo_of_request_credential_is_not_persisted(self):
        request = self.save("request.json", {"url": self.base + "/opaque",
                            "headers": {"Authorization": "Bearer fixture-private-value"}})
        record = self.command("probe", request)
        self.assertEqual(record["data"]["response"]["body"], "echo:[REDACTED]")
        self.assertNotIn("fixture-private-value", json.dumps(record))


if __name__ == "__main__":
    unittest.main()
