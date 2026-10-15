"""HAR assembly from decrypted flow data, and the mitmproxy reader boundary."""

import argparse
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_flows


class FakeHeaders(dict):
    def items(self):
        return super().items()


def fake_request(method="POST", url="https://grok.com/example.Service/Method", headers=None, body=b'{"a":1}',
                 query=None, timestamp=1700000000.5):
    return types.SimpleNamespace(method=method, pretty_url=url, headers=FakeHeaders(headers or {"content-type": "application/json"}),
                                content=body, query=query or {}, timestamp_start=timestamp)


def fake_response(status=200, headers=None, body=b'{"ok":true}'):
    return types.SimpleNamespace(status_code=status, reason="OK",
                                 headers=FakeHeaders(headers or {"content-type": "application/json"}), content=body)


class HarAssemblyTests(unittest.TestCase):
    def test_entry_carries_method_url_headers_and_bounded_bodies(self):
        entry = forge_flows._entry(fake_request(), fake_response(), 1024)
        self.assertEqual(entry["request"]["method"], "POST")
        self.assertEqual(entry["request"]["url"], "https://grok.com/example.Service/Method")
        self.assertEqual(entry["response"]["status"], 200)
        self.assertEqual(entry["request"]["postData"]["mimeType"], "application/json")
        self.assertEqual(entry["response"]["content"]["text"], '{"ok":true}')
        self.assertFalse(entry["response"]["_forge_body_truncated"])
        names = {header["name"] for header in entry["request"]["headers"]}
        self.assertEqual(names, {"content-type"})

    def test_body_cap_truncates_and_flags(self):
        entry = forge_flows._entry(fake_request(body=b"x" * 100), fake_response(body=b"y" * 100), 10)
        self.assertEqual(len(entry["request"]["postData"]["text"]), 10)
        self.assertEqual(entry["response"]["content"]["size"], 10)
        self.assertTrue(entry["response"]["_forge_body_truncated"])

    def test_missing_response_stays_an_observed_request(self):
        entry = forge_flows._entry(fake_request(), None, 1024)
        self.assertEqual(entry["response"]["status"], 0)
        self.assertEqual(entry["response"]["content"]["text"], "")

    def test_byte_header_values_are_decoded_without_crashing(self):
        entry = forge_flows._entry(fake_request(headers={b"x-bytes": b"value"}), fake_response(headers={}), 64)
        self.assertEqual(entry["request"]["headers"], [{"name": "x-bytes", "value": "value"}])


class FlowCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_flows.register(self.parser.add_subparsers())

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def run_command(self, *argv):
        args = self.parser.parse_args(["flow-to-har", *argv])
        return args.handler(args, self.store)

    def write(self, name, content):
        path = self.root / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def test_paths_and_bounds_are_validated_before_reading(self):
        self.write("dump.bin", b"not a flow dump")
        with self.assertRaisesRegex(ForgeError, "does not exist"):
            self.run_command("missing.bin", "--output", "out.har")
        with self.assertRaisesRegex(ForgeError, "project-local"):
            self.run_command(str(self.root.parent / "elsewhere.bin"), "--output", "out.har")
        with self.assertRaisesRegex(ForgeError, "new .har file"):
            self.run_command("dump.bin", "--output", "out.json")
        self.write("existing.har", "{}")
        with self.assertRaisesRegex(ForgeError, "already exists"):
            self.run_command("dump.bin", "--output", "existing.har")
        for flags in (("--limit", "0"), ("--limit", "100001"), ("--max-body-bytes", "0")):
            with self.assertRaisesRegex(ForgeError, "must be between"):
                self.run_command("dump.bin", "--output", "out.har", *flags)

    def test_unreadable_dump_reports_the_optional_dependency_or_the_format(self):
        self.write("broken.dump", b"\x00\x01 definitely not mitmproxy flows")
        try:
            import mitmproxy  # noqa: F401
        except ImportError:
            with self.assertRaisesRegex(ForgeError, "mitmproxy is required"):
                self.run_command("broken.dump", "--output", "out.har")
            return
        with self.assertRaisesRegex(ForgeError, "Flow dump could not be read"):
            self.run_command("broken.dump", "--output", "out.har")

    def test_junk_dump_never_publishes_a_har(self):
        self.write("junk.dump", b"junk")
        try:
            self.run_command("junk.dump", "--output", "out.har")
        except ForgeError:
            self.assertFalse((self.root / "out.har").exists())


if __name__ == "__main__":
    unittest.main()
