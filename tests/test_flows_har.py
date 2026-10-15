"""HAR assembly, the builtin tnetstring dump reader, and the mitmproxy fallback reader."""

import argparse
import base64
import builtins
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_flows

CAPTURES = Path(__file__).resolve().parents[1] / "notes/android-lab-pad-2026-10-15/captures"
PROTO_REQUEST = b"\x00\x00\x00\x00\x08\x08\x06\x1a\x04\xff\xfeVN"  # gRPC-web frame, protobuf payload, not UTF-8
PROTO_RESPONSE = b"\x00\x00\x00\x00\x06\x1f\x8b\x08\x00\xff\xfe"  # gRPC-web frame with bytes that are not UTF-8


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


def flow_state(method="POST", path="/v1/method", host="203.0.113.9", port=443, scheme="https",
               authority="api.example.test", request_body=b"", request_headers=(), response_status=200,
               response_body=b"", response_headers=(), response_trailers=(), websocket=None,
               http_version=b"HTTP/2.0", timestamp=1700000000.5):
    """One HTTPFlow state dict shaped like the frames mitmproxy writes."""
    def pairs(rows):
        return [[name.encode("utf-8") if isinstance(name, str) else name,
                 value.encode("utf-8") if isinstance(value, str) else value] for name, value in rows]

    request = {"method": method.encode(), "scheme": scheme.encode(), "authority": authority.encode(),
               "host": host, "port": port, "path": path.encode(), "http_version": http_version,
               "timestamp_start": timestamp, "timestamp_end": timestamp, "headers": pairs(request_headers),
               "content": request_body or None, "trailers": None}
    response = {"status_code": response_status, "reason": b"OK", "http_version": http_version,
                "timestamp_start": timestamp, "timestamp_end": timestamp,
                "headers": pairs(response_headers), "content": response_body or None,
                "trailers": pairs(response_trailers) or None}
    return {"type": b"http", "version": 21, "websocket": websocket, "request": request, "response": response}


def dump_bytes(states):
    return b"".join(forge_flows.tns_dumps(state) for state in states)


def read_dump(data):
    """Read a dump the way the commands do; return (flow views, reader counters)."""
    temporary = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
    with temporary:
        temporary.write(data)
    path = Path(temporary.name)
    try:
        views = []
        with path.open("rb") as stream:
            reader = forge_flows._DumpReader(stream)
            for frame in reader.frames():
                view = forge_flows._flow_view(frame)
                if view is not None:
                    views.append(view)
        return views, {"frames_read": reader.frames_read, "frames_skipped": reader.frames_skipped,
                       "parse_error": reader.parse_error}
    finally:
        path.unlink(missing_ok=True)


class TnetstringTests(unittest.TestCase):
    def test_scalars_use_the_documented_tags(self):
        self.assertEqual(forge_flows.tns_dumps(12345), b"5:12345#")
        self.assertEqual(forge_flows.tns_dumps(True), b"4:true!")
        self.assertEqual(forge_flows.tns_dumps(False), b"5:false!")
        self.assertEqual(forge_flows.tns_dumps(None), b"0:~")
        self.assertEqual(forge_flows.tns_dumps(b"abc"), b"3:abc,")
        self.assertEqual(forge_flows.tns_dumps("abc"), b"3:abc;")
        self.assertEqual(forge_flows.tns_dumps(1.5), b"3:1.5^")

    def test_nested_containers_bytes_and_negative_numbers_round_trip(self):
        value = {"a": [1, -2, {"b": b"\x00\xff", "c": -1.25}], "d": None, "e": True, "f": "Tự động"}
        encoded = forge_flows.tns_dumps(value)
        self.assertEqual(forge_flows.tns_loads(encoded), value)
        self.assertEqual(forge_flows.tns_loads(encoded)["a"][2]["b"], b"\x00\xff")
        self.assertEqual(forge_flows.tns_loads(encoded)["a"][1], -2)
        self.assertEqual(forge_flows.tns_loads(encoded)["a"][2]["c"], -1.25)

    def test_negative_ints_and_floats_survive_the_round_trip(self):
        self.assertEqual(forge_flows.tns_dumps(-9007199254740993), b"17:-9007199254740993#")
        self.assertEqual(forge_flows.tns_loads(forge_flows.tns_dumps(-0.5)), -0.5)

    def test_malformed_frames_are_rejected(self):
        for data in (b"", b"3:ab", b"5:12#", b"3:123x", b"2:12#extra", b"abc", b"1:a@"):
            with self.subTest(data=data), self.assertRaises(forge_flows.TnetstringError):
                forge_flows.tns_loads(data)

    def test_reader_stops_at_the_first_bad_frame_and_keeps_earlier_frames(self):
        views, stats = read_dump(dump_bytes([flow_state()] * 3) + b"99:short#")
        self.assertEqual(len(views), 3)
        self.assertEqual(stats["frames_read"], 3)
        self.assertEqual(stats["frames_skipped"], 1)
        self.assertTrue(stats["parse_error"])

    def test_reader_reports_a_frame_that_exceeds_the_frame_cap(self):
        views, stats = read_dump(b"%d:" % (forge_flows.MAX_FRAME_BYTES + 1) + b"xxxx")
        self.assertEqual(views, [])
        self.assertEqual((stats["frames_read"], stats["frames_skipped"]), (0, 1))
        self.assertIn("frame cap", stats["parse_error"])


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

    def test_binary_bodies_become_base64_with_an_encoding_flag(self):
        entry = forge_flows._entry(fake_request(body=b"\x00\x01\xfe"), fake_response(body=b"\x1f\x8b\x08"), 1024)
        self.assertEqual(entry["response"]["content"]["encoding"], "base64")
        self.assertEqual(entry["request"]["postData"]["encoding"], "base64")
        self.assertEqual(base64.b64decode(entry["response"]["content"]["text"]), b"\x1f\x8b\x08")
        self.assertEqual(base64.b64decode(entry["request"]["postData"]["text"]), b"\x00\x01\xfe")
        self.assertEqual(entry["response"]["content"]["size"], 3)

    def test_text_bodies_are_not_base64_and_keep_their_length(self):
        entry = forge_flows._entry(fake_request(body=b'{"a":1}'), fake_response(body="Tự động".encode()), 1024)
        self.assertNotIn("encoding", entry["response"]["content"])
        self.assertEqual(entry["response"]["content"]["text"], "Tự động")


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

    def synthetic(self, count=10):
        """`count` flows alternating json and binary gRPC bodies, the last one a websocket."""
        states = []
        for index in range(count):
            binary = index % 2 == 0
            states.append(flow_state(
                path=f"/v1/item/{index}?page={index}", method="POST" if binary else "GET",
                request_body=PROTO_REQUEST if binary else b"",
                response_body=PROTO_RESPONSE if binary else b'{"ok":true}',
                response_headers=[("content-type", "application/grpc" if binary else "application/json")],
                websocket={"closed": None} if index == count - 1 else None))
        return dump_bytes(states)

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

    def test_a_dump_that_is_not_tnetstring_names_the_fallback_reader(self):
        self.write("broken.dump", b"\x00\x01 definitely not a flow dump")
        with self.assertRaisesRegex(ForgeError, "--reader mitmproxy"):
            self.run_command("broken.dump", "--output", "out.har")
        self.assertFalse((self.root / "out.har").exists())

    def test_builtin_reader_parses_a_synthetic_dump_with_binary_bodies(self):
        self.write("flows.dump", self.synthetic())
        record = self.run_command("flows.dump", "--output", "out.har")["data"]
        self.assertEqual(record["reader"], "builtin")
        self.assertEqual((record["frames_read"], record["frames_skipped"]), (10, 0))
        self.assertIsNone(record["parse_error"])
        self.assertEqual(record["flows"], 10)
        self.assertEqual(record["bodies_encoded"], 10)  # five binary request/response pairs
        document = json.loads((self.root / "out.har").read_text(encoding="utf-8"))
        self.assertEqual(document["log"]["version"], "1.2")
        entries = document["log"]["entries"]
        self.assertEqual(len(entries), 10)
        self.assertEqual(entries[2]["request"]["url"], "https://api.example.test/v1/item/2?page=2")
        self.assertEqual(entries[2]["request"]["queryString"], [{"name": "page", "value": "2"}])
        self.assertEqual(entries[2]["request"]["method"], "POST")
        self.assertEqual(entries[1]["request"]["method"], "GET")
        self.assertEqual(entries[1]["response"]["status"], 200)
        encoded_request = entries[2]["request"]["postData"]
        self.assertEqual(encoded_request["encoding"], "base64")
        self.assertEqual(base64.b64decode(encoded_request["text"]), PROTO_REQUEST)
        self.assertEqual(base64.b64decode(entries[2]["response"]["content"]["text"]), PROTO_RESPONSE)
        self.assertEqual(entries[2]["response"]["content"]["encoding"], "base64")
        self.assertNotIn("encoding", entries[1]["response"]["content"])
        self.assertEqual(entries[1]["response"]["content"]["text"], '{"ok":true}')

    def test_a_websocket_upgrade_still_reaches_the_har(self):
        self.write("flows.dump", dump_bytes([flow_state(response_status=101,
                                                       response_headers=[("upgrade", "websocket")],
                                                       websocket={"closed": None})]))
        record = self.run_command("flows.dump", "--output", "out.har")["data"]
        entries = json.loads((self.root / "out.har").read_text(encoding="utf-8"))["log"]["entries"]
        self.assertEqual(record["flows"], 1)
        self.assertEqual(entries[0]["response"]["status"], 101)

    def test_trailing_garbage_keeps_the_flows_before_it(self):
        self.write("flows.dump", self.synthetic(4) + b"\x7f\x7f not a frame")
        record = self.run_command("flows.dump", "--output", "out.har")["data"]
        self.assertEqual(record["frames_read"], 4)
        self.assertEqual(record["frames_skipped"], 1)
        self.assertTrue(record["parse_error"])
        self.assertEqual(record["flows"], 4)
        self.assertEqual(len(json.loads((self.root / "out.har").read_text(encoding="utf-8"))["log"]["entries"]), 4)

    def test_a_truncated_final_frame_still_converts_the_earlier_flows(self):
        self.write("flows.dump", self.synthetic(3)[:-4])
        record = self.run_command("flows.dump", "--output", "out.har")["data"]
        self.assertEqual((record["frames_read"], record["frames_skipped"]), (2, 1))

    def test_an_empty_dump_is_not_an_error(self):
        self.write("flows.dump", b"")
        record = self.run_command("flows.dump", "--output", "out.har")["data"]
        self.assertEqual((record["frames_read"], record["flows"]), (0, 0))
        self.assertTrue((self.root / "out.har").is_file())

    def test_limit_and_body_cap_are_reported(self):
        self.write("flows.dump", self.synthetic(6))
        record = self.run_command("flows.dump", "--output", "out.har", "--limit", "2",
                                  "--max-body-bytes", "4")["data"]
        self.assertEqual(record["flows"], 2)
        self.assertEqual(record["flows_skipped"], 4)
        self.assertEqual(record["limit"], 2)
        self.assertTrue(record["bodies_truncated"] >= 1)
        entries = json.loads((self.root / "out.har").read_text(encoding="utf-8"))["log"]["entries"]
        self.assertTrue(any(entry["response"]["_forge_body_truncated"] for entry in entries))

    def test_mitmproxy_reader_reports_the_missing_optional_dependency(self):
        self.write("flows.dump", self.synthetic(2))
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "mitmproxy" or name.startswith("mitmproxy."):
                raise ImportError("mitmproxy is not installed")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", blocked):
            with self.assertRaisesRegex(ForgeError, "mitmproxy"):
                self.run_command("flows.dump", "--output", "out.har", "--reader", "mitmproxy")
        self.assertFalse((self.root / "out.har").exists())

    def test_junk_dump_never_publishes_a_har(self):
        self.write("junk.dump", b"junk")
        with self.assertRaises(ForgeError):
            self.run_command("junk.dump", "--output", "out.har")
        self.assertFalse((self.root / "out.har").exists())


@unittest.skipUnless((CAPTURES / "flows-grok.dump").is_file(), "lab captures are not part of the package")
class RealDumpParityTests(unittest.TestCase):
    """The builtin reader must agree with mitmproxy on the dumps captured on the lab Pad."""

    CASES = (("flows-grok.dump", 10), ("flows-control.dump", 7))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_flows.register(self.parser.add_subparsers())

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def test_builtin_counts_match_mitmproxy_and_the_recorded_totals(self):
        try:
            from mitmproxy.io import FlowReader
        except ImportError:
            self.skipTest("mitmproxy is not installed; counts were recorded by the capture session")
        for name, expected in self.CASES:
            path = CAPTURES / name
            if not path.is_file():
                self.skipTest(f"{name} is not present")
            with self.subTest(dump=name):
                views = []
                with path.open("rb") as stream:
                    reader = forge_flows._DumpReader(stream)
                    for frame in reader.frames():
                        view = forge_flows._flow_view(frame)
                        if view is not None:
                            views.append(view)
                with path.open("rb") as stream:
                    theirs = list(FlowReader(stream).stream())
                self.assertEqual(reader.frames_read, expected)
                self.assertEqual(reader.frames_skipped, 0)
                self.assertEqual(len(theirs), expected)
                self.assertEqual(len(views), expected)
                self.assertEqual([view.request.pretty_url for view in views],
                                 [flow.request.pretty_url for flow in theirs])
                self.assertEqual([view.response.status_code if view.response else 0 for view in views],
                                 [flow.response.status_code if flow.response else 0 for flow in theirs])

    def test_both_readers_convert_the_real_dump_identically(self):
        try:
            import mitmproxy  # noqa: F401
        except ImportError:
            self.skipTest("mitmproxy is not installed")
        source = self.root / "captures"
        source.mkdir()
        (source / "flows-grok.dump").write_bytes((CAPTURES / "flows-grok.dump").read_bytes())
        documents = {}
        for reader in ("builtin", "mitmproxy"):
            output = f"{reader}.har"
            args = self.parser.parse_args(["flow-to-har", "captures/flows-grok.dump", "--output", output,
                                           "--reader", reader])
            record = args.handler(args, self.store)["data"]
            self.assertEqual(record["frames_read"], 10)
            self.assertEqual(record["bodies_encoded"], 3)
            documents[reader] = json.loads((self.root / output).read_text(encoding="utf-8"))
        self.assertEqual(documents["builtin"], documents["mitmproxy"])


if __name__ == "__main__":
    unittest.main()
