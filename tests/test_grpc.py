"""grpc-analyze: gRPC-web frame splitting and bounded schema-less protobuf decoding."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_flows

CAPTURES = Path(__file__).resolve().parents[1] / "notes/android-lab-pad-2026-10-15/captures"
GRPC_TYPE = "application/grpc"


def frame(payload, flag=0):
    return bytes([flag]) + len(payload).to_bytes(4, "big") + payload


def grpc_body(*frames):
    return b"".join(frame(payload, flag) for payload, flag in frames)


def flow_state(path="/svc.Method/Call", method="POST", request_body=b"", response_body=b"",
               response_headers=(), response_trailers=(), request_type=GRPC_TYPE, response_type=GRPC_TYPE,
               status=200, websocket=None):
    """One HTTPFlow state dict with gRPC content types, shaped like a mitmproxy dump frame."""
    def pairs(rows):
        return [[name.encode(), value.encode()] for name, value in rows]

    headers = lambda kind, extra: ([("content-type", kind)] if kind else []) + list(extra)
    request = {"method": method.encode(), "scheme": b"https", "authority": b"api.example.test",
               "host": "203.0.113.9", "port": 443, "path": path.encode(), "http_version": b"HTTP/2.0",
               "timestamp_start": 1700000000.5, "timestamp_end": 1700000000.6,
               "headers": pairs(headers(request_type, ())), "content": request_body or None, "trailers": None}
    response = {"status_code": status, "reason": b"OK", "http_version": b"HTTP/2.0",
                "timestamp_start": 1700000000.5, "timestamp_end": 1700000000.6,
                "headers": pairs(headers(response_type, response_headers)), "content": response_body or None,
                "trailers": pairs(response_trailers) or None}
    return {"type": b"http", "version": 21, "websocket": websocket, "request": request, "response": response}


def dump_bytes(states):
    return b"".join(forge_flows.tns_dumps(state) for state in states)


class ProtoTests(unittest.TestCase):
    def decode(self, data, proto=None):
        proto = proto or forge_flows._Proto()
        tree, complete = proto.render(data)
        return tree, complete, proto

    def test_the_shapes_recorded_from_the_lab_capture_decode(self):
        self.assertEqual(self.decode(bytes.fromhex("0a0576692d564e"))[0], '1:"vi-VN"')
        self.assertEqual(self.decode(bytes.fromhex("08061a02564e2002"))[0], '1:6,3:"VN",4:2')

    def test_a_payload_that_stops_parsing_keeps_the_fields_before_the_failure(self):
        tree, complete, _ = self.decode(bytes.fromhex("0808061a02564e2002"))
        self.assertEqual(tree, "1:8,…")
        self.assertFalse(complete)

    def test_every_wire_type_decodes_and_nested_messages_recurse(self):
        payload = (bytes.fromhex("08ac02") + b"\x15" + bytes.fromhex("04030201") + b"\x19"
                   + (0x0102030405060708).to_bytes(8, "little") + b"\x22\x04" + bytes.fromhex("0a026869"))
        self.assertEqual(self.decode(payload)[0], '1:300,2:16909060,3:72623859790382856,4:{1:"hi"}')

    def test_negative_int64_varints_render_as_their_unsigned_value(self):
        self.assertEqual(self.decode(bytes.fromhex("08ffffffffffffffffff01"))[0], "1:18446744073709551615")

    def test_repeated_fields_keep_capture_order(self):
        self.assertEqual(self.decode(bytes.fromhex("0a0566697273740a067365636f6e64"))[0],
                         '1:"first",1:"second"')

    def test_non_utf8_payloads_become_bytes_with_a_digest(self):
        raw = bytes([0xFF, 0xFE, 0xFD])
        tree, _, _ = self.decode(bytes([0x0A, len(raw)]) + raw)
        self.assertEqual(tree, f"1:bytes(len=3 sha256={hashlib.sha256(raw).hexdigest()})")

    def test_values_over_the_character_cap_are_withheld(self):
        secret = "A" * 100
        tree, _, proto = self.decode(bytes([0x0A, 0x64]) + secret.encode())
        self.assertEqual(tree, f"1:str(len=100 sha256={hashlib.sha256(secret.encode()).hexdigest()})")
        self.assertNotIn("AAAA", tree)
        self.assertEqual(proto.withheld_values, 1)

    def test_short_values_are_kept_verbatim(self):
        tree, _, proto = self.decode(bytes([0x0A, 0x40]) + b"B" * 64)
        self.assertEqual(tree, '1:"' + "B" * 64 + '"')
        self.assertEqual(proto.withheld_values, 0)

    def test_depth_cap_reports_payloads_it_did_not_expand(self):
        inner = bytes.fromhex("0a026869")
        for _ in range(9):
            inner = bytes([0x0A, len(inner)]) + inner
        tree, _, proto = self.decode(inner)
        self.assertIn("deeper(len=", tree)
        self.assertTrue(proto.depth_capped >= 1)
        self.assertLessEqual(proto.depth_capped, 5)

    def test_node_cap_bounds_one_flow_and_marks_the_cut(self):
        tree, complete, proto = self.decode(b"\x08\x01" * 300)
        self.assertTrue(tree.endswith("…"))
        self.assertTrue(complete)
        self.assertEqual(proto.nodes, forge_flows.GRPC_NODES_PER_FLOW)
        self.assertEqual(proto.nodes_capped, 1)

    def test_a_failed_nested_parse_does_not_spend_the_node_budget(self):
        proto = forge_flows._Proto()
        before = proto.nodes
        tree, _ = proto.render(bytes([0x0A, 0x04]) + b"\xff\xffhe")
        self.assertIn("bytes(", tree)
        self.assertEqual(proto.nodes, before + 1)


class FrameTests(unittest.TestCase):
    def counters(self):
        return dict.fromkeys(("frames_capped",), 0)

    def test_frames_split_on_the_flag_and_big_endian_length(self):
        body = grpc_body((b"\n\x05vi-VN", 0), (b"grpc-status: 0\r\n", 0x80))
        frames, partial = forge_flows._frames(body, self.counters())
        self.assertFalse(partial)
        self.assertEqual([flag for flag, _ in frames], [0, 0x80])
        self.assertEqual(frames[0][1], b"\n\x05vi-VN")
        self.assertEqual(frames[1][1], b"grpc-status: 0\r\n")

    def test_an_incomplete_trailing_frame_is_reported_as_partial(self):
        body = grpc_body((b"abcdef", 0)) + b"\x00\x00\x00\x00\x09ab"
        frames, partial = forge_flows._frames(body, self.counters())
        self.assertTrue(partial)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0][1], b"abcdef")

    def test_a_trailing_short_header_is_partial(self):
        frames, partial = forge_flows._frames(b"\x00\x00", self.counters())
        self.assertEqual((frames, partial), ([], True))

    def test_the_frame_cap_reports_truncation(self):
        counters = self.counters()
        body = grpc_body(*[(b"x", 0)] * (forge_flows.GRPC_FRAMES_PER_FLOW + 5))
        frames, partial = forge_flows._frames(body, counters)
        self.assertTrue(partial)
        self.assertEqual(len(frames), forge_flows.GRPC_FRAMES_PER_FLOW)
        self.assertEqual(counters["frames_capped"], 1)


class AnalyzeCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_flows.register(self.parser.add_subparsers())

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def analyze(self, *argv):
        args = self.parser.parse_args(["grpc-analyze", *argv])
        return args.handler(args, self.store)

    def write(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return path

    def by_path(self, record, path):
        return next(flow for flow in record["flows_detail"] if flow["path"] == path)

    def test_a_gRPC_flow_reports_trees_trailers_and_counts(self):
        self.write("flows.dump", dump_bytes([
            flow_state(path="/grok_api.Models/ListModes",
                       request_body=frame(bytes.fromhex("0a0576692d564e")),
                       response_body=frame(bytes.fromhex("0a060a04") + b"auto"),
                       response_trailers=[("grpc-status", "0")]),
            flow_state(path="/ws/bot/", request_body=b"", response_body=b"", request_type=None,
                       response_type="text/plain", websocket={"closed": None}),
            flow_state(path="/_data/v1/app_config", method="GET", request_body=b"", response_body=b"{}",
                       request_type="application/json", response_type="application/json"),
        ]))
        record = self.analyze("flows.dump")["data"]
        self.assertEqual(record["schema"], "forge.grpc/v1")
        self.assertEqual(record["action"], "grpc-analyze")
        self.assertEqual(record["reader"], "builtin")
        self.assertEqual(record["frames_read"], 3)
        self.assertEqual(record["flows"], 2)
        self.assertEqual(record["grpc_flows"], 1)
        self.assertEqual(record["skipped_websocket"], 1)
        self.assertEqual(record["skipped_non_grpc"], 1)
        self.assertEqual((record["request_frames"], record["response_frames"]), (1, 1))
        self.assertIs(record["values_withheld"], True)
        grpc = self.by_path(record, "/grok_api.Models/ListModes")
        self.assertEqual(grpc["method"], "POST")
        self.assertEqual(grpc["status"], 200)
        self.assertEqual(grpc["request_fields"], ['1:"vi-VN"'])
        self.assertEqual(grpc["response_fields"], ['1:{1:"auto"}'])
        self.assertEqual(grpc["grpc_status"], 0)
        plain = self.by_path(record, "/_data/v1/app_config")
        self.assertIs(plain["grpc"], False)
        self.assertIsNone(plain["request_fields"])
        self.assertNotIn("grpc_status", plain)

    def test_grpc_web_trailer_frames_supply_the_status_and_a_decoded_message(self):
        self.write("flows.dump", dump_bytes([flow_state(
            response_body=grpc_body((b"\x08\x01", 0), (b"grpc-status: 5\r\ngrpc-message: No%20route%20found\r\n", 0x80)),
            response_trailers=())]))
        record = self.analyze("flows.dump")["data"]
        flow = record["flows_detail"][0]
        self.assertEqual(flow["grpc_status"], 5)
        self.assertEqual(flow["grpc_message"], "No route found")
        self.assertEqual(flow["response_fields"], ["1:1"])
        self.assertEqual(record["trailer_frames"], 1)

    def test_trailers_only_response_headers_supply_the_status(self):
        self.write("flows.dump", dump_bytes([flow_state(
            response_body=b"",
            response_headers=[("grpc-status", "3"), ("grpc-message", "KeyDescription%20not%20in%20allowlist")])]))
        record = self.analyze("flows.dump")["data"]
        flow = record["flows_detail"][0]
        self.assertEqual(flow["grpc_status"], 3)
        self.assertEqual(flow["grpc_message"], "KeyDescription not in allowlist")
        self.assertIsNone(flow["response_fields"])

    def test_compressed_frames_are_reported_but_not_decoded(self):
        self.write("flows.dump", dump_bytes([flow_state(response_body=frame(b"\x1f\x8b\x08\x00", 0x01))]))
        record = self.analyze("flows.dump")["data"]
        self.assertEqual(record["compressed_frames"], 1)
        self.assertTrue(record["flows_detail"][0]["response_fields"][0].startswith("compressed("))

    def test_truncated_frames_mark_the_flow_and_are_not_decoded(self):
        self.write("flows.dump", dump_bytes([flow_state(
            response_body=frame(bytes.fromhex("0801")) + b"\x00\x00\x00\x00\x40short")]))
        record = self.analyze("flows.dump")["data"]
        self.assertEqual(record["flows_with_truncated_frames"], 1)
        flow = record["flows_detail"][0]
        self.assertIs(flow["response_frames_truncated"], True)
        self.assertEqual(flow["response_frames"], 1)

    def test_limit_omits_flows_and_reports_the_omission(self):
        self.write("flows.dump", dump_bytes([flow_state(path=f"/svc/Call{i}", request_body=frame(b"\x08\x01"),
                                                        response_body=frame(b"\x08\x02")) for i in range(4)]))
        record = self.analyze("flows.dump", "--limit", "2")["data"]
        self.assertEqual(record["flows"], 2)
        self.assertEqual(record["flows_omitted"], 2)
        self.assertEqual(record["request_frames"], 2)
        for flags in (("--limit", "0"), ("--limit", "100001")):
            with self.assertRaisesRegex(ForgeError, "must be between"):
                self.analyze("flows.dump", *flags)

    def test_a_dump_that_is_not_tnetstring_names_the_fallback_reader(self):
        self.write("broken.dump", b"definitely not a flow dump")
        with self.assertRaisesRegex(ForgeError, "--reader mitmproxy"):
            self.analyze("broken.dump")
        with self.assertRaisesRegex(ForgeError, "does not exist"):
            self.analyze("missing.dump")

    def test_withheld_values_never_reach_the_record(self):
        secret = "captured-secret-" + "z" * 80
        self.write("flows.dump", dump_bytes([flow_state(request_body=frame(bytes([0x0A, len(secret)]) + secret.encode()),
                                                        response_body=frame(b"\x08\x01"))]))
        record = self.analyze("flows.dump")
        serialized = json.dumps(record, ensure_ascii=False)
        self.assertNotIn("zzzzzzzz", serialized)
        self.assertTrue(record["data"]["withheld_values"] >= 1)


@unittest.skipUnless((CAPTURES / "flows-grok.dump").is_file(), "lab captures are not part of the package")
class RealDumpGrpcTests(unittest.TestCase):
    """The lab capture is a read-only fixture: it must decode to the recorded gRPC shapes."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_flows.register(self.parser.add_subparsers())
        captures = self.root / "captures"
        captures.mkdir()
        (captures / "flows-grok.dump").write_bytes((CAPTURES / "flows-grok.dump").read_bytes())

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def test_real_flows_decode_with_caps_honoured(self):
        args = self.parser.parse_args(["grpc-analyze", "captures/flows-grok.dump"])
        record = args.handler(args, self.store)["data"]
        self.assertEqual((record["frames_read"], record["frames_skipped"]), (10, 0))
        self.assertEqual(record["flows"], 9)
        self.assertEqual(record["grpc_flows"], 4)
        self.assertEqual(record["skipped_websocket"], 1)
        self.assertEqual(record["skipped_non_grpc"], 5)
        self.assertIs(record["values_withheld"], True)
        self.assertTrue(record["withheld_values"] >= 1)
        self.assertTrue(record["nodes_capped"] >= 1)  # the price list exceeds 200 nodes
        flows = {flow["path"]: flow for flow in record["flows_detail"]}
        self.assertEqual(flows["/grok_api.Models/ListModes"]["request_fields"], ['1:"vi-VN"'])
        self.assertEqual(flows["/commerce.prepurchase.v1.PrePurchaseService/MultiGetSkuPricings"]["request_fields"],
                         ["1:6,3:\"VN\",4:2"])
        attestation = flows["/grok_api.AttestationService/RegisterAttestation"]
        self.assertEqual(attestation["grpc_status"], 3)
        self.assertIn("not in package allowlist", attestation["grpc_message"])
        self.assertIs(flows["/_data/v1/app_config"]["grpc"], False)
        self.assertTrue(all(flow["grpc_status"] == 0 for path, flow in flows.items()
                            if flow["grpc"] and path != "/grok_api.AttestationService/RegisterAttestation"))
        trees = [tree for flow in record["flows_detail"]
                 for tree in (flow["request_fields"] or []) + (flow["response_fields"] or [])]
        self.assertTrue(any("str(len=" in tree for tree in trees))  # long captured strings are withheld
        self.assertTrue(all(len(tree) < 20000 for tree in trees))


if __name__ == "__main__":
    unittest.main()
