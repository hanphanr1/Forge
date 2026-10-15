import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_pcap
import forge_protocol


# ---------------------------------------------------------------- builders

def ipv4(source, destination, protocol, body, *, identification=0, fragment=0):
    header = bytearray(b"\x45\x00")
    header += (20 + len(body)).to_bytes(2, "big")
    header += identification.to_bytes(2, "big")
    header += fragment.to_bytes(2, "big")
    header += bytes([0x40, protocol, 0, 0])
    header += socket.inet_aton(source)
    header += socket.inet_aton(destination)
    return bytes(header) + body


def ipv6(source, destination, next_header, body, *, extension=b""):
    header = bytearray((6 << 28).to_bytes(4, "big"))
    header += len(extension + body).to_bytes(2, "big")
    header += bytes([next_header, 64])
    header += socket.inet_pton(socket.AF_INET6, source)
    header += socket.inet_pton(socket.AF_INET6, destination)
    return bytes(header) + extension + body


def extension_header(next_header, length_units, payload=b""):
    """Option-style IPv6 extension header: (length_units + 1) * 8 bytes."""
    size = (length_units + 1) * 8
    return bytes([next_header, length_units]) + b"\x00" * (size - 2)


def tcp(source_port, destination_port, payload=b"", *, flags=0x18, header_bytes=20, seq=1):
    header = bytearray()
    header += source_port.to_bytes(2, "big")
    header += destination_port.to_bytes(2, "big")
    header += seq.to_bytes(4, "big")
    header += (0).to_bytes(4, "big")
    header += bytes([(header_bytes // 4) << 4, flags])
    header += (8192).to_bytes(2, "big")
    header += (0).to_bytes(2, "big")
    header += (0).to_bytes(2, "big")
    if header_bytes > 20:
        header += b"\x00" * (header_bytes - 20)
    return bytes(header) + payload


def udp(source_port, destination_port, payload=b""):
    return (source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big") +
            (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload)


def frame(payload, *, ethertype=0x0800, vlan=0):
    header = bytearray(b"\x00" * 12)
    if vlan:
        header += (0x8100).to_bytes(2, "big") + (vlan & 0x0FFF).to_bytes(2, "big")
    header += ethertype.to_bytes(2, "big")
    return bytes(header) + payload


def with_trailer(ip_packet, uid, package, *, vlan=0):
    """PCAPdroid layout: fake Ethernet, packet, 0..3 zero padding, 32-byte trailer."""
    ethertype = 0x0800 if ip_packet[0] >> 4 == 4 else 0x86DD
    ethered = frame(ip_packet, ethertype=ethertype, vlan=vlan)
    vlan_bytes = len(ethered) - 14 - len(ip_packet)
    padding = (-(len(ethered) - vlan_bytes)) % 4
    body = ethered + b"\x00" * padding
    trailer = (b"\x01\x07\x20\x21" + struct.pack(">i", uid) +
               package.encode("ascii")[:19].ljust(20, b"\x00"))
    record = body + trailer
    return record + (zlib.crc32(record) & 0xFFFFFFFF).to_bytes(4, "little")


def pcap_record(payload, *, seconds=1700000000, fraction=0, incl=None, orig=None, byte_order="little"):
    incl = len(payload) if incl is None else incl
    orig = incl if orig is None else orig
    return (seconds.to_bytes(4, byte_order) + fraction.to_bytes(4, byte_order) +
            incl.to_bytes(4, byte_order) + orig.to_bytes(4, byte_order) + payload)


def pcap(records, *, byte_order="little", link_type=1, snaplen=2048, nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    header = (magic.to_bytes(4, byte_order) + (2).to_bytes(2, byte_order) + (4).to_bytes(2, byte_order) +
              (0).to_bytes(4, byte_order) + (0).to_bytes(4, byte_order) + snaplen.to_bytes(4, byte_order) +
              link_type.to_bytes(4, byte_order))
    return header + b"".join(records)


def dns_labels(name):
    out = bytearray()
    for part in name.split("."):
        if part:
            out.append(len(part))
            out += part.encode("ascii")
    out.append(0)
    return bytes(out)


def dns_query(name, qtype=1, *, identification=0x1234):
    question = dns_labels(name) + qtype.to_bytes(2, "big") + b"\x00\x01"
    return (identification.to_bytes(2, "big") + b"\x01\x00" + (1).to_bytes(2, "big") +
            b"\x00\x00\x00\x00\x00\x00" + question)


def dns_response_cname(alias, qname="example.com"):
    question = dns_labels(qname) + b"\x00\x01\x00\x01"
    data = dns_labels(alias)
    answer = (b"\xc0\x0c" + (5).to_bytes(2, "big") + (1).to_bytes(2, "big") + (60).to_bytes(4, "big") +
              len(data).to_bytes(2, "big") + data)
    return (b"\x12\x34" + b"\x81\x80" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") +
            b"\x00\x00\x00\x00" + question + answer)


def dns_pointer_loop():
    return (b"\x12\x34" + b"\x01\x00" + (1).to_bytes(2, "big") + b"\x00\x00\x00\x00\x00\x00" +
            b"\xc0\x0c" + b"\x00\x01\x00\x01")


def client_hello(name=None, *, ech=False, compression=b"\x01\x00", extensions=b""):
    block = bytearray()
    if name is not None:
        encoded = name.encode("ascii")
        server_name = (3 + len(encoded)).to_bytes(2, "big") + b"\x00" + len(encoded).to_bytes(2, "big") + encoded
        block += (0).to_bytes(2, "big") + len(server_name).to_bytes(2, "big") + server_name
    if ech:
        block += (0xFE0D).to_bytes(2, "big") + (1).to_bytes(2, "big") + b"\x00"
    block += extensions
    body = bytearray(b"\x03\x03")
    body += b"\x11" * 32
    body += b"\x00"
    ciphers = b"\x13\x01\x13\x02\xc0\x2f"
    body += len(ciphers).to_bytes(2, "big") + ciphers
    body += compression
    body += len(block).to_bytes(2, "big") + block
    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def http_request(host="api.example.com", *, method="POST", target="/private/path?token=secret", body=b"password=hunter2"):
    return (method.encode("ascii") + b" " + target.encode("ascii") + b" HTTP/1.1\r\nHost: " +
            host.encode("ascii") + b"\r\nUser-Agent: forge\r\nContent-Length: " +
            str(len(body)).encode("ascii") + b"\r\n\r\n" + body)


# ---------------------------------------------------------------- tests

class PcapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_pcap.register(self.parser.add_subparsers())
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(self.store.close)

    def write(self, name, content):
        path = self.root / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def analyze(self, name="capture.pcap", *extra):
        args = self.parser.parse_args(["pcap-analyze", name, *extra])
        return args.handler(args, self.store)["data"]

    def dns_packet(self, name, *, source="10.0.0.5", server="8.8.8.8", payload=None, seconds=1700000000):
        message = dns_query(name) if payload is None else payload
        return pcap_record(frame(ipv4(source, server, 17, udp(40000, 53, message))), seconds=seconds)

    def http_packet(self, payload, *, source_port=51000, server="93.184.216.34", seconds=1700000000):
        """One plaintext HTTP request in its own direction flow, so every line is probed."""
        return pcap_record(frame(ipv4("10.0.0.5", server, 6, tcp(source_port, 80, payload, flags=0x18))),
                           seconds=seconds)

    def analysis_record(self, name="capture.pcap", *extra):
        args = self.parser.parse_args(["pcap-analyze", name, *extra])
        return args.handler(args, self.store)

    def protocol_map(self, record):
        return forge_protocol.protocol_map(argparse.Namespace(evidence=[record["id"]], limit=100,
                                                             max_endpoints=200), self.store)

    # ------------------------------------------------------------ framing

    def test_byte_order_and_timestamp_resolution_are_reported(self):
        payload = frame(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("example.com"))))
        for byte_order in ("little", "big"):
            self.write("capture.pcap", pcap([pcap_record(payload, fraction=250000, byte_order=byte_order)],
                                            byte_order=byte_order))
            data = self.analyze()
            self.assertEqual(data["format"]["byte_order"], byte_order)
            self.assertEqual(data["format"]["timestamp_resolution"], "microsecond")
            self.assertAlmostEqual(data["first_timestamp"], 1700000000.25, places=4)
        self.write("capture.pcap", pcap([pcap_record(payload, fraction=250500000)], nano=True))
        data = self.analyze()
        self.assertEqual(data["format"]["timestamp_resolution"], "nanosecond")
        self.assertAlmostEqual(data["first_timestamp"], 1700000000.2505, places=4)

    def test_big_endian_capture_decodes_ports_and_uid(self):
        packet = with_trailer(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, client_hello("big.example.com"))),
                              10234, "ai.x.grok")
        self.write("capture.pcap", pcap([pcap_record(packet, byte_order="big")], byte_order="big"))
        data = self.analyze()
        flow = data["flows"][0]
        self.assertEqual((flow["source_port"], flow["destination_port"]), (51000, 443))
        self.assertEqual(flow["uid"], 10234)
        self.assertEqual(data["format"]["byte_order"], "big")
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["big.example.com"])

    def test_pcapng_unknown_magic_and_modified_variant_are_rejected(self):
        self.write("capture.pcap", b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
        with self.assertRaisesRegex(ForgeError, "PCAPNG is not supported"):
            self.analyze()
        self.write("capture.pcap", b"GIF89a" + b"\x00" * 40)
        with self.assertRaisesRegex(ForgeError, "Not a classic PCAP"):
            self.analyze()
        modified = (0xA1B2CD34).to_bytes(4, "little") + b"\x00" * 40
        self.write("capture.pcap", modified)
        with self.assertRaisesRegex(ForgeError, "Modified PCAP"):
            self.analyze()
        self.write("capture.pcap", b"\xd4\xc3\xb2\xa1")
        with self.assertRaisesRegex(ForgeError, "shorter than the 24-byte"):
            self.analyze()
        self.write("capture.pcap", b"")
        with self.assertRaisesRegex(ForgeError, "0 bytes, shorter than the 24-byte"):
            self.analyze()

    def test_partial_record_framing_is_rejected(self):
        good = pcap_record(frame(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("example.com")))))
        self.write("capture.pcap", pcap([good]) + good[:9])
        with self.assertRaisesRegex(ForgeError, "partial record header"):
            self.analyze()
        self.write("capture.pcap", pcap([good[:-3]]))
        with self.assertRaisesRegex(ForgeError, "ends inside a packet record"):
            self.analyze()

    def test_declared_capture_truncation_is_a_fact_not_a_framing_error(self):
        full = ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, client_hello("cut.example.com")))
        record = pcap_record(frame(full[:30]), incl=len(frame(full[:30])), orig=len(frame(full)))
        self.write("capture.pcap", pcap([record]))
        data = self.analyze()
        self.assertEqual(data["captured_packet_truncations"], 1)
        self.assertEqual(data["truncated_dissections"], 1)
        self.assertEqual(data["malformed_packets"], 0)
        self.assertEqual(data["hosts"], [])

    def test_inconsistent_record_lengths_are_counted_malformed(self):
        payload = frame(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("example.com"))))
        self.write("capture.pcap", pcap([pcap_record(payload, incl=len(payload), orig=len(payload) - 4)]))
        data = self.analyze()
        self.assertEqual(data["malformed_packets"], 1)
        self.assertEqual(data["hosts"], [])

    def test_empty_and_header_only_captures_are_explicitly_empty(self):
        self.write("capture.pcap", pcap([]))
        data = self.analyze()
        self.assertTrue(data["success"])
        self.assertTrue(data["empty"])
        self.assertEqual(data["packets_scanned"], 0)
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["flows"], [])
        self.assertFalse(data["truncated"])
        self.assertIsNone(data["first_timestamp"])
        self.assertIsNone(data["duration_seconds"])

    # ------------------------------------------------------------ dissection

    def test_flows_report_endpoints_counts_and_timestamps(self):
        packets = [pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, b"abc", flags=0x02)),
                              ),
                               seconds=1700000000, fraction=0),
                   pcap_record(frame(ipv4("93.184.216.34", "10.0.0.5", 6, tcp(443, 51000, b"defgh", flags=0x10))),
                               seconds=1700000002, fraction=500000)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual(data["packets_scanned"], 2)
        self.assertEqual(len(data["flows"]), 2)
        outbound = [flow for flow in data["flows"] if flow["source_port"] == 51000][0]
        self.assertEqual((outbound["source_ip"], outbound["destination_ip"]), ("10.0.0.5", "93.184.216.34"))
        self.assertEqual(outbound["payload_bytes"], 3)
        self.assertEqual(outbound["packets"], 1)
        self.assertAlmostEqual(outbound["first_timestamp"], 1700000000.0, places=4)
        self.assertAlmostEqual(data["last_timestamp"], 1700000002.5, places=4)
        self.assertAlmostEqual(data["duration_seconds"], 2.5, places=4)
        self.assertEqual(data["tcp_packets"], 2)

    def test_udp_ipv6_and_extension_header_walk(self):
        packet = frame(ipv6("2001:db8::5", "2001:4860:4860::8888", 0,
                            udp(40000, 53, dns_query("v6.example.com")),
                            extension=extension_header(17, 0)), ethertype=0x86DD)
        self.write("capture.pcap", pcap([pcap_record(packet)]))
        data = self.analyze()
        self.assertEqual(data["ipv6_packets"], 1)
        hostnames = [entry["hostname"] for entry in data["hosts"]]
        self.assertEqual(hostnames, ["v6.example.com"])
        self.assertEqual(data["flows"][0]["source_ip"], "2001:db8::5")

    def test_ipv6_fragments_are_not_dissected(self):
        packet = frame(ipv6("2001:db8::5", "2001:4860:4860::8888", 44,
                            b"\x06\x00\x00\x00" + b"\x00" * 4 + tcp(51000, 443, b"payload")), ethertype=0x86DD)
        self.write("capture.pcap", pcap([pcap_record(packet)]))
        data = self.analyze()
        self.assertEqual(data["fragmented_packets"], 1)
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["flows"], [])

    def test_ipv4_fragments_are_counted_and_never_reassembled(self):
        first = pcap_record(frame(ipv4("10.0.0.5", "8.8.8.8", 6, tcp(51000, 443, b"abc"), fragment=0x2000)))
        second = pcap_record(frame(ipv4("10.0.0.5", "8.8.8.8", 6, b"\x00" * 8, fragment=1)))
        self.write("capture.pcap", pcap([first, second]))
        data = self.analyze()
        self.assertEqual(data["fragmented_packets"], 2)
        self.assertEqual(data["flows"], [])
        self.assertEqual(data["unsupported_packets"], 0)

    def test_raw_ip_link_types_are_supported(self):
        packet = ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("raw.example.com")))
        for link_type in (101, 12):
            self.write("capture.pcap", pcap([pcap_record(packet)], link_type=link_type))
            data = self.analyze()
            self.assertEqual(data["format"]["link_types"], [link_type])
            self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["raw.example.com"])

    def test_unknown_link_type_and_non_ip_frames_are_reported(self):
        self.write("capture.pcap", pcap([pcap_record(b"\xff" * 40)], link_type=147))
        data = self.analyze()
        self.assertEqual(data["unsupported_link_types"], [147])
        self.assertEqual(data["unsupported_packets"], 1)
        self.assertEqual(data["hosts"], [])

        arp = frame(b"\x00" * 28, ethertype=0x0806)
        self.write("capture.pcap", pcap([pcap_record(arp)]))
        data = self.analyze()
        self.assertEqual(data["unsupported_ethertypes"], [0x0806])
        self.assertEqual(data["unsupported_packets"], 1)

    def test_icmp_and_unknown_ip_protocols_are_listed(self):
        packets = [pcap_record(frame(ipv4("10.0.0.5", "8.8.8.8", 1, b"\x08\x00" + b"\x00" * 6))),
                   pcap_record(frame(ipv4("10.0.0.5", "8.8.8.8", 58, b"")))]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual(data["unsupported_ip_protocols"], [1, 58])
        self.assertEqual(data["unsupported_packets"], 2)
        self.assertEqual(data["flows"], [])

    def test_vlan_tags_are_bounded(self):
        inner = ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("vlan.example.com")))
        self.write("capture.pcap", pcap([pcap_record(frame(inner, vlan=42))]))
        data = self.analyze()
        self.assertEqual(data["vlan_packets"], 1)
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["vlan.example.com"])

        stacked = bytearray(b"\x00" * 12)
        for _ in range(5):
            stacked += (0x8100).to_bytes(2, "big") + (7).to_bytes(2, "big")
        stacked += (0x0800).to_bytes(2, "big")
        self.write("capture.pcap", pcap([pcap_record(bytes(stacked) + inner)]))
        data = self.analyze()
        self.assertEqual(data["unsupported_packets"], 1)
        self.assertEqual(data["hosts"], [])

    def test_pcapdroid_ethernet_header_fallback_when_trailer_did_not_fit(self):
        packet = ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("fallback.example.com")))
        self.write("capture.pcap", pcap([pcap_record(packet)]))
        data = self.analyze()
        self.assertEqual(data["linktype_fallbacks"], 1)
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["fallback.example.com"])

    # ------------------------------------------------------------ names

    def test_dns_queries_and_answer_names_are_normalized(self):
        packets = [self.dns_packet("Example.COM."),
                   pcap_record(frame(ipv4("8.8.8.8", "10.0.0.5", 17, udp(53, 40000, dns_response_cname("Alias.Example.Com")) )),
                               seconds=1700000001)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        hostnames = sorted(entry["hostname"] for entry in data["hosts"])
        self.assertEqual(hostnames, ["alias.example.com", "example.com"])
        kinds = {entry["hostname"]: [observation["kind"] for observation in entry["observations"]]
                 for entry in data["hosts"]}
        self.assertEqual(kinds["example.com"], ["dns_query"])
        self.assertEqual(kinds["alias.example.com"], ["dns_answer"])
        self.assertEqual(data["dns_messages"], 2)
        self.assertEqual(data["dns_questions"], 1)
        self.assertEqual(data["dns_answers"], 1)
        query = [entry for entry in data["hosts"] if entry["hostname"] == "example.com"][0]
        observation = query["observations"][0]
        self.assertEqual((observation["source_port"], observation["destination_port"]), (40000, 53))
        self.assertEqual((observation["source_ip"], observation["destination_ip"]), ("10.0.0.5", "8.8.8.8"))
        self.assertEqual(observation["timestamp"], 1700000000.0)
        self.assertEqual(observation["packet_index"], 0)
        answer = [entry for entry in data["hosts"] if entry["hostname"] == "alias.example.com"][0]
        self.assertEqual((answer["observations"][0]["source_ip"], answer["observations"][0]["destination_ip"]),
                         ("8.8.8.8", "10.0.0.5"))

    def test_dns_compression_pointer_loop_is_bounded_and_reported(self):
        self.write("capture.pcap", pcap([self.dns_packet("ignored", payload=dns_pointer_loop())]))
        data = self.analyze()
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["dns_messages_truncated"], 1)
        self.assertEqual(data["dns_messages"], 1)

    def test_invalid_dns_and_host_names_are_skipped(self):
        packets = [self.dns_packet("bad name.example"),
                   self.dns_packet("-leading.example", seconds=1700000001),
                   self.dns_packet("has$dollar.example", seconds=1700000002),
                   self.dns_packet("ok.example", seconds=1700000003)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["ok.example"])
        self.assertEqual(data["invalid_hostnames"], 3)
        self.assertEqual(data["dns_messages_truncated"], 0)
        self.assertEqual(data["dns_messages"], 4)

    def test_tls_sni_is_reassembled_across_segments(self):
        hello = client_hello("segmented.example.com")
        first = tcp(51000, 443, hello[:4], flags=0x18)
        second = tcp(51000, 443, hello[4:], flags=0x18, seq=5)
        packets = [pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6, first))),
                   pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6, second)), seconds=1700000001)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["segmented.example.com"])
        observation = data["hosts"][0]["observations"][0]
        self.assertEqual(observation["kind"], "tls_sni")
        self.assertFalse(observation["ech"])
        self.assertEqual(data["tls_client_hellos"], 1)
        self.assertEqual(data["flows"][0]["tls_sni"], "segmented.example.com")
        self.assertEqual(data["flows"][0]["app_layer_hint"], "tls_record")

    def test_tls_retransmission_is_not_appended_twice(self):
        hello = client_hello("retransmitted.example.com")
        prefix = frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, hello[:4], seq=1)))
        suffix = frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, hello[4:], seq=5)))
        self.write("capture.pcap", pcap([pcap_record(prefix), pcap_record(prefix), pcap_record(suffix)]))
        data = self.analyze()
        self.assertEqual([host["hostname"] for host in data["hosts"]], ["retransmitted.example.com"])
        self.assertEqual(data["tls_client_hellos"], 1)
        self.assertEqual(data["tcp_reassembly_gaps"], 0)

    def test_missing_tcp_bytes_do_not_produce_a_sni_claim(self):
        hello = client_hello("gapped.example.com")
        prefix = frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, hello[:4], seq=1)))
        suffix = frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, hello[4:], seq=8)))
        self.write("capture.pcap", pcap([pcap_record(prefix), pcap_record(suffix)]))
        data = self.analyze()
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["tcp_reassembly_gaps"], 1)
        self.assertTrue(data["truncated"])

    def test_short_client_hello_is_reported_as_unsupported(self):
        handshake = b"\x01" + (34).to_bytes(3, "big") + b"\x00" * 34
        record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
        payload = frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, record)))
        self.write("capture.pcap", pcap([pcap_record(payload)]))
        data = self.analyze()
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["tls_probe_unsupported"], 1)

    def test_tls_sni_reassembly_cap_reports_truncation_instead_of_a_name(self):
        # A ClientHello larger than the per-flow reassembly buffer is refused, not guessed.
        padding = (21).to_bytes(2, "big") + (12000).to_bytes(2, "big") + b"\x00" * 12000
        hello = client_hello("late.example.com", extensions=padding)
        self.assertGreater(len(hello), forge_pcap.PROBE_BUFFER)
        packets = [pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6,
                                          tcp(51000, 443, hello[index:index + 2000], seq=1 + index))), seconds=1700000000 + index)
                   for index in range(0, len(hello), 2000)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["tls_sni_truncated"], 1)
        self.assertEqual(data["tls_client_hellos"], 0)
        self.assertTrue(data["flows"][0]["probe_truncated"])

    def test_tls_client_hello_without_sni_and_with_ech(self):
        packets = [pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, client_hello(None))))),
                   pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6,
                                          tcp(51001, 443, client_hello("public.example.com", ech=True)))),
                               seconds=1700000001)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual(data["tls_client_hellos"], 2)
        self.assertEqual(data["tls_client_hellos_without_sni"], 1)
        self.assertEqual(data["tls_client_hellos_with_ech"], 1)
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["public.example.com"])
        self.assertTrue(data["hosts"][0]["observations"][0]["ech"])

    def test_plaintext_http_host_is_extracted_only_from_the_head(self):
        packets = [self.http_packet(http_request("plain.example.com"))]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["plain.example.com"])
        self.assertEqual(data["hosts"][0]["observations"][0]["kind"], "http_host")
        self.assertEqual(data["http_requests"], 1)
        self.assertEqual(data["http_hosts"], 1)
        self.assertEqual(data["http_request_lines"], 1)
        self.assertEqual(data["hosts"][0]["http_methods"], ["POST"])
        self.assertEqual(data["hosts"][0]["http_paths"], ["/private/path"])
        dumped = json.dumps(data)
        # The request line's method and origin-form path are reported; its query value, its other
        # headers and its body are never read, so none of them may appear.
        for leaked in ("token=secret", "hunter2", "Content-Length", "User-Agent", "HTTP/1.1"):
            self.assertNotIn(leaked, dumped)

    def test_request_line_query_values_and_bodies_never_reach_the_output(self):
        packets = [self.http_packet(http_request("query.example.com", method="POST",
                                                 target="/api/v1/items?token=private-query-value&mode=owned")),
                   self.http_packet(http_request("query.example.com", method="GET",
                                                 target="/api/v1/items/7?view=private-view-value"),
                                    source_port=51001, seconds=1700000001)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        self.assertEqual(data["hosts"][0]["hostname"], "query.example.com")
        self.assertEqual(data["hosts"][0]["http_methods"], ["POST", "GET"])
        self.assertEqual(data["hosts"][0]["http_paths"], ["/api/v1/items", "/api/v1/items/7"])
        self.assertEqual(data["http_request_lines"], 2)
        self.assertFalse(data["hosts"][0]["http_methods_omitted"])
        self.assertFalse(data["hosts"][0]["http_paths_omitted"])
        dumped = json.dumps(data)
        for leaked in ("private-query-value", "private-view-value", "token=", "view="):
            self.assertNotIn(leaked, dumped)

    def test_request_line_caps_report_omitted_methods_and_paths(self):
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "PURGE", "MKCOL"]
        self.assertGreater(len(methods), forge_pcap.HTTP_VALUES_PER_HOST)
        packets = [self.http_packet(http_request("capped.example.com", method=method, target=f"/item/{index}"),
                                    source_port=51000 + index, seconds=1700000000 + index)
                   for index, method in enumerate(methods)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        entry = data["hosts"][0]
        self.assertEqual(entry["http_methods"], methods[:forge_pcap.HTTP_VALUES_PER_HOST])
        self.assertEqual(entry["http_paths"], [f"/item/{index}" for index in range(forge_pcap.HTTP_VALUES_PER_HOST)])
        self.assertTrue(entry["http_methods_omitted"])
        self.assertTrue(entry["http_paths_omitted"])
        self.assertEqual(data["http_request_lines"], len(methods))
        self.assertEqual(data["limits"]["http_values_per_host"], forge_pcap.HTTP_VALUES_PER_HOST)
        self.assertTrue(data["truncated"])

    def test_request_line_metadata_requires_a_host_and_an_origin_form_target(self):
        packets = [self.http_packet(b"OPTIONS * HTTP/1.1\r\nHost: star.example.com\r\n\r\n"),
                   self.http_packet(b"GET http://absolute.example.com/x HTTP/1.1\r\nHost: abs.example.com\r\n\r\n",
                                    source_port=51001, seconds=1700000001),
                   self.http_packet(b"GET /origin/form HTTP/1.1\r\nHost: dot.example.com\r\n\r\n",
                                    source_port=51002, seconds=1700000002)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        hosts = {entry["hostname"]: entry for entry in data["hosts"]}
        self.assertEqual(sorted(hosts), ["abs.example.com", "dot.example.com", "star.example.com"])
        # Asterisk and absolute forms have no origin-form path: no method and no path are claimed.
        for name in ("abs.example.com", "star.example.com"):
            self.assertNotIn("http_methods", hosts[name])
            self.assertNotIn("http_paths", hosts[name])
        self.assertEqual(hosts["dot.example.com"]["http_methods"], ["GET"])
        self.assertEqual(hosts["dot.example.com"]["http_paths"], ["/origin/form"])
        self.assertEqual(data["http_requests"], 3)
        self.assertEqual(data["http_request_lines"], 1)
        self.assertNotIn("absolute.example.com/x", json.dumps(data))

    def test_http_head_without_host_header_yields_no_name(self):
        request = b"GET /private HTTP/1.0\r\nUser-Agent: forge\r\n\r\n"
        self.write("capture.pcap", pcap([pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6,
                                                                  tcp(51000, 80, request))))]))
        data = self.analyze()
        self.assertEqual(data["http_requests"], 1)
        self.assertEqual(data["http_hosts"], 0)
        self.assertEqual(data["http_request_lines"], 1)
        self.assertEqual(data["hosts"], [])
        self.assertNotIn("/private", json.dumps(data))

    def test_incomplete_tls_stream_is_reported_as_unresolved(self):
        hello = client_hello("never.example.com")
        packet = pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, hello[:4]))))
        self.write("capture.pcap", pcap([packet]))
        data = self.analyze()
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["tls_client_hellos"], 0)
        self.assertEqual(data["unresolved_probe_streams"], 1)

    def test_http_head_beyond_the_scan_window_reports_truncation(self):
        filler = b"X-Pad: " + b"a" * 200 + b"\r\n"
        request = b"GET /private HTTP/1.1\r\n" + filler * 25
        self.assertGreater(len(request), forge_pcap.HTTP_SCAN_BYTES)
        self.write("capture.pcap", pcap([pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6,
                                                                  tcp(51000, 80, request))))]))
        data = self.analyze()
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["http_probes_truncated"], 1)
        self.assertEqual(data["http_requests"], 0)
        self.assertTrue(data["flows"][0]["probe_truncated"])
        self.assertNotIn("/private", json.dumps(data))

    def test_quic_like_and_binary_payloads_yield_no_names(self):
        quic = b"\xc3\x00\x00\x00\x01\x08" + b"\x00" * 1100
        packets = [pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 17, udp(51000, 443, quic)))),
                   pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51001, 443, b"\x00\x01\x02\x03"))),
                               seconds=1700000001),
                   pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6,
                                          tcp(51002, 853, client_hello("dot.example.com")))), seconds=1700000002)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze()
        # DNS-over-TLS port does still carry a ClientHello; only its SNI is reported, nothing is decrypted.
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["dot.example.com"])
        self.assertFalse(data["decryption_performed"])
        self.assertEqual(data["dns_messages"], 0)

    def test_dns_over_tcp_length_prefix(self):
        message = dns_query("tcp.example.com")
        payload = len(message).to_bytes(2, "big") + message
        self.write("capture.pcap", pcap([pcap_record(frame(ipv4("10.0.0.5", "8.8.8.8", 6, tcp(40000, 53, payload))))]))
        data = self.analyze()
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["tcp.example.com"])

    def test_dns_over_tcp_split_message_is_reported_as_truncated(self):
        message = dns_query("split.example.com")
        payload = (len(message) + 4).to_bytes(2, "big") + message
        self.write("capture.pcap", pcap([pcap_record(frame(ipv4("10.0.0.5", "8.8.8.8", 6, tcp(40000, 53, payload))))]))
        data = self.analyze()
        self.assertEqual(data["hosts"], [])
        self.assertEqual(data["dns_messages_truncated"], 1)

    # ------------------------------------------------------------ trailer claims

    def test_pcapdroid_trailer_uid_and_hint_are_reported_as_claims(self):
        packet = with_trailer(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, client_hello("trailer.example.com"))),
                              10123, "ai.x.grok")
        self.write("capture.pcap", pcap([pcap_record(packet)]))
        data = self.analyze()
        self.assertEqual(data["trailer"]["packets"], 1)
        self.assertEqual(data["trailer"]["uid_values"], [10123])
        self.assertEqual(data["trailer"]["package_hints"], ["ai.x.grok"])
        self.assertFalse(data["trailer"]["package_hint_truncation_possible"])
        observation = data["hosts"][0]["observations"][0]
        self.assertEqual(observation["uid"], 10123)
        self.assertEqual(observation["package_hint"], "ai.x.grok")
        self.assertFalse(observation["package_hint_truncated"])
        self.assertEqual(data["flows"][0]["uid"], 10123)

    def test_long_package_hint_is_flagged_as_possibly_truncated(self):
        packet = with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("hint.example.com"))),
                              11000, "com.example.application.long")
        self.write("capture.pcap", pcap([pcap_record(packet)]))
        data = self.analyze()
        self.assertEqual(data["trailer"]["package_hints"], ["com.example.application"[:19]])
        self.assertTrue(data["trailer"]["package_hint_truncation_possible"])
        observation = data["hosts"][0]["observations"][0]
        self.assertEqual(observation["package_hint"], "com.example.application"[:19])
        self.assertTrue(observation["package_hint_truncated"])

    def test_unknown_uid_and_invalid_hint_are_not_resolved(self):
        packet = with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("unknown.example.com"))), -1, "")
        self.write("capture.pcap", pcap([pcap_record(packet)]))
        data = self.analyze()
        self.assertEqual(data["trailer"]["uid_unknown_packets"], 1)
        self.assertEqual(data["trailer"]["uid_values"], [])
        self.assertEqual(data["trailer"]["package_hints"], [])
        observation = data["hosts"][0]["observations"][0]
        self.assertIsNone(observation["uid"])
        self.assertIsNone(observation["package_hint"])

    def test_trailer_checksum_mismatch_is_not_treated_as_metadata(self):
        packet = with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("fcs.example.com"))),
                              10123, "ai.x.grok")
        corrupted = bytearray(packet)
        corrupted[-1] ^= 0xFF
        self.write("capture.pcap", pcap([pcap_record(bytes(corrupted))]))
        data = self.analyze()
        self.assertEqual(data["trailer"]["packets"], 0)
        self.assertEqual(data["trailer"]["checksum_mismatches"], 1)
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["fcs.example.com"])
        self.assertIsNone(data["hosts"][0]["observations"][0]["uid"])

    def test_trailer_inside_truncated_record_is_ignored(self):
        packet = with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("short.example.com"))),
                              10123, "ai.x.grok")
        record = pcap_record(packet[:20], incl=20, orig=len(packet))
        self.write("capture.pcap", pcap([record]))
        data = self.analyze()
        self.assertEqual(data["captured_packet_truncations"], 1)
        self.assertEqual(data["trailer"]["packets"], 0)

    # ------------------------------------------------------------ caps

    def test_byte_cap_stops_dissection_but_hashes_the_whole_file(self):
        records = [self.dns_packet(f"cap{index}.example", seconds=1700000000 + index) for index in range(4)]
        content = pcap(records)
        self.write("capture.pcap", content)
        data = self.analyze("capture.pcap", "--max-bytes", "60")
        self.assertEqual(data["scan_stopped"], "max_bytes")
        self.assertTrue(data["truncated"])
        self.assertEqual(data["packets_scanned"], 1)
        self.assertEqual(data["input"]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(data["input"]["size"], len(content))
        self.assertEqual(data["limits"]["max_bytes"], 60)

    def test_packet_cap_reports_the_reason(self):
        records = [self.dns_packet(f"packet{index}.example", seconds=1700000000 + index) for index in range(3)]
        self.write("capture.pcap", pcap(records))
        data = self.analyze("capture.pcap", "--max-packets", "2")
        self.assertEqual(data["scan_stopped"], "max_packets")
        self.assertEqual(data["packets_scanned"], 2)
        self.assertTrue(data["truncated"])

    def test_host_and_observation_caps_are_counted(self):
        hostnames = [f"host{index}.example" for index in range(3)]
        records = [self.dns_packet(name, seconds=1700000000 + index) for index, name in enumerate(hostnames)]
        records += [self.dns_packet("host0.example", seconds=1700000100 + index) for index in range(9)]
        self.write("capture.pcap", pcap(records))
        data = self.analyze("capture.pcap", "--max-hosts", "2")
        self.assertEqual(len(data["hosts"]), 2)
        self.assertEqual(data["hosts_omitted"], 1)
        self.assertTrue(data["truncated"])
        kept = [entry for entry in data["hosts"] if entry["hostname"] == "host0.example"][0]
        self.assertEqual(len(kept["observations"]), forge_pcap.OBSERVATIONS_PER_HOST)
        self.assertEqual(kept["observation_count"], 10)
        self.assertEqual(kept["observations_omitted"], 2)
        self.assertEqual(data["observations_omitted"], 2)

    def test_flow_cap_is_counted_without_losing_packet_counts(self):
        packets = [pcap_record(frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000 + index, 443, b"x"))))
                   for index in range(3)]
        self.write("capture.pcap", pcap(packets))
        data = self.analyze("capture.pcap", "--max-flows", "1")
        self.assertEqual(len(data["flows"]), 1)
        self.assertEqual(data["flows_omitted"], 2)
        self.assertEqual(data["packets_unrecorded"], 2)
        self.assertTrue(data["truncated"])

    def test_oversized_record_lengths_are_skipped_not_allocated(self):
        payload = frame(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("oversize.example.com"))))
        record = pcap_record(payload)
        size = forge_pcap.MAX_RECORD_BYTES + 1
        bogus = pcap_record(b"\x00" * size, incl=size, orig=size)
        self.write("capture.pcap", pcap([bogus, record]))
        data = self.analyze()
        self.assertEqual(data["records_skipped_oversized"], 1)
        self.assertEqual(data["unsupported_packets"], 1)
        self.assertEqual([entry["hostname"] for entry in data["hosts"]], ["oversize.example.com"])
        self.assertEqual(data["packets_scanned"], 2)

    def test_absurd_record_length_is_refused_without_allocating_it(self):
        huge = pcap_record(b"", incl=0xFFFFFFF0, orig=0xFFFFFFF0)
        self.write("capture.pcap", pcap([huge]))
        with self.assertRaisesRegex(ForgeError, "ends inside a packet record"):
            self.analyze()

    def test_analysis_cap_arguments_are_validated(self):
        self.write("capture.pcap", pcap([]))
        for argv in (["--max-bytes", "0"], ["--max-packets", "-1"], ["--max-hosts", "999999999"],
                     ["--max-flows", "0"]):
            args = self.parser.parse_args(["pcap-analyze", "capture.pcap", *argv])
            with self.assertRaisesRegex(ForgeError, "must be an integer from"):
                args.handler(args, self.store)
        with self.assertRaisesRegex(ForgeError, "max_bytes must be an integer"):
            forge_pcap.analyze_file(self.root / "capture.pcap", max_bytes=0)

    def test_input_paths_are_validated_before_reading(self):
        self.write("capture.pcap", pcap([]))
        for unsafe in ("\\\\server\\share\\capture.pcap", "capture.pcap:stream"):
            with self.assertRaisesRegex(ForgeError, "UNC|alternate data stream"):
                self.analyze(unsafe)
        with self.assertRaisesRegex(ForgeError, "regular file"):
            self.analyze(".")

    # ------------------------------------------------------------ provenance

    def capture_evidence(self, name="capture.pcap", *, kind="runtime", tool="pcapdroid", action="capture",
                         success=True, package="ai.x.grok", target_uid=10123, stored_path=None, **extra):
        blob = (self.root / name).read_bytes()
        data = {"schema": "forge.pcapdroid/v1", "tool": tool, "action": action, "success": success,
                "package": package, "target_uid": target_uid,
                "capture": {"path": stored_path or name, "sha256": hashlib.sha256(blob).hexdigest(),
                            "size": len(blob)}}
        data.update(extra)
        return self.store.add(kind, data)

    def map_evidence(self, candidates, *, index_content=None, tool="android", action="api-map", success=True):
        content = index_content or '{"text":"https://api.example.com"}\n'
        index_file = self.write("index.jsonl", content)
        index_record = self.store.add("analysis", {
            "tool": "static_index", "path": index_file.name,
            "index_sha256": hashlib.sha256(index_file.read_bytes()).hexdigest(),
            "index_size": index_file.stat().st_size, "records": 1})
        return self.store.add("analysis", {
            "schema": "forge.android-api-map/v1", "tool": tool, "action": action, "success": success,
            "index_evidence_id": index_record["id"], "index_sha256": index_record["data"]["index_sha256"],
            "api_candidates": candidates}), index_file

    def candidate(self, url, *, sha256=None):
        return {"url": url, "url_sha256": sha256 or hashlib.sha256(url.encode("utf-8")).hexdigest(),
                "category": "static_candidate"}

    def test_capture_citation_requires_a_matching_runtime_record(self):
        records = [self.dns_packet("cited.example.com"), self.dns_packet("other.example.com", seconds=1700000001)]
        self.write("capture.pcap", pcap(records))
        capture = self.capture_evidence(target_uid=10123, stored_path=str(self.root / "capture.pcap"))
        data = self.analyze("capture.pcap", "--capture-evidence", capture["id"])
        self.assertEqual(data["evidence_ids"], [capture["id"]])
        citation = data["capture"]
        self.assertTrue(citation["sha256_matches"] and citation["size_matches"] and citation["path_matches"])
        self.assertEqual(citation["path"], str(self.root / "capture.pcap"))
        self.assertEqual(citation["target_uid"], 10123)
        self.assertFalse(citation["capture_truncated"])
        attribution = data["uid_attribution"]
        self.assertEqual(attribution["target_uid"], 10123)
        self.assertEqual(attribution["observations"], {"target": 0, "other": 0, "unknown": 2})
        self.assertEqual(attribution["flow_packets"], {"target": 0, "other": 0, "unknown": 2})

    def test_capture_citation_splits_target_other_and_unknown_traffic(self):
        packets = [pcap_record(with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17,
                                                 udp(40000, 53, dns_query("target.example.com"))), 10123, "ai.x.grok")),
                   pcap_record(with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17,
                                                 udp(40001, 53, dns_query("other.example.com"))), 1000, "com.other"),
                               seconds=1700000001)]
        self.write("capture.pcap", pcap(packets))
        capture = self.capture_evidence(target_uid=10123)
        data = self.analyze("capture.pcap", "--capture-evidence", capture["id"])
        attribution = data["uid_attribution"]
        self.assertEqual(attribution["observations"], {"target": 1, "other": 1, "unknown": 0})
        self.assertEqual(attribution["flow_packets"], {"target": 1, "other": 1, "unknown": 0})

    def test_packet_attribution_does_not_inherit_a_later_flow_uid(self):
        payloads = [
            frame(ipv4("10.0.0.5", "8.8.8.8", 17, udp(40000, 53, dns_query("unknown.example.com")))),
            with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17,
                              udp(40000, 53, dns_query("target.example.com"))), 10123, "ai.x.grok"),
            with_trailer(ipv4("10.0.0.5", "8.8.8.8", 17,
                              udp(40000, 53, dns_query("other.example.com"))), 1000, "com.other"),
        ]
        self.write("capture.pcap", pcap([pcap_record(payload) for payload in payloads]))
        capture = self.capture_evidence(target_uid=10123)
        data = self.analyze("capture.pcap", "--capture-evidence", capture["id"])
        self.assertEqual(data["uid_attribution"]["flow_packets"], {"target": 1, "other": 1, "unknown": 1})
        self.assertEqual(data["uid_attribution"]["observations"], {"target": 1, "other": 1, "unknown": 1})

    def test_capture_citation_reports_a_capture_size_overrun(self):
        self.write("capture.pcap", pcap([self.dns_packet("overrun.example.com")]))
        capture = self.capture_evidence(max_dump_size_reached=True, empty=False)
        data = self.analyze("capture.pcap", "--capture-evidence", capture["id"])
        self.assertTrue(data["capture"]["capture_truncated"])
        self.assertEqual(data["capture"]["capture_truncation_flags"], ["max_dump_size_reached"])
        self.assertIs(data["capture"]["capture_empty"], False)
        self.assertTrue(data["truncated"])

    def test_capture_citation_rejects_failures_and_changed_bytes(self):
        self.write("capture.pcap", pcap([self.dns_packet("changed.example.com")]))
        capture = self.capture_evidence()
        failed = self.capture_evidence(name="capture.pcap", success=False)
        with self.assertRaisesRegex(ForgeError, "not a successful capture"):
            self.analyze("capture.pcap", "--capture-evidence", failed["id"])
        wrong_kind = self.capture_evidence(kind="analysis", tool="adb")
        with self.assertRaisesRegex(ForgeError, "must cite a runtime pcapdroid capture record"):
            self.analyze("capture.pcap", "--capture-evidence", wrong_kind["id"])
        self.write("capture.pcap", pcap([self.dns_packet("rewritten.example.com")]))
        with self.assertRaisesRegex(ForgeError, "SHA256 differs"):
            self.analyze("capture.pcap", "--capture-evidence", capture["id"])

    def test_capture_citation_rejects_a_different_path(self):
        content = pcap([self.dns_packet("same.example.com")])
        self.write("capture.pcap", content)
        self.write("copy.pcap", content)
        capture = self.capture_evidence(name="copy.pcap")
        with self.assertRaisesRegex(ForgeError, "not the file recorded by"):
            self.analyze("capture.pcap", "--capture-evidence", capture["id"])

    def test_capture_citation_without_uid_omits_attribution(self):
        self.write("capture.pcap", pcap([self.dns_packet("nouid.example.com")]))
        capture = self.capture_evidence(target_uid=None)
        data = self.analyze("capture.pcap", "--capture-evidence", capture["id"])
        self.assertIsNone(data["capture"]["target_uid"])
        self.assertNotIn("uid_attribution", data)

    def test_decryption_performed_truth_table(self):
        plaintext = [self.http_packet(http_request("decrypted.example.com", method="GET", target="/v1/items"))]
        self.write("capture.pcap", pcap(plaintext))

        # No cited capture: the key stays false and no basis is invented.
        data = self.analyze()
        self.assertFalse(data["decryption_performed"])
        self.assertNotIn("decryption_basis", data)

        # A cited capture that never asked for TLS decryption: decoded lines were plaintext.
        silent = self.capture_evidence()
        data = self.analyze("capture.pcap", "--capture-evidence", silent["id"])
        self.assertFalse(data["decryption_performed"])
        self.assertFalse(data["capture"]["decryption_requested"])
        self.assertEqual(data["decryption_basis"],
                         {"decryption_requested": False, "http_request_lines": 1,
                          "rule": forge_pcap.DECRYPTION_RULE})

        for declaration in ({"decryption_requested": True}, {"settings": {"tls_decryption": True}},
                            {"settings": {"tls_decryption": "true"}}):
            with self.subTest(declaration=sorted(declaration)):
                asking = self.capture_evidence(**declaration)
                data = self.analyze("capture.pcap", "--capture-evidence", asking["id"])
                self.assertTrue(data["capture"]["decryption_requested"])
                self.assertTrue(data["decryption_performed"])
                self.assertEqual(data["decryption_basis"]["http_request_lines"], 1)

        # A capture that asked for decryption but holds no decoded request line proves nothing.
        hello = frame(ipv4("10.0.0.5", "93.184.216.34", 6, tcp(51000, 443, client_hello("pinned.example.com"))))
        self.write("capture.pcap", pcap([pcap_record(hello)]))
        asking = self.capture_evidence(decryption_requested=True)
        data = self.analyze("capture.pcap", "--capture-evidence", asking["id"])
        self.assertEqual(data["http_request_lines"], 0)
        self.assertFalse(data["decryption_performed"])
        self.assertEqual(data["decryption_basis"],
                         {"decryption_requested": True, "http_request_lines": 0,
                          "rule": forge_pcap.DECRYPTION_RULE})

    # ------------------------------------------------------------ protocol map

    def test_protocol_map_copies_request_lines_without_creating_url_identities(self):
        self.write("capture.pcap", pcap([
            self.http_packet(http_request("api.example.com", method="GET",
                                          target="/api/v1/items?token=private-query-value"))]))
        record = self.analysis_record()
        result = self.protocol_map(record)
        self.assertEqual([endpoint["host"] for endpoint in result["endpoints"]], ["api.example.com"])
        endpoint = result["endpoints"][0]
        self.assertNotIn("url", endpoint)
        self.assertNotIn("method", endpoint)
        self.assertEqual(len(endpoint["observations"]), 1)
        observation = endpoint["observations"][0]
        self.assertEqual(observation["category"], "captured_network")
        self.assertEqual(observation["http_methods"], ["GET"])
        self.assertEqual(observation["http_paths"], ["/api/v1/items"])
        self.assertIn("not a successful call", observation["note"])
        self.assertFalse(result["input_truncated"])
        self.assertEqual(result["limits"]["http_values_per_host"], forge_protocol.MAX_NETWORK_HTTP_VALUES)
        dumped = json.dumps(result)
        for leaked in ("private-query-value", "captured_http"):
            self.assertNotIn(leaked, dumped)

    def test_protocol_map_bounds_stored_request_line_values(self):
        wide = self.store.add("analysis", {
            "schema": "forge.pcap/v1", "tool": "pcap", "action": "pcap-analyze", "success": True,
            "category": "captured_network", "http_request_lines": 12,
            "hosts": [{"hostname": "wide.example", "observations": [{"kind": "http_host", "timestamp": 1.0}],
                       "http_methods": [f"M{index}" for index in range(12)],
                       "http_paths": [f"/p{index}" for index in range(12)]}]})
        result = self.protocol_map(wide)
        observation = result["endpoints"][0]["observations"][0]
        self.assertEqual(len(observation["http_methods"]), forge_protocol.MAX_NETWORK_HTTP_VALUES)
        self.assertEqual(len(observation["http_paths"]), forge_protocol.MAX_NETWORK_HTTP_VALUES)
        self.assertTrue(result["input_truncated"])
        unusable = self.store.add("analysis", {
            "schema": "forge.pcap/v1", "tool": "pcap", "action": "pcap-analyze", "success": True,
            "category": "captured_network",
            "hosts": [{"hostname": "unusable.example", "observations": [{"kind": "http_host"}],
                       "http_paths": ["/ok", 7, ""]}]})
        result = self.protocol_map(unusable)
        observation = result["endpoints"][0]["observations"][0]
        self.assertEqual(observation["http_paths"], ["/ok"])
        self.assertNotIn("http_methods", observation)
        self.assertTrue(result["input_truncated"])

    def test_map_citation_matches_exact_hostnames_only(self):
        self.write("capture.pcap", pcap([self.dns_packet("api.example.com"),
                                         self.dns_packet("cdn.example.com", seconds=1700000001)]))
        candidates = [self.candidate("https://api.example.com/v1/login"),
                      self.candidate("https://evil-example.com/v1/login"),
                      self.candidate("https://example.com/"),
                      self.candidate("https://api.example.com/v1/other")]
        mapping, _ = self.map_evidence(candidates)
        data = self.analyze("capture.pcap", "--map-evidence", mapping["id"])
        matches = data["static_host_matches"]
        self.assertEqual([entry["hostname"] for entry in matches], ["api.example.com", "api.example.com"])
        self.assertEqual(len({entry["static_candidate_sha256"] for entry in matches}), 2)
        logins = [entry for entry in matches
                  if entry["static_candidate_sha256"] == hashlib.sha256(b"https://api.example.com/v1/login").hexdigest()]
        self.assertEqual(len(logins), 1)
        self.assertEqual(logins[0]["category"], "static_host_match")
        self.assertEqual(logins[0]["evidence_ids"], [mapping["id"]])
        self.assertEqual(data["evidence_ids"], [mapping["id"]])
        self.assertEqual(data["map_citations"][0]["exact_hostname_matches"], 2)
        self.assertNotIn("/v1/login", json.dumps(data["static_host_matches"]))

    def test_map_citation_rejects_wrong_records_and_changed_index(self):
        self.write("capture.pcap", pcap([self.dns_packet("api.example.com")]))
        mapping, index_file = self.map_evidence([self.candidate("https://api.example.com/x")])
        failed, _ = self.map_evidence([self.candidate("https://api.example.com/x")], success=False)
        with self.assertRaisesRegex(ForgeError, "not a successful api-map analysis"):
            self.analyze("capture.pcap", "--map-evidence", failed["id"])
        wrong, _ = self.map_evidence([self.candidate("https://api.example.com/x")], tool="pcap")
        with self.assertRaisesRegex(ForgeError, "must cite an android api-map analysis record"):
            self.analyze("capture.pcap", "--map-evidence", wrong["id"])
        with self.assertRaisesRegex(ForgeError, "Unknown evidence ID"):
            self.analyze("capture.pcap", "--map-evidence", "ev_missing")
        index_file.write_text('{"text":"rewritten"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ForgeError, "changed after the API map"):
            self.analyze("capture.pcap", "--map-evidence", mapping["id"])

    def test_map_citation_ignores_candidates_without_host_or_hash(self):
        self.write("capture.pcap", pcap([self.dns_packet("api.example.com")]))
        candidates = [{"category": "static_candidate"},
                      {"url": "https://api.example.com/x", "url_sha256": "not-a-hash"},
                      self.candidate("https://api.example.com/y")]
        mapping, _ = self.map_evidence(candidates)
        data = self.analyze("capture.pcap", "--map-evidence", mapping["id"])
        self.assertEqual(len(data["static_host_matches"]), 1)
        self.assertEqual(data["map_citations"][0]["candidates_without_hostname_or_hash"], 2)

    def test_no_match_is_reported_without_inventing_evidence(self):
        self.write("capture.pcap", pcap([self.dns_packet("observed.example.com")]))
        mapping, _ = self.map_evidence([self.candidate("https://api.example.com/x")])
        data = self.analyze("capture.pcap", "--map-evidence", mapping["id"])
        self.assertEqual(data["static_host_matches"], [])
        self.assertEqual(data["evidence_ids"], [mapping["id"]])



if __name__ == "__main__":
    unittest.main()
