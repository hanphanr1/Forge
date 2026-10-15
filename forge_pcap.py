"""Bounded classic-PCAP metadata analysis with optional cited capture/map provenance.

Reads classic (libpcap) captures, validates record framing, and reports connection
metadata and host names only. Supported observations are DNS query/answer names,
TLS ClientHello SNI and plaintext HTTP Host, plus the method and origin-form request
path of a decoded plaintext request line. Payload bytes, query strings, headers
(other than Host), bodies and credentials are never returned, FORGE itself never
decrypts anything (only a cited capture record can declare that decryption was
requested), and nothing here is replayable.

Reported top-level fields (JSON-safe):

- ``schema``/``tool``/``action``/``category``/``success``: ``forge.pcap/v1``/``pcap``/``pcap-analyze``/``captured_network``/``True``
- ``input``: ``{sha256, size}`` of the whole file, hashed even when caps stop dissection
- ``format``: byte order, version, timestamp resolution, snaplen, link types, record bound
- ``packets_scanned``/``bytes_scanned``/``scan_stopped``/``truncated``
- ``malformed_packets``/``unsupported_packets``/``captured_packet_truncations``/``truncated_dissections``
- ``fragmented_packets``/``records_skipped_oversized``/``vlan_packets``/``linktype_fallbacks``
- ``unsupported_link_types``/``unsupported_ethertypes``/``unsupported_ip_protocols`` and omission flags
- ``dns_messages``/``dns_questions``/``dns_answers``/``tls_client_hellos``/``http_requests``/
  ``http_request_lines`` counters; ``http_request_lines`` counts request lines whose method and
  origin-form path were decoded, whether or not a host name was recorded for them
- ``hosts``: ``[{hostname, observations, observation_count, observations_omitted}]``; a host with
  decoded request lines also carries bounded ``http_methods``/``http_paths`` and their omission flags
- ``flows``: bounded directional connection summaries with first/last observed timestamps
- ``trailer``: PCAPdroid trailer claim counters (uid values, package hints, checksum mismatches)
- ``first_timestamp``/``last_timestamp``/``duration_seconds``/``empty``
- ``decryption_performed`` (computed, never assumed) and ``scope``
- ``limits`` echo of the applied bounds
- with ``--capture-evidence``: ``capture`` citation, ``decryption_basis``, ``evidence_ids`` and, when the
  capture declares a ``target_uid``, ``uid_attribution`` counts that keep target, other and unknown UID
  traffic separate instead of calling every packet target traffic
- with ``--map-evidence``: ``static_host_matches``, ``map_citations``, ``static_host_match_note``

PCAPdroid trailer UID and package hint values are per-packet claims written by the
capturing app, not independent attestation of the sending process. The 20-byte
package hint field holds a package name truncated to 19 characters, so a hint of
that length can never be treated as an exact package identity.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import zlib
from urllib.parse import urlsplit

from forge_core import ForgeError


SCHEMA = "forge.pcap/v1"
TOOL = "pcap"
ACTION = "pcap-analyze"
CATEGORY = "captured_network"

FILE_HEADER = 24
RECORD_HEADER = 16
DRAIN_CHUNK = 1024 * 1024

MAGIC_MICROSECOND = 0xA1B2C3D4
MAGIC_NANOSECOND = 0xA1B23C4D
MAGIC_MODIFIED = 0xA1B2CD34
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_RECORD_BYTES = 262144
MAX_PACKETS_LIMIT = 10000000
MAX_HOSTS_LIMIT = 100000
MAX_FLOWS_LIMIT = 100000

DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_PACKETS = 100000
DEFAULT_MAX_HOSTS = 1000
DEFAULT_MAX_FLOWS = 1000

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_BSD = 12
ETHERNET_HEADER = 14
IP_ETHERTYPES = frozenset((0x0800, 0x86DD))
VLAN_ETHERTYPES = frozenset((0x8100, 0x88A8, 0x9100))
MAX_VLAN_TAGS = 4

IPV4 = 4
IPV6 = 6
IPV4_HEADER = 20
IPV6_HEADER = 40
IPV6_EXTENSION_HEADERS = frozenset((0, 43, 51, 60))
IPV6_OPTION_HEADERS = frozenset((0, 43, 60))
IPV6_FRAGMENT_HEADER = 44
MAX_IPV6_EXTENSION_HEADERS = 8

TCP = 6
UDP = 17
TCP_HEADER = 20
UDP_HEADER = 8
DNS_PORT = 53

PCAPDROID_MAGIC = b"\x01\x07\x20\x21"
PCAPDROID_TRAILER = 32
PCAPDROID_APPNAME = 20
PCAPDROID_HINT_CHARS = 19

PROBE_BUFFER = 8192
HTTP_SCAN_BYTES = 4096
MAX_HTTP_METHOD_CHARS = 8
MAX_HTTP_PATH_CHARS = 2048
TLS_MAX_RECORD = 16384 + 2048
TLS_MAX_HANDSHAKE = 65536
TLS_HELLO_MINIMUM = 34
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SERVER_NAME = 0x0000
EXTENSION_ENCRYPTED_CLIENT_HELLO = 0xFE0D

DNS_HEADER = 12
MAX_DNS_QUESTIONS = 16
MAX_DNS_ANSWERS = 16
MAX_DNS_NAME_JUMPS = 32
MAX_DNS_NAME_BYTES = 255
DNS_NAME_TYPES = frozenset((2, 5, 12, 39))
DNS_MX = 15
DNS_SRV = 33
DNS_SOA = 6

OBSERVATIONS_PER_HOST = 8
HTTP_VALUES_PER_HOST = 8
MAX_UNSUPPORTED_VALUES = 32
MAX_OMITTED_FLOW_KEYS = 256
MAX_TRAILER_VALUES = 32
CAPTURE_TRUNCATION_FLAGS = ("truncated", "capture_truncated", "max_dump_size_reached", "max_bytes_reached",
                            "dump_truncated", "size_limit_reached")

MAX_MAP_CANDIDATES = 5000
MAX_STATIC_MATCHES = 1000
MAX_INDEX_VERIFY_BYTES = 256 * 1024 * 1024

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_ACK = 0x10

COUNTER_NAMES = (
    "truncated_dissections",
    "fragmented_packets",
    "ipv6_extension_chains_refused",
    "records_skipped_oversized",
    "vlan_packets",
    "linktype_fallbacks",
    "ipv4_packets",
    "ipv6_packets",
    "tcp_packets",
    "tcp_reassembly_gaps",
    "udp_packets",
    "payload_bytes",
    "packets_unrecorded",
    "observations_omitted",
    "hosts_omitted",
    "dns_messages",
    "dns_messages_truncated",
    "dns_questions",
    "dns_answers",
    "tls_client_hellos",
    "tls_client_hellos_with_ech",
    "tls_client_hellos_without_sni",
    "tls_probe_unsupported",
    "tls_sni_truncated",
    "http_requests",
    "http_hosts",
    "http_request_lines",
    "http_probes_truncated",
    "invalid_hostnames",
    "trailer_packets",
    "trailer_checksum_mismatches",
    "uid_unknown_packets",
    "invalid_package_hints",
)

SCOPE = (
    "Observed packets from one classic PCAP file, not successful application calls, sessions or "
    "authentication: every host name and connection summary is derived from packets that the file "
    "already contains, with the record timestamp. "
    "FORGE uses no decryption and no key material, and never requests either: QUIC, ECH payloads, DoH, "
    "DoT, pinned or otherwise encrypted traffic can only contribute names that the capture already "
    "holds in plaintext, which is possible only when PCAPdroid itself decrypted before writing the "
    "file and the cited capture record declares that decryption was requested. Payload bytes are never "
    "returned. "
    "Only DNS question names, names inside DNS answer record data (CNAME/NS/PTR/SOA/MX/SRV), TLS "
    "ClientHello SNI, plaintext HTTP Host and the method with the origin-form request path of a decoded "
    "request line are reported. That path stops at the query string, keeps percent-encoding and is "
    "bounded; query strings, headers other than Host, bodies and credentials are never copied into the "
    "output. A request line whose target is not origin-form contributes no method and no path, and "
    "request-line values are attached only to a host name that was itself recorded. "
    "decryption_performed is true only when the cited capture record declares that TLS decryption was "
    "requested and at least one request line was decoded from this file; it is a declared setting plus "
    "a decoded-line fact reported by decryption_basis, never proof that one flow was decrypted. "
    "DNS, TLS and HTTP observations are independent: no DNS-to-TLS or DNS-to-HTTP causality is "
    "inferred from ordering or timing. "
    "PCAPdroid trailer UID and app package hint are file-declared per-packet claims, not independent "
    "attestation of the sending process, and a hint of 19 characters may be a truncated package name. "
    "Framing, fragmentation, reassembly and SNI/HTTP limits are conservative: unparseable, "
    "unsupported, fragmented, oversized or capture-truncated packets are counted as explicit facts "
    "and are never guessed or partially accepted. "
    "Names are extracted from flows that were recorded within the flow cap, so packets counted as "
    "unrecorded contribute no name observation and no flow summary."
)

DECRYPTION_RULE = (
    "decryption_performed is true only when the cited capture record declares that TLS decryption was "
    "requested and this analysis decoded at least one HTTP request line. FORGE decrypts nothing and "
    "installs nothing: PCAPdroid writes the bytes it already decrypted into the capture, so decoded "
    "request lines in a capture whose record requested decryption are consistent with decryption "
    "without proving that any particular flow was decrypted, and decoded request lines in a capture "
    "that never requested decryption are plaintext traffic instead."
)

_LABEL = re.compile(r"[a-z0-9_-]{1,63}\Z")
_PACKAGE_HINT = re.compile(r"[A-Za-z0-9._-]{1,20}\Z")
_HTTP_METHOD_BYTES = ("[A-Z]{1,%d}" % MAX_HTTP_METHOD_CHARS).encode("ascii")
_HTTP_REQUEST_LINE = re.compile(rb"(" + _HTTP_METHOD_BYTES + rb") ([\x21-\x7e]{1,2048}) HTTP/1\.[01]\r\n\Z")
_HTTP_PREFIX = re.compile(_HTTP_METHOD_BYTES + rb" [\x21-\x7e]")
_HTTP_PATH = re.compile(("/[\\x21-\\x7e]{0,%d}\\Z" % (MAX_HTTP_PATH_CHARS - 1)).encode("ascii"))
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")

STATIC_MATCH_NOTE = (
    "An exact hostname match only says the observed connection and the static candidate share a host. "
    "The URL path, endpoint, request builder, parameters and runtime execution are not proven, and the "
    "static candidate was never replayed or confirmed by this analysis."
)


# ---------------------------------------------------------------- helpers


def _bounded(name, value, maximum, minimum=1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ForgeError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _bounded_add(values, item, limit):
    """Append one distinct value; return True when the bound dropped it."""
    if item in values:
        return False
    if len(values) >= limit:
        return True
    values.append(item)
    return False


def _hostname(raw):
    """Return a normalized LDH host name, or None when it is not a usable name.

    Conservative: ASCII only, so a punycode ``xn--`` label is kept as its ASCII form
    and never decoded; case is folded and a single trailing root dot is dropped.
    """
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("ascii")
        except UnicodeDecodeError:
            return None
    else:
        text = str(raw)
    if not text or len(text) > 254 or re.search(r"[\x00-\x20\x7f]", text):
        return None
    text = text.rstrip(".").lower()
    if not text or len(text) > 253:
        return None
    labels = text.split(".")
    for label in labels:
        if not _LABEL.match(label) or label.startswith("-") or label.endswith("-"):
            return None
    return text


def _timestamp(seconds, fraction, resolution):
    divisor = 1000000000.0 if resolution == "nanosecond" else 1000000.0
    return round(seconds + fraction / divisor, 6)


class _Reader:
    """Streams one file, hashing and sizing every byte it reads."""

    def __init__(self, handle):
        self.handle = handle
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, count):
        data = self.handle.read(count)
        self.digest.update(data)
        self.size += len(data)
        return data

    def drain(self):
        while True:
            block = self.handle.read(DRAIN_CHUNK)
            if not block:
                return
            self.digest.update(block)
            self.size += len(block)


def _open_input(path):
    candidate = Path(path)
    try:
        info = candidate.lstat()
    except OSError as error:
        raise ForgeError(f"Cannot read PCAP input: {error}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ForgeError("PCAP input must be a regular file, not a symlink, directory or device")
    if info.st_size > MAX_FILE_BYTES:
        raise ForgeError(f"PCAP input exceeds the {MAX_FILE_BYTES}-byte analysis limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise ForgeError(f"Cannot open PCAP input: {error}") from error
    if not os.path.samestat(info, os.fstat(descriptor)):
        os.close(descriptor)
        raise ForgeError("PCAP input changed while being opened")
    return os.fdopen(descriptor, "rb")


def _file_header(reader):
    raw = reader.read(FILE_HEADER)
    if len(raw) < FILE_HEADER:
        # A just-created or not-yet-flushed dump is start evidence only, never capture evidence.
        raise ForgeError("PCAP input is %d bytes, shorter than the 24-byte classic PCAP file header; a "
                         "zero-length or not-yet-flushed dump is not usable network capture" % len(raw))
    magic = raw[0:4]
    if magic == PCAPNG_MAGIC:
        raise ForgeError("PCAPNG is not supported; capture with the classic PCAP format (pcapng_format=false)")
    byte_order = resolution = None
    for candidate in ("little", "big"):
        value = int.from_bytes(magic, candidate)
        if value == MAGIC_MICROSECOND:
            byte_order, resolution = candidate, "microsecond"
            break
        if value == MAGIC_NANOSECOND:
            byte_order, resolution = candidate, "nanosecond"
            break
        if value == MAGIC_MODIFIED:
            raise ForgeError("Modified PCAP variants (magic 0xa1b2cd34) are not supported; export a "
                             "standard classic PCAP")
    if byte_order is None:
        raise ForgeError("Not a classic PCAP file: unexpected file magic 0x%08x" % int.from_bytes(magic, "little"))
    version_major = int.from_bytes(raw[4:6], byte_order)
    version_minor = int.from_bytes(raw[6:8], byte_order)
    if version_major != 2 or version_minor > 4:
        raise ForgeError("Unsupported PCAP version %d.%d; only classic PCAP 2.4-layout files are parsed"
                         % (version_major, version_minor))
    snaplen = int.from_bytes(raw[16:20], byte_order)
    if snaplen == 0:
        raise ForgeError("PCAP file header declares a snaplen of 0, so records cannot be framed")
    return {"byte_order": byte_order, "resolution": resolution, "version": "%d.%d" % (version_major, version_minor),
            "snaplen": snaplen, "link_type": int.from_bytes(raw[20:24], byte_order)}


# ---------------------------------------------------------------- DNS


def _dns_name(message, offset, bound=None):
    """Return (name_bytes, end_offset) or (None, ...) when the name is unusable.

    Compression pointers must point strictly backwards, so decoding always
    terminates; a forward or self pointer is refused instead of followed.
    """
    if bound is None:
        bound = len(message)
    labels = []
    total = 0
    position = offset
    end = None
    jumps = 0
    following = False
    while True:
        limit = len(message) if following else min(bound, len(message))
        if position >= limit:
            return None, None
        length = message[position]
        if length == 0:
            position += 1
            if end is None:
                end = position
            break
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(message):
                return None, None
            pointer = ((length & 0x3F) << 8) | message[position + 1]
            if end is None:
                end = position + 2
            if pointer >= position:
                # A self or forward pointer would not terminate.
                return None, None
            jumps += 1
            if jumps > MAX_DNS_NAME_JUMPS:
                return None, None
            position = pointer
            following = True
            continue
        if length & 0xC0:
            return None, None
        position += 1
        if position + length > limit:
            return None, None
        total += length + 1
        if total > MAX_DNS_NAME_BYTES:
            return None, None
        labels.append(message[position:position + length])
        position += length
    if not labels:
        return None, end
    return b".".join(labels), end


def _dns_rdata_names(message, record_type, start, stop):
    names = []
    if record_type in DNS_NAME_TYPES:
        name, _ = _dns_name(message, start, stop)
        names.append(name)
    elif record_type == DNS_MX:
        name, _ = _dns_name(message, start + 2, stop)
        names.append(name)
    elif record_type == DNS_SRV:
        name, _ = _dns_name(message, start + 6, stop)
        names.append(name)
    elif record_type == DNS_SOA:
        primary, position = _dns_name(message, start, stop)
        names.append(primary)
        if position is not None:
            mailbox, _ = _dns_name(message, position, stop)
            names.append(mailbox)
    return [name for name in names if name]


def _dns_message(message):
    """Return ([(kind, name_bytes)], truncated, questions_read, answers_read)."""
    if len(message) < DNS_HEADER:
        return [], True, 0, 0
    flags = int.from_bytes(message[2:4], "big")
    declared_questions = int.from_bytes(message[4:6], "big")
    declared_answers = int.from_bytes(message[6:8], "big")
    observations = []
    truncated = False
    position = DNS_HEADER
    if not flags & 0x8000:
        truncated = declared_questions > MAX_DNS_QUESTIONS
        read = 0
        for _ in range(min(declared_questions, MAX_DNS_QUESTIONS)):
            name, end = _dns_name(message, position)
            if end is None or end + 4 > len(message):
                truncated = True
                break
            observations.append(("dns_query", name))
            position = end + 4
            read += 1
        return observations, truncated, read, 0
    if declared_questions > MAX_DNS_QUESTIONS:
        return [], True, 0, 0
    for _ in range(declared_questions):
        _, end = _dns_name(message, position)
        if end is None or end + 4 > len(message):
            return [], True, 0, 0
        position = end + 4
    truncated = declared_answers > MAX_DNS_ANSWERS
    read = 0
    for _ in range(min(declared_answers, MAX_DNS_ANSWERS)):
        # The owner name is deliberately not reported: it repeats the queried name,
        # whose observation is the question section of the same exchange.
        _, end = _dns_name(message, position)
        if end is None or end + 10 > len(message):
            truncated = True
            break
        record_type = int.from_bytes(message[end:end + 2], "big")
        data_length = int.from_bytes(message[end + 8:end + 10], "big")
        start = end + 10
        stop = start + data_length
        if stop > len(message):
            truncated = True
            break
        for name in _dns_rdata_names(message, record_type, start, stop):
            observations.append(("dns_answer", name))
        position = stop
        read += 1
    return observations, truncated, 0, read


# ---------------------------------------------------------------- TLS / HTTP


def _server_name(data):
    if len(data) < 2:
        return None
    total = int.from_bytes(data[0:2], "big")
    if total + 2 > len(data):
        return None
    position = 2
    end = 2 + total
    while position + 3 <= end:
        kind = data[position]
        length = int.from_bytes(data[position + 1:position + 3], "big")
        position += 3
        if position + length > end:
            return None
        if kind == 0:
            return data[position:position + length]
        position += length
    return None


def _hello_body(body):
    flags = {"server_name": None, "encrypted_client_hello": False}
    if len(body) <= TLS_HELLO_MINIMUM:
        return "unsupported", None, flags
    position = TLS_HELLO_MINIMUM
    session_length = body[position]
    position += 1
    if position + session_length > len(body):
        return "unsupported", None, flags
    position += session_length
    if position + 2 > len(body):
        return "unsupported", None, flags
    cipher_length = int.from_bytes(body[position:position + 2], "big")
    position += 2
    if cipher_length == 0 or cipher_length % 2 or position + cipher_length > len(body):
        return "unsupported", None, flags
    position += cipher_length
    if position + 1 > len(body):
        return "unsupported", None, flags
    compression_length = body[position]
    position += 1
    if position + compression_length > len(body):
        return "unsupported", None, flags
    position += compression_length
    if position == len(body):
        return "client_hello", None, flags
    if position + 2 > len(body):
        return "unsupported", None, flags
    total = int.from_bytes(body[position:position + 2], "big")
    position += 2
    if position + total > len(body):
        return "unsupported", None, flags
    end = position + total
    while position + 4 <= end:
        extension_type = int.from_bytes(body[position:position + 2], "big")
        extension_length = int.from_bytes(body[position + 2:position + 4], "big")
        position += 4
        if position + extension_length > end:
            return "unsupported", None, flags
        if extension_type == EXTENSION_SERVER_NAME:
            flags["server_name"] = _server_name(body[position:position + extension_length])
        elif extension_type == EXTENSION_ENCRYPTED_CLIENT_HELLO:
            flags["encrypted_client_hello"] = True
        position += extension_length
    if position != end:
        return "unsupported", None, flags
    return "client_hello", flags["server_name"], flags


def _client_hello(data):
    """Return (status, sni_bytes, extension_flags) for a stream starting at a TLS record."""
    if len(data) < 5:
        return "needmore", None, {}
    if data[0] != 0x16 or data[1] != 0x03 or data[2] not in (0x01, 0x02, 0x03, 0x04):
        return "unsupported", None, {}
    length = int.from_bytes(data[3:5], "big")
    if length == 0 or length > TLS_MAX_RECORD:
        return "unsupported", None, {}
    if len(data) < 5 + length:
        return "needmore", None, {}
    handshake = data[5:5 + length]
    if len(handshake) < 4:
        return "unsupported", None, {}
    if handshake[0] != HANDSHAKE_CLIENT_HELLO:
        return "not_client_hello", None, {}
    declared = int.from_bytes(handshake[1:4], "big")
    if declared < TLS_HELLO_MINIMUM or declared > TLS_MAX_HANDSHAKE:
        return "unsupported", None, {}
    if len(handshake) < 4 + declared:
        return "needmore", None, {}
    return _hello_body(handshake[4:4 + declared])


def _http_request(data):
    """Return (status, host_bytes, method_bytes, path_bytes) for one plaintext request head.

    The method and path are returned together or not at all: the request-line pattern already
    validates the method as A-Z within ``MAX_HTTP_METHOD_CHARS``, and the path is kept only when
    the target is origin-form, so its query string, its header block and its body are never
    returned and are never partially accepted.
    """
    if not _HTTP_PREFIX.match(data[:12]):
        return "unsupported", None, None, None
    line_end = data.find(b"\r\n")
    if line_end < 0:
        if len(data) < HTTP_SCAN_BYTES:
            return "needmore", None, None, None
        return "truncated", None, None, None
    match = _HTTP_REQUEST_LINE.match(data[:line_end + 2])
    if match is None:
        return "unsupported", None, None, None
    if match.group(1) == b"CONNECT":
        # authority-form request target carries no Host header
        return "unsupported", None, None, None
    method, path = match.group(1), match.group(2).split(b"?", 1)[0]
    if _HTTP_PATH.match(path) is None:
        # Absolute, asterisk or authority form: no origin-form path exists to report.
        method = path = None
    head = data[line_end + 2:]
    head_end = head.find(b"\r\n\r\n")
    if head_end < 0:
        if len(head) < HTTP_SCAN_BYTES:
            return "needmore", None, None, None
        return "truncated", None, None, None
    for line in head[:head_end].split(b"\r\n"):
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"host":
            return "ok", value.strip(), method, path
    return "ok", None, method, path


# ---------------------------------------------------------------- scan state


class _Scan:
    """Bounded mutable state for one capture file. No payload is ever retained."""

    def __init__(self, *, link_type, max_hosts, max_flows):
        self.link_type = link_type
        self.max_hosts = max_hosts
        self.max_flows = max_flows
        self.hosts = {}
        self.flows = {}
        self.probes = {}
        self.omitted_flow_keys = set()
        self.omitted_flow_keys_truncated = False
        self.link_types = {link_type}
        self.unsupported_link_types = []
        self.unsupported_ethertypes = []
        self.unsupported_protocols = []
        self.unsupported_link_types_omitted = False
        self.unsupported_ethertypes_omitted = False
        self.unsupported_protocols_omitted = False
        self.trailer_uids = []
        self.trailer_hints = []
        self.uid_packet_counts = {}
        self.uid_packet_counts_omitted = False
        self.trailer_uids_omitted = False
        self.trailer_hints_omitted = False
        self.package_hint_truncation_possible = False
        self.counters = {}
        self.truncated = False
        self.packets = 0
        self.first_timestamp = None
        self.last_timestamp = None

    # ------------------------------------------------------------ counters

    def bump(self, name, amount=1):
        if amount:
            self.counters[name] = self.counters.get(name, 0) + amount

    def count(self, name):
        return self.counters.get(name, 0)

    def short(self, record_truncated):
        """A packet whose captured bytes are too short to dissect."""
        self.bump("truncated_dissections" if record_truncated else "malformed_packets")

    def unsupported(self, *, protocol=None, ethertype=None, link_type=None):
        self.bump("unsupported_packets")
        if protocol is not None and _bounded_add(self.unsupported_protocols, protocol, MAX_UNSUPPORTED_VALUES):
            self.unsupported_protocols_omitted = True
        if ethertype is not None and _bounded_add(self.unsupported_ethertypes, ethertype, MAX_UNSUPPORTED_VALUES):
            self.unsupported_ethertypes_omitted = True
        if link_type is not None and _bounded_add(self.unsupported_link_types, link_type, MAX_UNSUPPORTED_VALUES):
            self.unsupported_link_types_omitted = True

    # ------------------------------------------------------------ trailer

    def trailer(self, data):
        """Return (uid, package_hint, hint_truncated) from a valid PCAPdroid trailer."""
        if len(data) < ETHERNET_HEADER + PCAPDROID_TRAILER:
            return None
        block = data[-PCAPDROID_TRAILER:]
        if block[0:4] != PCAPDROID_MAGIC:
            return None
        # UID/magic are network-order; Ethernet FCS from Android's writer is little-endian.
        if zlib.crc32(data[:-4]) & 0xFFFFFFFF != int.from_bytes(block[28:32], "little"):
            # The magic is there but the frame checksum is not: refuse the claim.
            self.bump("trailer_checksum_mismatches")
            return None
        self.bump("trailer_packets")
        raw_uid = int.from_bytes(block[4:8], "big", signed=True)
        if raw_uid < 0:
            self.bump("uid_unknown_packets")
            uid = None
        else:
            uid = raw_uid
            key = str(uid)
            if key in self.uid_packet_counts or len(self.uid_packet_counts) < MAX_TRAILER_VALUES:
                self.uid_packet_counts[key] = self.uid_packet_counts.get(key, 0) + 1
            else:
                self.uid_packet_counts_omitted = True
                self.truncated = True
            if _bounded_add(self.trailer_uids, uid, MAX_TRAILER_VALUES):
                self.trailer_uids_omitted = True
        text = block[8:8 + PCAPDROID_APPNAME].rstrip(b"\x00")
        hint = None
        truncated = False
        if text:
            try:
                decoded = text.decode("ascii")
            except UnicodeDecodeError:
                decoded = ""
            if decoded.lower() == "unknown":
                decoded = ""
            if not _PACKAGE_HINT.match(decoded):
                if decoded:
                    self.bump("invalid_package_hints")
            else:
                hint = decoded
                truncated = len(decoded) >= PCAPDROID_HINT_CHARS
                if truncated:
                    self.package_hint_truncation_possible = True
                if _bounded_add(self.trailer_hints, hint, MAX_TRAILER_VALUES):
                    self.trailer_hints_omitted = True
        return uid, hint, truncated

    # ------------------------------------------------------------ hosts

    def observe(self, kind, name, *, index, timestamp, endpoints, trailer, ech=False):
        if name is None:
            return
        entry = self.hosts.get(name)
        if entry is None:
            if len(self.hosts) >= self.max_hosts:
                self.bump("hosts_omitted")
                self.truncated = True
                return
            entry = {"hostname": name, "observations": [], "observation_count": 0, "observations_omitted": 0}
            self.hosts[name] = entry
        entry["observation_count"] += 1
        if len(entry["observations"]) >= OBSERVATIONS_PER_HOST:
            entry["observations_omitted"] += 1
            self.bump("observations_omitted")
            self.truncated = True
            return
        uid, hint, hint_truncated = trailer if trailer is not None else (None, None, False)
        observation = {"kind": kind, "packet_index": index, "timestamp": timestamp,
                       "source_ip": endpoints[0], "destination_ip": endpoints[1],
                       "source_port": endpoints[2], "destination_port": endpoints[3],
                       "uid": uid, "package_hint": hint, "package_hint_truncated": hint_truncated}
        if kind == "tls_sni":
            observation["ech"] = bool(ech)
        entry["observations"].append(observation)

    # ------------------------------------------------------------ flows

    def flow(self, key, *, ip_version, protocol, source_ip, source_port, destination_ip,
             destination_port, timestamp, trailer):
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self.bump("packets_unrecorded")
                self.truncated = True
                if key not in self.omitted_flow_keys:
                    if len(self.omitted_flow_keys) >= MAX_OMITTED_FLOW_KEYS:
                        self.omitted_flow_keys_truncated = True
                    else:
                        self.omitted_flow_keys.add(key)
                return None
            uid, hint, hint_truncated = trailer if trailer is not None else (None, None, False)
            flow = {"ip_version": ip_version, "protocol": protocol,
                    "source_ip": source_ip, "source_port": source_port,
                    "destination_ip": destination_ip, "destination_port": destination_port,
                    "packets": 0, "payload_bytes": 0,
                    "first_timestamp": timestamp, "last_timestamp": timestamp,
                    "app_layer_hint": None, "tls_sni": None, "http_host": None, "probe_truncated": False,
                    "uid": uid, "package_hint": hint, "package_hint_truncated": hint_truncated}
            self.flows[key] = flow
        flow["packets"] += 1
        flow["first_timestamp"] = min(flow["first_timestamp"], timestamp)
        flow["last_timestamp"] = max(flow["last_timestamp"], timestamp)
        if flow["uid"] is None and trailer is not None and trailer[0] is not None:
            flow["uid"] = trailer[0]
        if flow["package_hint"] is None and trailer is not None and trailer[1] is not None:
            flow["package_hint"] = trailer[1]
            flow["package_hint_truncated"] = trailer[2]
        return flow

    # ------------------------------------------------------------ packets

    def packet(self, data, index, timestamp, *, truncated, malformed_record):
        self.packets += 1
        self.first_timestamp = timestamp if self.first_timestamp is None else min(self.first_timestamp, timestamp)
        self.last_timestamp = timestamp if self.last_timestamp is None else max(self.last_timestamp, timestamp)
        if malformed_record:
            # incl_len larger than orig_len: the framing itself is inconsistent.
            self.bump("malformed_packets")
            return
        if truncated:
            self.bump("captured_packet_truncations")
        trailer = self.trailer(data)
        offset = self._link_offset(data, truncated)
        if offset is None:
            return
        self._network(data[offset:], index, timestamp, truncated, trailer)

    def _link_offset(self, data, truncated):
        if self.link_type in (LINKTYPE_RAW, LINKTYPE_RAW_BSD):
            return 0
        if self.link_type != LINKTYPE_ETHERNET:
            self.unsupported(link_type=self.link_type)
            return None
        if len(data) < ETHERNET_HEADER:
            self.short(truncated)
            return None
        ethertype = int.from_bytes(data[12:14], "big")
        offset = ETHERNET_HEADER
        tags = 0
        while ethertype in VLAN_ETHERTYPES:
            if tags >= MAX_VLAN_TAGS or len(data) < offset + 4:
                self.unsupported(ethertype=ethertype)
                return None
            ethertype = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
            tags += 1
        if tags:
            self.bump("vlan_packets")
        if ethertype in IP_ETHERTYPES:
            return offset
        if data[0] >> 4 in (IPV4, IPV6):
            # PCAPdroid skips the fake Ethernet header when the trailer does not fit the snaplen.
            self.bump("linktype_fallbacks")
            return 0
        self.unsupported(ethertype=ethertype)
        return None

    def _network(self, payload, index, timestamp, truncated, trailer):
        if not payload:
            self.short(truncated)
            return
        version = payload[0] >> 4
        if version == IPV4:
            self._ipv4(payload, index, timestamp, truncated, trailer)
        elif version == IPV6:
            self._ipv6(payload, index, timestamp, truncated, trailer)
        else:
            self.short(truncated)

    def _ipv4(self, payload, index, timestamp, truncated, trailer):
        if len(payload) < IPV4_HEADER:
            self.short(truncated)
            return
        header_length = (payload[0] & 0x0F) * 4
        if header_length < IPV4_HEADER:
            self.bump("malformed_packets")
            return
        total_length = int.from_bytes(payload[2:4], "big")
        if total_length < header_length:
            self.bump("malformed_packets")
            return
        if len(payload) < header_length:
            self.short(truncated)
            return
        fragment = int.from_bytes(payload[6:8], "big")
        if fragment & 0x2000 or fragment & 0x1FFF:
            # Fragments are never reassembled and never dissected further.
            self.bump("fragmented_packets")
            return
        self.bump("ipv4_packets")
        body = payload[header_length:min(total_length, len(payload))]
        self._transport(IPV4, payload[9], socket.inet_ntoa(payload[12:16]), socket.inet_ntoa(payload[16:20]),
                        body, index, timestamp, truncated, trailer)

    def _ipv6(self, payload, index, timestamp, truncated, trailer):
        if len(payload) < IPV6_HEADER:
            self.short(truncated)
            return
        next_header = payload[6]
        declared = int.from_bytes(payload[4:6], "big")
        position = IPV6_HEADER
        end = min(IPV6_HEADER + declared, len(payload))
        hops = 0
        while next_header in IPV6_EXTENSION_HEADERS or next_header == IPV6_FRAGMENT_HEADER:
            if next_header == IPV6_FRAGMENT_HEADER:
                # Fragments are never reassembled, including an offset-zero first fragment.
                self.bump("fragmented_packets")
                return
            if hops >= MAX_IPV6_EXTENSION_HEADERS:
                self.bump("ipv6_extension_chains_refused")
                self.bump("unsupported_packets")
                return
            if position + 2 > end:
                self.short(truncated)
                return
            length = payload[position + 1]
            step = (length + 1) * 8 if next_header in IPV6_OPTION_HEADERS else (length + 2) * 4
            if position + step > end:
                self.short(truncated)
                return
            next_header = payload[position]
            position += step
            hops += 1
        self.bump("ipv6_packets")
        body = payload[position:end]
        self._transport(IPV6, next_header, socket.inet_ntop(socket.AF_INET6, payload[8:24]),
                        socket.inet_ntop(socket.AF_INET6, payload[24:40]), body,
                        index, timestamp, truncated, trailer)

    def _transport(self, ip_version, protocol, source, destination, body, index, timestamp,
                   truncated, trailer):
        if protocol == TCP:
            self.bump("tcp_packets")
            if len(body) < TCP_HEADER:
                self.short(truncated)
                return
            source_port = int.from_bytes(body[0:2], "big")
            destination_port = int.from_bytes(body[2:4], "big")
            header_length = (body[12] >> 4) * 4
            if header_length < TCP_HEADER:
                self.bump("malformed_packets")
                return
            flags = body[13]
            if header_length > len(body):
                self.short(truncated)
                payload = b""
            else:
                payload = body[header_length:]
            self.bump("payload_bytes", len(payload))
            key = (ip_version, TCP, source, source_port, destination, destination_port)
            endpoints = (source, destination, source_port, destination_port)
            flow = self.flow(key, ip_version=ip_version, protocol="tcp", source_ip=source,
                             source_port=source_port, destination_ip=destination,
                             destination_port=destination_port, timestamp=timestamp, trailer=trailer)
            if flow is None:
                return
            flow["payload_bytes"] += len(payload)
            if DNS_PORT in (source_port, destination_port):
                if payload:
                    self._dns_tcp(payload, index, timestamp, endpoints, trailer)
                return
            self.probe(key, flow, payload, flags, index, timestamp, endpoints, trailer,
                       sequence=int.from_bytes(body[4:8], "big"))
            return
        if protocol == UDP:
            self.bump("udp_packets")
            if len(body) < UDP_HEADER:
                self.short(truncated)
                return
            source_port = int.from_bytes(body[0:2], "big")
            destination_port = int.from_bytes(body[2:4], "big")
            length = int.from_bytes(body[4:6], "big")
            if length < UDP_HEADER:
                self.bump("malformed_packets")
                return
            payload = body[UDP_HEADER:min(length, len(body))]
            self.bump("payload_bytes", len(payload))
            key = (ip_version, UDP, source, source_port, destination, destination_port)
            endpoints = (source, destination, source_port, destination_port)
            flow = self.flow(key, ip_version=ip_version, protocol="udp", source_ip=source,
                             source_port=source_port, destination_ip=destination,
                             destination_port=destination_port, timestamp=timestamp, trailer=trailer)
            if flow is None:
                return
            flow["payload_bytes"] += len(payload)
            if payload and DNS_PORT in (source_port, destination_port):
                self.dns(payload, index, timestamp, endpoints, trailer)
            return
        self.unsupported(protocol=protocol)

    # ------------------------------------------------------------ names

    def dns(self, message, index, timestamp, endpoints, trailer):
        if len(message) < DNS_HEADER:
            self.bump("dns_messages_truncated")
            return
        self.bump("dns_messages")
        observations, truncated, questions, answers = _dns_message(message)
        self.bump("dns_questions", questions)
        self.bump("dns_answers", answers)
        if truncated:
            self.bump("dns_messages_truncated")
        for kind, raw in observations:
            name = _hostname(raw)
            if name is None:
                self.bump("invalid_hostnames")
                continue
            self.observe(kind, name, index=index, timestamp=timestamp, endpoints=endpoints, trailer=trailer)

    def _dns_tcp(self, payload, index, timestamp, endpoints, trailer):
        if len(payload) < 2:
            self.bump("dns_messages_truncated")
            return
        length = int.from_bytes(payload[0:2], "big")
        if length == 0 or length > len(payload) - 2:
            # DNS over TCP messages spanning segments are not reassembled.
            self.bump("dns_messages_truncated")
            return
        self.dns(payload[2:2 + length], index, timestamp, endpoints, trailer)

    def probe(self, key, flow, payload, flags, index, timestamp, endpoints, trailer, *, sequence):
        state = self.probes.get(key)
        initial_syn = bool(flags & FLAG_SYN and not flags & FLAG_ACK)
        if state is None or (initial_syn and state["syn_sequence"] != sequence):
            if state is None and len(self.probes) >= self.max_flows:
                return
            state = {"kind": None, "buffer": bytearray(), "decided": False, "truncated": False,
                     "syn_sequence": sequence if initial_syn else None,
                     "next_sequence": (sequence + 1) & 0xFFFFFFFF if initial_syn else None,
                     "trailer": None}
            self.probes[key] = state
        if state["decided"] or not payload:
            return
        payload_sequence = (sequence + int(bool(flags & FLAG_SYN))) & 0xFFFFFFFF
        if state["next_sequence"] is not None:
            delta = ((payload_sequence - state["next_sequence"] + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            if delta > 0:
                state["decided"] = True
                state["buffer"].clear()
                flow["probe_truncated"] = True
                self.truncated = True
                self.bump("tcp_reassembly_gaps")
                return
            if delta < 0:
                overlap = min(-delta, len(payload))
                payload = payload[overlap:]
                payload_sequence = (payload_sequence + overlap) & 0xFFFFFFFF
                if not payload:
                    return
        state["next_sequence"] = (payload_sequence + len(payload)) & 0xFFFFFFFF
        if state["kind"] is None:
            if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
                state["kind"] = "tls"
            elif _HTTP_PREFIX.match(payload[:12]):
                state["kind"] = "http"
            else:
                state["decided"] = True
                return
            state["trailer"] = trailer
            flow["app_layer_hint"] = "tls_record" if state["kind"] == "tls" else "http_request"
        elif state["trailer"] != trailer:
            state["trailer"] = None
        room = PROBE_BUFFER - len(state["buffer"])
        if room <= 0:
            return
        state["buffer"].extend(payload[:room])
        if len(payload) > room:
            state["truncated"] = True
        if state["kind"] == "tls":
            self._tls(state, flow, index, timestamp, endpoints, state["trailer"])
        else:
            self._http(state, flow, index, timestamp, endpoints, state["trailer"])

    def _tls(self, state, flow, index, timestamp, endpoints, trailer):
        status, sni, flags = _client_hello(bytes(state["buffer"]))
        if status == "needmore":
            if state["truncated"]:
                state["decided"] = True
                state["buffer"] = bytearray()
                flow["probe_truncated"] = True
                self.bump("tls_sni_truncated")
            return
        state["decided"] = True
        state["buffer"] = bytearray()
        if status == "unsupported":
            self.bump("tls_probe_unsupported")
            return
        if status != "client_hello":
            return
        self.bump("tls_client_hellos")
        if flags["encrypted_client_hello"]:
            self.bump("tls_client_hellos_with_ech")
        if sni is None:
            self.bump("tls_client_hellos_without_sni")
            return
        name = _hostname(sni)
        if name is None:
            self.bump("invalid_hostnames")
            return
        flow["tls_sni"] = name
        self.observe("tls_sni", name, index=index, timestamp=timestamp, endpoints=endpoints,
                     trailer=trailer, ech=flags["encrypted_client_hello"])

    def _http(self, state, flow, index, timestamp, endpoints, trailer):
        status, host, method, path = _http_request(bytes(state["buffer"]))
        if status == "needmore":
            if state["truncated"]:
                state["decided"] = True
                state["buffer"] = bytearray()
                flow["probe_truncated"] = True
                self.bump("http_probes_truncated")
            return
        state["decided"] = True
        state["buffer"] = bytearray()
        if status == "truncated":
            # Request head longer than the bounded scan window: refused, never partially parsed.
            flow["probe_truncated"] = True
            self.bump("http_probes_truncated")
            return
        if status != "ok":
            return
        self.bump("http_requests")
        if method is not None:
            self.bump("http_request_lines")
        if host is None:
            return
        name = _hostname(host)
        if name is None:
            self.bump("invalid_hostnames")
            return
        flow["http_host"] = name
        self.bump("http_hosts")
        self.observe("http_host", name, index=index, timestamp=timestamp, endpoints=endpoints, trailer=trailer)
        if method is not None:
            self.request_line(name, method, path)

    def request_line(self, name, method, path):
        """Attach one decoded request line's method and origin-form path to its host entry.

        ``observe`` runs first for the same request, so a missing entry means the host bound
        dropped the name and the request line has no host identity to be reported against.
        """
        entry = self.hosts.get(name)
        if entry is None:
            return
        if "http_methods" not in entry:
            entry["http_methods"], entry["http_paths"] = [], []
            entry["http_methods_omitted"] = entry["http_paths_omitted"] = False
        if _bounded_add(entry["http_methods"], method.decode("ascii"), HTTP_VALUES_PER_HOST):
            entry["http_methods_omitted"] = True
            self.truncated = True
        if _bounded_add(entry["http_paths"], path.decode("ascii"), HTTP_VALUES_PER_HOST):
            entry["http_paths_omitted"] = True
            self.truncated = True

    # ------------------------------------------------------------ output

    def summary(self, header, reader, scanned_bytes, stopped):
        hosts = [self.hosts[name] for name in sorted(self.hosts)]
        flows = sorted(self.flows.values(),
                       key=lambda flow: (flow["ip_version"], flow["protocol"], flow["source_ip"],
                                         flow["source_port"], flow["destination_ip"], flow["destination_port"]))
        result = {
            "schema": SCHEMA, "tool": TOOL, "action": ACTION, "category": CATEGORY, "success": True,
            "input": {"sha256": reader.digest.hexdigest(), "size": reader.size},
            "format": {"container": "pcap", "byte_order": header["byte_order"], "version": header["version"],
                       "timestamp_resolution": header["resolution"], "snaplen": header["snaplen"],
                       "link_types": sorted(self.link_types), "record_length_bound": MAX_RECORD_BYTES},
            "packets_scanned": self.packets,
            "bytes_scanned": scanned_bytes,
            "scan_stopped": stopped,
            "truncated": bool(self.truncated or stopped != "complete"),
            "malformed_packets": self.count("malformed_packets"),
            "unsupported_packets": self.count("unsupported_packets"),
            "captured_packet_truncations": self.count("captured_packet_truncations"),
            "unsupported_link_types": self.unsupported_link_types,
            "unsupported_ethertypes": self.unsupported_ethertypes,
            "unsupported_ip_protocols": self.unsupported_protocols,
            "unsupported_values_omitted": {"link_types": self.unsupported_link_types_omitted,
                                           "ethertypes": self.unsupported_ethertypes_omitted,
                                           "ip_protocols": self.unsupported_protocols_omitted},
            "trailer": {"packets": self.count("trailer_packets"),
                        "checksum_mismatches": self.count("trailer_checksum_mismatches"),
                        "uid_values": self.trailer_uids, "uid_values_omitted": self.trailer_uids_omitted,
                        "package_hints": self.trailer_hints, "package_hints_omitted": self.trailer_hints_omitted,
                        "uid_unknown_packets": self.count("uid_unknown_packets"),
                        "invalid_package_hints": self.count("invalid_package_hints"),
                        "uid_packet_counts": self.uid_packet_counts,
                        "uid_packet_counts_omitted": self.uid_packet_counts_omitted,
                        "package_hint_truncation_possible": self.package_hint_truncation_possible},
            "flows_omitted": len(self.omitted_flow_keys),
            "flows_omitted_truncated": self.omitted_flow_keys_truncated,
            "unresolved_probe_streams": sum(1 for state in self.probes.values() if not state["decided"]),
            "first_timestamp": self.first_timestamp, "last_timestamp": self.last_timestamp,
            "duration_seconds": (round(self.last_timestamp - self.first_timestamp, 6)
                                 if self.first_timestamp is not None and self.last_timestamp is not None else None),
            "hosts": hosts, "flows": flows,
            "empty": not hosts and not flows,
            "limits": {"max_bytes": None, "max_packets": None, "max_hosts": self.max_hosts,
                       "max_flows": self.max_flows, "observations_per_host": OBSERVATIONS_PER_HOST,
                       "probe_buffer_bytes": PROBE_BUFFER, "http_head_bytes": HTTP_SCAN_BYTES,
                       "http_method_chars": MAX_HTTP_METHOD_CHARS, "http_path_chars": MAX_HTTP_PATH_CHARS,
                       "http_values_per_host": HTTP_VALUES_PER_HOST,
                       "dns_questions_per_message": MAX_DNS_QUESTIONS,
                       "dns_answers_per_message": MAX_DNS_ANSWERS,
                       "vlan_tags": MAX_VLAN_TAGS, "ipv6_extension_headers": MAX_IPV6_EXTENSION_HEADERS},
            "decryption_performed": False,
            "scope": SCOPE,
        }
        for name in COUNTER_NAMES:
            result[name] = self.count(name)
        return result


# ---------------------------------------------------------------- entry points


def analyze_file(path, *, max_bytes=DEFAULT_MAX_BYTES, max_packets=DEFAULT_MAX_PACKETS,
                 max_hosts=DEFAULT_MAX_HOSTS, max_flows=DEFAULT_MAX_FLOWS):
    """Analyze one classic PCAP file and return JSON-safe metadata.

    The whole file is hashed and sized even when a cap stops dissection. Framing
    errors (bad magic, partial header or record, unsupported PCAP variant) are
    refused with ``ForgeError`` instead of being accepted in part.
    """
    _bounded("max_bytes", max_bytes, MAX_FILE_BYTES)
    _bounded("max_packets", max_packets, MAX_PACKETS_LIMIT)
    _bounded("max_hosts", max_hosts, MAX_HOSTS_LIMIT)
    _bounded("max_flows", max_flows, MAX_FLOWS_LIMIT)
    stream = _open_input(path)
    try:
        reader = _Reader(stream)
        header = _file_header(reader)
        scan = _Scan(link_type=header["link_type"], max_hosts=max_hosts, max_flows=max_flows)
        scanned = FILE_HEADER
        stopped = "complete"
        while True:
            if scanned >= max_bytes:
                stopped = "max_bytes"
                break
            if scan.packets >= max_packets:
                stopped = "max_packets"
                break
            raw = reader.read(RECORD_HEADER)
            if not raw:
                break
            if len(raw) < RECORD_HEADER:
                raise ForgeError("PCAP file ends with a partial record header; it is truncated or still "
                                 "being written")
            seconds = int.from_bytes(raw[0:4], header["byte_order"])
            fraction = int.from_bytes(raw[4:8], header["byte_order"])
            incl_len = int.from_bytes(raw[8:12], header["byte_order"])
            orig_len = int.from_bytes(raw[12:16], header["byte_order"])
            scanned += RECORD_HEADER
            if incl_len > MAX_RECORD_BYTES:
                # Never allocate an attacker-declared record length: skip it in bounded chunks.
                remaining = incl_len
                while remaining:
                    block = reader.read(min(remaining, DRAIN_CHUNK))
                    if not block:
                        raise ForgeError("PCAP file ends inside a packet record; it is truncated or still "
                                         "being written")
                    remaining -= len(block)
                scanned += incl_len
                scan.packets += 1
                scan.bump("records_skipped_oversized")
                scan.bump("unsupported_packets")
                continue
            data = reader.read(incl_len) if incl_len else b""
            if len(data) < incl_len:
                raise ForgeError("PCAP file ends inside a packet record; it is truncated or still being written")
            scanned += incl_len
            scan.packet(data, scan.packets, _timestamp(seconds, fraction, header["resolution"]),
                        truncated=incl_len < orig_len, malformed_record=incl_len > orig_len)
        reader.drain()
        result = scan.summary(header, reader, scanned, stopped)
        result["limits"]["max_bytes"] = max_bytes
        result["limits"]["max_packets"] = max_packets
        return result
    finally:
        stream.close()


# ---------------------------------------------------------------- citations


def _citation_sha(value):
    if not isinstance(value, str) or not _SHA256.match(value.lower()):
        return None
    return value.lower()


def _decryption_requested(data):
    """True when one capture record declares that TLS decryption was requested.

    The declaration is a requested setting of the capturing app: a capture that never asked
    for TLS decryption cannot hold decrypted bytes, but asking for it is not evidence that any
    particular traffic was decrypted. The same request appears both as the record's
    ``decryption_requested`` evidence flag and as its ``settings.tls_decryption`` setting.
    """
    if data.get("decryption_requested") is True:
        return True
    settings = data.get("settings")
    if not isinstance(settings, dict):
        return False
    # The adb command line renders the setting as "true"; a parsed record keeps the Python bool.
    return settings.get("tls_decryption") in (True, "true")


def _capture_citation(store, evidence_id, path, digest):
    record = store.get(evidence_id)
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    if record["kind"] != "runtime" or data.get("tool") != "pcapdroid" or data.get("action") != "capture":
        raise ForgeError(f"--capture-evidence {evidence_id} must cite a runtime pcapdroid capture record")
    if data.get("success") is not True:
        raise ForgeError(f"--capture-evidence {evidence_id} is not a successful capture")
    capture = data.get("capture")
    if not isinstance(capture, dict):
        raise ForgeError(f"--capture-evidence {evidence_id} has no retrieved capture metadata")
    sha256 = _citation_sha(capture.get("sha256"))
    size = capture.get("size")
    stored_path = capture.get("path")
    if sha256 is None or type(size) is not int or size < 0:
        raise ForgeError(f"--capture-evidence {evidence_id} capture metadata has no valid SHA256 and size")
    if not isinstance(stored_path, str) or not stored_path:
        raise ForgeError(f"--capture-evidence {evidence_id} capture metadata has no local path")
    if sha256 != digest["sha256"]:
        raise ForgeError("PCAP bytes changed after the captured evidence was recorded: SHA256 differs from "
                         f"--capture-evidence {evidence_id}")
    if size != digest["size"]:
        raise ForgeError("PCAP bytes changed after the captured evidence was recorded: size differs from "
                         f"--capture-evidence {evidence_id}")
    stored = Path(stored_path)
    if not stored.is_absolute():
        stored = store.root / stored
    if stored.resolve() != Path(path).resolve():
        raise ForgeError("Analyzed file is not the file recorded by --capture-evidence " + evidence_id)
    overrun = sorted(name for name in CAPTURE_TRUNCATION_FLAGS if data.get(name) is True)
    return {"evidence_id": record["id"], "path": stored_path, "sha256": sha256, "size": size,
            "package": data.get("package") if isinstance(data.get("package"), str) else None,
            "target_uid": data.get("target_uid") if type(data.get("target_uid")) is int else None,
            "capture_empty": data.get("empty") if isinstance(data.get("empty"), bool) else None,
            "decryption_requested": _decryption_requested(data),
            "sha256_matches": True, "size_matches": True, "path_matches": True,
            "capture_truncation_flags": overrun,
            "capture_truncated": bool(overrun),
            "note": "The capture record is the caller's own runtime evidence. The app filter is a requested "
                    "setting, so the file name and the filter are not proof that a packet belongs to the "
                    "target package; only per-packet trailer UID claims are counted. PCAP trailer UID and "
                    "package hint values remain file claims, and a 19-character package hint is never "
                    "treated as a full package name."}


def _uid_attribution(metadata, target_uid):
    """Split observed names and flows by their per-packet trailer UID claim."""
    observations = {"target": 0, "other": 0, "unknown": 0}
    for entry in metadata["hosts"]:
        for observation in entry["observations"]:
            uid = observation["uid"]
            if uid is None:
                observations["unknown"] += 1
            elif uid == target_uid:
                observations["target"] += 1
            else:
                observations["other"] += 1
    packets = {"target": 0, "other": 0, "unknown": 0}
    counts = metadata["trailer"]["uid_packet_counts"]
    packets["target"] = counts.get(str(target_uid), 0)
    packets["other"] = sum(counts.values()) - packets["target"]
    packets["unknown"] = metadata["packets_scanned"] - sum(counts.values())
    return {"target_uid": target_uid,
            "basis": "per-packet PCAPdroid trailer UID claims; omitted or absent UID claims remain unknown",
            "observations": observations, "flow_packets": packets,
            "note": "The capture app filter is a requested setting, not proof: name observations and flows "
                    "without a trailer UID claim, or with a different UID, are counted as unknown or other "
                    "traffic and are never attributed to the target package. A 19-character package hint is a "
                    "truncated claim and is not used for attribution."}


def _verify_index(store, record, data):
    index_id = data.get("index_evidence_id")
    if not isinstance(index_id, str) or not index_id:
        raise ForgeError(f"Map evidence {record['id']} does not cite the static index it was built from")
    expected = _citation_sha(data.get("index_sha256"))
    if expected is None:
        raise ForgeError(f"Map evidence {record['id']} has no valid static index SHA256")
    index_record = store.get(index_id)
    index_data = index_record.get("data") if isinstance(index_record.get("data"), dict) else {}
    if index_record["kind"] != "analysis" or index_data.get("tool") != "static_index":
        raise ForgeError(f"Map evidence {record['id']} cites {index_id}, which is not a static_index record")
    expected_size = index_data.get("index_size")
    if type(expected_size) is not int or expected_size < 0:
        raise ForgeError(f"Static index evidence {index_id} has no valid recorded size")
    stored = index_data.get("path")
    if not isinstance(stored, str) or not stored:
        raise ForgeError(f"Static index evidence {index_id} has no local path")
    resolved = Path(stored)
    if not resolved.is_absolute():
        resolved = store.root / resolved
    resolved = resolved.resolve()
    try:
        resolved.relative_to(store.root.resolve())
    except ValueError as error:
        raise ForgeError(f"Static index evidence {index_id} is outside the project directory") from error
    if expected_size > MAX_INDEX_VERIFY_BYTES:
        raise ForgeError(f"Static index for {record['id']} is larger than the {MAX_INDEX_VERIFY_BYTES}-byte "
                         "re-verification limit")
    try:
        info = resolved.lstat()
    except OSError as error:
        raise ForgeError(f"Static index cited by {record['id']} is no longer available: {error}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ForgeError(f"Static index cited by {record['id']} is not a regular file")
    digest = hashlib.sha256()
    size = 0
    with resolved.open("rb") as stream:
        while size <= expected_size:
            block = stream.read(DRAIN_CHUNK)
            if not block:
                break
            size += len(block)
            digest.update(block)
    if size != expected_size or digest.hexdigest() != expected:
        raise ForgeError(f"Static index bytes changed after the API map {record['id']} was recorded")
    if index_data.get("index_sha256") != expected:
        raise ForgeError(f"API map {record['id']} and static index {index_id} disagree on the index SHA256")
    return {"evidence_id": record["id"], "index_evidence_id": index_id,
            "index_sha256": expected, "index_size": expected_size, "index_verified": True}


def _static_matches(store, evidence_ids, hosts):
    observed = {entry["hostname"] for entry in hosts}
    matches = {}
    citations = []
    for evidence_id in dict.fromkeys(evidence_ids):
        record = store.get(evidence_id)
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        if record["kind"] != "analysis" or data.get("tool") != "android" or data.get("action") != "api-map":
            raise ForgeError(f"--map-evidence {evidence_id} must cite an android api-map analysis record")
        if data.get("success") is not True:
            raise ForgeError(f"--map-evidence {evidence_id} is not a successful api-map analysis")
        provenance = _verify_index(store, record, data)
        candidates = data.get("api_candidates")
        if not isinstance(candidates, list):
            raise ForgeError(f"--map-evidence {evidence_id} has no api_candidates list")
        scanned = 0
        unusable = 0
        found = 0
        for candidate in candidates[:MAX_MAP_CANDIDATES]:
            if not isinstance(candidate, dict):
                unusable += 1
                continue
            url = candidate.get("url")
            hostname = None
            if isinstance(url, str):
                try:
                    hostname = _hostname(urlsplit(url).hostname or "")
                except ValueError:
                    hostname = None
            candidate_sha = _citation_sha(candidate.get("url_sha256"))
            if hostname is None or candidate_sha is None:
                unusable += 1
                continue
            scanned += 1
            if hostname not in observed:
                continue
            found += 1
            matches.setdefault((hostname, candidate_sha), []).append(record["id"])
        citations.append({**provenance, "candidates": len(candidates), "exact_host_bearing_candidates": scanned,
                          "candidates_without_hostname_or_hash": unusable,
                          "candidates_omitted": max(0, len(candidates) - MAX_MAP_CANDIDATES),
                          "exact_hostname_matches": found})
    ordered = sorted(matches.items(), key=lambda item: (item[0][0], item[0][1]))
    entries = [{"hostname": hostname, "static_candidate_sha256": candidate_sha,
                "category": "static_host_match", "evidence_ids": sorted(set(ids))}
               for (hostname, candidate_sha), ids in ordered[:MAX_STATIC_MATCHES]]
    return entries, citations, len(ordered) > MAX_STATIC_MATCHES


def pcap_analyze(args, store):
    for name, value, maximum in (("max-bytes", args.max_bytes, MAX_FILE_BYTES),
                                 ("max-packets", args.max_packets, MAX_PACKETS_LIMIT),
                                 ("max-hosts", args.max_hosts, MAX_HOSTS_LIMIT),
                                 ("max-flows", args.max_flows, MAX_FLOWS_LIMIT)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ForgeError(f"--{name} must be an integer from 1 to {maximum}")
    path = _input_path(store, args.path)
    metadata = analyze_file(path, max_bytes=args.max_bytes, max_packets=args.max_packets,
                            max_hosts=args.max_hosts, max_flows=args.max_flows)
    evidence_ids = []
    if args.capture_evidence:
        citation = _capture_citation(store, args.capture_evidence, path, metadata["input"])
        metadata["capture"] = citation
        evidence_ids.append(args.capture_evidence)
        metadata["decryption_performed"] = bool(citation["decryption_requested"] and
                                                metadata["http_request_lines"] > 0)
        metadata["decryption_basis"] = {"decryption_requested": citation["decryption_requested"],
                                        "http_request_lines": metadata["http_request_lines"],
                                        "rule": DECRYPTION_RULE}
        if citation["capture_truncated"]:
            # The capture itself reported a size overrun, so this file is not the whole session.
            metadata["truncated"] = True
        if citation["target_uid"] is not None:
            metadata["uid_attribution"] = _uid_attribution(metadata, citation["target_uid"])
    if args.map_evidence:
        entries, citations, omitted = _static_matches(store, args.map_evidence, metadata["hosts"])
        metadata["static_host_matches"] = entries
        metadata["map_citations"] = citations
        metadata["static_host_match_note"] = STATIC_MATCH_NOTE
        metadata["truncated"] = metadata["truncated"] or omitted
        for citation in citations:
            evidence_ids.append(citation["evidence_id"])
    if evidence_ids:
        metadata["evidence_ids"] = list(dict.fromkeys(evidence_ids))
    return store.add("analysis", metadata)


def _input_path(store, value):
    text = str(value)
    if not text or "\x00" in text:
        raise ForgeError("PCAP input path is empty or invalid")
    if text.startswith("\\\\") or text.startswith("//"):
        raise ForgeError("PCAP input cannot be a UNC path or network share")
    body = text[2:] if re.match(r"^[A-Za-z]:", text) else text
    if ":" in body:
        raise ForgeError("PCAP input path cannot address an alternate data stream")
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = store.root / path
    try:
        resolved = path.resolve()
    except OSError as error:
        raise ForgeError(f"PCAP input path cannot be resolved: {error}") from error
    try:
        info = resolved.lstat()
    except OSError as error:
        raise ForgeError(f"Cannot read PCAP input: {error}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ForgeError("PCAP input must be a regular file, not a symlink, directory or device")
    return resolved


def register(subparsers):
    parser = subparsers.add_parser("pcap-analyze",
                                   help="Report bounded host and connection metadata from an explicit "
                                        "classic PCAP without decrypting payloads")
    parser.add_argument("path", help="Classic PCAP file; project-relative or absolute local path")
    parser.add_argument("--capture-evidence", metavar="ID",
                        help="Runtime pcapdroid capture record this file must match (SHA256, size and path)")
    parser.add_argument("--map-evidence", action="append", default=[], metavar="ID",
                        help="Successful android api-map analysis record; repeatable")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"Maximum capture bytes dissected (1..{MAX_FILE_BYTES}, default: "
                             f"{DEFAULT_MAX_BYTES}); the whole file is still hashed")
    parser.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS,
                        help=f"Maximum packet records dissected (1..{MAX_PACKETS_LIMIT}, default: "
                             f"{DEFAULT_MAX_PACKETS})")
    parser.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
                        help=f"Maximum distinct host names retained (1..{MAX_HOSTS_LIMIT}, default: "
                             f"{DEFAULT_MAX_HOSTS})")
    parser.add_argument("--max-flows", type=int, default=DEFAULT_MAX_FLOWS,
                        help=f"Maximum directional flows retained (1..{MAX_FLOWS_LIMIT}, default: "
                             f"{DEFAULT_MAX_FLOWS})")
    parser.set_defaults(handler=pcap_analyze)
