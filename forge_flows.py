"""Read decrypted flow dumps, emit HAR, and decode gRPC endpoints.

A capture that asks PCAPdroid for TLS decryption writes decrypted requests to mitmproxy, not into
the PCAP file. PCAPdroid can hand mitmproxy extra options, so `pcapdroid-capture --tls-decryption
--mitmproxy-opts "-w <path>"` makes the addon write a flow dump the operator can pull back.

Those dumps are concatenated tnetstring frames, one HTTPFlow state per frame, so this module reads
them with the standard library alone (`--reader builtin`, the default). mitmproxy stays an optional
fallback reader for dumps the builtin parser rejects (`--reader mitmproxy`). `flow-to-har` turns a
dump into a HAR document that `har-import` normalizes, redacts and cites; `grpc-analyze` splits
gRPC-web frames and decodes schema-less protobuf field trees so the endpoints behind a mobile API
are readable before anyone writes a checker.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote

from forge_core import ForgeError

SCHEMA = "forge.flows/v1"
GRPC_SCHEMA = "forge.grpc/v1"
TOOL = "mitmproxy"
ACTION = "flow-to-har"
GRPC_ACTION = "grpc-analyze"
HAR_VERSION = "1.2"
CREATOR = {"name": "forge-flow-to-har", "version": "1"}
READERS = ("builtin", "mitmproxy")
MAX_FLOWS = 100000
MAX_BODY_BYTES = 64 * 1024 * 1024
MAX_DUMP_BYTES = 1024 * 1024 * 1024
MAX_FRAME_BYTES = 256 * 1024 * 1024
MAX_LENGTH_DIGITS = 12
GRPC_NODES_PER_FLOW = 200
GRPC_DEPTH_CAP = 6
GRPC_VALUE_CHARS = 64
GRPC_FRAMES_PER_FLOW = 256
GRPC_FLAG_TRAILERS = 0x80
GRPC_FLAG_COMPRESSED = 0x01

SETUP_HINT = ("--reader mitmproxy needs the optional mitmproxy reader: install the optional extra "
              "(python -m pip install 'forge-protocol[flows]') and retry, or drop --reader to use the "
              "builtin tnetstring reader")
PARSE_HINT = ("the dump is not a tnetstring flow dump; re-pull the file from the device and retry, or "
              "use --reader mitmproxy when it was written as HAR or by an incompatible mitmproxy version")
SCOPE = ("Decrypted requests observed by a local mitmproxy instance in a repackaged or user-trusted "
         "client only. Import the HAR with har-import; this command makes no network calls, the dump may "
         "hold private bodies, and bodies that are not UTF-8 text are stored base64-encoded so nothing is "
         "silently mangled.")
GRPC_SCOPE = ("Schema-less wire decode of captured gRPC-web frames: numbers are wire field numbers, not "
              "names, and repeated numbers keep capture order. A length-delimited payload is expanded as a "
              "nested message only when it parses completely as one; 'str(len= sha256=)' is text withheld for "
              "length, 'bytes(...)' is not UTF-8 text, 'deeper(...)' was not expanded because of the depth cap, "
              "and a trailing '…' marks a message cut short by the node cap. 'len=' counts characters for text "
              "and bytes for opaque values; sha256 covers the raw bytes. Field trees are captured traffic: "
              "treat them as private and re-derive credentials live.")

_STREAM_END = object()

# tnetstring type tags, as written by mitmproxy.io.tnetstring.
_TAG_BYTES = 0x2C  # ,
_TAG_STRING = 0x3B  # ;
_TAG_INT = 0x23  # #
_TAG_FLOAT = 0x5E  # ^
_TAG_BOOL = 0x21  # !
_TAG_NULL = 0x7E  # ~
_TAG_LIST = 0x5D  # ]
_TAG_DICT = 0x7D  # }

_WIRE_VARINT = 0
_WIRE_FIXED64 = 1
_WIRE_LENGTH = 2
_WIRE_FIXED32 = 5

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class TnetstringError(ValueError):
    """One frame is not a well-formed tnetstring."""


class _WireError(ValueError):
    """One protobuf field does not parse."""


def _text(value):
    """Byte-preserving decode: dump strings are percent-encoded ASCII, so latin-1 never raises."""
    return value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else str(value)


# --------------------------------------------------------------------------- tnetstring


def tns_dumps(value):
    """Serialise one value as a tnetstring frame; the exact inverse of the builtin reader."""
    if value is None:
        return b"0:~"
    if value is True:
        return b"4:true!"
    if value is False:
        return b"5:false!"
    if isinstance(value, (bytes, bytearray)):
        payload, tag = bytes(value), b","
    elif isinstance(value, str):
        payload, tag = value.encode("utf-8"), b";"
    elif isinstance(value, int):
        payload, tag = str(value).encode("ascii"), b"#"
    elif isinstance(value, float):
        payload, tag = repr(value).encode("ascii"), b"^"
    elif isinstance(value, (list, tuple)):
        payload, tag = b"".join(tns_dumps(item) for item in value), b"]"
    elif isinstance(value, dict):
        payload, tag = b"".join(tns_dumps(key) + tns_dumps(item) for key, item in value.items()), b"}"
    else:
        raise ForgeError("tnetstring writer needs ints, floats, strings, bytes, booleans, lists or dicts, "
                         f"not {type(value).__name__}")
    return b"%d:" % len(payload) + payload + tag


def _length_prefix(data, index):
    """Parse `<digits>:` at `index`; return (length, index after the colon)."""
    end = index
    while end < len(data) and 0x30 <= data[end] <= 0x39:
        end += 1
        if end - index > MAX_LENGTH_DIGITS:
            raise TnetstringError(f"length prefix longer than {MAX_LENGTH_DIGITS} digits")
    if end == index:
        raise TnetstringError("missing length prefix")
    if end >= len(data) or data[end] != 0x3A:
        raise TnetstringError("length prefix is not terminated by ':'")
    return int(data[index:end]), end + 1


def _decode(payload, tag):
    """Decode one tnetstring value from its payload bytes and type tag."""
    if tag == _TAG_BYTES:
        return payload
    if tag == _TAG_STRING:
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise TnetstringError("string payload is not valid UTF-8") from error
    if tag == _TAG_INT:
        try:
            return int(payload)
        except ValueError as error:
            raise TnetstringError(f"invalid integer payload {bytes(payload[:16])!r}") from error
    if tag == _TAG_FLOAT:
        try:
            return float(payload)
        except ValueError as error:
            raise TnetstringError(f"invalid float payload {bytes(payload[:16])!r}") from error
    if tag == _TAG_BOOL:
        if payload == b"true":
            return True
        if payload == b"false":
            return False
        raise TnetstringError(f"invalid boolean payload {bytes(payload[:16])!r}")
    if tag == _TAG_NULL:
        if payload:
            raise TnetstringError("null payload is not empty")
        return None
    if tag == _TAG_LIST:
        items, cursor = [], 0
        while cursor < len(payload):
            item, cursor = _nested(payload, cursor)
            items.append(item)
        return items
    if tag == _TAG_DICT:
        items, cursor = {}, 0
        while cursor < len(payload):
            key, cursor = _nested(payload, cursor)
            item, cursor = _nested(payload, cursor)
            items[key] = item
        return items
    raise TnetstringError(f"unknown type tag {bytes([tag])!r}")


def _nested(data, index):
    """Parse the value starting at `index`; return (value, index after it)."""
    length, cursor = _length_prefix(data, index)
    end = cursor + length
    if end >= len(data):
        raise TnetstringError(f"declared {length} payload bytes, {len(data) - cursor} available")
    return _decode(data[cursor:end], data[end]), end + 1


def tns_loads(data):
    """Parse exactly one tnetstring frame from `data`, rejecting trailing bytes."""
    value, index = _nested(data, 0)
    if index != len(data):
        raise TnetstringError(f"{len(data) - index} bytes follow one complete frame")
    return value


class _DumpReader:
    """Stream the concatenated tnetstring frames of a mitmproxy dump, one frame at a time.

    A malformed frame ends iteration and is reported through `frames_skipped` and `parse_error`
    instead of raising, so a capture killed mid-write still converts every completely written flow.
    Reads stop at `limit` bytes; that is reported as `truncated` by the caller.
    """

    def __init__(self, stream, limit=MAX_DUMP_BYTES):
        self._stream = stream
        self._remaining = limit
        self.frames_read = 0
        self.frames_skipped = 0
        self.parse_error = None
        self.bytes_read = 0

    def _read(self, size):
        if self._remaining <= 0:
            return b""
        chunk = self._stream.read(min(size, self._remaining))
        self._remaining -= len(chunk)
        self.bytes_read += len(chunk)
        return chunk

    def _read_exactly(self, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = self._read(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _frame(self):
        digits = bytearray()
        while True:
            char = self._read(1)
            if not char:
                if not digits:
                    return _STREAM_END
                raise TnetstringError("length prefix is truncated")
            if char == b":":
                break
            if not char.isdigit():
                raise TnetstringError(f"length prefix byte {char!r} is not a digit")
            digits += char
            if len(digits) > MAX_LENGTH_DIGITS:
                raise TnetstringError(f"length prefix longer than {MAX_LENGTH_DIGITS} digits")
        if not digits:
            raise TnetstringError("missing length prefix")
        length = int(digits)
        if length > MAX_FRAME_BYTES:
            raise TnetstringError(f"frame declares {length} payload bytes, above the "
                                  f"{MAX_FRAME_BYTES}-byte frame cap")
        payload = self._read_exactly(length)
        if len(payload) != length:
            raise TnetstringError(f"frame declares {length} payload bytes, {len(payload)} available")
        tag = self._read(1)
        if not tag:
            raise TnetstringError(f"frame of {length} payload bytes is missing its type tag")
        return _decode(payload, tag[0])

    def frames(self):
        """Yield parsed frames until the stream ends or the first frame fails to parse."""
        while True:
            try:
                frame = self._frame()
            except TnetstringError as error:
                self.frames_skipped += 1
                self.parse_error = str(error)
                return
            if frame is _STREAM_END:
                return
            self.frames_read += 1
            yield frame


# --------------------------------------------------------------------------- flow views


class _Pairs:
    """Ordered name/value pairs with case-insensitive HAR-style lookup."""

    __slots__ = ("_rows",)

    def __init__(self, rows=()):
        self._rows = [(name, value) for name, value in rows]

    def items(self):
        return list(self._rows)

    def get(self, name, default=None):
        wanted = _text(name).lower()
        for candidate, value in self._rows:
            if _text(candidate).lower() == wanted:
                return _text(value)
        return default


class _MessageView:
    """A dump request or response reduced to the fields HAR assembly and gRPC decoding read."""

    __slots__ = ("method", "pretty_url", "headers", "content", "query", "timestamp_start", "trailers",
                 "status_code", "reason", "http_version", "path", "scheme", "host", "port", "authority")

    def __init__(self, **fields):
        for name in self.__slots__:
            setattr(self, name, fields.get(name))


class _FlowView:
    """One flow read from a dump, exposing only what the commands use."""

    __slots__ = ("request", "response", "websocket")

    def __init__(self, request, response, websocket):
        self.request = request
        self.response = response
        self.websocket = websocket


def _pairs(rows):
    pairs = []
    for row in rows or ():
        if isinstance(row, (list, tuple)) and len(row) == 2:
            pairs.append((row[0], row[1]))
    return _Pairs(pairs)


def _body_bytes(value):
    return bytes(value) if isinstance(value, (bytes, bytearray)) else b""


def _http_version(value):
    text = _text(value) if value else "HTTP/2.0"
    return "HTTP/2" if text.startswith("HTTP/2") else text


def _split_authority(authority):
    host, _, port = authority.rpartition(":")
    if not host or not port.isdigit():
        return authority, 0
    return host, int(port)


def _host_header(method, http_version, authority, headers):
    """The host/authority the client asked for, not the socket address it reached."""
    if method == "CONNECT" or http_version.startswith("HTTP/2") or http_version.startswith("HTTP/3"):
        return authority or (headers.get("Host", "") or "")
    return headers.get("Host", "") or ""


def _pretty_url(method, scheme, authority, host, port, path):
    """Rebuild the requested URL: authority/host header first, socket host as the last resort."""
    if method == "CONNECT":
        return authority or (f"{host}:{port}" if host else "")
    if authority:
        pretty_host, pretty_port = _split_authority(authority)
    else:
        pretty_host, pretty_port = host, port
    if not pretty_port:
        pretty_port = _DEFAULT_PORTS.get(scheme) or 443
    if pretty_port != _DEFAULT_PORTS.get(scheme):
        pretty_host = f"{pretty_host}:{pretty_port}"
    return f"{scheme}://{pretty_host}{path}"


def _query(url):
    query = url.split("?", 1)[1].split("#", 1)[0] if "?" in url else ""
    return _Pairs(parse_qsl(query, keep_blank_values=True))


def _request_view(state):
    method = _text(state.get("method", "")).upper()
    scheme = _text(state.get("scheme", "")) or "http"
    authority = _text(state.get("authority", ""))
    host = _text(state.get("host", ""))
    port = state.get("port") if isinstance(state.get("port"), int) else 0
    path = _text(state.get("path", ""))
    path = "" if path == "*" else path
    http_version = _http_version(state.get("http_version"))
    headers = _pairs(state.get("headers"))
    url = _pretty_url(method, scheme, _host_header(method, http_version, authority, headers), host, port, path)
    return _MessageView(method=method, pretty_url=url, headers=headers,
                        content=_body_bytes(state.get("content")), query=_query(url),
                        timestamp_start=state.get("timestamp_start") or 0,
                        trailers=_pairs(state.get("trailers")), http_version=http_version,
                        path=path, scheme=scheme, host=host, port=port, authority=authority)


def _response_view(state):
    if not isinstance(state, dict):
        return None
    return _MessageView(method=None, pretty_url=None, headers=_pairs(state.get("headers")),
                        content=_body_bytes(state.get("content")), query=None,
                        timestamp_start=state.get("timestamp_start") or 0,
                        trailers=_pairs(state.get("trailers")), status_code=state.get("status_code") or 0,
                        reason=_text(state.get("reason", "")), http_version=_http_version(state.get("http_version")),
                        path=None, scheme=None, host=None, port=0, authority=None)


def _flow_view(state):
    """Reduce one dump frame to a request/response pair, or None when it is not an http flow."""
    if not isinstance(state, dict) or _text(state.get("type", "")).lower() != "http":
        return None
    request_state = state.get("request")
    if not isinstance(request_state, dict):
        return None
    return _FlowView(request=_request_view(request_state), response=_response_view(state.get("response")),
                     websocket=bool(state.get("websocket")))


def _new_stats(reader):
    return {"reader": reader, "frames_read": 0, "frames_skipped": 0, "parse_error": None,
            "dump_bytes": 0, "dump_truncated": False}


def _mitmproxy_flows(source):
    try:
        from mitmproxy import io as mitm_io  # optional dependency, imported only for --reader mitmproxy
    except ImportError as error:
        raise ForgeError(SETUP_HINT) from error
    with source.open("rb") as stream:
        try:
            yield from mitm_io.FlowReader(stream).stream()
        except Exception as error:  # mitmproxy raises its own FlowReadException types
            raise ForgeError(f"flow dump could not be read with mitmproxy: {error}") from error


def _read_flows(source, reader, stats):
    """Yield flow views from `source`, recording the reader's format counters into `stats`."""
    stats["dump_bytes"] = source.stat().st_size
    stats["dump_truncated"] = stats["dump_bytes"] > MAX_DUMP_BYTES
    if reader == "mitmproxy":
        stats["reader"] = "mitmproxy"
        for flow in _mitmproxy_flows(source):
            stats["frames_read"] += 1
            view = _flow_view(flow.get_state())  # mitmproxy objects and dumps share one view path
            if view is not None:
                yield view
        return
    stats["reader"] = "builtin"
    with source.open("rb") as stream:
        dump = _DumpReader(stream)
        try:
            for frame in dump.frames():
                view = _flow_view(frame)
                if view is not None:
                    yield view
        finally:
            stats["frames_read"] = dump.frames_read
            stats["frames_skipped"] = dump.frames_skipped
            stats["parse_error"] = dump.parse_error


def _require_parsed(stats):
    """A dump whose very first frame is unreadable is reported, not converted into an empty HAR."""
    if stats["frames_read"] == 0 and stats["frames_skipped"]:
        raise ForgeError(f"flow dump could not be parsed: {stats['parse_error']}; {PARSE_HINT}")


# --------------------------------------------------------------------------- HAR


def _headers(message):
    if message is None:
        return []
    return [{"name": _text(name), "value": _text(value)} for name, value in message.headers.items()]


def _header(message, name):
    return _text(message.headers.get(name, "") or "") if message is not None else ""


def _body_text(raw):
    """Return (har_text, encoding): anything that is not UTF-8 text keeps its bytes as base64."""
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return base64.b64encode(raw).decode("ascii"), "base64"


def _entry(request, response, body_limit):
    """Build one HAR entry from a request/response pair, bounded by body_limit bytes."""
    request_body = bytes(getattr(request, "content", b"") or b"")[:body_limit]
    response_body = bytes(getattr(response, "content", b"") or b"") if response is not None else b""
    truncated = len(response_body) > body_limit
    response_body = response_body[:body_limit]
    request_text, request_encoding = _body_text(request_body)
    response_text, response_encoding = _body_text(response_body)
    content = {"size": len(response_body), "mimeType": _header(response, "content-type"), "text": response_text}
    if response_encoding:
        content["encoding"] = response_encoding
    entry = {
        "startedDateTime": datetime.fromtimestamp(getattr(request, "timestamp_start", 0) or 0,
                                                  timezone.utc).isoformat(),
        "time": 0,
        "request": {
            "method": _text(request.method),
            "url": _text(request.pretty_url),
            "httpVersion": getattr(request, "http_version", None) or "HTTP/2",
            "cookies": [],
            "headers": _headers(request),
            "queryString": [{"name": _text(name), "value": _text(value)}
                            for name, value in request.query.items()],
            "headersSize": -1,
            "bodySize": len(request_body),
        },
        "response": {
            "status": int(getattr(response, "status_code", 0) or 0) if response is not None else 0,
            "statusText": _text(getattr(response, "reason", "") or "") if response is not None else "",
            "httpVersion": getattr(response, "http_version", None) or "HTTP/2",
            "cookies": [],
            "headers": _headers(response),
            "content": content,
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(response_body),
        },
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }
    if request_body:
        post = {"mimeType": _header(request, "content-type") or "application/octet-stream", "text": request_text}
        if request_encoding:
            post["encoding"] = request_encoding
        entry["request"]["postData"] = post
    entry["response"]["_forge_body_truncated"] = truncated
    return entry


def flow_to_har(args, store):
    source = _input(store, args.path)
    if not source.is_file():
        raise ForgeError("flow-to-har requires one regular project-local flow dump file")
    if not 1 <= args.limit <= MAX_FLOWS:
        raise ForgeError(f"--limit must be between 1 and {MAX_FLOWS}")
    if not 1 <= args.max_body_bytes <= MAX_BODY_BYTES:
        raise ForgeError(f"--max-body-bytes must be between 1 and {MAX_BODY_BYTES}")
    output = _new_output(store, args.output)
    stats = _new_stats(args.reader)
    entries, skipped, truncated, encoded = [], 0, 0, 0
    for flow in _read_flows(source, args.reader, stats):
        if flow.request is None or len(entries) >= args.limit:
            skipped += 1
            continue
        entry = _entry(flow.request, flow.response, args.max_body_bytes)
        truncated += bool(entry["response"]["_forge_body_truncated"])
        encoded += int("encoding" in entry["response"]["content"])
        encoded += int("encoding" in entry["request"].get("postData", {}))
        entries.append(entry)
    document = {"log": {"version": HAR_VERSION, "creator": CREATOR, "entries": entries}}
    _require_parsed(stats)  # never publish a HAR from a dump the reader rejected outright
    output.write_text(json.dumps(document), encoding="utf-8")
    record = {
        "schema": SCHEMA, "tool": TOOL, "action": ACTION, "success": True,
        "input": _relative(store, source), "output_path": _relative(store, output),
        "flows": len(entries), "flows_skipped": skipped,
        "bodies_truncated": truncated, "bodies_encoded": encoded,
        "limit": args.limit, "max_body_bytes": args.max_body_bytes,
        "output_sha256": _hash_file(output),
        "scope": SCOPE,
    }
    record.update(stats)
    return store.add("analysis", record)


# --------------------------------------------------------------------------- gRPC


def _varint(data, index):
    value = 0
    shift = 0
    while index < len(data):
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, index
        shift += 7
        if shift > 63:
            raise _WireError("varint longer than 10 bytes")
    raise _WireError("varint is truncated")


def _take(data, index, size):
    if index + size > len(data):
        raise _WireError(f"declared {size} bytes, {len(data) - index} available")
    return data[index:index + size]


def _printable(payload):
    """Return the text when the payload is UTF-8 without control characters, else None."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def _utf8(payload):
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _opaque(payload):
    return f"len={len(payload)} sha256={hashlib.sha256(payload).hexdigest()}"


class _Proto:
    """Decode one flow's protobuf payloads into bounded field trees without a schema."""

    def __init__(self, nodes=GRPC_NODES_PER_FLOW, depth=GRPC_DEPTH_CAP, value_chars=GRPC_VALUE_CHARS):
        self.nodes_cap = nodes
        self.depth_cap = depth
        self.value_chars = value_chars
        self.nodes = 0
        self.nodes_capped = 0
        self.depth_capped = 0
        self.withheld_values = 0

    def render(self, data):
        """Render one payload as a field tree; return (tree, complete)."""
        return self._render(data, 1)

    def _render(self, data, depth):
        fields = []
        index = 0
        while index < len(data):
            if self.nodes >= self.nodes_cap:
                self.nodes_capped += 1
                fields.append("…")
                return ",".join(fields), True
            try:
                field, index = self._field(data, index, depth)
            except _WireError:
                fields.append("…")
                return ",".join(fields), False
            fields.append(field)
            self.nodes += 1
        return ",".join(fields), True

    def _try_nested(self, payload, depth):
        """Render `payload` as a nested message, restoring the budget when it does not parse."""
        nodes, capped, withheld = self.nodes, self.nodes_capped, self.withheld_values
        tree, complete = self._render(payload, depth)
        if not complete:
            self.nodes, self.nodes_capped, self.withheld_values = nodes, capped, withheld
            return None
        return tree

    def _delimited(self, payload, depth):
        text = _printable(payload)
        if text is not None:
            return self._quoted(payload, text)
        if depth < self.depth_cap:
            nested = self._try_nested(payload, depth + 1)
            if nested is not None:
                return "{" + nested + "}"
        else:
            self.depth_capped += 1
            return f"deeper({_opaque(payload)})"
        text = _utf8(payload)
        if text is not None:
            return self._quoted(payload, text)
        return f"bytes({_opaque(payload)})"

    def _quoted(self, payload, text):
        if len(text) <= self.value_chars:
            return json.dumps(text, ensure_ascii=False)
        self.withheld_values += 1
        return f"str(len={len(text)} sha256={hashlib.sha256(payload).hexdigest()})"

    def _field(self, data, index, depth):
        key, index = _varint(data, index)
        number, wire = key >> 3, key & 0x07
        if number == 0:
            raise _WireError("field number 0")
        if wire == _WIRE_VARINT:
            value, index = _varint(data, index)
            return f"{number}:{value}", index
        if wire == _WIRE_FIXED64:
            return f"{number}:{int.from_bytes(_take(data, index, 8), 'little')}", index + 8
        if wire == _WIRE_FIXED32:
            return f"{number}:{int.from_bytes(_take(data, index, 4), 'little')}", index + 4
        if wire == _WIRE_LENGTH:
            length, index = _varint(data, index)
            payload = _take(data, index, length)
            return f"{number}:{self._delimited(payload, depth)}", index + length
        raise _WireError(f"wire type {wire}")


def _frames(body, counters):
    """Split one direction's body into gRPC-web frames: flag byte + 4-byte big-endian length."""
    frames, index, partial = [], 0, False
    while index < len(body):
        if len(frames) >= GRPC_FRAMES_PER_FLOW:
            counters["frames_capped"] += 1
            partial = True
            break
        if len(body) - index < 5:
            partial = True
            break
        flag = body[index]
        length = int.from_bytes(body[index + 1:index + 5], "big")
        start = index + 5
        end = start + length
        if end > len(body):
            partial = True
            break
        frames.append((flag, body[start:end]))
        index = end
    return frames, partial


def _is_grpc(message):
    return bool(message) and _header(message, "content-type").split(";", 1)[0].strip().lower().startswith(
        "application/grpc")


def _trailer_pairs(frames):
    """Collect grpc-status/grpc-message from gRPC-web trailer frames (flag bit 0x80)."""
    rows = []
    for flag, payload in frames:
        if flag & GRPC_FLAG_TRAILERS:
            for line in payload.decode("latin-1").splitlines():
                name, _, value = line.partition(":")
                if name.strip():
                    rows.append((name.strip(), value.strip()))
    return _Pairs(rows)


def _trees(frames, proto, counters):
    trees = []
    for flag, payload in frames:
        if flag & GRPC_FLAG_TRAILERS:
            counters["trailer_frames"] += 1
            continue
        if flag & GRPC_FLAG_COMPRESSED:
            counters["compressed_frames"] += 1
            trees.append(f"compressed({_opaque(payload)})")
            continue
        tree, complete = proto.render(payload)
        if not complete:
            counters["undecodable_frames"] += 1
        trees.append(tree)
    return trees or None


def _grpc_outcome(response, trailers):
    """Prefer HTTP trailers, then gRPC-web trailer frames, then trailers-only response headers."""
    for pairs in (response.trailers if response is not None else None, trailers,
                  response.headers if response is not None else None):
        if pairs is None:
            continue
        status = pairs.get("grpc-status")
        message = pairs.get("grpc-message")
        if status is None and message is None:
            continue
        if status is not None:
            status = int(status) if status.strip().lstrip("-").isdigit() else status
        if message is not None:
            message = unquote(message)
        return status, message
    return None, None


def _analyze_flow(view, proto, counters):
    request, response = view.request, view.response
    grpc = _is_grpc(request) or _is_grpc(response)
    record = {"path": request.path, "method": request.method,
              "status": response.status_code if response is not None else 0, "grpc": grpc,
              "request_fields": None, "response_fields": None}
    if not grpc:
        counters["skipped_non_grpc"] += 1
        return record
    counters["grpc_flows"] += 1
    request_frames, request_partial = _frames(request.content or b"", counters)
    response_frames, response_partial = _frames((response.content or b"") if response is not None else b"", counters)
    counters["request_frames"] += len(request_frames)
    counters["response_frames"] += len(response_frames)
    if request_partial or response_partial:
        counters["flows_with_truncated_frames"] += 1
    record.update({
        "request_fields": _trees(request_frames, proto, counters),
        "response_fields": _trees(response_frames, proto, counters),
        "request_frames": len(request_frames), "response_frames": len(response_frames),
    })
    if request_partial:
        record["request_frames_truncated"] = True
    if response_partial:
        record["response_frames_truncated"] = True
    status, message = _grpc_outcome(response, _trailer_pairs(response_frames))
    if status is not None:
        record["grpc_status"] = status
    if message is not None:
        record["grpc_message"] = message
    return record


def grpc_analyze(args, store):
    source = _input(store, args.path)
    if not source.is_file():
        raise ForgeError("grpc-analyze requires one regular project-local flow dump file")
    if not 1 <= args.limit <= MAX_FLOWS:
        raise ForgeError(f"--limit must be between 1 and {MAX_FLOWS}")
    stats = _new_stats(args.reader)
    counters = dict.fromkeys(("grpc_flows", "skipped_websocket", "skipped_non_grpc", "request_frames",
                              "response_frames", "trailer_frames", "compressed_frames", "undecodable_frames",
                              "flows_with_truncated_frames", "frames_capped", "nodes", "nodes_capped",
                              "depth_capped", "withheld_values"), 0)
    flows, omitted = [], 0
    for view in _read_flows(source, args.reader, stats):
        if view.websocket:
            counters["skipped_websocket"] += 1
            continue
        if len(flows) >= args.limit:
            omitted += 1
            continue
        proto = _Proto()
        flows.append(_analyze_flow(view, proto, counters))
        counters["nodes"] += proto.nodes
        counters["nodes_capped"] += proto.nodes_capped
        counters["depth_capped"] += proto.depth_capped
        counters["withheld_values"] += proto.withheld_values
    _require_parsed(stats)
    record = {
        "schema": GRPC_SCHEMA, "tool": TOOL, "action": GRPC_ACTION, "success": True,
        "input": _relative(store, source), "flows": len(flows), "flows_omitted": omitted,
        "limit": args.limit, "flows_detail": flows,
        "values_withheld": True, "nodes_cap": GRPC_NODES_PER_FLOW, "depth_cap": GRPC_DEPTH_CAP,
        "value_chars_cap": GRPC_VALUE_CHARS, "frames_cap": GRPC_FRAMES_PER_FLOW,
        "scope": GRPC_SCOPE,
    }
    record.update(counters)
    record.update(stats)
    return store.add("analysis", record)


# --------------------------------------------------------------------------- paths


def _input(store, value):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = store.root / path
    path = path.resolve()
    try:
        path.relative_to(store.root.resolve())
    except ValueError as error:
        raise ForgeError("Supply a project-local flow dump inside the target folder") from error
    if not path.exists():
        raise ForgeError(f"Flow dump does not exist: {value}")
    return path


def _new_output(store, value):
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ForgeError("Provide a new --output path for the HAR file")
    path = Path(value.strip())
    if not path.is_absolute():
        path = store.root / path
    path = path.resolve()
    try:
        path.relative_to(store.root.resolve())
    except ValueError as error:
        raise ForgeError("HAR output must stay inside the target folder") from error
    if path.suffix.lower() != ".har":
        raise ForgeError("--output must name a new .har file")
    if path.exists():
        raise ForgeError("Output already exists; choose a new --output path")
    if not path.parent.is_dir():
        raise ForgeError("Output directory does not exist")
    return path


def _relative(store, path):
    return path.resolve().relative_to(store.root.resolve()).as_posix()


def _hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reader_option(parser):
    parser.add_argument("--reader", choices=READERS, default="builtin",
                        help="Dump reader: builtin parses tnetstring frames with the standard library; "
                             "mitmproxy uses the optional dependency as a fallback")


def register(subparsers):
    parser = subparsers.add_parser("flow-to-har",
                                   help="Convert a mitmproxy flow dump into HAR for har-import "
                                        "(decrypted capture output, not the PCAP file)")
    parser.add_argument("path")
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=1000,
                        help=f"Maximum retained flows (1..{MAX_FLOWS})")
    parser.add_argument("--max-body-bytes", type=int, default=1024 * 1024,
                        help=f"Per-body byte cap (1..{MAX_BODY_BYTES})")
    _reader_option(parser)
    parser.set_defaults(handler=flow_to_har)

    parser = subparsers.add_parser("grpc-analyze",
                                   help="Split gRPC-web frames in a flow dump and decode schema-less "
                                        "protobuf field trees (field numbers, not names)")
    parser.add_argument("path")
    parser.add_argument("--limit", type=int, default=200,
                        help=f"Maximum analyzed flows (1..{MAX_FLOWS})")
    _reader_option(parser)
    parser.set_defaults(handler=grpc_analyze)
