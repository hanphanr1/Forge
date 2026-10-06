"""Loopback capture ingest, WebSocket frame metadata, and stored API shape summaries."""

from __future__ import annotations

import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from forge_core import EvidenceStore, ForgeError, redact_url, scrub_text
from forge_network import _har_entry, _load_json, _safe_body, _sanitize
from forge_protocol import _body_fields, _http
import forge_tasks


_LISTEN_HOST = "127.0.0.1"
_DRAIN_LIMIT = 65536
_POLL_SECONDS = 0.25
_REQUEST_TIMEOUT = 5.0
_MAX_TOKEN_BYTES = 256
_MAX_BODY = 16777216
_MAX_FRAME_BYTES = 16777216
_OPCODES = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}
_FRAME_TYPES = {"text", "binary", "continuation", "close", "ping", "pong"}
_DIRECTIONS = {"send": "request", "sent": "request", "request": "request", "client": "request",
               "outgoing": "request", "tx": "request", "receive": "response", "received": "response",
               "response": "response", "server": "response", "incoming": "response", "rx": "response"}
_CAPTURE_SCOPE = ("An accepted exchange is a redacted import of what a local client pushed to this loopback "
                  "receiver. The receiver identifies no capture tool, authenticates no user and is not live proof "
                  "of target traffic or of an authenticated flow.")
_SHAPE_SCOPE = ("Method/path identities, status counts, header names and body field names only; query, header and "
                "body values are never exported. Stored observations are historical and do not prove current "
                "server behavior.")
_FRAME_SCOPE = ("Directions, opcode labels, payload byte counts, close codes and JSON field-name paths only; "
                "payloads, header values and query values are never exported. A parsed capture is not proof that "
                "the endpoint behaves the same now.")


def _listen_host(host=_LISTEN_HOST):
    if host != _LISTEN_HOST:
        raise ForgeError("capture-ingest binds loopback only and refuses any other host")
    return host


def _bounded_names(values, limit):
    names = sorted({scrub_text(str(value)) for value in values})
    return names[:limit], len(names) > limit


def _source_path(store, value):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = store.root / path
    try:
        return path.resolve().relative_to(store.root).as_posix()
    except (ValueError, OSError, RuntimeError):
        return str(path)


# --------------------------------------------------------------------------- capture-ingest

class _CaptureState:
    def __init__(self, options):
        self.route = options["route"]
        self.max_body = options["max_body"]
        self.max_records = options["max_records"]
        self.token = options["token"]
        self.deadline = None
        self.bound = None
        self.accepted = 0
        self.rejected = 0
        self.rejects = {}
        self.bytes_read = 0
        self.records = []
        self.entries_available = 0
        self.records_omitted = 0
        self.truncated = False
        self.handler_errors = 0
        self.stop = False
        self.stop_reason = None

    def reject(self, reason):
        self.rejected += 1
        self.rejects[reason] = self.rejects.get(reason, 0) + 1


class _CaptureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "forge-capture"
    sys_version = ""
    timeout = _REQUEST_TIMEOUT

    def log_message(self, *args):
        pass

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()

    def _remaining(self):
        state = self.server.state
        return state.deadline - time.monotonic()

    def _request_path(self):
        try:
            return urlsplit(self.path).path
        except ValueError:
            return None

    def _handle(self):
        state = self.server.state
        try:
            self.connection.settimeout(min(_REQUEST_TIMEOUT, max(0.1, self._remaining())))
        except OSError:
            pass
        if self._remaining() <= 0:
            self._finish(503, "deadline_expired", 0)
            return
        length = self._content_length()
        if self.command != "POST":
            self._finish(405, "wrong_method", length, allow="POST")
            return
        if self._request_path() != state.route:
            self._finish(404, "wrong_route", length)
            return
        if not self._authorized():
            self._finish(401, "unauthorized", length)
            return
        if self.headers.get("Transfer-Encoding"):
            self._finish(501, "unsupported_transfer_encoding", 0)
            return
        if length is None:
            self._finish(411, "missing_length", 0)
            return
        if length < 0:
            self._finish(400, "invalid_length", 0)
            return
        if length > state.max_body:
            self._finish(413, "oversized_body", length)
            return
        if len(state.records) >= state.max_records:
            self._finish(429, "record_limit", length)
            return
        body = self._read_body(length)
        if body is None:
            self._finish(408, "incomplete_body", 0)
            return
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError):
            self._finish(400, "malformed_json", 0)
            return
        entries, reason = _document_entries(document)
        if reason:
            self._finish(400, reason, 0)
            return
        available = len(entries)
        selected = entries[:state.max_records - len(state.records)]
        if not selected:
            self._finish(429, "record_limit", 0)
            return
        try:
            records, truncated = _store_har_entries(self.server.store, selected, state.max_body)
        except (ForgeError, RecursionError, TypeError, KeyError, ValueError):
            self._finish(400, "invalid_entry", 0)
            return
        except Exception:
            self._finish(500, "storage_failure", 0)
            return
        state.accepted += 1
        state.records.extend(record["id"] for record in records)
        state.entries_available += available
        state.records_omitted += available - len(selected)
        state.truncated = state.truncated or truncated
        if len(state.records) >= state.max_records:
            state.stop = True
            state.stop_reason = "max_records"
        self._finish(200, None, 0, payload={"ok": True, "stored": len(records), "available": available,
                                            "omitted": available - len(selected), "truncated": truncated,
                                            "records_stored": len(state.records)})

    def _authorized(self):
        token = self.server.state.token
        if token is None:
            return True
        supplied = self.headers.get("X-Forge-Token")
        if not supplied:
            header = self.headers.get("Authorization", "")
            if header.lower().startswith("bearer "):
                supplied = header[7:].strip()
        if not supplied:
            return False
        try:
            return hmac.compare_digest(str(supplied).encode("utf-8"), token.encode("utf-8"))
        except UnicodeError:
            return False

    def _content_length(self):
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            length = int(raw.strip())
        except (TypeError, ValueError):
            return -1
        return length

    def _drain(self, length):
        if not isinstance(length, int) or length <= 0:
            return
        state = self.server.state
        try:
            self.connection.settimeout(min(_REQUEST_TIMEOUT, 0.5))
            remaining = min(length, _DRAIN_LIMIT)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                state.bytes_read += len(chunk)
                remaining -= len(chunk)
        except (OSError, ValueError):
            pass

    def _read_body(self, length):
        state = self.server.state
        try:
            self.connection.settimeout(min(_REQUEST_TIMEOUT, max(0.1, self._remaining())))
        except OSError:
            return None
        try:
            body = self.rfile.read(length)
        except (OSError, ValueError):
            return None
        state.bytes_read += len(body)
        if len(body) != length:
            return None
        return body

    def _finish(self, code, reason, drain, payload=None, allow=None):
        state = self.server.state
        self.close_connection = True
        if reason is not None:
            state.reject(reason)
        self._drain(drain)
        if payload is None:
            payload = {"ok": False, "error": reason, "accepted": state.accepted, "rejected": state.rejected}
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if allow is not None:
            self.send_header("Allow", allow)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


class _Listener(HTTPServer):
    allow_reuse_address = True

    def __init__(self, address, state, store):
        self.state = state
        self.store = store
        super().__init__(address, _CaptureHandler)

    def handle_error(self, request, client_address):
        self.state.handler_errors += 1


def _document_entries(document):
    if isinstance(document, dict):
        log = document.get("log")
        if isinstance(log, dict) and isinstance(log.get("entries"), list):
            return log["entries"], None if log["entries"] else "empty_document"
        if isinstance(document.get("request"), dict) and isinstance(document.get("response"), dict):
            return [document], None
        return None, "unsupported_document"
    if isinstance(document, list):
        return document, None if document else "empty_document"
    return None, "unsupported_document"


def _store_har_entries(store, entries, max_body):
    """Normalize entries exactly like forge_network.handle_har_import and store har_exchange evidence."""
    secrets = set()
    items = [_har_entry(entry, max_body, [], secrets) for entry in entries]
    records, truncated = [], False
    for item in items:
        item["response"]["body"] = _safe_body(item["response"]["body"], secrets, item["response"]["truncated"])
        if isinstance(item["request"]["body"], str):
            item["request"]["body"] = _safe_body(item["request"]["body"], secrets, False)
        item["redaction"]["known_secret_count"] = len(secrets)
        truncated = truncated or bool(item["response"]["truncated"])
        records.append(store.add("har_exchange", _sanitize(item, secrets)))
    return records, truncated


def _capture_options(args):
    port = args.port
    if type(port) is not int or not 0 <= port <= 65535:
        raise ForgeError("--port must be between 0 and 65535")
    if type(args.seconds) is not int or not 1 <= args.seconds <= 3600:
        raise ForgeError("--seconds must be between 1 and 3600")
    if type(args.max_body) is not int or not 1 <= args.max_body <= _MAX_BODY:
        raise ForgeError("--max-body must be between 1 and 16777216")
    if type(args.max_records) is not int or not 1 <= args.max_records <= 5000:
        raise ForgeError("--max-records must be between 1 and 5000")
    route = args.route
    if (not isinstance(route, str) or not route.startswith("/") or len(route) > 256
            or any(character in route for character in "?#") or any(character.isspace() for character in route)):
        raise ForgeError("--route must be an absolute request path without query, fragment or whitespace")
    token = args.token
    if token is not None and (not isinstance(token, str) or not token
                              or len(token.encode("utf-8")) > _MAX_TOKEN_BYTES):
        raise ForgeError("--token must be a nonempty string of at most 256 bytes")
    return {"port": port, "seconds": args.seconds, "max_body": args.max_body, "max_records": args.max_records,
            "route": route, "token": token}


def _serve(options, store, *, stop=None, notify=None):
    """Run the bounded loopback receiver.

    Imported exchanges are written through a dedicated store connection created here, because a listener
    callback may run on a different thread than the caller's store (SQLite connections are thread-bound).
    """
    writer = EvidenceStore(store.root)
    listener = None
    state = _CaptureState(options)
    try:
        try:
            listener = _Listener((_listen_host(), options["port"]), state, writer)
        except OSError as error:
            raise ForgeError(f"Cannot bind the loopback receiver on {_LISTEN_HOST}:{options['port']}: "
                             f"{error}") from None
        state.bound = {"host": listener.server_address[0], "port": listener.server_address[1], "route": state.route}
        if state.bound["host"] != _LISTEN_HOST:
            raise ForgeError("capture-ingest refused to serve a non-loopback bind address")
        state.deadline = time.monotonic() + options["seconds"]
        if notify is not None:
            notify(dict(state.bound))
        reason = "deadline"
        try:
            while True:
                remaining = state.deadline - time.monotonic()
                if remaining <= 0:
                    reason = "deadline"
                    break
                if state.stop:
                    reason = state.stop_reason or "max_records"
                    break
                if stop is not None and stop.is_set():
                    reason = "stopped"
                    break
                listener.timeout = min(_POLL_SECONDS, max(0.01, remaining))
                listener.handle_request()
        except KeyboardInterrupt:
            reason = "interrupted"
        elapsed = round(options["seconds"] - max(0.0, state.deadline - time.monotonic()), 3)
        return {"listener": {**state.bound, "loopback_only": True},
                "lifetime_seconds": options["seconds"], "elapsed_seconds": elapsed,
                "stopped_reason": reason, "token_required": state.token is not None,
                "accepted_requests": state.accepted, "rejected_requests": state.rejected,
                "rejected_reasons": dict(sorted(state.rejects.items())),
                "exchanges_stored": len(state.records), "evidence": list(state.records),
                "entries_available": state.entries_available, "records_omitted": state.records_omitted,
                "bytes_read": state.bytes_read, "truncated": state.truncated,
                "handler_errors": state.handler_errors,
                "limits": {"max_body_bytes": state.max_body, "max_records": state.max_records,
                           "drain_bytes": _DRAIN_LIMIT},
                "scope": _CAPTURE_SCOPE}
    finally:
        if listener is not None:
            listener.server_close()
        writer.close()


def handle_capture_ingest(args, store):
    forge_tasks.check_scope(store, "capture-ingest", network=True)
    options = _capture_options(args)

    def announce(listener):
        print(f"forge capture-ingest: listening on {listener['host']}:{listener['port']}{listener['route']} "
              f"for {options['seconds']}s", file=sys.stderr, flush=True)

    return _serve(options, store, notify=announce)


# --------------------------------------------------------------------------- websocket-analyze

def _redact_websocket_url(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[INVALID URL REDACTED]"
    if parts.scheme not in {"ws", "wss"}:
        return redact_url(url)
    netloc = parts.netloc.rsplit("@", 1)[-1]
    mapped = urlunsplit(("https" if parts.scheme == "wss" else "http", netloc, parts.path, parts.query, ""))
    restored = urlsplit(redact_url(mapped))
    prefix = "[REDACTED]@" if "@" in parts.netloc else ""
    return urlunsplit((parts.scheme, prefix + restored.netloc, restored.path, restored.query, ""))


def _frame_fields(message):
    if not isinstance(message, dict):
        return None
    direction = "unknown"
    for key in ("direction", "dir"):
        value = message.get(key)
        if isinstance(value, str):
            mapped = _DIRECTIONS.get(value.strip().lower())
            if mapped:
                direction = mapped
                break
    opcode = message.get("opcode", message.get("opCode"))
    if isinstance(opcode, str) and opcode.strip().isdigit():
        opcode = int(opcode.strip())
    if isinstance(opcode, bool) or not isinstance(opcode, int) or not 0 <= opcode <= 15:
        opcode = None
    kind = message.get("type")
    name = kind.strip().lower() if isinstance(kind, str) else None
    if name is not None and direction == "unknown" and name in _DIRECTIONS:
        direction = _DIRECTIONS[name]
    if opcode is not None:
        label = _OPCODES.get(opcode, "opcode-" + str(opcode))
    elif name in _FRAME_TYPES:
        label = name
    else:
        label = "unknown"
    data = message.get("data")
    if isinstance(data, str):
        text = data
    elif isinstance(data, (dict, list)):
        text = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    else:
        text = None
    size = len(text.encode("utf-8", errors="replace")) if text is not None else None
    code = message.get("code")
    if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 65535:
        code = None
    return direction, label, size, text, code


def _root_kind(text):
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return "object"
    if stripped.startswith("["):
        return "array"
    return "scalar"


def _frame_shape(text, fields_limit):
    """Return (paths, root_kind, omitted, unparsed) for one payload without exporting any value."""
    fields = _body_fields({"body": text, "headers": {}})
    if fields["body_unparsed"]:
        return [], None, bool(fields["fields_omitted"]), True
    path_set = set(fields["json_field_paths"])
    paths, omitted = _bounded_names(path_set, fields_limit)
    return paths, _root_kind(text), omitted or fields["fields_omitted"], False


def _session(url, messages, args):
    frames_observed = messages if isinstance(messages, list) else []
    parsed, omitted = frames_observed[:args.max_frames], max(0, len(frames_observed) - args.max_frames)
    directions = {"request": 0, "response": 0, "unknown": 0}
    types = {}
    sizes = []
    codes = set()
    close_frames = 0
    payload_missing = 0
    shape_paths = set()
    shape_omitted = False
    json_frames = 0
    unparsed_frames = 0
    empty_frames = 0
    roots = {"object": 0, "array": 0, "scalar": 0}
    invalid_frames = 0
    bytes_skipped = 0
    for message in parsed:
        frame = _frame_fields(message)
        if frame is None:
            invalid_frames += 1
            continue
        direction, label, size, text, code = frame
        directions[direction] += 1
        types[label] = types.get(label, 0) + 1
        if label == "close":
            close_frames += 1
            if code is not None:
                codes.add(code)
        if size is None:
            payload_missing += 1
        else:
            sizes.append(size)
            if text is None:
                continue
        if text is None or not text.strip():
            empty_frames += 1
            continue
        if len(text.encode("utf-8", errors="replace")) > args.max_frame_bytes:
            bytes_skipped += 1
            shape_omitted = True
            continue
        paths, root, truncated, unparsed = _frame_shape(text, args.max_fields)
        if unparsed:
            unparsed_frames += 1
        else:
            json_frames += 1
            roots[root] += 1
        shape_omitted = shape_omitted or truncated
        for path in paths:
            if len(shape_paths) < args.max_fields:
                shape_paths.add(path)
            else:
                shape_omitted = True
    return {"url": _redact_websocket_url(url) if isinstance(url, str) else None, "url_redacted": True,
            "frames_observed": len(frames_observed), "frames_parsed": len(parsed) - invalid_frames,
            "frames_omitted": omitted, "invalid_frames": invalid_frames,
            "directions": directions, "frame_types": dict(sorted(types.items())),
            "payload_bytes": {"frames_measured": len(sizes), "min": min(sizes) if sizes else None,
                              "max": max(sizes) if sizes else None, "total": sum(sizes),
                              "frames_without_payload": payload_missing},
            "close_frames": close_frames, "close_codes": sorted(codes),
            "json_shape": {"json_frames": json_frames, "unparsed_frames": unparsed_frames,
                           "empty_frames": empty_frames, "root_kinds": roots,
                           "field_paths": sorted(shape_paths)[:args.max_fields],
                           "frames_over_byte_limit": bytes_skipped, "field_paths_omitted": shape_omitted},
            "values_withheld": True}


def _source_sessions(document):
    if isinstance(document, dict):
        log = document.get("log")
        if isinstance(log, dict) and isinstance(log.get("entries"), list):
            return "har", _har_sessions(log["entries"])
        if isinstance(document.get("frames"), list):
            return "frames", [{"url": document.get("url"), "messages": document["frames"]}]
        raise ForgeError("WebSocket source must be a HAR document, {'url', 'frames'}, or a frames-object array")
    if isinstance(document, list):
        if all(isinstance(item, dict) and isinstance(item.get("frames"), list) for item in document):
            return "frames", [{"url": item.get("url"), "messages": item["frames"]} for item in document]
        if all(isinstance(item, dict) for item in document):
            return "har", _har_sessions(document)
        raise ForgeError("WebSocket source arrays must contain objects")
    raise ForgeError("WebSocket source must be a HAR document, {'url', 'frames'}, or a frames-object array")


def _har_url(entry):
    request = entry.get("request")
    url = request.get("url") if isinstance(request, dict) else None
    if isinstance(url, str):
        return url
    fallback = entry.get("_webSocketURL")
    return fallback if isinstance(fallback, str) else None


def _har_sessions(entries):
    sessions = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ("_webSocketMessages", "_webSocketFrames"):
            value = entry.get(key)
            if isinstance(value, list):
                sessions.append({"url": _har_url(entry), "messages": value})
                break
    return sessions


def _websocket_options(args):
    if type(args.max_sources) is not int or not 1 <= args.max_sources <= 5000:
        raise ForgeError("--max-sources must be between 1 and 5000")
    if type(args.max_sessions) is not int or not 1 <= args.max_sessions <= 5000:
        raise ForgeError("--max-sessions must be between 1 and 5000")
    if type(args.max_frames) is not int or not 1 <= args.max_frames <= 200000:
        raise ForgeError("--max-frames must be between 1 and 200000")
    if type(args.max_frame_bytes) is not int or not 1 <= args.max_frame_bytes <= _MAX_FRAME_BYTES:
        raise ForgeError("--max-frame-bytes must be between 1 and 16777216")
    if type(args.max_fields) is not int or not 1 <= args.max_fields <= 2000:
        raise ForgeError("--max-fields must be between 1 and 2000")
    if not args.sources:
        raise ForgeError("websocket-analyze requires at least one source file")


def websocket_analyze(args, store):
    _websocket_options(args)
    sources = args.sources[:args.max_sources]
    results = []
    totals = {"frames_observed": 0, "frames_parsed": 0, "frames_omitted": 0}
    for name in sources:
        document = _load_json(name, store)
        kind, sessions = _source_sessions(document)
        selected = sessions[:args.max_sessions]
        report = [_session(session["url"], session["messages"], args) for session in selected]
        for item in report:
            totals["frames_observed"] += item["frames_observed"]
            totals["frames_parsed"] += item["frames_parsed"]
            totals["frames_omitted"] += item["frames_omitted"]
        results.append({"source": _source_path(store, name), "format": kind,
                        "sessions_observed": len(sessions), "sessions_parsed": len(selected),
                        "sessions_omitted": len(sessions) - len(selected), "sessions": report})
    return {"schema_version": 1, "sources": results, "sources_observed": len(args.sources),
            "sources_parsed": len(sources), "sources_omitted": len(args.sources) - len(sources),
            **totals, "values_withheld": True,
            "limits": {"max_sources": args.max_sources, "max_sessions_per_source": args.max_sessions,
                       "max_frames_per_session": args.max_frames, "max_frame_bytes": args.max_frame_bytes,
                       "max_field_paths_per_session": args.max_fields},
            "scope": _FRAME_SCOPE}


# --------------------------------------------------------------------------- api-shape

def _shape_records(args, store):
    if args.evidence:
        records = []
        for evidence_id in dict.fromkeys(args.evidence):
            record = store.get(evidence_id)
            if record["kind"] not in ("http_probe", "har_exchange"):
                raise ForgeError(f"api-shape requires http_probe or har_exchange evidence IDs, not {record['kind']}")
            if not isinstance(record["data"], dict):
                raise ForgeError(f"Evidence {evidence_id} has invalid HTTP metadata")
            records.append(record)
        return records, False
    rows = store.connection.execute(
        "SELECT id, kind, created_at, data FROM evidence WHERE kind IN (?, ?) "
        "ORDER BY created_at DESC, rowid DESC LIMIT ?",
        ("http_probe", "har_exchange", args.limit + 1)).fetchall()
    records = [{"id": row[0], "kind": row[1], "created_at": row[2], "data": json.loads(row[3])} for row in rows[:args.limit]]
    for record in records:
        if not isinstance(record["data"], dict):
            raise ForgeError(f"Evidence {record['id']} has invalid HTTP metadata")
    return records, len(rows) > args.limit


def _host_key(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[unknown]", None, None
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if not host:
        return "[unknown]", None, None
    return host, port, host + ":" + str(port) if port is not None else host


def _redacted_path(url):
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "/"


def _new_domain(host):
    return {"domain": host, "ports": set(), "observations": 0, "evidence_ids": [], "method_paths": {},
            "statuses": {}, "response_status_unobserved": 0, "unparsed_bodies": 0, "body_observations": 0,
            "request_header_names": set(), "response_header_names": set(), "request_json_field_paths": set(),
            "response_json_field_paths": set(), "request_form_field_names": set(), "response_form_field_names": set(),
            "query_field_names": set()}


def _shape_options(args):
    for value in args.domain:
        if (not isinstance(value, str) or not value.strip()
                or any(character in value for character in "/?#@ \\")):
            raise ForgeError("--domain must be a hostname or hostname:port without scheme, path or credentials")
    for name, value, low, high in (("--limit", args.limit, 1, 1000), ("--max-domains", args.max_domains, 1, 500),
                                   ("--max-paths", args.max_paths, 1, 2000), ("--max-names", args.max_names, 1, 2000),
                                   ("--max-statuses", args.max_statuses, 1, 500), ("--max-ids", args.max_ids, 1, 1000)):
        if type(value) is not int or not low <= value <= high:
            raise ForgeError(f"{name} must be between {low} and {high}")


def api_shape(args, store):
    _shape_options(args)
    records, window_truncated = _shape_records(args, store)
    wanted = {value.strip().lower() for value in args.domain}
    domains = {}
    considered = 0
    input_fields_omitted = False
    for record in records:
        identity, observation, _citation = _http(record)
        host, port, host_key = _host_key(identity["url"])
        if wanted and host not in wanted and host_key not in wanted:
            continue
        considered += 1
        domain = domains.setdefault(host_key, _new_domain(host))
        if port is not None:
            domain["ports"].add(port)
        domain["observations"] += 1
        if len(domain["evidence_ids"]) < args.max_ids:
            domain["evidence_ids"].append(record["id"])
        path = _redacted_path(identity["url"])
        identity_key = (identity["method"], path)
        domain["method_paths"][identity_key] = domain["method_paths"].get(identity_key, 0) + 1
        status = observation["response_status"]
        if status is None:
            domain["response_status_unobserved"] += 1
        else:
            domain["statuses"][str(status)] = domain["statuses"].get(str(status), 0) + 1
        for name in observation["query_field_names"]:
            domain["query_field_names"].add(name)
        for name in observation["request_header_names"]:
            domain["request_header_names"].add(name)
        for name in observation["response_header_names"]:
            domain["response_header_names"].add(name)
        for side, prefix in (("request_body", "request"), ("response_body", "response")):
            body = observation[side]
            domain["body_observations"] += 1
            if body["body_unparsed"]:
                domain["unparsed_bodies"] += 1
            for name in body["form_field_names"]:
                domain[f"{prefix}_form_field_names"].add(name)
            for name in body["json_field_paths"]:
                domain[f"{prefix}_json_field_paths"].add(name)
        input_fields_omitted = input_fields_omitted or observation["metadata_omitted"] or any(
            observation[side]["fields_omitted"] for side in ("request_body", "response_body"))
    ordered = sorted(domains.items(), key=lambda item: (-item[1]["observations"], item[0]))
    selected = ordered[:args.max_domains]
    report = []
    flags = {"domains_omitted": len(ordered) > len(selected), "paths_omitted": False, "names_omitted": False,
             "statuses_omitted": False, "ids_omitted": False}
    for key, domain in selected:
        method_paths = sorted(domain["method_paths"].items(), key=lambda item: (-item[1], item[0]))
        paths_omitted = len(method_paths) > args.max_paths
        statuses = sorted(domain["statuses"].items(), key=lambda item: int(item[0]))
        statuses_omitted = len(statuses) > args.max_statuses
        ids_omitted = len(domain["evidence_ids"]) >= args.max_ids and domain["observations"] > args.max_ids
        names_lists = {}
        names_omitted = False
        for field in ("request_header_names", "response_header_names", "request_json_field_paths",
                      "response_json_field_paths", "request_form_field_names", "response_form_field_names",
                      "query_field_names"):
            names, omitted = _bounded_names(domain[field], args.max_names)
            names_lists[field] = names
            names_omitted = names_omitted or omitted
        flags["paths_omitted"] = flags["paths_omitted"] or paths_omitted
        flags["names_omitted"] = flags["names_omitted"] or names_omitted
        flags["statuses_omitted"] = flags["statuses_omitted"] or statuses_omitted
        flags["ids_omitted"] = flags["ids_omitted"] or ids_omitted
        report.append({"domain": domain["domain"], "host": key, "ports": sorted(domain["ports"]),
                       "observations": domain["observations"], "evidence_ids": domain["evidence_ids"],
                       "method_paths": [{"method": method, "path": path, "observations": count}
                                        for (method, path), count in method_paths[:args.max_paths]],
                       "statuses": dict(statuses[:args.max_statuses]),
                       "response_status_unobserved": domain["response_status_unobserved"],
                       "body_observations": domain["body_observations"],
                       "unparsed_bodies": domain["unparsed_bodies"],
                       "paths_omitted": paths_omitted, "statuses_omitted": statuses_omitted,
                       "names_omitted": names_omitted, "ids_omitted": ids_omitted, **names_lists})
    return {"schema_version": 1, "selection": "explicit" if args.evidence else "newest_window",
            "evidence_ids": [record["id"] for record in records], "considered": considered,
            "window_truncated": window_truncated, "input_fields_omitted": input_fields_omitted,
            "domains": report, "values_withheld": True,
            "limits": {"limit": args.limit, "max_domains": args.max_domains, "max_paths_per_domain": args.max_paths,
                       "max_names_per_list": args.max_names, "max_statuses_per_domain": args.max_statuses,
                       "max_evidence_ids_per_domain": args.max_ids},
            "scope": _SHAPE_SCOPE, **flags}


# --------------------------------------------------------------------------- registration

def register(subparsers):
    ingest = subparsers.add_parser("capture-ingest",
                                   help="Receive HAR pushes on a bounded loopback endpoint and store imported exchanges")
    ingest.add_argument("--port", type=int, default=0,
                        help="Loopback port; 0 binds an ephemeral port that is announced and reported (default: 0)")
    ingest.add_argument("--seconds", type=int, default=60, help="Hard listener lifetime in seconds (1..3600, default: 60)")
    ingest.add_argument("--max-body", type=int, default=8388608,
                        help="Maximum accepted request body bytes (1..16777216, default: 8388608)")
    ingest.add_argument("--max-records", type=int, default=200,
                        help="Maximum stored exchanges before the listener stops (1..5000, default: 200)")
    ingest.add_argument("--route", default="/report", help="Absolute request path accepted for POST (default: /report)")
    ingest.add_argument("--token", help="Optional shared token; requires X-Forge-Token or Authorization: Bearer")
    ingest.set_defaults(handler=handle_capture_ingest)

    frames = subparsers.add_parser("websocket-analyze",
                                   help="Summarize WebSocket frame metadata from HAR or explicit frames JSON")
    frames.add_argument("sources", nargs="+", help="HAR files with _webSocketMessages/_webSocketFrames, or {'url','frames'} JSON")
    frames.add_argument("--max-sources", type=int, default=20, help="Maximum source files read (1..5000, default: 20)")
    frames.add_argument("--max-sessions", type=int, default=50,
                        help="Maximum sessions reported per source (1..5000, default: 50)")
    frames.add_argument("--max-frames", type=int, default=2000,
                        help="Maximum frames parsed per session (1..200000, default: 2000)")
    frames.add_argument("--max-frame-bytes", type=int, default=65536,
                        help="Maximum payload bytes parsed per frame (1..16777216, default: 65536)")
    frames.add_argument("--max-fields", type=int, default=200,
                        help="Maximum JSON field-name paths kept per session (1..2000, default: 200)")
    frames.set_defaults(handler=websocket_analyze)

    shape = subparsers.add_parser("api-shape",
                                  help="Summarize stored HTTP evidence names and statuses per domain without values")
    shape.add_argument("--domain", action="append", default=[], metavar="HOST",
                       help="Only this hostname or hostname:port; repeatable (default: every observed domain)")
    shape.add_argument("--evidence", action="append", default=[], metavar="ID",
                       help="Explicit http_probe/har_exchange evidence IDs; repeatable, takes precedence over --limit")
    shape.add_argument("--limit", type=int, default=100, help="Newest stored HTTP records without --evidence (1..1000)")
    shape.add_argument("--max-domains", type=int, default=50, help="Maximum domains reported (1..500, default: 50)")
    shape.add_argument("--max-paths", type=int, default=100,
                       help="Maximum method/path identities per domain (1..2000, default: 100)")
    shape.add_argument("--max-names", type=int, default=200, help="Maximum names per name list (1..2000, default: 200)")
    shape.add_argument("--max-statuses", type=int, default=50,
                       help="Maximum distinct statuses per domain (1..500, default: 50)")
    shape.add_argument("--max-ids", type=int, default=50,
                       help="Maximum cited evidence IDs per domain (1..1000, default: 50)")
    shape.set_defaults(handler=api_shape)
