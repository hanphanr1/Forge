"""Convert a mitmproxy flow dump into HAR for the existing import path.

A capture that asks PCAPdroid for TLS decryption writes decrypted requests to mitmproxy, not into
the PCAP file. PCAPdroid can hand mitmproxy extra options, so `pcapdroid-capture --tls-decryption
--mitmproxy-opts "-w <path>"` makes the addon write a flow dump the operator can pull back. This
module turns that dump into a HAR document, which `har-import` already normalizes, redacts and
cites. mitmproxy is an optional dependency: the reader is imported only when a dump is converted.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import re

from forge_core import ForgeError

SCHEMA = "forge.flows/v1"
TOOL = "mitmproxy"
ACTION = "flow-to-har"
MAX_FLOWS = 100000
MAX_BODY_BYTES = 64 * 1024 * 1024
HAR_VERSION = "1.2"
CREATOR = {"name": "forge-flow-to-har", "version": "1"}
SETUP_HINT = ("mitmproxy is required to read flow dumps: install the optional extra "
              "(python -m pip install 'forge-protocol[flows]') and retry")


def _text(value):
    return value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else str(value)


def _headers(message):
    if message is None:
        return []
    return [{"name": _text(name), "value": _text(value)} for name, value in message.headers.items()]


def _entry(request, response, body_limit):
    """Build one HAR entry from a request/response pair, bounded by body_limit bytes."""
    request_body = bytes(getattr(request, "content", b"") or b"")[:body_limit]
    response_body = bytes(getattr(response, "content", b"") or b"") if response is not None else b""
    truncated = len(response_body) > body_limit
    response_body = response_body[:body_limit]
    entry = {
        "startedDateTime": datetime.fromtimestamp(getattr(request, "timestamp_start", 0) or 0,
                                                  timezone.utc).isoformat(),
        "time": 0,
        "request": {
            "method": _text(request.method),
            "url": _text(request.pretty_url),
            "httpVersion": "HTTP/2",
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
            "httpVersion": "HTTP/2",
            "cookies": [],
            "headers": _headers(response),
            "content": {"size": len(response_body),
                        "mimeType": _text(response.headers.get("content-type", "")) if response is not None else "",
                        "text": response_body.decode("utf-8", "replace")},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(response_body),
        },
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }
    if request_body:
        entry["request"]["postData"] = {
            "mimeType": _text(request.headers.get("content-type", "application/octet-stream")),
            "text": request_body.decode("utf-8", "replace"),
        }
    entry["response"]["_forge_body_truncated"] = truncated
    return entry


def _read_flows(dump_path):
    try:
        from mitmproxy import io as mitm_io  # optional dependency, imported only for this command
    except ImportError as error:
        raise ForgeError(SETUP_HINT) from error
    with dump_path.open("rb") as stream:
        try:
            yield from mitm_io.FlowReader(stream).stream()
        except Exception as error:  # mitmproxy raises its own FlowReadException types
            raise ForgeError(f"Flow dump could not be read: {error}") from error


def flow_to_har(args, store):
    source = _input(store, args.path)
    if not source.is_file():
        raise ForgeError("flow-to-har requires one regular project-local flow dump file")
    if not 1 <= args.limit <= MAX_FLOWS:
        raise ForgeError(f"--limit must be between 1 and {MAX_FLOWS}")
    if not 1 <= args.max_body_bytes <= MAX_BODY_BYTES:
        raise ForgeError(f"--max-body-bytes must be between 1 and {MAX_BODY_BYTES}")
    output = _new_output(store, args.output)
    entries, skipped, truncated = [], 0, 0
    for flow in _read_flows(source):
        if len(entries) >= args.limit:
            skipped += 1
            continue
        request = getattr(flow, "request", None)
        if request is None:
            skipped += 1
            continue
        entry = _entry(request, getattr(flow, "response", None), args.max_body_bytes)
        truncated += bool(entry["response"]["_forge_body_truncated"])
        entries.append(entry)
    document = {"log": {"version": HAR_VERSION, "creator": CREATOR, "entries": entries}}
    output.write_text(json.dumps(document), encoding="utf-8")
    return store.add("analysis", {
        "schema": SCHEMA, "tool": TOOL, "action": ACTION, "success": True,
        "input": _relative(store, source), "output_path": _relative(store, output),
        "flows": len(entries), "flows_skipped": skipped,
        "bodies_truncated": truncated, "limit": args.limit, "max_body_bytes": args.max_body_bytes,
        "output_sha256": _hash_file(output),
        "scope": "Decrypted requests observed by a local mitmproxy instance in a repackaged or "
                 "user-trusted client only. Import the HAR with har-import; this command makes no "
                 "network calls and the dump may hold private bodies.",
    })


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
    import hashlib
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    parser.set_defaults(handler=flow_to_har)
