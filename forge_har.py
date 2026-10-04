from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import stat
import tempfile
from urllib.parse import urlsplit

from forge_core import ForgeError
import forge_network as network
import forge_tasks


_OMIT_HEADERS = {"host", "content-length", "connection", "transfer-encoding", "accept-encoding", "proxy-connection"}
_PSEUDO_HEADERS = {":method", ":scheme", ":authority", ":path", ":protocol"}


def _invalid_number(value):
    raise ValueError("Non-finite JSON number")


def _input_bytes(store, value, maximum):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = store.root / path
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ForgeError("HAR input must be a regular file, not a symlink or pipe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        if not os.path.samestat(info, os.fstat(source.fileno())):
            raise ForgeError("HAR input changed while being opened")
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise ForgeError("HAR input exceeds --max-input-bytes")
    try:
        har = json.loads(raw.decode("utf-8-sig"), parse_constant=_invalid_number)
    except (UnicodeError, ValueError, RecursionError):
        raise ForgeError("HAR must be a complete UTF-8 JSON document") from None
    log = har.get("log") if isinstance(har, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ForgeError("HAR must contain a nonempty log.entries array")
    return raw, entries


def _binding(bindings, entry, component, pointer, *, format="text"):
    variable = f"HAR_{entry + 1}_{component}_{len(bindings) + 1}"
    bindings.append({"variable": variable, "entry": entry, "pointer": pointer, "format": format})
    return "${" + variable + "}"


def _pointer(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def _json_template(value, bindings, entry, pointer, depth=0):
    if depth > 32 or len(bindings) >= 5000:
        raise ForgeError("JSON request is too complex for field-by-field parameterization")
    if isinstance(value, str):
        return _binding(bindings, entry, "JSON", pointer) if value else ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        raise ForgeError("Numeric values require a whole-body template to preserve their type")
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if network._SENSITIVE.search(key) and not isinstance(child, str):
                raise ForgeError("Non-string credential field requires a whole-body template")
            result[key] = _json_template(child, bindings, entry, pointer + "/" + _pointer(key), depth + 1)
        return result
    if isinstance(value, list):
        return [_json_template(child, bindings, entry, pointer + f"/{index}", depth + 1) for index, child in enumerate(value)]
    return value


def _entry(entry, number, bindings, warnings):
    prefix = f"Entry {number + 1}"
    if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
        raise ForgeError(prefix + ": request object is required")
    request = entry["request"]
    method, url = request.get("method"), request.get("url")
    if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]+", method):
        raise ForgeError(prefix + ": request method must contain letters only")
    try:
        parsed = urlsplit(url) if isinstance(url, str) else None
        valid = parsed is not None and parsed.scheme in {"http", "https"} and parsed.hostname and parsed.port != 0
    except ValueError:
        valid = False
    if not valid or re.search(r"[\x00-\x20\x7f]", url):
        raise ForgeError(prefix + ": request URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ForgeError(prefix + ": URL userinfo is unsupported; use an explicit Authorization header")
    base = f"/log/entries/{number}/request"
    # Whole URLs keep escaping intact and do not copy credentials hidden in paths/query/hostnames.
    spec = {"method": method.upper(), "url": _binding(bindings, number, "URL", base + "/url", format="http_url"), "headers": {}}
    headers = request.get("headers", [])
    if not isinstance(headers, list):
        raise ForgeError(prefix + ": headers must be name/value objects")
    seen = set()
    content_type = None
    for index, header in enumerate(headers):
        if not isinstance(header, dict) or not isinstance(header.get("name"), str) or not isinstance(header.get("value"), str):
            raise ForgeError(prefix + ": headers must be name/value objects")
        name, value = header["name"], header["value"]
        lower = name.lower()
        if lower in _PSEUDO_HEADERS:
            warnings.append({"entry": number, "type": "transport_header_omitted", "name": name})
            continue
        if not network._HEADER_NAME.fullmatch(name) or re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value):
            raise ForgeError(prefix + ": invalid or multiline request header")
        if lower in seen:
            raise ForgeError(prefix + ": duplicate request headers cannot be represented safely")
        seen.add(lower)
        if lower in _OMIT_HEADERS:
            warnings.append({"entry": number, "type": "transport_header_omitted", "name": name})
            continue
        if lower == "content-type":
            content_type = value
        spec["headers"][name] = _binding(bindings, number, "HEADER", base + f"/headers/{index}/value") if value else ""
        if lower == "cookie":
            warnings.append({"entry": number, "type": "captured_cookie", "message": "Remove this header to use fresh cookies from probe-run's session instead."})
    cookies = request.get("cookies", [])
    if not isinstance(cookies, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str) for item in cookies):
        raise ForgeError(prefix + ": cookies must be named string values")
    if cookies and "cookie" not in seen:
        spec["headers"]["Cookie"] = _binding(bindings, number, "COOKIE", base + "/cookies", format="cookie_header")
        warnings.append({"entry": number, "type": "captured_cookie", "message": "Construct the explicit cookie header, or remove it to use the live cookie session."})
    post = request.get("postData")
    if post is None:
        return spec
    if not isinstance(post, dict):
        raise ForgeError(prefix + ": postData must be an object")
    if post.get("encoding") is not None:
        raise ForgeError(prefix + ": encoded/binary request bodies are unsupported")
    mime = post.get("mimeType", content_type or "")
    if not isinstance(mime, str):
        raise ForgeError(prefix + ": body MIME type must be a string")
    media = mime.split(";", 1)[0].strip().lower()
    if "content-type" not in seen and mime:
        spec["headers"]["Content-Type"] = _binding(bindings, number, "MIME", base + "/postData/mimeType")
    if media.startswith("multipart/"):
        raise ForgeError(prefix + ": multipart/file bodies need explicit reconstruction, not a guessed replay")
    if "text" in post:
        text = post["text"]
        if not isinstance(text, str):
            raise ForgeError(prefix + ": request body text must be a string")
        if media == "application/json" or media.endswith("+json"):
            try:
                value = json.loads(text, parse_constant=_invalid_number)
            except (ValueError, RecursionError):
                raise ForgeError(prefix + ": JSON request body is incomplete or invalid") from None
            start = len(bindings)
            try:
                spec["json"] = _json_template(value, bindings, number, base + "/postData/text#")
            except ForgeError:
                del bindings[start:]
                spec["body"] = _binding(bindings, number, "BODY", base + "/postData/text", format="json_text")
                warnings.append({"entry": number, "type": "whole_json_body", "message": "Whole-body environment input preserves non-string credentials, types and complex shapes."})
        else:
            spec["body"] = _binding(bindings, number, "BODY", base + "/postData/text") if text else ""
    elif "params" in post:
        params = post["params"]
        if media != "application/x-www-form-urlencoded" or not isinstance(params, list):
            raise ForgeError(prefix + ": params-only bodies require URL-encoded form MIME type")
        if any(not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str) or "fileName" in item for item in params):
            raise ForgeError(prefix + ": form params must be named string values, without files")
        spec["body"] = _binding(bindings, number, "FORM", base + "/postData/params", format="form_urlencoded")
        warnings.append({"entry": number, "type": "form_encoding", "message": "Encode ordered params, including duplicates, into this environment value."})
    else:
        raise ForgeError(prefix + ": postData has neither complete text nor form params")
    return spec


def har_to_flow(args, store):
    if type(args.limit) is not int or not 1 <= args.limit <= 1000:
        raise ForgeError("--limit must be between 1 and 1000")
    if type(args.max_input_bytes) is not int or not 1 <= args.max_input_bytes <= 128 * 1024 * 1024:
        raise ForgeError("--max-input-bytes must be between 1 and 134217728")
    relative = forge_tasks._file_path(store, args.output)
    destination = store.root / relative
    if destination.exists():
        raise ForgeError("Flow output already exists; choose a new --output path")
    raw, entries = _input_bytes(store, args.har, args.max_input_bytes)
    bindings, warnings = [], []
    specs = [_entry(entry, index, bindings, warnings) for index, entry in enumerate(entries[:args.limit])]
    data = (json.dumps(specs, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    forge_tasks._file_path(store, relative.as_posix(), relative_only=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".forge-flow-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    record = store.add("har_flow", {"source_sha256": hashlib.sha256(raw).hexdigest(), "output": relative.as_posix(),
                                    "output_sha256": hashlib.sha256(data).hexdigest(), "converted": len(specs), "available": len(entries),
                                    "omitted": len(entries) - len(specs), "replayed": False,
                                    "variables": bindings, "warnings": warnings,
                                    "limits": ["All captured URLs and header/string-body values require explicit environment input; values are never exported.",
                                               "JSON field names and non-sensitive non-string constants remain; review the template before sharing.",
                                               "Classification rules and extraction bindings must be supplied from verified protocol knowledge.",
                                               "A capture is not a successful live replay; no request was sent."]})
    return {"record": record, "output": relative.as_posix(), "variables": bindings, "warnings": warnings,
            "converted": len(specs), "available": len(entries), "omitted": len(entries) - len(specs), "replayed": False}


def register(subparsers):
    command = subparsers.add_parser("har-to-flow", help="Export editable request templates from an explicit HAR without replay or credential values")
    command.add_argument("har", help="Explicit UTF-8 HAR input file")
    command.add_argument("--output", required=True, help="New project-relative flow JSON file; never overwritten")
    command.add_argument("--limit", type=int, default=50, help="Maximum entries to convert, preserving captured order")
    command.add_argument("--max-input-bytes", type=int, default=16 * 1024 * 1024, help="Bounded HAR input bytes")
    command.set_defaults(handler=har_to_flow)
