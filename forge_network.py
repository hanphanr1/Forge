"""Explicit HTTP exchanges, redacted HAR imports, and evidence comparisons."""

import base64
import binascii
import gzip
import http.client
import http.cookiejar
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

from forge_core import ForgeError, redact, scrub_text


_FLOW = re.compile(r"\$\{flow\.([A-Za-z_][A-Za-z0-9_]*)\}")
_REFERENCE = re.compile(r"\$\{(flow\.[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*)\}")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_SENSITIVE = re.compile(
    r"password|passwd|passphrase|(?:^|[_-])(?:pass|pwd)(?:$|[_-])|secret|token|"
    r"authorization|cookie|session|credential|csrf|xsrf|email|username|"
    r"api[_-]?key|private[_-]?key", re.I
)
_REDACTED = re.compile(r"\[(?:redacted|removed)\]|<(?:redacted|removed)>|^REDACTED$", re.I)
_JSON_FIELDS = re.compile(
    r'(?P<key>"(?:\\.|[^"\\])*")\s*:\s*'
    r'(?P<value>"(?:\\.|[^"\\])*"|"(?:\\.|[^"\\])*\\?\Z|'
    r'-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
)
_MISSING = object()


def _load_json(path, store):
    path = Path(path).expanduser()
    if not path.is_absolute():
        path = store.root / path
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ForgeError(f"Cannot read JSON file {path}: {exc}") from None


def _add_secret(secrets, value, allow_redacted=False):
    if isinstance(value, str) and value and (allow_redacted or not _REDACTED.search(value)):
        secrets.add(value)
        decoded = urllib.parse.unquote(value)
        if decoded != value:
            secrets.add(decoded)
        for form in (urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value, safe=""),
                     json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value, ensure_ascii=True)[1:-1]):
            secrets.add(form)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        secrets.add(json.dumps(value))
    elif isinstance(value, (dict, list)):
        for item in value.values() if isinstance(value, dict) else value:
            _add_secret(secrets, item, allow_redacted)


def _sensitive_json_key(key):
    try:
        key = json.loads(key)
    except ValueError:
        key = key[1:-1]
    return bool(_SENSITIVE.search(key))


def _gather_secrets(value, secrets):
    if isinstance(value, dict):
        for key, item in value.items():
            if _SENSITIVE.search(str(key)):
                _add_secret(secrets, item)
                if isinstance(item, str):
                    # Bearer tokens and individual cookie values can be echoed alone.
                    if str(key).lower() in ("authorization", "proxy-authorization"):
                        parts = item.split(None, 1)
                        if len(parts) == 2:
                            _add_secret(secrets, parts[1])
                        if parts and parts[0].lower() == "basic" and len(parts) == 2:
                            try:
                                decoded = base64.b64decode(parts[1], validate=True).decode("utf-8")
                                _add_secret(secrets, decoded)
                                if ":" in decoded:
                                    _add_secret(secrets, decoded.split(":", 1)[1])
                            except (ValueError, UnicodeError):
                                pass
                    if "cookie" in str(key).lower():
                        for line in item.splitlines():
                            parts = line.split(";")
                            if str(key).lower() == "set-cookie":
                                parts = parts[:1]
                            for part in parts:
                                if "=" in part:
                                    _add_secret(secrets, part.split("=", 1)[1].strip())
            _gather_secrets(item, secrets)
    elif isinstance(value, list):
        for item in value:
            _gather_secrets(item, secrets)
    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            _gather_secrets(parsed, secrets)
        for key, item in urllib.parse.parse_qsl(value, keep_blank_values=True):
            if _SENSITIVE.search(key):
                _add_secret(secrets, item)
        for match in _JSON_FIELDS.finditer(value):
            if _sensitive_json_key(match["key"]):
                try:
                    field = json.loads(match["value"])
                except ValueError:
                    field = match["value"].lstrip('"')
                _add_secret(secrets, field)


def _url_secrets(url, secrets):
    try:
        parsed = urllib.parse.urlsplit(url)
        for value in (parsed.username, parsed.password):
            _add_secret(secrets, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            if _SENSITIVE.search(key):
                _add_secret(secrets, value)
    except ValueError:
        pass


def _substitute(value, secrets, bindings, environment):
    if isinstance(value, str):
        def replace(match):
            name = match.group(1)
            if name.startswith("flow."):
                variable = name[5:]
                if variable not in bindings:
                    raise ForgeError(f"Flow variable {variable} is not available")
                return bindings[variable]
            if name not in environment:
                if name not in os.environ:
                    raise ForgeError(f"Environment variable {name} is not defined")
                environment[name] = os.environ[name]
            secret = environment[name]
            _add_secret(secrets, secret)
            return secret
        return _REFERENCE.sub(replace, value)
    if isinstance(value, list):
        return [_substitute(item, secrets, bindings, environment) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(item, secrets, bindings, environment) for key, item in value.items()}
    return value


def _flow_references(value, allowed=False):
    references = set()
    if isinstance(value, str):
        if re.search(r"\$\{flow(?:\.|[^A-Za-z0-9_}]|$)", _FLOW.sub("", value)):
            raise ForgeError("Malformed flow variable reference")
        references.update(_FLOW.findall(value))
        if references and not allowed:
            raise ForgeError("Flow variables are allowed only in URL path/query, header values, and request bodies")
    elif isinstance(value, dict):
        for key, item in value.items():
            _flow_references(key)
            references.update(_flow_references(item, allowed))
    elif isinstance(value, list):
        for item in value:
            references.update(_flow_references(item, allowed))
    return references


def _validate_dependencies(spec, available):
    if not isinstance(spec, dict):
        raise ForgeError("Each request spec must be a JSON object")
    references = set()
    for field, value in spec.items():
        _flow_references(field)
        references.update(_flow_references(value, field in {"url", "headers", "json", "body"}))
    url = spec.get("url")
    if isinstance(url, str):
        authority = re.match(r"^[^:/?#]*://[^/?#]*", url)
        _flow_references(authority.group(0) if authority else url)
        if "#" in url:
            _flow_references(url.split("#", 1)[1])
    missing = references - available
    if missing:
        raise ForgeError(f"Undefined or forward flow references: {', '.join(sorted(missing))}")


def _validate_extract(extract):
    if not isinstance(extract, dict):
        raise ForgeError("Request extract must be an object")
    prepared = {}
    for name, selector in extract.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ForgeError("Extraction variable names must be valid identifiers")
        if not isinstance(selector, dict) or len(selector) != 1:
            raise ForgeError(f"Extractor {name}: specify exactly one json_path or header")
        if "json_path" in selector:
            prepared[name] = {"json_path": selector["json_path"], "parts": _path_parts(selector["json_path"])}
        elif "header" in selector and isinstance(selector["header"], str) and _HEADER_NAME.fullmatch(selector["header"]):
            prepared[name] = {"header": selector["header"].lower()}
        else:
            raise ForgeError(f"Extractor {name}: expected a JSON path or valid HTTP header name")
    return prepared


def _has_redacted(value):
    if isinstance(value, str):
        return bool(_REDACTED.search(value))
    if isinstance(value, dict):
        return any(_has_redacted(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_redacted(item) for item in value)
    return False


def _path_parts(path):
    if not isinstance(path, str) or not path:
        raise ForgeError("Rule json_path must be a nonempty string")
    if path == "$":
        return []
    if path.startswith("/"):
        if re.search(r"~(?![01])", path):
            raise ForgeError("Invalid JSON pointer escape in json_path")
        return [part.replace("~1", "/").replace("~0", "~") for part in path[1:].split("/")]
    path = path[2:] if path.startswith("$.") else path
    if not re.fullmatch(r"[^.\[\]\s]+(?:\[\d+\])*(?:\.[^.\[\]\s]+(?:\[\d+\])*)*", path):
        raise ForgeError("json_path must be a JSON pointer, '$', or dotted path with numeric indexes")
    return re.findall(r"[^.\[\]]+", path)


def _validate_rules(rules):
    if not isinstance(rules, list):
        raise ForgeError("Classification rules must be a JSON array")
    compiled = []
    for index, rule in enumerate(rules):
        prefix = f"Rule {index + 1}"
        if not isinstance(rule, dict) or set(rule) - {"bucket", "contains", "json_path", "equals", "regex", "status"}:
            raise ForgeError(f"{prefix}: expected an object with bucket and one body predicate")
        if not isinstance(rule.get("bucket"), str) or not rule["bucket"].strip():
            raise ForgeError(f"{prefix}: bucket must be a nonempty string")
        predicates = [key for key in ("contains", "json_path", "regex") if key in rule]
        if len(predicates) != 1 or ("equals" in rule and "json_path" not in rule):
            raise ForgeError(f"{prefix}: specify exactly one of contains, json_path (with optional equals), or regex")
        prepared = dict(rule)
        if "contains" in rule and (not isinstance(rule["contains"], str) or not rule["contains"]):
            raise ForgeError(f"{prefix}: contains must be a nonempty string")
        if "json_path" in rule:
            prepared["parts"] = _path_parts(rule["json_path"])
        if "regex" in rule:
            if not isinstance(rule["regex"], str) or not rule["regex"]:
                raise ForgeError(f"{prefix}: regex must be a nonempty string")
            try:
                prepared["pattern"] = re.compile(rule["regex"])
            except re.error as exc:
                raise ForgeError(f"{prefix}: invalid regex: {exc}") from None
        if "status" in rule:
            statuses = rule["status"] if isinstance(rule["status"], list) else [rule["status"]]
            if not statuses or any(type(value) is not int or not 100 <= value <= 599 for value in statuses):
                raise ForgeError(f"{prefix}: status must be an HTTP status integer or nonempty list of them")
            prepared["statuses"] = statuses
        compiled.append(prepared)
    return compiled


def _classify(body, status, rules):
    parsed = _MISSING
    for index, rule in enumerate(rules):
        if "statuses" in rule and status not in rule["statuses"]:
            continue
        if "contains" in rule:
            matched = rule["contains"] in body
        elif "pattern" in rule:
            matched = bool(rule["pattern"].search(body))
        else:
            if parsed is _MISSING:
                try:
                    parsed = json.loads(body)
                except ValueError:
                    parsed = None
            value = parsed
            for part in rule["parts"]:
                if isinstance(value, dict):
                    value = value.get(part, _MISSING)
                elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                    value = value[int(part)]
                else:
                    value = _MISSING
                if value is _MISSING:
                    break
            matched = value is not _MISSING and ("equals" not in rule or value == rule["equals"])
            if not rule["parts"] and parsed is None:
                # Distinguish a valid JSON null from a non-JSON response.
                matched = body.strip() == "null" and ("equals" not in rule or rule["equals"] is None)
        if matched:
            return rule["bucket"], index
    return "UNKNOWN", None


def _sanitize(value, secrets):
    def sanitize_keys(item):
        if isinstance(item, dict):
            return {scrub_text(str(key), secrets=tuple(secrets)):
                    "[REDACTED]" if _SENSITIVE.search(str(key)) else sanitize_keys(child)
                    for key, child in item.items()}
        if isinstance(item, list):
            return [sanitize_keys(child) for child in item]
        return item
    return sanitize_keys(redact(value, secrets=tuple(secrets)))


def _decode_body(raw, headers):
    content_type = next((value for key, value in headers.items() if key.lower() == "content-type"), "")
    match = re.search(r"charset\s*=\s*[\"']?([^\s;\"']+)", content_type, re.I)
    encoding = match.group(1) if match else "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _safe_body(text, secrets, truncated):
    try:
        value = json.loads(text)
    except ValueError:
        value = text
    _gather_secrets(value, secrets)
    if isinstance(value, (dict, list)):
        return _sanitize(value, secrets)
    def mask_field(match):
        if _sensitive_json_key(match["key"]):
            prefix = match.group(0)[:match.start("value") - match.start()]
            return prefix + '"[REDACTED]"'
        return match.group(0)
    safe = scrub_text(_JSON_FIELDS.sub(mask_field, text), secrets=tuple(secrets))
    if truncated:
        # A byte limit may cut a known credential before its final character.
        for secret in sorted(secrets, key=len, reverse=True):
            for length in range(min(len(secret) - 1, len(safe)), 0, -1):
                if safe.endswith(secret[:length]):
                    safe = safe[:-length] + "[REDACTED]"
                    break
    return safe


def _validate_spec(spec, default_rules, secrets):
    if not isinstance(spec, dict):
        raise ForgeError("Each request spec must be a JSON object")
    allowed = {"url", "method", "headers", "json", "body", "proxy", "context", "rules", "extract"}
    extra = set(spec) - allowed
    if extra:
        raise ForgeError(f"Unknown request fields: {', '.join(sorted(extra))}")
    _gather_secrets(spec, secrets)
    url = spec.get("url")
    if not isinstance(url, str):
        raise ForgeError("Request url must be a string")
    _url_secrets(url, secrets)
    try:
        parsed = urllib.parse.urlsplit(url)
        valid_url = parsed.scheme in ("http", "https") and bool(parsed.hostname) and parsed.port != 0
    except ValueError:
        valid_url = False
    if not valid_url or re.search(r"[\x00-\x20\x7f]", url):
        raise ForgeError("Request url must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ForgeError("URL userinfo is not supported; supply credentials through explicit headers")
    method = spec.get("method", "GET")
    if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]+", method):
        raise ForgeError("Request method must contain letters only")
    headers = spec.get("headers", {})
    if not isinstance(headers, dict) or any(
        not isinstance(key, str) or not _HEADER_NAME.fullmatch(key)
        or not isinstance(value, str) or re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value)
        for key, value in headers.items()
    ):
        raise ForgeError("Request headers must map valid HTTP header names to single-line strings")
    if "json" in spec and "body" in spec:
        raise ForgeError("Specify json OR body, not both")
    if "body" in spec and not isinstance(spec["body"], str):
        raise ForgeError("Request body must be a string; use json for structured data")
    context = spec.get("context", {})
    if not isinstance(context, dict):
        raise ForgeError("Request context must be an object")
    proxy = spec.get("proxy")
    if proxy is not None:
        if not isinstance(proxy, str):
            raise ForgeError("Request proxy must be a URL string")
        _url_secrets(proxy, secrets)
        try:
            proxy_url = urllib.parse.urlsplit(proxy)
            valid_proxy = proxy_url.scheme in ("http", "https", "socks5", "socks5h") and bool(proxy_url.hostname)
            proxy_url.port
        except ValueError:
            valid_proxy = False
        if not valid_proxy:
            raise ForgeError("Proxy must be an http://, https://, socks5://, or socks5h:// URL")
    request = {"method": method.upper(), "url": url, "headers": dict(headers), "body": spec.get("json", spec.get("body"))}
    if _has_redacted({**request, "proxy": proxy}):
        raise ForgeError("Redacted evidence cannot be replayed: supply an explicit request with real values or ${ENV_VAR}")
    data = None
    if "json" in spec:
        try:
            data = json.dumps(spec["json"], ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise ForgeError(f"Invalid JSON request body: {exc}") from None
        if not any(key.lower() == "content-type" for key in headers):
            request["headers"]["Content-Type"] = "application/json"
    elif "body" in spec:
        try:
            data = spec["body"].encode("utf-8")
        except UnicodeError:
            raise ForgeError("Request body contains invalid Unicode") from None
    rules = _validate_rules(spec["rules"]) if "rules" in spec else default_rules
    return {"request": request, "data": data, "proxy": proxy, "context": context, "rules": rules,
            "extract": _validate_extract(spec.get("extract", {}))}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _UrllibSession:
    name = "urllib"
    error_types = (urllib.error.URLError, OSError, ValueError, http.client.HTTPException, ForgeError, EOFError, zlib.error)

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.openers = {}

    def request(self, spec, timeout, max_body, secrets):
        proxy = spec["proxy"]
        if proxy and urllib.parse.urlsplit(proxy).scheme not in ("http", "https"):
            raise ForgeError("urllib supports HTTP(S) proxies only; use --transport curl_cffi for SOCKS proxies")
        if proxy not in self.openers:
            self.openers[proxy] = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
                urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect(),
            )
        request = urllib.request.Request(spec["request"]["url"], data=spec["data"],
                                         headers=spec["request"]["headers"], method=spec["request"]["method"])
        self.jar.add_cookie_header(request)
        sent_headers = dict(request.header_items())
        _gather_secrets(sent_headers, secrets)
        try:
            response = self.openers[proxy].open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            headers = _headers_dict(response.headers.items())
            encoding = response.headers.get("Content-Encoding", "").strip().lower()
            if encoding in {"gzip", "x-gzip"}:
                with gzip.GzipFile(fileobj=response) as decoded:
                    raw = decoded.read(max_body + 1)
            elif encoding in {"", "identity"}:
                raw = response.read(max_body + 1)
            else:
                raise ForgeError(f"urllib cannot decode Content-Encoding {encoding}; use --transport curl_cffi")
            status = response.code
        for cookie in self.jar:
            _add_secret(secrets, cookie.value)
        return status, headers, raw[:max_body], len(raw) > max_body, sent_headers

    def close(self):
        self.jar.clear()
        self.openers.clear()


class _CurlSession:
    name = "curl_cffi"

    def __init__(self, impersonate):
        try:
            from curl_cffi import requests
            from curl_cffi.requests.exceptions import RequestException
        except ImportError:
            raise ForgeError("curl_cffi transport is unavailable. Install it with 'python -m pip install curl_cffi', or use --transport urllib without impersonation.") from None
        self.session = requests.Session(trust_env=False)
        self.impersonate = impersonate
        self.error_types = (RequestException, OSError, ValueError)

    def request(self, spec, timeout, max_body, secrets):
        headers = spec["request"]["headers"]
        for cookie in self.session.cookies.jar:
            _add_secret(secrets, cookie.value)
        kwargs = {"headers": headers, "data": spec["data"], "timeout": timeout,
                  "allow_redirects": False, "stream": True}
        if spec["proxy"]:
            kwargs["proxy"] = spec["proxy"]
        if self.impersonate:
            kwargs["impersonate"] = self.impersonate
        response = self.session.request(spec["request"]["method"], spec["request"]["url"], **kwargs)
        try:
            response_headers = _headers_dict(response.headers.multi_items())
            chunks = []
            received = 0
            for chunk in response.iter_content(chunk_size=min(max_body + 1, 65536)):
                if not chunk:
                    continue
                chunk = chunk[:max_body + 1 - received]
                chunks.append(chunk)
                received += len(chunk)
                if received > max_body:
                    break
            raw = b"".join(chunks)
            sent_headers = dict(response.request.headers) if response.request else dict(headers)
            for cookie in self.session.cookies.jar:
                _add_secret(secrets, cookie.value)
            _gather_secrets(sent_headers, secrets)
            return response.status_code, response_headers, raw[:max_body], len(raw) > max_body, sent_headers
        finally:
            response.close()

    def close(self):
        self.session.close()


def _headers_dict(pairs):
    result = {}
    for key, value in pairs:
        key = str(key).lower()
        value = str(value)
        result[key] = result[key] + "\n" + value if key in result else value
    return result


def _live_options(args):
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ForgeError("--timeout must be a finite positive number")
    if args.max_body < 1:
        raise ForgeError("--max-body must be positive")
    if args.impersonate and args.transport != "curl_cffi":
        raise ForgeError("--impersonate/--fingerprint requires explicit --transport curl_cffi; urllib does not emulate mobile TLS")


def _json_at(value, parts):
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part, _MISSING)
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return _MISSING
    return value


def _extract_response(text, headers, truncated, extract, bindings, secrets):
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = _MISSING
    metadata = {}
    outputs = {}
    for name, selector in extract.items():
        if "header" in selector:
            value = headers.get(selector["header"], _MISSING)
            if isinstance(value, str):
                for line in value.splitlines():
                    _add_secret(secrets, line, allow_redacted=True)
            public_selector = {"header": selector["header"]}
        else:
            value = _json_at(parsed, selector["parts"])
            public_selector = {"json_path": selector["json_path"]}
        if value is not _MISSING:
            _add_secret(secrets, value, allow_redacted=True)
        if truncated:
            error = "truncated_response"
        elif value is _MISSING:
            error = "missing_value"
        elif not isinstance(value, str) or not value:
            error = "expected_nonempty_string"
        elif "\r" in value or "\n" in value:
            error = "newline_or_ambiguous_value"
        elif _REDACTED.search(value):
            error = "redacted_value"
        else:
            error = None
            outputs[name] = value
        metadata[name] = {**public_selector, "succeeded": error is None}
        if error:
            metadata[name]["error"] = error

    # Mask declared locations even when the value cannot be used as a binding.
    safe_headers = dict(headers)
    safe_parsed = parsed
    for selector in extract.values():
        if "header" in selector:
            if selector["header"] in safe_headers:
                safe_headers[selector["header"]] = "[REDACTED]"
        elif safe_parsed is not _MISSING:
            parts = selector["parts"]
            if not parts:
                safe_parsed = "[REDACTED]"
                continue
            parent = _json_at(safe_parsed, parts[:-1])
            if isinstance(parent, dict) and parts[-1] in parent:
                parent[parts[-1]] = "[REDACTED]"
            elif isinstance(parent, list) and parts[-1].isdigit() and int(parts[-1]) < len(parent):
                parent[int(parts[-1])] = "[REDACTED]"
    json_extract = any("json_path" in selector for selector in extract.values())
    if json_extract:
        safe_text = json.dumps(safe_parsed, ensure_ascii=False) if safe_parsed is not _MISSING else '"[REDACTED]"'
    else:
        safe_text = text
    failed = any(not item["succeeded"] for item in metadata.values())
    if not failed:
        bindings.update(outputs)
    return metadata, failed, safe_text, safe_headers


def _exchange(spec, args, session, secrets, bindings):
    started = time.perf_counter()
    transport = {"name": session.name, "impersonate": args.impersonate,
                 "tls_emulation": bool(args.impersonate), "redirects": False, "retries": 0,
                 "proxy": spec["proxy"]}
    error = None
    extraction = {}
    extraction_error = False
    try:
        status, headers, raw, truncated, sent_headers = session.request(spec, args.timeout, args.max_body, secrets)
    except session.error_types as exc:
        elapsed = (time.perf_counter() - started) * 1000
        error = scrub_text(str(exc), secrets=tuple(secrets))
        response = {"status": None, "headers": {}, "body": None, "truncated": False, "error": error}
        request = spec["request"]
        bucket, matched = "UNKNOWN", None
    else:
        elapsed = (time.perf_counter() - started) * 1000
        text = _decode_body(raw, headers)
        _gather_secrets(headers, secrets)
        _gather_secrets(text, secrets)
        bucket, matched = _classify(text, status, spec["rules"])
        if spec["extract"]:
            extraction, extraction_error, text, headers = _extract_response(
                text, headers, truncated, spec["extract"], bindings, secrets)
        body = _safe_body(text, secrets, truncated)
        response = {"status": status, "headers": headers, "body": body, "truncated": truncated,
                    "captured_bytes": len(raw), "body_limit_bytes": args.max_body}
        request = {**spec["request"], "headers": sent_headers}
    data = {"source": "live_probe", "request": request, "response": response, "transport": transport,
            "context": spec["context"], "bucket": bucket, "matched_rule_index": matched,
            "elapsed_ms": round(elapsed, 3),
            "redaction": {"applied": True, "known_secret_count": len(secrets), "replayable": False}}
    if spec["extract"]:
        if error is not None:
            extraction = {name: {key: value for key, value in selector.items() if key != "parts"}
                          | {"succeeded": False, "error": "transport_error"}
                          for name, selector in spec["extract"].items()}
        data["extraction"] = [{"variable": name, **details} for name, details in extraction.items()]
    return _sanitize(data, secrets), error, bucket, extraction_error


def _prepare_live(args, store, many):
    _live_options(args)
    raw_defaults = _load_json(args.rules, store) if args.rules else []
    _flow_references(raw_defaults)
    defaults = _validate_rules(raw_defaults)
    raw = _load_json(args.requests if many else args.request, store)
    if many:
        if not isinstance(raw, list) or not raw:
            raise ForgeError("probe-run requires a nonempty JSON array of explicit request specs")
    else:
        raw = [raw]
    secrets = set()
    environment = {}
    available = {}
    specs = []
    try:
        for template in raw:
            _validate_dependencies(template, set(available))
            materialized = _substitute(template, secrets, available, environment)
            preflight_secrets = set()
            spec = _validate_spec(materialized, defaults, preflight_secrets)
            secrets.update(preflight_secrets)
            if args.transport == "urllib" and spec["proxy"] and urllib.parse.urlsplit(spec["proxy"]).scheme not in ("http", "https"):
                raise ForgeError("urllib supports HTTP(S) proxies only; use --transport curl_cffi for SOCKS proxies")
            specs.append({"template": template, "defaults": defaults})
            available.update({name: "${flow." + name + "}" for name in spec["extract"]})
    except ForgeError as exc:
        message = scrub_text(str(exc), secrets=tuple(secrets))
        secrets.clear()
        environment.clear()
        raise ForgeError(message) from None
    return specs, secrets, environment


def handle_probe(args, store):
    specs, secrets, environment = _prepare_live(args, store, False)
    bindings = {}
    session = None
    try:
        session = _CurlSession(args.impersonate) if args.transport == "curl_cffi" else _UrllibSession()
        spec = _validate_spec(_substitute(specs[0]["template"], secrets, bindings, environment),
                              specs[0]["defaults"], secrets)
        data, error, bucket, extraction_error = _exchange(spec, args, session, secrets, bindings)
        record = store.add("http_probe", _sanitize(data, secrets))
        if error is not None:
            raise ForgeError(f"Probe transport error (evidence {record['id']}): {error}")
        if extraction_error and bucket != "TERMINAL":
            raise ForgeError(f"Probe extraction error (evidence {record['id']})")
        return record
    finally:
        if session is not None:
            session.close()
        bindings.clear()
        environment.clear()
        secrets.clear()


def handle_probe_run(args, store):
    specs, secrets, environment = _prepare_live(args, store, True)
    bindings = {}
    session = None
    pending = []
    reason = None
    stop_buckets = set(args.stop_bucket or ["TERMINAL"])
    try:
        session = _CurlSession(args.impersonate) if args.transport == "curl_cffi" else _UrllibSession()
        for prepared in specs:
            try:
                spec = _validate_spec(_substitute(prepared["template"], secrets, bindings, environment),
                                      prepared["defaults"], secrets)
            except ForgeError as exc:
                if not pending:
                    raise ForgeError(scrub_text(str(exc), secrets=tuple(secrets))) from None
                reason = {"type": "extraction_error",
                          "message": "Materialized request rejected: " + scrub_text(str(exc), secrets=tuple(secrets))}
                break
            data, error, bucket, extraction_error = _exchange(spec, args, session, secrets, bindings)
            pending.append(data)
            if error is not None:
                reason = {"type": "transport_error", "message": error}
                break
            if bucket in stop_buckets:
                reason = {"type": "bucket", "bucket": bucket}
                break
            if extraction_error:
                reason = {"type": "extraction_error", "message": "Response extraction failed"}
                break
        # Nothing enters SQLite/WAL until later extractions can redact earlier echoes.
        records = []
        for data in pending:
            data["redaction"]["known_secret_count"] = len(secrets)
            records.append(store.add("http_probe", _sanitize(data, secrets)))
        if reason is not None:
            reason = _sanitize(reason, secrets)
            reason["evidence_id"] = records[-1]["id"]
        return {"exchanges": records, "completed": len(records), "requested": len(specs),
                "stopped": reason is not None, "stop_reason": reason, "session_reused": True}
    finally:
        if session is not None:
            session.close()
        bindings.clear()
        environment.clear()
        secrets.clear()
        pending.clear()


def _har_headers(items):
    if not isinstance(items, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                                         or not isinstance(item.get("value"), str) for item in items):
        raise ForgeError("HAR headers must be arrays of name/value objects")
    return _headers_dict((item["name"], item["value"]) for item in items)


def _har_entry(entry, max_body, rules, secrets):
    if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict) or not isinstance(entry.get("response"), dict):
        raise ForgeError("Each HAR entry must contain request and response objects")
    request, response = entry["request"], entry["response"]
    if not isinstance(request.get("url"), str) or not isinstance(request.get("method"), str):
        raise ForgeError("HAR request url and method must be strings")
    status = response.get("status")
    if type(status) is not int:
        raise ForgeError("HAR response status must be an integer")
    request_headers = _har_headers(request.get("headers", []))
    response_headers = _har_headers(response.get("headers", []))
    post = request.get("postData", {})
    if not isinstance(post, dict):
        raise ForgeError("HAR postData must be an object")
    body = post.get("text")
    if body is not None and not isinstance(body, str):
        raise ForgeError("HAR postData.text must be a string")
    if body is None and "params" in post:
        params = post["params"]
        if not isinstance(params, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in params):
            raise ForgeError("HAR postData.params must be an array of named values")
        body = {item["name"]: item.get("value") for item in params}
    content = response.get("content", {})
    if not isinstance(content, dict) or not isinstance(content.get("text", ""), str):
        raise ForgeError("HAR response content must contain a text string when present")
    text = content.get("text", "")
    encoding = content.get("encoding")
    if encoding == "base64":
        try:
            raw = base64.b64decode(text, validate=True)
        except (ValueError, binascii.Error):
            raise ForgeError("HAR contains invalid base64 response content") from None
    elif encoding is None:
        try:
            raw = text.encode("utf-8")
        except UnicodeError:
            raise ForgeError("HAR response text contains invalid Unicode") from None
    else:
        raise ForgeError(f"Unsupported HAR content encoding: {encoding}")
    truncated = len(raw) > max_body
    text = (_decode_body(raw[:max_body], response_headers) if encoding == "base64"
            else raw[:max_body].decode("utf-8", errors="replace"))
    for item in (request_headers, response_headers, body, text):
        _gather_secrets(item, secrets)
    _url_secrets(request["url"], secrets)
    for owner in (request, response):
        cookies = owner.get("cookies", [])
        if not isinstance(cookies, list):
            raise ForgeError("HAR cookies must be an array")
        for cookie in cookies:
            if isinstance(cookie, dict):
                _add_secret(secrets, cookie.get("value"))
    bucket, matched = _classify(text, status, rules)
    elapsed = entry.get("time")
    if elapsed is not None and (not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed)):
        raise ForgeError("HAR entry time must be a finite number")
    return {"source": "har_import", "request": {"method": request["method"], "url": request["url"],
            "headers": request_headers, "body": body},
            "response": {"status": status, "headers": response_headers, "body": text,
                         "truncated": truncated, "captured_bytes": min(len(raw), max_body),
                         "body_limit_bytes": max_body, "content_available": "text" in content},
            "transport": {"name": "har", "replayed": False}, "context": {"started_at": entry.get("startedDateTime")},
            "bucket": bucket, "matched_rule_index": matched, "elapsed_ms": elapsed,
            "redaction": {"applied": True, "replayable": False}}


def handle_har_import(args, store):
    if args.limit < 1 or args.max_body < 1:
        raise ForgeError("--limit and --max-body must be positive")
    rules = _validate_rules(_load_json(args.rules, store)) if args.rules else []
    har = _load_json(args.har, store)
    log = har.get("log") if isinstance(har, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ForgeError("HAR must contain log.entries as an array")
    secrets = set()
    data = [_har_entry(entry, args.max_body, rules, secrets) for entry in entries[:args.limit]]
    records = []
    for item in data:
        item["response"]["body"] = _safe_body(item["response"]["body"], secrets, item["response"]["truncated"])
        if isinstance(item["request"]["body"], str):
            item["request"]["body"] = _safe_body(item["request"]["body"], secrets, False)
        item["redaction"]["known_secret_count"] = len(secrets)
        records.append(store.add("har_exchange", _sanitize(item, secrets)))
    return {"exchanges": records, "imported": len(records), "available": len(entries),
            "omitted": max(0, len(entries) - args.limit), "replayed": False}


def _body_value(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            pass
    return value


def _nested_diff(left, right, path=""):
    changes = []
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            child = path + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if key not in left:
                changes.append({"path": child, "change": "added", "after": right[key]})
            elif key not in right:
                changes.append({"path": child, "change": "removed", "before": left[key]})
            else:
                changes.extend(_nested_diff(left[key], right[key], child))
    elif isinstance(left, list) and isinstance(right, list):
        for index in range(max(len(left), len(right))):
            child = path + "/" + str(index)
            if index >= len(left):
                changes.append({"path": child, "change": "added", "after": right[index]})
            elif index >= len(right):
                changes.append({"path": child, "change": "removed", "before": left[index]})
            else:
                changes.extend(_nested_diff(left[index], right[index], child))
    elif type(left) is not type(right) or left != right:
        changes.append({"path": path or "/", "change": "changed", "before": left, "after": right})
    return changes


def handle_diff(args, store):
    left_record, right_record = store.get(args.left), store.get(args.right)
    for record in (left_record, right_record):
        if record["kind"] not in ("http_probe", "har_exchange"):
            raise ForgeError("diff requires http_probe or har_exchange evidence IDs")
    left, right = left_record["data"], right_record["data"]
    result = {"left": left_record["id"], "right": right_record["id"],
              "status": _nested_diff(left["response"].get("status"), right["response"].get("status")),
              "bucket": _nested_diff(left.get("bucket"), right.get("bucket")), "request": {}, "response": {},
              "redacted_comparison": True}
    for side in ("request", "response"):
        for field in (("method", "url", "headers", "body") if side == "request" else ("headers", "body", "truncated")):
            before, after = left[side].get(field), right[side].get(field)
            if field == "headers":
                before = _headers_dict((before or {}).items())
                after = _headers_dict((after or {}).items())
            elif field == "body":
                before, after = _body_value(before), _body_value(after)
            result[side][field] = _nested_diff(before, after)
    result["changed"] = bool(result["status"] or result["bucket"] or any(
        changes for side in ("request", "response") for changes in result[side].values()))
    return result


def _live_arguments(parser):
    parser.add_argument("--rules", help="JSON array of body classification rules; request rules override these")
    parser.add_argument("--transport", choices=("urllib", "curl_cffi"), default="urllib")
    parser.add_argument("--impersonate", "--fingerprint", dest="impersonate", help="curl_cffi impersonation profile, not a promise of mobile TLS equivalence")
    parser.add_argument("--timeout", type=float, default=30.0, help="Transport timeout in seconds (default: 30)")
    parser.add_argument("--max-body", type=int, default=1048576, help="Maximum captured response bytes (default: 1048576)")


def register(subparsers):
    probe = subparsers.add_parser("probe", help="Send one explicit JSON request and save redacted evidence")
    probe.add_argument("request", help="Request JSON file")
    _live_arguments(probe)
    probe.set_defaults(handler=handle_probe)

    run = subparsers.add_parser("probe-run", help="Execute a JSON request array sequentially in one cookie session")
    run.add_argument("requests", help="JSON array of request specs (not an account list)")
    _live_arguments(run)
    run.add_argument("--stop-bucket", action="append", help="Stop after this classified bucket; repeatable (default: TERMINAL)")
    run.set_defaults(handler=handle_probe_run)

    har = subparsers.add_parser("har-import", help="Import a limited number of redacted HAR exchanges without replay")
    har.add_argument("har", help="HAR JSON file")
    har.add_argument("--limit", type=int, default=50, help="Maximum entries to import (default: 50)")
    har.add_argument("--max-body", type=int, default=1048576, help="Maximum response bytes per entry")
    har.add_argument("--rules", help="JSON array of body classification rules")
    har.set_defaults(handler=handle_har_import)

    diff = subparsers.add_parser("diff", help="Compare request/response bodies, headers, status, and buckets by evidence ID")
    diff.add_argument("left", help="Earlier network evidence ID")
    diff.add_argument("right", help="Later network evidence ID")
    diff.set_defaults(handler=handle_diff)
