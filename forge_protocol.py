"""Read-only, metadata-only protocol observations with evidence citations."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlsplit

from forge_core import ForgeError, redact_url, scrub_text


KINDS = ("http_probe", "har_exchange", "analysis", "search")
STATIC_TOOL = "static_index"
NETWORK_TOOL = "pcap"
MAP_TOOL = "android"
MAP_ACTION = "api-map"
INPUT_NOTE = ("protocol-map input is live/imported HTTP evidence, a search record, a static index, an "
              "android api-map analysis, or a pcap-analyze analysis; a pcapdroid capture record carries no "
              "hosts of its own, so pass its cited pcap-analyze record instead")
MAX_FIELDS = 256
MAX_NODES = 2048
MAX_DEPTH = 16
MAX_BODY_BYTES = 1024 * 1024
MAX_OBSERVATIONS = 100
MAX_CITATIONS = 100
MAX_TOTAL_OBSERVATIONS = 20000
MAX_NETWORK_HOSTS = 200
MAX_NETWORK_MATCHES = 200
MAX_NETWORK_KINDS = 8
MAX_NETWORK_HTTP_VALUES = 8


def _relevant(record):
    if record["kind"] == "analysis":
        data = record.get("data")
        if not isinstance(data, dict):
            return False
        if data.get("tool") == NETWORK_TOOL:
            return True
        return data.get("tool") == STATIC_TOOL or (data.get("tool") == MAP_TOOL and
                                                   data.get("action") == MAP_ACTION)
    return record["kind"] in KINDS


def _is_map(record):
    data = record["data"]
    return data.get("tool") == MAP_TOOL and data.get("action") == MAP_ACTION


def _records(args, store):
    if not 1 <= args.limit <= 1000:
        raise ForgeError("Protocol map --limit must be between 1 and 1000")
    if not 1 <= args.max_endpoints <= 5000:
        raise ForgeError("Protocol map --max-endpoints must be between 1 and 5000")
    if args.evidence:
        records = []
        for evidence_id in dict.fromkeys(args.evidence):
            record = store.get(evidence_id)
            if not _relevant(record):
                raise ForgeError(f"Evidence {evidence_id} is not protocol-map input ({record['kind']}); {INPUT_NOTE}")
            if not isinstance(record.get("data"), dict):
                raise ForgeError(f"Evidence {evidence_id} has invalid protocol metadata")
            records.append(record)
        return records, False
    rows = store.connection.execute(
        "SELECT id, kind, created_at, data FROM evidence WHERE kind IN (?, ?, ?) "
        "OR (kind='analysis' AND (json_extract(data, '$.tool') IN (?, ?) "
        "OR (json_extract(data, '$.tool') = ? AND json_extract(data, '$.action') = ?))) "
        "ORDER BY created_at DESC, rowid DESC LIMIT ?",
        ("http_probe", "har_exchange", "search", STATIC_TOOL, NETWORK_TOOL, MAP_TOOL, MAP_ACTION,
         args.limit + 1)).fetchall()
    records = [{"id": row[0], "kind": row[1], "created_at": row[2], "data": json.loads(row[3])}
               for row in rows[:args.limit]]
    for record in records:
        if not isinstance(record["data"], dict):
            raise ForgeError(f"Evidence {record['id']} has invalid protocol metadata")
    return records, len(rows) > args.limit


def _names(values):
    names = sorted({scrub_text(str(name)) for name in values})
    return names[:MAX_FIELDS], len(names) > MAX_FIELDS


def _headers(side):
    headers = side.get("headers", {})
    return headers if isinstance(headers, dict) else {}


def _body_fields(side):
    body = side.get("body")
    content_type = next((str(value).lower().split(";", 1)[0].strip()
                         for key, value in _headers(side).items() if key.lower() == "content-type"), "")
    result = {"json_field_paths": [], "form_field_names": [], "fields_omitted": False,
              "body_unparsed": False}
    if body is None:
        return result
    if isinstance(body, str):
        if len(body) > MAX_BODY_BYTES:
            result.update(fields_omitted=True, body_unparsed=True)
            return result
        if content_type == "application/x-www-form-urlencoded":
            try:
                names, omitted = _names(key for key, _ in parse_qsl(body, keep_blank_values=True,
                                                                  max_num_fields=MAX_NODES))
            except ValueError:
                result.update(fields_omitted=True, body_unparsed=True)
                return result
            result.update(form_field_names=names, fields_omitted=omitted)
            return result
        try:
            body = json.loads(body)
        except (ValueError, RecursionError):
            result["body_unparsed"] = bool(body)
            return result
    if content_type in {"application/x-www-form-urlencoded", "multipart/form-data"}:
        if isinstance(body, dict):
            names, omitted = _names(body)
            result.update(form_field_names=names, fields_omitted=omitted)
        else:
            result["body_unparsed"] = True
        return result
    paths = set()
    stack = [(body, "", 0)]
    nodes = 0
    while stack:
        node, path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or len(paths) >= MAX_FIELDS:
            result["fields_omitted"] = True
            break
        if isinstance(node, (dict, list)) and depth >= MAX_DEPTH:
            result["fields_omitted"] = bool(node) or result["fields_omitted"]
            continue
        if isinstance(node, dict):
            for key, value in node.items():
                escaped = scrub_text(str(key)).replace("~", "~0").replace("/", "~1")
                child = path + "/" + escaped
                paths.add(child)
                if len(paths) >= MAX_FIELDS:
                    result["fields_omitted"] = True
                    break
                stack.append((value, child, depth + 1))
        elif isinstance(node, list):
            # Numeric array positions are structure, not captured values.
            available = max(0, MAX_NODES - nodes - len(stack))
            if len(node) > available:
                result["fields_omitted"] = True
            stack.extend((value, path + "/" + str(index), depth + 1)
                         for index, value in enumerate(node[:available]))
    result["json_field_paths"] = sorted(paths)
    return result


def _citation(record, location=None):
    citation = {"evidence_id": record["id"]}
    if isinstance(location, dict):
        # Never copy text, body, extracted values, or filesystem paths to open.
        keys = ("source", "member", "line", "column", "offset", "byte_offset", "offset_space",
                "compression", "encoding", "index_source", "kind", "sha256", "size", "class_name")
        citation["location"] = {key: scrub_text(value) if isinstance(value, str) else value
                                for key, value in location.items() if key in keys and
                                isinstance(value, (str, int, float, bool))}
    return citation


def _http(record):
    data = record["data"]
    request, response = data.get("request", {}), data.get("response", {})
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise ForgeError(f"Evidence {record['id']} has invalid HTTP metadata")
    if not isinstance(request.get("url"), str) or not isinstance(request.get("method"), str):
        raise ForgeError(f"Evidence {record['id']} has no observed HTTP URL/method")
    captured = record["kind"] == "har_exchange"
    expected_source = "har_import" if captured else "live_probe"
    if data.get("source") != expected_source:
        raise ForgeError(f"Evidence {record['id']} has inconsistent HTTP provenance")
    status = response.get("status")
    observed = type(status) is int and 100 <= status <= 599
    url = redact_url(request["url"])
    try:
        query, query_omitted = _names(key for key, _ in parse_qsl(urlsplit(url).query,
                                    keep_blank_values=True, max_num_fields=MAX_NODES))
    except ValueError:
        query, query_omitted = [], True
    request_headers, request_omitted = _names(_headers(request))
    response_headers, response_omitted = _names(_headers(response))
    request_fields, response_fields = _body_fields(request), _body_fields(response)
    extraction = data.get("extraction", [])
    selectors = []
    if isinstance(extraction, list):
        for item in extraction[:MAX_FIELDS]:
            if isinstance(item, dict):
                selectors.append({key: scrub_text(value) if isinstance(value, str) else value
                                  for key, value in item.items() if key in
                                  {"variable", "header", "json_path", "succeeded", "error"} and
                                  isinstance(value, (str, bool))})
    observation = {"category": "captured_http" if captured else "live_http",
                   "proven_live": not captured and observed, "proven_auth_path": False,
                   "response_observed": observed, "response_status": status if observed else None,
                   "response_truncated": bool(response.get("truncated")),
                   "response_error": scrub_text(response["error"]) if response.get("error") else None,
                   "query_field_names": query, "request_header_names": request_headers,
                   "response_header_names": response_headers,
                   "request_body": request_fields, "response_body": response_fields,
                   "extraction_selectors": selectors,
                   "metadata_omitted": query_omitted or request_omitted or response_omitted or
                       isinstance(extraction, list) and len(extraction) > MAX_FIELDS}
    return {"url": url, "method": scrub_text(request["method"])}, observation, _citation(record)


def _http_values(entry, key):
    """Return (bounded values, omitted) for one request-line list on a stored host entry.

    ``(None, False)`` means the entry declares no such list at all. Unusable items and values
    beyond the bound are reported as omitted rather than silently dropped.
    """
    values = entry.get(key)
    if not isinstance(values, list):
        return None, False
    usable = [value for value in values if isinstance(value, str) and value]
    text = sorted({scrub_text(value) for value in usable})
    omitted = len(text) > MAX_NETWORK_HTTP_VALUES or len(usable) != len(values)
    return text[:MAX_NETWORK_HTTP_VALUES], omitted


def _network(record):
    """Host identities observed in one cited packet analysis, with bounded request-line metadata.

    No path is invented: a host identity stays a host, and the copied method and origin-form
    request path come from the cited analysis exactly as it reported them, with no query string.
    """
    data = record["data"]
    hosts = data.get("hosts")
    capture = data.get("capture")
    if not isinstance(hosts, list):
        raise ForgeError(f"Evidence {record['id']} has invalid packet metadata")
    capture_sha = capture.get("sha256") if isinstance(capture, dict) else None
    capture_size = capture.get("size") if isinstance(capture, dict) else None
    location = {"kind": "packet_host"}
    if isinstance(capture_sha, str):
        location["sha256"] = capture_sha
    if type(capture_size) is int:
        location["size"] = capture_size
    emitted, hosts_omitted = [], len(hosts) > MAX_NETWORK_HOSTS
    kinds_omitted = False
    http_values_omitted = False
    for entry in hosts[:MAX_NETWORK_HOSTS]:
        if not isinstance(entry, dict) or not isinstance(entry.get("hostname"), str):
            continue
        observations = entry.get("observations")
        if not isinstance(observations, list):
            continue
        kinds = {}
        timestamps = []
        for item in observations:
            if not isinstance(item, dict) or not isinstance(item.get("kind"), str):
                continue
            if item["kind"] not in kinds and len(kinds) >= MAX_NETWORK_KINDS:
                kinds_omitted = True
                continue
            kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
            timestamp = item.get("timestamp")
            if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
                timestamps.append(round(float(timestamp), 6))
        methods, methods_omitted = _http_values(entry, "http_methods")
        paths, paths_omitted = _http_values(entry, "http_paths")
        http_values_omitted |= methods_omitted or paths_omitted
        observation = {"category": "captured_network", "proven_live": False, "proven_auth_path": False,
                       "observation_kinds": {name: kinds[name] for name in sorted(kinds)},
                       "observation_count": len(observations),
                       "first_timestamp": min(timestamps) if timestamps else None,
                       "last_timestamp": max(timestamps) if timestamps else None,
                       "decryption_performed": bool(data.get("decryption_performed")),
                       "note": "Hostname came from packet metadata (DNS/TLS SNI/plaintext Host); it is not a "
                               "successful call, and a copied request method and origin-form path keep no "
                               "query string, header or body and prove no authentication."}
        if methods is not None:
            observation["http_methods"] = methods
        if paths is not None:
            observation["http_paths"] = paths
        emitted.append(({"host": scrub_text(entry["hostname"])}, observation, _citation(record, location)))
    matches = data.get("static_host_matches")
    match_note = data.get("static_host_match_note")
    match_omitted = isinstance(matches, list) and len(matches) > MAX_NETWORK_MATCHES
    for entry in (matches[:MAX_NETWORK_MATCHES] if isinstance(matches, list) else []):
        if not isinstance(entry, dict) or not isinstance(entry.get("hostname"), str):
            continue
        sha = entry.get("static_candidate_sha256")
        if not isinstance(sha, str):
            continue
        observation = {"category": "static_host_match", "proven_live": False, "proven_auth_path": False,
                       "static_candidate_sha256": sha,
                       "note": scrub_text(match_note) if isinstance(match_note, str) else
                               "An observed hostname equals a static candidate host; the path, method and body "
                               "from that candidate are not proven."}
        citations = [_citation(record, {"kind": "static_host_match"})]
        for evidence_id in (entry.get("evidence_ids") or [])[:MAX_FIELDS]:
            if isinstance(evidence_id, str) and evidence_id.startswith("ev_"):
                citations.append({"evidence_id": evidence_id, "location": {"kind": "static_candidate"}})
        emitted.append(({"host": scrub_text(entry["hostname"])}, observation, citations))
    return emitted, hosts_omitted or match_omitted or kinds_omitted or http_values_omitted


def protocol_map(args, store):
    records, window_truncated = _records(args, store)
    endpoints = {}
    flags = {"window_truncated": window_truncated, "input_truncated": False,
             "output_truncated": False, "observations_omitted": False,
             "citations_omitted": False, "fields_omitted": False}
    sampled = []
    total = 0

    def add(identity, observation, citations):
        nonlocal total
        citations = [citations] if isinstance(citations, dict) else list(citations)
        key = json.dumps(identity, sort_keys=True)
        if key not in endpoints:
            if len(endpoints) >= args.max_endpoints:
                flags["output_truncated"] = True
                return
            endpoints[key] = {**identity, "proven_live": False, "proven_auth_path": False,
                              "observations": []}
        endpoint = endpoints[key]
        signature = json.dumps(observation, sort_keys=True)
        for existing in endpoint["observations"]:
            if json.dumps({k: v for k, v in existing.items() if k != "citations"}, sort_keys=True) == signature:
                for citation in citations:
                    if citation in existing["citations"]:
                        continue
                    if len(existing["citations"]) >= MAX_CITATIONS:
                        flags["citations_omitted"] = True
                    else:
                        existing["citations"].append(citation)
                return
        if len(endpoint["observations"]) >= MAX_OBSERVATIONS or total >= MAX_TOTAL_OBSERVATIONS:
            flags["observations_omitted"] = True
            return
        endpoint["observations"].append({**observation, "citations": list(citations)[:MAX_CITATIONS]})
        endpoint["proven_live"] |= observation["proven_live"]
        total += 1

    for record in records:
        data = record["data"]
        flags["input_truncated"] |= bool(data.get("truncated") or data.get("omitted"))
        if record["kind"] in {"http_probe", "har_exchange"}:
            identity, observation, citation = _http(record)
            flags["input_truncated"] |= observation["response_truncated"]
            flags["fields_omitted"] |= observation["metadata_omitted"] or any(
                observation[side]["fields_omitted"] for side in ("request_body", "response_body"))
            add(identity, observation, citation)
            continue
        if record["kind"] == "analysis" and data.get("tool") == NETWORK_TOOL:
            observed, truncated = _network(record)
            flags["input_truncated"] |= truncated
            for identity, observation, citations in observed:
                add(identity, observation, citations)
            continue
        if record["kind"] == "analysis" and _is_map(record):
            candidates = data.get("api_candidates")
            if not isinstance(candidates, list):
                raise ForgeError(f"Evidence {record['id']} has invalid api-map candidates")
            flags["input_truncated"] |= len(candidates) > 100
            for candidate in candidates[:100]:
                if not isinstance(candidate, dict) or not isinstance(candidate.get("url"), str):
                    continue
                location = candidate.get("source_occurrences")
                location = location[0] if isinstance(location, list) and location and \
                    isinstance(location[0], dict) else None
                sha = candidate.get("url_sha256")
                observation = {"category": "static_candidate", "proven_live": False, "proven_auth_path": False}
                if isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha):
                    observation["static_candidate_sha256"] = sha
                add({"url": redact_url(candidate["url"])}, observation, _citation(record, location))
            continue
        if record["kind"] == "analysis":
            candidates = data.get("endpoint_candidates", [])
            sampled.append({"evidence_id": record["id"], "metadata_candidate_limit": 100,
                            "sampling_possible": len(candidates) >= 100 if isinstance(candidates, list) else False})
            batches = [(candidates, None, 100)]
        else:
            matches = data.get("matches", [])
            if not isinstance(matches, list):
                raise ForgeError(f"Evidence {record['id']} has invalid search matches")
            flags["input_truncated"] |= len(matches) > 1000
            batches = [(match.get("endpoint_candidates", []), match, 20)
                       for match in matches[:1000] if isinstance(match, dict)]
        for candidates, location, bound in batches:
            if not isinstance(candidates, list):
                raise ForgeError(f"Evidence {record['id']} has invalid endpoint candidates")
            flags["input_truncated"] |= len(candidates) > bound
            for candidate in candidates[:bound]:
                if not isinstance(candidate, dict) or not isinstance(candidate.get("value"), str):
                    continue
                add({"url": redact_url(candidate["value"])},
                    {"category": "static_candidate", "proven_live": False, "proven_auth_path": False},
                    _citation(record, candidate.get("location", location)))
    return {"schema_version": 1, "evidence_ids": [record["id"] for record in records],
            "selection": "explicit" if args.evidence else "newest_relevant",
            "endpoints": list(endpoints.values()), "empty": not endpoints, **flags,
            "static_candidate_sampling": sampled,
            "limits": {"max_endpoints": args.max_endpoints, "record_window": args.limit,
                       "fields_per_body_or_name_list": MAX_FIELDS, "body_parse_characters": MAX_BODY_BYTES,
                       "body_nodes": MAX_NODES, "body_depth": MAX_DEPTH,
                       "observations_per_endpoint": MAX_OBSERVATIONS, "total_observations": MAX_TOTAL_OBSERVATIONS,
                       "citations_per_observation": MAX_CITATIONS, "search_matches_per_record": 1000,
                       "search_candidates_per_match": 20, "hosts_per_packet_record": MAX_NETWORK_HOSTS,
                       "static_host_matches_per_record": MAX_NETWORK_MATCHES,
                       "observation_kinds_per_host": MAX_NETWORK_KINDS,
                       "http_values_per_host": MAX_NETWORK_HTTP_VALUES},
            "authentication_verified": False}


def register(subparsers):
    parser = subparsers.add_parser("protocol-map",
                                   help="Map stored HTTP observations, packet-level hosts and cited static "
                                        "candidates without I/O")
    parser.add_argument("--evidence", action="append", default=[], metavar="ID",
                        help="Select explicit evidence IDs; repeatable, takes precedence over --limit")
    parser.add_argument("--limit", type=int, default=100, help="Newest relevant records (1..1000)")
    parser.add_argument("--max-endpoints", type=int, default=200, help="Maximum endpoint identities (1..5000)")
    parser.set_defaults(handler=protocol_map)
