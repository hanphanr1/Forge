"""Immutable, cited comparisons of stored protocol and client observations."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.parse import urlsplit, urlunsplit
import zipfile
import zlib

from forge_artifacts import ARCHIVES, CHUNK, _candidates, _safe_member, _zip_entries
from forge_core import ForgeError, redact, redact_url, scrub_text
from forge_protocol import _citation, protocol_map

SCHEMA_VERSION = 1


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _ordered(values):
    return [json.loads(value) for value in sorted({_canonical(item) for item in values})]


def protocol_snapshot(args, store):
    mapped = protocol_map(args, store)
    return store.add("protocol_snapshot", {
        "schema_version": SCHEMA_VERSION,
        "options": {"evidence": list(dict.fromkeys(args.evidence)), "limit": args.limit,
                    "max_endpoints": args.max_endpoints},
        "map": mapped,
    })


def _snapshot(store, evidence_id):
    record = store.get(evidence_id)
    data = record["data"]
    if record["kind"] != "protocol_snapshot" or not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ForgeError(f"Evidence {evidence_id} is not a supported protocol snapshot")
    mapped = data.get("map")
    if not isinstance(mapped, dict) or mapped.get("schema_version") != 1 or not isinstance(mapped.get("endpoints"), list):
        raise ForgeError(f"Evidence {evidence_id} has invalid snapshot metadata")
    return record


def _endpoint_identity(endpoint):
    url = endpoint.get("url")
    if not isinstance(url, str):
        raise ForgeError("Snapshot endpoint has no URL")
    try:
        parts = urlsplit(url)
        # Query names are a comparison dimension, not separate endpoint identities.
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except ValueError:
        url = "[INVALID URL REDACTED]"
    identity = {"url": url}
    if "method" in endpoint:
        identity["method"] = endpoint["method"]
    return identity


def _protocol_view(record):
    mapped = record["data"]["map"]
    entries = {}
    ambiguities = []
    for endpoint in mapped["endpoints"]:
        identity = _endpoint_identity(endpoint)
        key = _canonical(identity)
        entry = entries.setdefault(key, {"identity": identity, "observations": [], "urls": set()})
        entry["urls"].add(endpoint["url"])
        observations = endpoint.get("observations")
        if not isinstance(observations, list) or any(not isinstance(item, dict) for item in observations):
            raise ForgeError("Snapshot endpoint has invalid observations")
        entry["observations"].extend(observations)
    for key in sorted(entries):
        entry = entries[key]
        observations = entry["observations"]
        dimensions = {}
        for field in ("category", "response_status", "query_field_names", "request_header_names",
                      "response_header_names", "extraction_selectors"):
            values = []
            for item in observations:
                value = item.get(field)
                if field.endswith("_names") or field == "extraction_selectors":
                    if isinstance(value, list):
                        values.extend(value)
                elif value is not None:
                    values.append(value)
            dimensions[field] = _ordered(values)
        for side in ("request_body", "response_body"):
            for field in ("json_field_paths", "form_field_names"):
                dimensions[side + "." + field] = _ordered(
                    name for item in observations if isinstance(item.get(side), dict)
                    for name in item[side].get(field, []))
        dimensions["provenance"] = _ordered({k: v for k, v in item.items() if k not in {
            "citations", "category", "response_status", "query_field_names", "request_header_names",
            "response_header_names", "extraction_selectors", "request_body", "response_body"}} |
            {side: {k: v for k, v in item.get(side, {}).items()
                    if k not in {"json_field_paths", "form_field_names"}}
             for side in ("request_body", "response_body") if isinstance(item.get(side), dict)}
            for item in observations)
        entry["dimensions"] = dimensions
        entry["observations"] = _ordered(observations)
        if len(entry["urls"]) > 1 or any("REDACTED" in url for url in entry["urls"]):
            ambiguities.append({"identity": entry["identity"], "query_variants": len(entry["urls"]),
                                "redacted_identity": any("REDACTED" in url for url in entry["urls"])})
        del entry["urls"]
    return entries, ambiguities


def _protocol_scope(record):
    return {key: value for key, value in record["data"]["map"].items() if key != "endpoints"}


def protocol_diff(args, store):
    before, after = _snapshot(store, args.before), _snapshot(store, args.after)
    left, left_ambiguous = _protocol_view(before)
    right, right_ambiguous = _protocol_view(after)
    changed = []
    for key in sorted(left.keys() & right.keys()):
        dimensions = {name: {"before": left[key]["dimensions"][name], "after": right[key]["dimensions"][name]}
                      for name in left[key]["dimensions"]
                      if left[key]["dimensions"][name] != right[key]["dimensions"][name]}
        if dimensions:
            changed.append({"identity": left[key]["identity"], "changes": dimensions,
                            "before_observations": left[key]["observations"],
                            "after_observations": right[key]["observations"]})
    left_scope, right_scope = _protocol_scope(before), _protocol_scope(after)
    omissions = [name for name in ("window_truncated", "input_truncated", "output_truncated",
                 "observations_omitted", "citations_omitted", "fields_omitted")
                 if left_scope.get(name) or right_scope.get(name)]
    sampling = any(item.get("sampling_possible") for scope in (left_scope, right_scope)
                   for item in scope.get("static_candidate_sampling", []))
    return store.add("protocol_diff", {
        "schema_version": SCHEMA_VERSION, "before_id": before["id"], "after_id": after["id"],
        "identity_policy": "URL scheme/authority/path and observed method; query/fragment excluded; static method unknown",
        "added": [right[key] for key in sorted(right.keys() - left.keys())],
        "removed": [left[key] for key in sorted(left.keys() - right.keys())], "changed": changed,
        "before_scope": left_scope, "after_scope": right_scope,
        "scope_changes": {name: {"before": left_scope.get(name), "after": right_scope.get(name)}
                          for name in sorted(left_scope.keys() | right_scope.keys())
                          if left_scope.get(name) != right_scope.get(name)},
        "selection_options": {"before": before["data"]["options"], "after": after["data"]["options"]},
        "ambiguities": {"before": left_ambiguous, "after": right_ambiguous},
        "complete": not omissions and not sampling and not left_ambiguous and not right_ambiguous,
        "limitations": {"omission_flags": omissions, "static_sampling_possible": sampling,
                        "absence_is_not_server_removal": True, "redacted_values_not_compared": True},
        "authentication_verified": False,
    })


def _bounded_int(value):
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ForgeError("Comparison limits must be integers") from exc
    if number <= 0:
        raise ForgeError("Comparison limits must be positive")
    return number


def _stored_file(store, value):
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ForgeError("Comparison requires a relative stored .forge path")
    path = store.root / value
    try:
        relative = path.relative_to(store.root)
        if relative.parts[0] != ".forge" or ".." in relative.parts:
            raise ValueError
        path.resolve(strict=True).relative_to(store.directory.resolve(strict=True))
        current = store.root
        for part in relative.parts:
            current /= part
            if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
                raise ValueError
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError
    except (OSError, ValueError, RuntimeError) as exc:
        raise ForgeError("Stored comparison input must be a regular, nonlinked file inside .forge") from exc
    return path


def _hash_file(path, maximum):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ForgeError("Comparison input is not a regular file")
        while block := source.read(min(CHUNK, maximum - size + 1)):
            size += len(block)
            if size > maximum:
                raise ForgeError("Stored input exceeds --max-input-bytes")
            digest.update(block)
    return digest.hexdigest(), size


def _artifact(store, record, args):
    data = record["data"]
    if not isinstance(data, dict):
        raise ForgeError("Client comparison artifact has invalid metadata")
    expected = data.get("sha256")
    if record["kind"] != "artifact" or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ForgeError("Client comparison artifact has invalid SHA256 metadata")
    path = _stored_file(store, data.get("path"))
    digest, size = _hash_file(path, args.max_input_bytes)
    if digest != expected or type(data.get("size")) is not int or size != data["size"]:
        raise ForgeError("Stored artifact hash/size mismatch; comparison not published")
    return path, {"evidence_id": record["id"], "sha256": digest, "size": size,
                  "version": data.get("version"), "platform": data.get("platform"),
                  "filename": data.get("filename"), "hash_verified": True}


def _inventory(path, artifact_id, args, filename=None):
    files, omitted = {}, []
    total = 0
    with path.open("rb") as source:
        magic = source.read(4)
    if not magic.startswith(b"PK") and Path(filename or "").suffix.lower() not in ARCHIVES:
        digest, size = _hash_file(path, args.max_input_bytes)
        return {"artifact": {"sha256": digest, "size": size, "hash_basis": "artifact_bytes",
                             "citations": [{"evidence_id": artifact_id}]}}, omitted
    try:
        _zip_entries(path, args.max_entries)
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = {}
            for info in infos:
                key = PurePosixPath(info.filename.replace("\\", "/")).as_posix().casefold()
                names[key] = names.get(key, 0) + 1
            for info in sorted(infos, key=lambda item: (item.filename, item.header_offset)):
                name = info.filename
                key = PurePosixPath(name.replace("\\", "/")).as_posix().casefold()
                mode = (info.external_attr >> 16) & 0o170000
                reason = None
                if not _safe_member(name) or any(":" in part for part in name.replace("\\", "/").split("/")):
                    reason = "unsafe member path"
                elif names[key] > 1:
                    reason = "duplicate/aliased member identity"
                elif mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    reason = "nonregular member (including symlink)"
                elif info.is_dir():
                    continue
                elif mode == stat.S_IFDIR:
                    reason = "inconsistent directory metadata"
                elif info.flag_bits & 1:
                    reason = "encrypted member"
                elif info.file_size > max(1, info.compress_size) * 200:
                    reason = "compression ratio exceeds 200:1"
                elif info.file_size > args.max_file_bytes:
                    reason = "member exceeds --max-file-bytes"
                elif total + info.file_size > args.max_total_bytes:
                    reason = "member exceeds --max-total-bytes"
                if reason:
                    omitted.append({"member": scrub_text(name), "reason": reason})
                    continue
                total += info.file_size
                digest, size = hashlib.sha256(), 0
                with archive.open(info) as source:
                    while block := source.read(min(CHUNK, args.max_file_bytes - size + 1)):
                        size += len(block)
                        if size > args.max_file_bytes or size > info.file_size:
                            raise ForgeError("ZIP member expanded beyond declared size/cap")
                        digest.update(block)
                if size != info.file_size:
                    raise ForgeError("ZIP member size mismatch")
                files[PurePosixPath(name.replace("\\", "/")).as_posix()] = {
                    "sha256": digest.hexdigest(), "size": size, "hash_basis": "member_bytes",
                    "citations": [{"evidence_id": artifact_id, "location": {"member": scrub_text(name)}}]}
    except (OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error) as exc:
        raise ForgeError(f"Cannot inventory stored archive: {exc}") from exc
    return files, omitted


def _index_record(record):
    if record["kind"] != "analysis" or not isinstance(record.get("data"), dict) or record["data"].get("tool") != "static_index":
        raise ForgeError("Client comparison requires artifact or static_index analysis evidence")
    if not isinstance(record["data"].get("input"), str):
        raise ForgeError("Static index has no input provenance")
    return record


def _logical_file(item, data):
    if isinstance(item.get("member"), str):
        return PurePosixPath(item["member"].replace("\\", "/")).as_posix()
    source = item.get("source")
    if not isinstance(source, str):
        return "[unknown source]"
    if source == data["input"]:
        return "artifact"
    prefix = data["input"].rstrip("/") + "/"
    return source[len(prefix):] if source.startswith(prefix) else source


def _read_index(store, record, args):
    data = record["data"]
    path = _stored_file(store, data.get("path"))
    expected, size = _hash_file(path, args.max_input_bytes)
    creation_hash_available = "index_sha256" in data or "index_size" in data
    if creation_hash_available:
        creation_hash = data.get("index_sha256")
        if (not isinstance(creation_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", creation_hash)
                or type(data.get("index_size")) is not int
                or (expected, size) != (creation_hash, data["index_size"])):
            raise ForgeError("Stored index hash/size mismatch; comparison not published")
    files, strings, endpoints, omitted = {}, {}, {}, []
    digest, count, total = hashlib.sha256(), 0, 0
    member_offsets, ambiguous_members = {}, set()
    stopped = False
    with path.open("rb") as source:
        while True:
            raw = source.readline(128 * 1024 + 1)
            if not raw:
                break
            if len(raw) > 128 * 1024:
                raise ForgeError("Stored index record exceeds safe size")
            digest.update(raw)
            total += len(raw)
            if total > args.max_input_bytes:
                raise ForgeError("Stored index exceeds --max-input-bytes")
            count += 1
            if count > args.max_records:
                stopped = True
                continue
            try:
                item = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                raise ForgeError("Stored index contains invalid JSON") from exc
            if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                raise ForgeError("Stored index record requires source-located text")
            item = redact(item)
            item["text"] = scrub_text(item["text"][:4096])
            name = _logical_file(item, data)
            if not _safe_member(name) or any(":" in part for part in name.split("/")):
                omitted.append({"member": scrub_text(name), "reason": "unsafe indexed file identity"})
                continue
            if isinstance(item.get("member"), str) and type(item.get("member_header_offset")) is int:
                offsets = member_offsets.setdefault(name.casefold(), set())
                offsets.add(item["member_header_offset"])
                if len(offsets) > 1:
                    ambiguous_members.add(name.casefold())
            if name not in files and len(files) >= args.max_entries:
                stopped = True
                continue
            entry = files.setdefault(name, {"hash": hashlib.sha256(), "size": 0, "records": 0})
            projection = _canonical({k: v for k, v in item.items() if k not in {"source", "index_source", "member"}}).encode()
            entry["hash"].update(len(projection).to_bytes(8, "big") + projection)
            entry["size"] += len(projection)
            entry["records"] += 1
            citation = _citation(record, item)
            text_digest = hashlib.sha256(item["text"].encode("utf-8")).hexdigest()
            string_key = _canonical([name, text_digest])
            string = strings.setdefault(string_key, {"file": name, "sha256": text_digest,
                                                     "hash_basis": "redacted_index_text", "citations": []})
            if citation not in string["citations"]:
                if len(string["citations"]) < 20:
                    string["citations"].append(citation)
                else:
                    stopped = True
            for candidate in _candidates(item):
                url = redact_url(candidate["value"])
                if url not in endpoints and len(endpoints) >= args.max_endpoints:
                    stopped = True
                    continue
                endpoint = endpoints.setdefault(url, {"url": url, "proven_live": False,
                                                        "proven_auth_path": False, "citations": []})
                if citation not in endpoint["citations"]:
                    if len(endpoint["citations"]) < 20:
                        endpoint["citations"].append(citation)
                    else:
                        stopped = True
    if digest.hexdigest() != expected or total != size:
        raise ForgeError("Stored index changed while being read")
    if type(data.get("records")) is not int or count != data["records"]:
        raise ForgeError("Stored index record count disagrees with evidence")
    if stopped:
        omitted.append({"reason": "comparison index/entry/endpoint/citation cap reached"})
    if data.get("truncated"):
        omitted.append({"reason": "original static indexing was truncated", "skipped": data.get("skipped", [])})
    if ambiguous_members:
        omitted.extend({"member": scrub_text(name), "reason": "duplicate/aliased indexed member identity"}
                       for name in sorted(files) if name.casefold() in ambiguous_members)
        files = {name: value for name, value in files.items() if name.casefold() not in ambiguous_members}
        strings = {key: value for key, value in strings.items() if value["file"].casefold() not in ambiguous_members}
        endpoints = {key: {**value, "citations": [citation for citation in value["citations"]
                     if str(citation.get("location", {}).get("member", "")).casefold() not in ambiguous_members]}
                     for key, value in endpoints.items()}
        endpoints = {key: value for key, value in endpoints.items() if value["citations"]}
    inventory = {name: {"sha256": entry["hash"].hexdigest(), "size": entry["size"],
                       "records": entry["records"], "hash_basis": "redacted_index_projection",
                       "citations": [{"evidence_id": record["id"]}]}
                 for name, entry in files.items()}
    return inventory, strings, endpoints, omitted, {
        "evidence_id": record["id"], "path": data["path"], "sha256": expected, "size": size,
        "hash_verified": creation_hash_available,
        "hash_note": "Creation-time index hash verified" if creation_hash_available else
                     "Read-time hash pinned during comparison; legacy static indexes have no creation-time hash",
        "records": count, "input": data["input"], "truncated": bool(data.get("truncated"))}


def _client_side(store, evidence_id, index_id, artifact_id, args):
    primary = store.get(evidence_id)
    if not isinstance(primary.get("data"), dict):
        raise ForgeError("Client input has invalid metadata")
    if primary["kind"] == "artifact":
        if artifact_id:
            raise ForgeError("--before-artifact/--after-artifact apply only to primary static indexes")
        artifact = primary
        index = _index_record(store.get(index_id)) if index_id else None
    else:
        index = _index_record(primary)
        if index_id:
            raise ForgeError("--before-index/--after-index apply only to primary artifacts")
        artifact = store.get(artifact_id) if artifact_id else None
    inventory, strings, endpoints, omissions, metadata = {}, {}, {}, [], {}
    if artifact:
        path, metadata["artifact"] = _artifact(store, artifact, args)
        inventory, omitted = _inventory(path, artifact["id"], args, artifact["data"].get("filename"))
        omissions.extend(omitted)
    if index:
        if artifact and index["data"]["input"] != artifact["data"]["path"]:
            raise ForgeError("Paired static index must reference the corresponding stored artifact blob")
        projected, strings, endpoints, omitted, metadata["index"] = _read_index(store, index, args)
        omissions.extend(omitted)
        if not artifact:
            inventory = projected
            omissions.append({"reason": "Index projections do not establish original file bytes, sizes, or files without indexed strings"})
        else:
            unsafe = {item.get("member") for item in omissions if "member" in item}
            strings = {key: value for key, value in strings.items() if value["file"] not in unsafe}
            endpoints = {key: {**value, "citations": [citation for citation in value["citations"]
                         if citation.get("location", {}).get("member") not in unsafe]}
                         for key, value in endpoints.items()}
            endpoints = {key: value for key, value in endpoints.items() if value["citations"]}
    else:
        omissions.append({"reason": "No explicit static index supplied; endpoint and source-located string comparison unavailable"})
    if artifact:
        final_digest, final_size = _hash_file(path, args.max_input_bytes)
        if (final_digest, final_size) != (metadata["artifact"]["sha256"], metadata["artifact"]["size"]):
            raise ForgeError("Stored artifact changed during comparison")
    return {"primary_id": primary["id"], "metadata": metadata, "files": inventory,
            "strings": strings, "endpoints": endpoints, "omissions": omissions}


def _set_diff(left, right):
    return {"added": [right[key] for key in sorted(right.keys() - left.keys())],
            "removed": [left[key] for key in sorted(left.keys() - right.keys())]}


def client_diff(args, store):
    for name, maximum in (("max_entries", 100000), ("max_records", 100000), ("max_endpoints", 5000)):
        if not 1 <= getattr(args, name) <= maximum:
            raise ForgeError(f"--{name.replace('_', '-')} must be between 1 and {maximum}")
    before = _client_side(store, args.before, args.before_index, args.before_artifact, args)
    after = _client_side(store, args.after, args.after_index, args.after_artifact, args)
    bases = {item["hash_basis"] for side in (before, after) for item in side["files"].values()}
    if "redacted_index_projection" in bases and len(bases) > 1:
        raise ForgeError("Cannot compare raw artifact inventories against index projections; supply matching paired artifacts/indexes")
    files = {"added": [{"file": key, **after["files"][key]} for key in sorted(after["files"].keys() - before["files"].keys())],
             "removed": [{"file": key, **before["files"][key]} for key in sorted(before["files"].keys() - after["files"].keys())],
             "changed": [{"file": key, "before": before["files"][key], "after": after["files"][key]}
                         for key in sorted(before["files"].keys() & after["files"].keys())
                         if any(before["files"][key].get(name) != after["files"][key].get(name)
                                for name in ("sha256", "size", "hash_basis"))]}
    ambiguous = [url for side in (before, after) for url in side["endpoints"] if "REDACTED" in url]
    ambiguous_files = sorted({scrub_text(name) for side in (before, after) for name in side["files"]
                              if "REDACTED" in name or scrub_text(name) != name})
    index_unverified = any(side["metadata"].get("index", {}).get("hash_verified") is False for side in (before, after))
    return store.add("client_diff", {
        "schema_version": SCHEMA_VERSION, "before_id": args.before, "after_id": args.after,
        "before": {**{key: value for key, value in before.items() if key not in {"files", "strings", "endpoints"}},
                   "files": [{"file": key, **value} for key, value in sorted(before["files"].items())]},
        "after": {**{key: value for key, value in after.items() if key not in {"files", "strings", "endpoints"}},
                  "files": [{"file": key, **value} for key, value in sorted(after["files"].items())]},
        "metadata_changes": {field: {"before": before["metadata"].get("artifact", {}).get(field),
                                     "after": after["metadata"].get("artifact", {}).get(field)}
                             for field in ("sha256", "size", "version", "platform", "filename")
                             if before["metadata"].get("artifact", {}).get(field) !=
                                after["metadata"].get("artifact", {}).get(field)},
        "files": files, "endpoint_candidates": _set_diff(before["endpoints"], after["endpoints"]),
        "source_strings": _set_diff(before["strings"], after["strings"]),
        "complete": not before["omissions"] and not after["omissions"] and not ambiguous and not ambiguous_files and not index_unverified,
        "file_inventory_complete": not any(side["omissions"] and any(
            "member" in item or "projection" in item.get("reason", "") for item in side["omissions"])
            for side in (before, after)),
        "limits": {name: getattr(args, name) for name in ("max_input_bytes", "max_file_bytes", "max_total_bytes",
                   "max_entries", "max_records", "max_endpoints")},
        "limitations": {"redacted_endpoint_ambiguities": sorted(set(ambiguous)),
                        "redacted_file_identity_ambiguities": ambiguous_files,
                        "legacy_index_creation_hash_unavailable": index_unverified,
                        "strings_are_redacted_hashes_not_source_exports": True,
                        "absence_is_not_server_removal": True},
        "authentication_verified": False, "server_changes_verified": False,
    })


def register(subparsers):
    parser = subparsers.add_parser("protocol-snapshot", help="Persist a cited, metadata-only protocol map")
    parser.add_argument("--evidence", action="append", default=[], metavar="ID")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--max-endpoints", type=int, default=200)
    parser.set_defaults(handler=protocol_snapshot)
    parser = subparsers.add_parser("protocol-diff", help="Compare immutable protocol snapshots, not server behavior")
    parser.add_argument("--before", required=True, metavar="ID")
    parser.add_argument("--after", required=True, metavar="ID")
    parser.set_defaults(handler=protocol_diff)
    parser = subparsers.add_parser("client-diff", help="Compare stored artifact bytes and cited static-index projections")
    parser.add_argument("--before", required=True, metavar="ID")
    parser.add_argument("--after", required=True, metavar="ID")
    for side in ("before", "after"):
        parser.add_argument(f"--{side}-index", metavar="ID", help="Static index of this artifact's stored blob")
        parser.add_argument(f"--{side}-artifact", metavar="ID", help="Stored artifact referenced by this primary static index")
    parser.add_argument("--max-input-bytes", type=_bounded_int, default=256 * 1024 * 1024)
    parser.add_argument("--max-file-bytes", type=_bounded_int, default=16 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=_bounded_int, default=128 * 1024 * 1024)
    parser.add_argument("--max-entries", type=_bounded_int, default=10000)
    parser.add_argument("--max-records", type=_bounded_int, default=10000)
    parser.add_argument("--max-endpoints", type=_bounded_int, default=5000)
    parser.set_defaults(handler=client_diff)
