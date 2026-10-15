"""Explicit, bounded evidence handoffs without local blobs or capture payloads."""
from __future__ import annotations

from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

from forge_core import ForgeError, scrub_text, utc_now
import forge_tasks
from forge_version import __version__

_ID = re.compile(r"ev_[a-f0-9]{32}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_REFERENCES = {"evidence", "evidence_id", "evidence_ids", "citations", "positive", "negative", "runs", "verification", "included", "before_id", "after_id", "before", "after"}
_PRIVATE = {"body", "text", "stdout", "stderr", "raw", "content", "script", "snippet", "command", "command_template", "args", "args_template", "stdin_json", "stdin_template", "goal", "next_action", "notes", "source_path", "filename", "source_url", "final_url", "path", "input", "output", "version_output"}
_FLAGS = {"success", "passed", "timed_out", "truncated", "source_changed", "runtime_changed", "window_truncated", "input_truncated", "output_truncated", "fields_omitted", "observations_omitted", "citations_omitted", "authentication_verified", "proven_auth_path", "proven_live", "empty", "stopped", "complete", "sampling_possible", "is_compatible", "binary_unchanged", "file_inventory_complete", "server_changes_verified", "schema_inferred", "network_performed", "values_exported", "fragment_expansion_performed", "response_observed", "partial", "apply", "dry_run", "force", "read_only", "network_action", "device_write", "pseudo_c_truncated", "embedded_gadget_matches", "time_window_filtered"}
_NUMBERS = {"size", "index_size", "schema_version", "status", "response_status", "returncode", "exit_code", "elapsed_ms", "stdout_bytes", "stderr_bytes", "records", "entries", "converted", "available", "omitted", "completed", "requested", "line", "column", "byte_offset", "offset", "depth", "count", "min_sdk", "api_level", "java_files", "error_count", "record_bytes", "blob_bytes", "bytes_freed", "blobs", "orphan_blobs", "referenced_blobs", "pseudo_c_lines", "gadget_size", "gadget_bitness", "archive_entries", "bytes_pulled", "duration_seconds", "logcat_line_count", "logcat_line_cap_per_pid", "logcat_omitted_lines", "process_rows_omitted_before", "process_rows_omitted_after", "session_pids_omitted", "index_records_scanned", "candidate_count", "candidate_omitted", "source_files_scanned", "source_bytes_scanned", "source_files_omitted", "source_bytes_omitted", "source_occurrence_count", "source_occurrences_omitted"}
_SAFE_STRINGS = {"package", "version_name", "version_code", "primary_cpu_abi", "split", "split_names", "class_name", "dex_member"}
_ENUMS = {
    "bucket": {"HIT", "FREE", "FAIL", "TERMINAL", "RETRY", "ERROR", "BADFORMAT", "CUSTOM", "RISK"},
    "expected_bucket": {"HIT", "FREE", "FAIL"},
    "control": {"positive", "negative"},
    "state": {"OBSERVED", "INFERRED", "UNKNOWN", "CONTRADICTED", "active", "blocked", "completed"},
    "category": {"static_candidate", "captured_http", "live_http", "captured_network", "static_host_match"},
    "source": {"static_candidate", "captured_http", "live_http", "live_probe", "har_import", "local_import"},
    "member_filter": {"dex"},
    "context_kind": {"method", "field_initializer", "class_scope", "comment", "unsupported"},
    "resolution": {"syntactic_constructor_binding", "direct_field_initializer",
                   "same_class_field_candidate", "same_class_name_candidate", "cross_file_name_candidate"},
    "marker_kind": {"url_call", "dispatch_call", "retrofit_annotation"},
    "receiver_kind": {"bare", "this", "owner_class", "named_receiver", "expression", "constructor"},
    "kind": {"dns_query", "dns_answer", "tls_sni", "http_host"},
    "method": {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"},
    "tool": {"static_index", "radare2", "graphql_analyze", "adb", "frida", "jadx", "android", "apktool", "apksigner",
             "idevice_id", "idevicepair", "pcap", "pcapdroid"},
    "action": {"imports", "exports", "strings", "functions", "disasm", "xrefs", "callgraph", "devices", "install",
               "install-multiple", "preflight", "pull", "push", "pull-package", "observe", "packages", "package",
               "frida-prerequisite", "apk-info", "decode", "manifest", "rebuild", "sign", "gadget", "ios-devices",
               "ios-pair", "decompile", "api-map", "capture", "pcap-analyze", "caller-map",
               "capture-session", "capture-rejected"},
    "schema": {"forge.target-run/v2", "forge.target-verification/v2", "forge.native.v1", "forge.android.v1",
               "forge.apk/v1", "forge.ios.v1", "forge.pcap/v1", "forge.pcapdroid/v1",
               "forge.android-caller-map/v1"},
    "status": {"authorized", "absent", "unauthorized", "offline", "multiple", "missing-tool", "adb-failed",
               "incomplete-device-facts", "success", "failed", "timeout", "partial", "unavailable", "tool-failed",
               "observed", "paired", "not-paired", "unknown"},
}
_CONTAINERS = {"sources_before", "sources_after", "current_sources", "files", "facts", "package_facts", "manifest", "api_candidates", "dex_locations", "source_occurrences", "binary", "binary_before", "binary_after", "runtime", "runtime_before", "runtime_after", "runtime_current", "fingerprint", "executable", "before", "after", "limits", "selection", "map", "identity", "endpoints", "observations", "before_observations", "after_observations", "before_scope", "after_scope", "citations", "location", "request", "response", "device", "devices", "counts", "summary", "changes", "added", "removed", "changed", "planned", "deleted", "filters", "invocation"}
_PRIVATE |= {"method_name", "field_name", "parameter_name"}
_FLAGS |= {"trace_truncated"}
_NUMBERS |= {"trace_items", "trace_items_omitted", "literal_line", "literal_column",
             "method_line", "method_end_line", "constructor_line", "argument_index",
             "assignment_line", "overload_count"}
_CONTAINERS |= {"source_traces", "field_links", "uses", "callers", "request_markers"}
_PRIVATE |= {"hostname", "source_ip", "destination_ip", "uid", "package_hint", "remote",
             "remote_name", "api_key", "api_key_env", "collector_host"}
_FLAGS |= {"decryption_performed", "capture_started_observed", "capture_stopped_observed",
           "package_hint_truncated", "decryption_requested",
           "operator_approved_tls_decryption", "attempted", "overload_aware", "declaration_ambiguous",
           "possible_owners_omitted", "http_methods_omitted", "http_paths_omitted"}
_NUMBERS |= {"packets_scanned", "malformed_packets", "unsupported_packets", "packet_index",
             "timestamp", "source_port", "destination_port", "hosts_omitted",
             "flows_omitted", "host_observations_omitted", "captured_packet_truncations"}
_CONTAINERS |= {"capture", "hosts", "flows", "static_host_matches"}
_NUMBERS |= {"packets_scanned", "malformed_packets", "unsupported_packets", "packet_index",
             "timestamp", "source_port", "destination_port", "hosts_omitted",
             "flows_omitted", "host_observations_omitted", "captured_packet_truncations",
             "http_request_lines", "repeats", "attempted_windows", "completed_windows",
             "gap_seconds", "seconds", "max_bytes", "window_index", "window_count", "index",
             "candidates_omitted", "candidates_filtered", "declarations_skipped",
             "annotation_uses_skipped", "files_enumerated", "files_scanned", "files_skipped_kt",
             "files_omitted", "bytes_scanned", "bytes_omitted"}
_CONTAINERS |= {"capture", "hosts", "flows", "static_host_matches", "windows", "failures",
                "force_stop_action", "launch_action", "service_precheck", "service_after_session",
                "decryption_basis"}
_SAFE_STRINGS |= {"http_methods"}
_PRIVATE |= {"file", "receiver", "http_paths", "decryption_scope"}
_SCOPE = [
    "Metadata projection only: raw bodies, streams, argv, stdin, local paths, captures, screenshots and artifact blobs are excluded.",
    "Claims are author statements, not independently proven findings; free-text claims are withheld unless explicitly requested.",
    "Static/captured/live provenance stays separate. HTTP status and program-reported buckets do not independently attest authentication.",
    "Hashes identify declared bytes, not dependency closure, signing, device identity or every transient modification.",
    "Unknown fields and free-text limitations are withheld. Inspect the manifest and cited local records before disclosure.",
]
_PUBLIC = _FLAGS | _NUMBERS | _CONTAINERS | _REFERENCES | set(_ENUMS) | {"sha256", "source_sha256", "output_sha256", "protocol_sha256", "binary_sha256", "url", "endpoint", "package", "version_name", "version_code", "primary_cpu_abi", "split_names", "split", "class_name", "dex_member"}
_PUBLIC |= {"static_candidate_sha256"}


def _references(value):
    pending = [(value, False, 0)]
    seen = set()
    nodes = 0
    omitted = False
    while pending:
        item, active, depth = pending.pop()
        nodes += 1
        if nodes > 20000 or depth > 32:
            omitted = True
            if nodes > 20000:
                break
            continue
        if isinstance(item, str):
            if active and _ID.fullmatch(item):
                seen.add(item)
        elif isinstance(item, dict):
            for key, child in item.items():
                if nodes + len(pending) >= 20000:
                    omitted = True
                    break
                if key not in _PRIVATE:
                    pending.append((child, active or key in _REFERENCES, depth + 1))
        elif isinstance(item, list):
            room = max(0, 20000 - nodes - len(pending))
            omitted |= len(item) > room
            pending.extend((child, active, depth + 1) for child in item[:room])
    return sorted(seen), omitted


def _project(value, key="", depth=0, budget=None):
    if budget is None:
        budget = [20000]
    budget[0] -= 1
    if depth > 32 or budget[0] < 0:
        return None
    if key in _PRIVATE:
        return None
    if key in _FLAGS:
        return value if type(value) is bool else None
    if key in _NUMBERS and type(value) in (int, float):
        return value if abs(value) < 10**20 else None
    if key in _SAFE_STRINGS and isinstance(value, str) and len(value) <= 256 and not any(ord(char) < 32 for char in value):
        if key == "package" and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", value):
            return None
        if key == "version_code" and not re.fullmatch(r"\d{1,20}", value):
            return None
        return scrub_text(value)
    if key == "tool" and isinstance(value, dict):
        return {"name": value["name"]} if value.get("name") in _ENUMS["tool"] else None
    if key in _ENUMS:
        return value if isinstance(value, str) and value in _ENUMS[key] else None
    if key in {"sha256", "source_sha256", "output_sha256", "protocol_sha256", "binary_sha256", "static_candidate_sha256"}:
        return value if isinstance(value, str) and _HASH.fullmatch(value) else None
    if key in {"url", "endpoint"} and isinstance(value, str):
        return {"redacted_identity_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(), "identity_withheld": True}
    if key in _REFERENCES and isinstance(value, str):
        return value if _ID.fullmatch(value) else None
    if isinstance(value, dict):
        result = {}
        for name, child in value.items():
            if name in _PUBLIC:
                projected = _project(child, name, depth + 1, budget)
                if projected is not None:
                    result[name] = projected
        return result
    if isinstance(value, list):
        return [projected for child in value[:1000] if (projected := _project(child, key, depth + 1, budget)) is not None]
    return None


def _record(store, evidence_id, maximum):
    if not isinstance(evidence_id, str) or not _ID.fullmatch(evidence_id):
        raise ForgeError("Bundle evidence IDs must be canonical FORGE IDs")
    row = store.connection.execute("SELECT length(CAST(data AS BLOB)) FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if row is None:
        return None
    if row[0] > maximum:
        raise ForgeError("A selected record exceeds --max-record-bytes; no bundle was published")
    return store.get(evidence_id)


def bundle(args, store):
    for name, value, maximum in [("limit", args.limit, 1000), ("max-bytes", args.max_bytes, 32 * 1024 * 1024), ("max-record-bytes", args.max_record_bytes, 64 * 1024 * 1024)]:
        if type(value) is not int or not 1 <= value <= maximum:
            raise ForgeError(f"--{name} must be an integer from 1 to {maximum}")
    selected = list(dict.fromkeys(args.evidence or []))
    if not selected or len(selected) > args.limit:
        raise ForgeError("Select at least one --evidence ID, within --limit")
    relative = forge_tasks._file_path(store, args.output)
    destination = store.root / relative
    if destination.exists():
        raise ForgeError("Bundle output already exists; choose a new path")
    queue = deque(selected)
    queued = set(selected)
    visited, records, missing, omitted = set(), [], set(), set()
    reference_truncated = False
    omitted_occurrences = 0
    omitted_sampled = False
    shared_bytes = 0
    while queue:
        evidence_id = queue.popleft()
        queued.discard(evidence_id)
        record = _record(store, evidence_id, args.max_record_bytes)
        visited.add(evidence_id)
        if record is None:
            if evidence_id in selected:
                raise ForgeError("Selected bundle evidence is unavailable")
            missing.add(evidence_id)
            continue
        refs, capped = _references(record["data"])
        reference_truncated |= capped
        metadata_budget = [20000]
        projected = _project(record["data"], budget=metadata_budget)
        shared = {"id": record["id"], "kind": scrub_text(record["kind"]), "created_at": record["created_at"], "facts": projected, "citations": refs, "projection_lossy": True, "metadata_node_cap_reached": metadata_budget[0] <= 0}
        if record["kind"] == "claim":
            shared["finding"] = scrub_text(record["data"].get("text", "")) if args.include_findings else "[WITHHELD: free-text finding]"
            shared["finding_text_included"] = args.include_findings
        shared_bytes += len(json.dumps(shared, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        if shared_bytes > args.max_bytes:
            raise ForgeError("Bundle projections exceed --max-bytes; no output was published")
        records.append(shared)
        for ref in refs:
            if ref in visited or ref in queued:
                continue
            if len(visited) + len(queued) >= args.limit:
                omitted_occurrences += 1
                if len(omitted) < 1000:
                    omitted.add(ref)
                elif ref not in omitted:
                    omitted_sampled = True
            else:
                queued.add(ref)
                queue.append(ref)
    evidence = (json.dumps({"schema_version": 1, "records": records}, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    lines = ["# FORGE evidence handoff", "", "Metadata-only, lossy projection. Read manifest.json for exclusions and incomplete citations.", ""]
    for record in records:
        lines.append(f"- {record['kind']} `{record['id']}`: {json.dumps(record['facts'], ensure_ascii=False)}")
        if "finding" in record:
            lines.append("  Finding: " + record["finding"].replace("\n", " "))
    lines.extend(["", "## Scope limits", *["- " + item for item in _SCOPE], ""])
    report = "\n".join(lines).encode("utf-8")
    members = {"evidence.json": evidence, "report.md": report}
    manifest = {"schema_version": 1, "forge_version": __version__, "created_at": utc_now(), "selected_ids": selected, "included_ids": [record["id"] for record in records], "missing_reference_ids": sorted(missing), "omitted_reference_ids": sorted(omitted), "omitted_reference_occurrences": omitted_occurrences, "omitted_references_sampled": omitted_sampled, "reference_scan_truncated": reference_truncated, "closure_complete": not (missing or omitted_occurrences or reference_truncated), "free_text_findings_included": args.include_findings, "raw_materials_included": False, "projection_lossy": True, "scope_limits": _SCOPE, "members": [{"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()} for name, content in members.items()]}
    members["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if sum(map(len, members.values())) > args.max_bytes:
        raise ForgeError("Bundle content exceeds --max-bytes; no output was published")
    destination.parent.mkdir(parents=True, exist_ok=True)
    forge_tasks._file_path(store, relative.as_posix(), relative_only=True)
    fd, temporary = tempfile.mkstemp(prefix=".forge-bundle-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w+b") as output:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, content in members.items():
                    archive.writestr(name, content)
            output.flush()
            os.fsync(output.fileno())
            output.seek(0)
            digest = hashlib.sha256(output.read()).hexdigest()
            size = output.tell()
        if size > args.max_bytes:
            raise ForgeError("Bundle ZIP exceeds --max-bytes; no output was published")
        forge_tasks._file_path(store, relative.as_posix(), relative_only=True)
        os.link(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    record = store.add("handoff_bundle", {"schema_version": 1, "output": relative.as_posix(), "sha256": digest, "size": size, "evidence_ids": manifest["included_ids"], "closure_complete": manifest["closure_complete"], "raw_materials_included": False, "free_text_findings_included": args.include_findings})
    return {"record": record, "output": relative.as_posix(), "manifest": manifest}


def register(subparsers):
    parser = subparsers.add_parser("bundle", help="Publish a new bounded metadata-only ZIP handoff from explicit evidence IDs")
    parser.add_argument("--evidence", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--max-record-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--include-findings", action="store_true", help="Include scrubbed author prose; inspect private claim text before disclosure")
    parser.set_defaults(handler=bundle)
