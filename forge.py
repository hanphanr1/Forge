from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

from forge_core import EvidenceStore, ForgeError, load_json, redact, utc_now
from forge_version import __version__
import forge_tasks


PLATFORM_ORDER = ["mobile_graphql", "desktop", "ios_rest", "android_rest", "windows_native", "web"]


def initialize(args, store):
    return forge_tasks.initialize(args, store, PLATFORM_ORDER)


def evidence(args, store):
    return {"records": store.list(args.kind, args.limit)}


def show(args, store):
    return store.get(args.id)


def status(args, store):
    recent = store.list(limit=20)
    task = store.list("task", 1)
    verification = store.list("control_verification", 1)
    target_verification = store.list("target_verification", 1)
    return {"project": str(store.root), "task": task[0] if task else None,
            "latest_control_gate": verification[0] if verification else None,
            "latest_target_verification": target_verification[0] if target_verification else None,
            "progress": forge_tasks.task_status(store),
            "recent": [{"id": record["id"], "kind": record["kind"], "created_at": record["created_at"]} for record in recent],
            "note": "Verification records are historical and scoped. Probe controls do not prove target execution; target controls do not independently attest authentication."}


def claim(args, store):
    ids = args.evidence or []
    for evidence_id in ids:
        store.get(evidence_id)
    if args.state == "OBSERVED" and not ids:
        raise ForgeError("OBSERVED claims require at least one --evidence ID")
    return store.add("claim", {"text": args.text, "state": args.state, "evidence": ids,
                               "scope": args.scope,
                               "meaning": "Agent-authored statement; citations are retained, not independently proven by the store"})


def hook_evidence(args, store):
    if bool(args.state_dependency) != bool(args.state_evidence):
        raise ForgeError("--state-dependency and --state-evidence must be supplied together, or both omitted")
    for identifier in (args.static_evidence, args.dynamic_evidence, args.state_evidence):
        if identifier:
            store.get(identifier)
    triple = {
        "static_location": {"text": args.static_location, "evidence": args.static_evidence},
        "dynamic_proof": {"text": args.dynamic_proof, "evidence": args.dynamic_evidence},
        "state_dependency": ({"text": args.state_dependency, "evidence": args.state_evidence}
                             if args.state_dependency else {"text": None, "evidence": None,
                                                            "state": "not-established"}),
    }
    return store.add("claim", {
        "text": args.text, "state": args.state,
        "evidence": [item for item in (args.static_evidence, args.dynamic_evidence, args.state_evidence) if item],
        "scope": args.scope, "package": args.package, "hook": triple,
        "meaning": "Hook evidence kept as one triple: where the boundary is, what proved it at runtime, and which "
                   "local state it depends on. A missing state dependency is recorded as not-established rather than "
                   "assumed. Citations are retained, not independently proven by the store.",
    })


def verify(args, store):
    positive = store.get(args.positive)
    negative = store.get(args.negative)
    if positive["id"] == negative["id"]:
        raise ForgeError("Positive and negative controls must be distinct live exchanges")
    for record in (positive, negative):
        if record["kind"] != "http_probe" or record["data"].get("source") != "live_probe":
            raise ForgeError("Controls must be live http_probe evidence, not imported HAR or static observations")
        data = record["data"]
        if data.get("response", {}).get("status") is None or data.get("response", {}).get("truncated"):
            raise ForgeError("Control response must be complete and have an observed HTTP status")
    if positive["data"].get("bucket") not in {"HIT", "FREE"}:
        raise ForgeError("Positive control must have a body-classified HIT or FREE result")
    if negative["data"].get("bucket") != "FAIL":
        raise ForgeError("Negative control must have a body-classified FAIL result")
    for field in ("client", "egress"):
        values = [record["data"].get("context", {}).get(field) for record in (positive, negative)]
        if any(not isinstance(value, str) or not value.strip() or "[REDACTED]" in value for value in values):
            raise ForgeError(f"Both control request contexts must declare non-secret '{field}' identifiers")
        if values[0] != values[1]:
            raise ForgeError(f"Controls differ in {field}; rerun with the same client and egress")
    for field in ("method", "url"):
        if positive["data"].get("request", {}).get(field) != negative["data"].get("request", {}).get(field):
            raise ForgeError(f"Controls must exercise the same request {field}")
    if positive["data"].get("transport") != negative["data"].get("transport"):
        raise ForgeError("Controls must use the same HTTP transport configuration")
    protocol_path = Path(args.protocol).expanduser()
    if not protocol_path.is_absolute():
        protocol_path = store.root / protocol_path
    protocol = load_json(protocol_path)
    if not isinstance(protocol, dict) or not protocol:
        raise ForgeError("Protocol must be a nonempty JSON object describing the observed flow")
    protocol_evidence = protocol.get("evidence")
    if not isinstance(protocol_evidence, list) or not protocol_evidence or not all(isinstance(item, str) for item in protocol_evidence):
        raise ForgeError("Protocol must cite an 'evidence' list of observed IDs")
    for evidence_id in protocol_evidence:
        store.get(evidence_id)
    canonical = json.dumps(redact(protocol), ensure_ascii=False, sort_keys=True).encode("utf-8")
    return store.add("control_verification", {"passed": True, "positive": positive["id"], "negative": negative["id"],
                                             "protocol_sha256": hashlib.sha256(canonical).hexdigest(),
                                             "protocol": redact(protocol), "context": positive["data"]["context"],
                                             "limits": ["client/egress identifiers are agent-declared, not independently measured",
                                                        "Only this protocol and these probe controls passed; checker runtime and other branches need separate execution"]})


def report(args, store):
    records = store.list(limit=args.limit)
    lines = ["# FORGE evidence report", "", f"Generated UTC: {utc_now()}",
             "", f"Project: `{store.root.name}`", "", "## Observations", "",
             "Claims below are agent-authored. Static strings do not prove a live endpoint.", "",
             "Passing probe controls does not verify the generated checker end-to-end.", ""]
    lines.extend(["Target-control records prove declared processes and reported outcomes; they do not independently attest authentication or egress.", ""])
    for record in reversed(records):
        lines.extend([f"### {record['kind']} `{record['id']}`", "", f"UTC: {record['created_at']}", "", "```json",
                      json.dumps(record["data"], ensure_ascii=False, indent=2), "```", ""])
    lines.extend(["## đã thử và KHÔNG được", ""])
    failed = [record for record in records if record["data"].get("success") is False or record["data"].get("error")]
    if failed:
        for record in failed:
            lines.append(f"- `{record['id']}` ({record['kind']}): inspect the recorded error/return code above.")
    else:
        lines.append("No failed tool executions in this report window. This does not imply all protocols were tried.")
    lines.extend(["", f"Window: newest {len(records)} records (limit {args.limit}); local artifact blobs are not embedded.", ""])
    directory = store.root / "notes"
    directory.mkdir(exist_ok=True)
    record = store.add("report", {"included": [item["id"] for item in records]})
    path = directory / f"{utc_now()[:10]}_forge_{record['id'][3:11]}.md"
    with path.open("x", encoding="utf-8") as output:
        output.write("\n".join(lines))
    return {"path": str(path), "record": record, "included": len(records)}


def parser():
    cli = argparse.ArgumentParser(description="FORGE: local evidence and analysis tools for your existing AI agent")
    cli.add_argument("--version", action="version", version=f"FORGE {__version__}")
    cli.add_argument("--project", default=".", help="Existing target folder; evidence stays under its .forge directory")
    commands = cli.add_subparsers(dest="command", required=True)
    command = commands.add_parser("init", help="Save target goal, authorization scope and agent workflow constraints")
    command.add_argument("--target", required=True)
    command.add_argument("--goal", default="Discover and verify the target protocol, then implement its checker")
    command.add_argument("--authorization", choices=forge_tasks.AUTHORIZATION, default="unspecified",
                         help="Caller-declared authorization status for this target")
    command.add_argument("--basis", choices=["unspecified", "written_contract", "bug_bounty_scope", "ctf_public",
                                             "own_system", "lab_only"], default="unspecified")
    command.add_argument("--network-profile", choices=forge_tasks.NETWORK_PROFILES, default="unspecified",
                         help="offline blocks network and device steps for this task")
    command.add_argument("--in-scope", action="append", help="Declared in-scope asset; repeatable")
    command.add_argument("--out-of-scope", action="append", help="Declared out-of-scope asset; repeatable")
    command.set_defaults(handler=initialize)
    command = commands.add_parser("status", help="Read current task progress and recent project evidence")
    command.set_defaults(handler=status)
    command = commands.add_parser("evidence", help="List sanitized evidence")
    command.add_argument("--kind")
    command.add_argument("--limit", type=int, default=20)
    command.set_defaults(handler=evidence)
    command = commands.add_parser("show", help="Read one cited evidence record")
    command.add_argument("id")
    command.set_defaults(handler=show)
    command = commands.add_parser("claim", help="Save a scoped statement with citations")
    command.add_argument("text")
    command.add_argument("--state", choices=["OBSERVED", "INFERRED", "UNKNOWN", "CONTRADICTED"], default="INFERRED")
    command.add_argument("--evidence", action="append")
    command.add_argument("--scope", required=True, help="Artifact version, run ID or other applicability boundary")
    command.set_defaults(handler=claim)
    command = commands.add_parser("hook-evidence",
                                  help="Save one hook evidence triple: static location, dynamic proof, state dependency")
    command.add_argument("text")
    command.add_argument("--package", required=True, help="Target package or module the boundary belongs to")
    command.add_argument("--static-location", required=True, help="Observed class/method/symbol/asset location")
    command.add_argument("--static-evidence", required=True, help="Cited record for the static location")
    command.add_argument("--dynamic-proof", required=True, help="Observed runtime proof such as a hook log")
    command.add_argument("--dynamic-evidence", required=True, help="Cited record for the dynamic proof")
    command.add_argument("--state-dependency", help="Local state the boundary needs (prefs row, nonce, keystore flag)")
    command.add_argument("--state-evidence", help="Cited record for the state dependency")
    command.add_argument("--state", choices=["OBSERVED", "INFERRED", "UNKNOWN", "CONTRADICTED"], default="OBSERVED")
    command.add_argument("--scope", required=True, help="Artifact version, run ID or other applicability boundary")
    command.set_defaults(handler=hook_evidence)
    command = commands.add_parser("verify", help="Gate protocol evidence on real positive and negative probe controls")
    command.add_argument("--positive", required=True)
    command.add_argument("--negative", required=True)
    command.add_argument("--protocol", required=True)
    command.set_defaults(handler=verify)
    command = commands.add_parser("report", help="Export sanitized evidence to a new notes Markdown file")
    command.add_argument("--limit", type=int, default=100)
    command.set_defaults(handler=report)
    import forge_artifacts
    import forge_network
    import forge_runtime
    import forge_har
    import forge_execution
    import forge_protocol
    import forge_comparisons
    import forge_graphql
    import forge_android
    import forge_apktool
    import forge_ios
    import forge_retention
    import forge_capture
    import forge_bundle
    for module in (forge_tasks, forge_artifacts, forge_network, forge_runtime, forge_har, forge_execution, forge_protocol,
                   forge_comparisons, forge_graphql, forge_android, forge_apktool, forge_ios, forge_retention,
                   forge_capture, forge_bundle):
        module.register(commands)
    return cli


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = parser().parse_args(argv)
    store = None
    try:
        store = EvidenceStore(args.project)
        result = args.handler(args, store)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, default=str))
        return 0
    except (ForgeError, OSError, ValueError, sqlite3.Error) as error:
        print(json.dumps({"ok": False, "error": str(redact(str(error)))}, ensure_ascii=False), file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
