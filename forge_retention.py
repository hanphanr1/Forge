"""Read-only evidence storage inventory and append-only-aware evidence pruning.

``storage-report`` never writes. ``evidence-prune`` plans by default and only
deletes with ``--apply``; every run appends one ``maintenance`` audit record that
is itself never prunable. Pruning violates FORGE's append-only assumption:
deleted ids stay deleted and any citation pointing at them stops resolving.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import re

from forge_core import ForgeError, scrub_text, utc_now


MAINTENANCE_KIND = "maintenance"
# Records whose citations pin other evidence in place.
CITATION_KINDS = ("claim", "control_verification", "target_verification", "task", "checkpoint", "task_checkpoint")
DEFAULT_MAX_SCAN_ROWS = 200000
_LISTING_CAP = 100
_OLDER_THAN_MAX = 36500
_BLOB_NAME = re.compile(r"[a-f0-9]{64}")
_EVIDENCE_ID = re.compile(r"\bev_[0-9a-f]{32}\b")
_SHA256_TOKEN = re.compile(r"(?<![0-9a-f])[a-f0-9]{64}(?![0-9a-f])")
_APPEND_ONLY_WARNING = ("Pruning violates FORGE's append-only evidence assumption: deleted ids stay deleted, "
                        "storage space is not reclaimed until the database file is rewritten, and every citation "
                        "pointing at a removed id will no longer resolve.")


def _row_cap(args):
    cap = getattr(args, "max_scan_rows", DEFAULT_MAX_SCAN_ROWS)
    if type(cap) is not int or cap < 1:
        raise ForgeError("--max-scan-rows must be a positive integer")
    return cap


def _scan_rows(store, cap=DEFAULT_MAX_SCAN_ROWS):
    """Read evidence rows oldest-first, bounded to ``cap`` rows."""
    cursor = store.connection.execute("SELECT id, kind, created_at, data FROM evidence ORDER BY rowid")
    rows, truncated, corrupt = [], False, 0
    try:
        for evidence_id, kind, created_at, text in cursor:
            if len(rows) >= cap:
                truncated = True
                break
            try:
                data = json.loads(text)
            except ValueError:
                data, corrupt = None, corrupt + 1
            rows.append({"id": evidence_id, "kind": kind, "created_at": created_at, "text": text, "data": data})
    finally:
        cursor.close()
    return rows, truncated, corrupt


def _parse_time(value):
    text = str(value)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _file_bytes(path):
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def _database_files(store):
    database = store.directory / "evidence.sqlite3"
    return {
        "path": database.relative_to(store.root).as_posix(),
        "bytes": _file_bytes(database),
        "wal_bytes": _file_bytes(database.with_name(database.name + "-wal")),
        "shm_bytes": _file_bytes(database.with_name(database.name + "-shm")),
    }


def _blob_files(store):
    directory = store.directory / "blobs"
    if not directory.is_dir():
        return []
    found = []
    for entry in sorted(directory.iterdir(), key=lambda item: item.name):
        if not _BLOB_NAME.fullmatch(entry.name) or entry.is_symlink() or not entry.is_file():
            continue
        found.append({"sha256": entry.name, "bytes": _file_bytes(entry)})
    return found


def _referenced_hashes(rows):
    """SHA-256 tokens any non-audit evidence row mentions.

    Maintenance rows name the blobs a past run planned or removed; treating those
    as live references would make an orphan unprunable after the first dry run.
    """
    referenced = set()
    for row in rows:
        if row["kind"] == MAINTENANCE_KIND:
            continue
        referenced.update(_SHA256_TOKEN.findall(row["text"]))
    return referenced


def _kind_summary(rows):
    summary = {}
    for row in rows:
        entry = summary.get(row["kind"])
        if entry is None:
            entry = summary[row["kind"]] = {"kind": row["kind"], "records": 0, "bytes": 0,
                                            "oldest_created_at": row["created_at"],
                                            "newest_created_at": row["created_at"]}
        entry["records"] += 1
        entry["bytes"] += len(row["text"].encode("utf-8"))
        if row["created_at"] < entry["oldest_created_at"]:
            entry["oldest_created_at"] = row["created_at"]
        if row["created_at"] > entry["newest_created_at"]:
            entry["newest_created_at"] = row["created_at"]
    return sorted(summary.values(), key=lambda entry: (-entry["bytes"], entry["kind"]))


def storage_report(args, store):
    cap = _row_cap(args)
    rows, truncated, corrupt = _scan_rows(store, cap)
    blobs = _blob_files(store)
    referenced = _referenced_hashes(rows)
    used = [blob for blob in blobs if blob["sha256"] in referenced]
    orphans = [blob for blob in blobs if blob["sha256"] not in referenced]

    def totals(items):
        return {"count": len(items), "bytes": sum(item["bytes"] for item in items)}

    return {
        "project": str(store.root),
        "records": {"total": len(rows), "bytes": sum(len(row["text"].encode("utf-8")) for row in rows),
                    "kinds": _kind_summary(rows)},
        "blobs": {"total": totals(blobs), "referenced": totals(used), "unreferenced": {
            **totals(orphans),
            "sha256": [blob["sha256"] for blob in orphans[:_LISTING_CAP]],
            "sha256_omitted": max(0, len(orphans) - _LISTING_CAP)}},
        "database": _database_files(store),
        "scan": {"records_scanned": len(rows), "row_cap": cap,
                 "truncated": truncated, "unparseable_records": corrupt},
        "note": ("Read-only inventory. Referenced blobs are those whose SHA-256 appears in some evidence row; "
                 "an unreferenced blob may still belong to an interrupted write, so removal stays explicit."),
    }


def _prune_inputs(args):
    apply_, dry_run = bool(getattr(args, "apply", False)), bool(getattr(args, "dry_run", False))
    if apply_ and dry_run:
        raise ForgeError("--apply and --dry-run cannot be combined; omit --dry-run to apply")
    blobs_mode = bool(getattr(args, "unreferenced_blobs", False))
    days = getattr(args, "older_than", None)
    if not blobs_mode and days is None:
        raise ForgeError("evidence-prune requires --unreferenced-blobs, --older-than DAYS, or both")
    if days is not None and (type(days) is not int or not 1 <= days <= _OLDER_THAN_MAX):
        raise ForgeError(f"--older-than must be an integer between 1 and {_OLDER_THAN_MAX} days")
    raw_kinds = getattr(args, "kind", None)
    kinds = []
    for value in raw_kinds or []:
        cleaned = scrub_text(str(value).strip())
        if not cleaned:
            raise ForgeError("--kind must be nonempty")
        if cleaned not in kinds:
            kinds.append(cleaned)
    if raw_kinds and days is None:
        raise ForgeError("--kind narrows --older-than; it requires --older-than DAYS")
    return {"apply": apply_, "dry_run": not apply_, "blobs": blobs_mode, "days": days, "kinds": kinds,
            "force": bool(getattr(args, "force", False)),
            "modes": ([name for name, on in (("unreferenced_blobs", blobs_mode), ("older_than", days is not None)) if on])}


def _active_task(store):
    cursor = store.connection.execute(
        "SELECT id, created_at, data FROM evidence WHERE kind='task' ORDER BY created_at DESC, rowid DESC")
    try:
        for evidence_id, created_at, text in cursor:
            try:
                data = json.loads(text)
            except ValueError:
                continue
            if isinstance(data, dict) and data.get("state") == "active":
                return {"id": evidence_id, "created_at": created_at}
    finally:
        cursor.close()
    return None


def _latest_checkpoint(store, task_id):
    row = store.connection.execute(
        "SELECT id, created_at FROM evidence WHERE kind='task_checkpoint' AND json_extract(data, '$.task_id')=? "
        "ORDER BY CAST(json_extract(data, '$.revision') AS INTEGER) DESC, rowid DESC LIMIT 1", (task_id,)).fetchone()
    return {"id": row[0], "created_at": row[1]} if row else None


def _audit(store, options, *, plan, refused, deleted, skipped, before, after, scan):
    record = store.add(MAINTENANCE_KIND, {
        "command": "evidence-prune", "modes": options["modes"],
        "filters": {"older_than_days": options["days"], "kinds": options["kinds"]},
        "apply": options["apply"], "dry_run": options["dry_run"], "force": options["force"],
        "refused": refused,
        "before": before, "after": after,
        "planned": {"records": len(plan["records"]), "blobs": len(plan["blobs"])},
        "deleted": {"records": len(deleted["records"]), "blobs": len(deleted["blobs"]),
                    "record_bytes": deleted["record_bytes"], "blob_bytes": deleted["blob_bytes"],
                    "bytes_freed": deleted["record_bytes"] + deleted["blob_bytes"]},
        "skipped": skipped, "scan": scan,
        "append_only_violation": True,
        "citation_warning": "Citations pointing at removed ids will no longer resolve.",
        "meaning": "Local storage maintenance audit; pruning is irreversible and does not prove any record was obsolete.",
        "created_at": utc_now(),
    })
    return record


def _plan_prune(options, rows):
    cited_ids = set()
    for row in rows:
        if row["kind"] in CITATION_KINDS:
            cited_ids.update(_EVIDENCE_ID.findall(row["text"]))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=options["days"])) if options["days"] is not None else None
    skipped = {"recent": 0, "kind_filter": 0, "unparseable_timestamp": 0, "corrupt_record": 0,
               "cited": 0, "citation_source": 0, "maintenance": 0}
    selected = []
    if cutoff is not None:
        for row in rows:
            if options["kinds"] and row["kind"] not in options["kinds"]:
                skipped["kind_filter"] += 1
                continue
            if row["kind"] == MAINTENANCE_KIND:
                skipped["maintenance"] += 1
                continue
            created = _parse_time(row["created_at"])
            if created is None:
                skipped["unparseable_timestamp"] += 1
                continue
            if created >= cutoff:
                skipped["recent"] += 1
                continue
            if row["data"] is None:
                skipped["corrupt_record"] += 1
                continue
            if not options["force"] and row["id"] in cited_ids:
                skipped["cited"] += 1
                continue
            if not options["force"] and row["kind"] in CITATION_KINDS:
                skipped["citation_source"] += 1
                continue
            selected.append(row)
    return {"cutoff": cutoff, "records": selected, "skipped": skipped,
            "referenced_hashes": _referenced_hashes(rows) if options["blobs"] else set()}


def evidence_prune(args, store):
    options = _prune_inputs(args)
    cap = _row_cap(args)
    rows, truncated, corrupt = _scan_rows(store, cap)
    plan = _plan_prune(options, rows)
    blobs = _blob_files(store)
    plan["blobs"] = ([blob for blob in blobs if blob["sha256"] not in plan["referenced_hashes"]]
                     if options["blobs"] else [])

    before = {"records": len(rows), "blobs": len(blobs),
              "record_bytes": sum(len(row["text"].encode("utf-8")) for row in rows),
              "blob_bytes": sum(blob["bytes"] for blob in blobs)}
    scan = {"records_scanned": len(rows), "row_cap": cap,
            "truncated": truncated, "unparseable_records": corrupt}

    refusal = None
    if truncated:
        refusal = "reference scan row cap reached; blob orphanhood or citation coverage cannot be proven"
    elif plan["records"]:
        task = _active_task(store)
        if task:
            checkpoint = _latest_checkpoint(store, task["id"])
            boundary_text = checkpoint["created_at"] if checkpoint else task["created_at"]
            boundary = _parse_time(boundary_text)
            conflicts = [row for row in plan["records"]
                         if boundary is None or (_parse_time(row["created_at"]) or datetime.now(timezone.utc)) > boundary]
            if conflicts:
                refusal = (f"active task {task['id']} "
                           f"(latest checkpoint {checkpoint['id'] if checkpoint else 'none'}) would lose "
                           f"{len(conflicts)} record(s) created after it")

    if refusal:
        record = _audit(store, options, plan=plan, refused=refusal, skipped=plan["skipped"],
                        deleted={"records": [], "blobs": [], "record_bytes": 0, "blob_bytes": 0},
                        before=before, after=before, scan=scan)
        raise ForgeError(f"evidence-prune refused: {refusal}; nothing was deleted (audit evidence {record['id']})")

    deleted = {"records": [], "blobs": [], "record_bytes": 0, "blob_bytes": 0}
    if options["apply"]:
        for blob in plan["blobs"]:
            try:
                os.unlink(store.blob_path(blob["sha256"]))
            except FileNotFoundError:
                continue
            deleted["blobs"].append(blob["sha256"])
            deleted["blob_bytes"] += blob["bytes"]
        if plan["records"]:
            identifiers = [row["id"] for row in plan["records"]]
            with store.connection:
                store.connection.executemany("DELETE FROM evidence WHERE id=?", [(item,) for item in identifiers])
            deleted["records"] = identifiers
            deleted["record_bytes"] = sum(len(row["text"].encode("utf-8")) for row in plan["records"])

    # Counted before the maintenance audit row below is appended, so "after" describes the pruned store.
    after_rows = store.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    after = {"records": after_rows, "blobs": len(_blob_files(store)),
             "record_bytes": before["record_bytes"] - deleted["record_bytes"],
             "blob_bytes": before["blob_bytes"] - deleted["blob_bytes"]}
    record = _audit(store, options, plan=plan, refused=None, skipped=plan["skipped"],
                    deleted=deleted, before=before, after=after, scan=scan)

    return {
        "apply": options["apply"], "dry_run": options["dry_run"], "modes": options["modes"],
        "filters": {"older_than_days": options["days"], "kinds": options["kinds"], "force": options["force"]},
        "planned": {"records": [row["id"] for row in plan["records"][:_LISTING_CAP]],
                    "records_omitted": max(0, len(plan["records"]) - _LISTING_CAP),
                    "blobs": [blob["sha256"] for blob in plan["blobs"][:_LISTING_CAP]],
                    "blobs_omitted": max(0, len(plan["blobs"]) - _LISTING_CAP)},
        "deleted": {"records": len(deleted["records"]), "blobs": len(deleted["blobs"]),
                    "record_bytes": deleted["record_bytes"], "blob_bytes": deleted["blob_bytes"],
                    "bytes_freed": deleted["record_bytes"] + deleted["blob_bytes"]},
        "skipped": plan["skipped"], "scan": scan,
        "before": before, "after": after,
        "audit": {"id": record["id"], "kind": MAINTENANCE_KIND},
        "note": _APPEND_ONLY_WARNING + " This maintenance audit record is appended by every run and is never pruned.",
        "citation_warning": "Citations pointing at removed ids will no longer resolve.",
    }


def register(subparsers):
    parser = subparsers.add_parser("storage-report", help="Read-only inventory of evidence rows, blobs and database size")
    parser.add_argument("--max-scan-rows", type=int, default=DEFAULT_MAX_SCAN_ROWS,
                        help=f"Bound rows scanned for reference facts (default {DEFAULT_MAX_SCAN_ROWS})")
    parser.set_defaults(handler=storage_report)

    parser = subparsers.add_parser("evidence-prune", help="Plan (default) or delete unreferenced blobs and old evidence rows")
    parser.add_argument("--dry-run", action="store_true", help="Plan and audit only; this is the default")
    parser.add_argument("--apply", action="store_true", help="Actually delete the planned records and blobs")
    parser.add_argument("--unreferenced-blobs", action="store_true", help="Target blobs that no evidence row references")
    parser.add_argument("--older-than", type=int, metavar="DAYS",
                        help=f"Target records created more than DAYS ago (1..{_OLDER_THAN_MAX})")
    parser.add_argument("--kind", action="append", help="Restrict --older-than to this evidence kind; repeatable")
    parser.add_argument("--force", action="store_true",
                        help="Also allow deleting cited evidence and citation-source records")
    parser.add_argument("--max-scan-rows", type=int, default=DEFAULT_MAX_SCAN_ROWS,
                        help=f"Bound rows scanned for citation facts (default {DEFAULT_MAX_SCAN_ROWS})")
    parser.set_defaults(handler=evidence_prune)
