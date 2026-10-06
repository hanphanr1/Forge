from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import sqlite3
import stat
from urllib.parse import urlsplit

from forge_core import EvidenceStore, ForgeError, redact_url, scrub_text


PHASES = ("discover", "analyze", "probe", "implement", "verify")
STATES = ("active", "blocked", "completed")
AUTHORIZATION = ("unspecified", "granted", "pending", "denied")
NETWORK_PROFILES = ("unspecified", "offline", "lab_only", "authorized_target_only", "unrestricted_lab")
_AUTHORIZATION_BASES = ("unspecified", "written_contract", "bug_bounty_scope", "ctf_public", "own_system", "lab_only")
_NEXT_DISCOVERY = "Use agent web/browser tools to identify official clients; save observed artifacts with provenance."
_MEANING = "Agent-reported progress; citations and file hashes do not prove execution or verification."
# Includes the artifact directory-index exclusions, plus explicit secret stores.
_EXCLUDED_DIRECTORIES = {
    ".forge", ".git", ".venv", "venv", "node_modules", "results", "__pycache__",
    "credentials", "secrets", "accounts", "cookies", "data", "captures", "tools",
}
_EXCLUDED_FILES = {"accounts", "accounts.txt", "proxies.txt", "keys.txt", "credentials.json", "cookies.txt"}
_SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db"}


def initialize(args, store, platform_order):
    try:
        target = urlsplit(args.target)
        valid = target.scheme in {"http", "https"} and target.hostname
    except ValueError as exc:
        raise ForgeError("--target must be an HTTP(S) URL") from exc
    if not valid:
        raise ForgeError("--target must be an HTTP(S) URL; use the official site identified by the agent")
    # Stored key names deliberately avoid the words the core redactor treats as credential
    # bearers (for example a stored key literally named "authorization" would be masked).
    scope = {
        "scope_status": getattr(args, "authorization", "unspecified") or "unspecified",
        "scope_basis": getattr(args, "basis", "unspecified") or "unspecified",
        "in_scope": list(getattr(args, "in_scope", None) or []),
        "out_of_scope": list(getattr(args, "out_of_scope", None) or []),
        "network_profile": getattr(args, "network_profile", "unspecified") or "unspecified",
    }
    if scope["scope_status"] not in AUTHORIZATION:
        raise ForgeError(f"--authorization must be one of {', '.join(AUTHORIZATION)}")
    if scope["scope_basis"] not in _AUTHORIZATION_BASES:
        raise ForgeError(f"--basis must be one of {', '.join(_AUTHORIZATION_BASES)}")
    if scope["network_profile"] not in NETWORK_PROFILES:
        raise ForgeError(f"--network-profile must be one of {', '.join(NETWORK_PROFILES)}")
    if scope["scope_status"] == "granted" and scope["scope_basis"] == "unspecified":
        raise ForgeError("An authorization status of 'granted' needs a --basis such as own_system or ctf_public")
    record = store.add("task", {
        "target": redact_url(args.target), "goal": args.goal,
        "phase": "discover", "state": "active", "revision": 0,
        "summary": "Task initialized; discovery has not been performed.",
        "next_action": _NEXT_DISCOVERY, "blockers": [], "evidence": [], "files": [],
        "platform_order": list(platform_order),
        "scope": scope,
        "constraints": {"prefer_captchaless": True, "live_evidence_required": True,
                        "solver_spending": "requires_user_approval", "account_data": "explicit_user_scope_only"},
        "meaning": _MEANING,
    })
    workflow = Path(__file__).parent / "WORKFLOW.md"
    return {"task": record, "next": _NEXT_DISCOVERY,
            "workflow": str(workflow) if workflow.is_file() else "https://github.com/hanphanr1/Forge/blob/main/WORKFLOW.md"}


def _task(store, task_id=None):
    if task_id is None:
        records = store.list("task", 1)
        return records[0] if records else None
    record = store.get(task_id)
    if record["kind"] != "task":
        raise ForgeError("--task must identify a task evidence record")
    return record


def _current(store, task_id):
    row = store.connection.execute(
        "SELECT id FROM evidence WHERE kind='task_checkpoint' AND json_extract(data, '$.task_id')=? "
        "ORDER BY CAST(json_extract(data, '$.revision') AS INTEGER) DESC, rowid DESC LIMIT 1", (task_id,)
    ).fetchone()
    return store.get(row[0]) if row else None


def _progress(task, snapshot):
    data = (snapshot or task)["data"]
    return {
        "task_id": task["id"], "checkpoint_id": snapshot["id"] if snapshot else None,
        "revision": data.get("revision", 0) if snapshot else 0,
        "phase": data.get("phase", "discover"), "state": data.get("state", "active"),
        "summary": data.get("summary", data.get("goal", "Legacy task; no checkpoint recorded.")),
        "next_action": data.get("next_action", _NEXT_DISCOVERY),
        "blockers": data.get("blockers", []), "evidence": data.get("evidence", []),
        "files": data.get("files", []), "scope": data.get("scope", {"scope_status": "unspecified"}),
        "meaning": _MEANING,
    }


def _task_for_scope(store):
    """Read the newest task, tolerating a store bound to another thread.

    The evidence connection is thread-bound, so a caller that embeds a command on a worker
    thread (for example a listener) still needs the gate to read the same database rather than
    crash. A short-lived same-thread connection reads it; the gate stays enforced.
    """
    try:
        return _task(store, None)
    except sqlite3.ProgrammingError:
        borrowed = EvidenceStore(store.root)
        try:
            return _task(borrowed, None)
        finally:
            borrowed.close()


def check_scope(store, activity, network=False, device=False):
    """Refuse active work that the current task scope forbids.

    Absent or unspecified scope is not a gate; only an explicit denial, or an
    explicitly offline profile on a step that performs network/device I/O, blocks.
    """
    task = _task_for_scope(store)
    if task is None:
        return None
    scope = task["data"].get("scope") or {}
    authorization = scope.get("scope_status", "unspecified")
    profile = scope.get("network_profile", "unspecified")
    if authorization == "denied" and (network or device):
        raise ForgeError(f"Task scope denies active work; the declared authorization status is denied. Update the task "
                         f"scope before running {activity}")
    if profile == "offline" and (network or device):
        kind = "network" if network else "device"
        raise ForgeError(f"Task scope forbids {kind} activity because the network profile is offline; "
                         f"{activity} was not started")
    return {"activity": activity, "scope_status": authorization, "scope_basis": scope.get("scope_basis", "unspecified"),
            "network_profile": profile, "in_scope": scope.get("in_scope", []),
            "out_of_scope": scope.get("out_of_scope", []),
            "active": bool(network or device),
            "meaning": "Scope is caller-declared task metadata; it is not independent proof of authorization. Local "
                       "analysis of already-obtained artifacts is not blocked by a denied or offline scope."}


def task_status(store, task_id=None):
    task = _task(store, task_id)
    return _progress(task, _current(store, task["id"])) if task else None


def history(args, store):
    if type(args.limit) is not int or not 1 <= args.limit <= 1000:
        raise ForgeError("--limit must be between 1 and 1000")
    if type(args.after_revision) is not int or args.after_revision < 0:
        raise ForgeError("--after-revision must be a nonnegative integer")
    task = _task(store, args.task)
    if not task:
        raise ForgeError("No task exists; initialize a task first")
    rows = store.connection.execute(
        "SELECT id, kind, created_at, data FROM evidence "
        "WHERE kind='task_checkpoint' AND json_extract(data, '$.task_id')=? "
        "AND CAST(json_extract(data, '$.revision') AS INTEGER)>? "
        "ORDER BY CAST(json_extract(data, '$.revision') AS INTEGER), rowid LIMIT ?",
        (task["id"], args.after_revision, args.limit + 1),
    ).fetchall()
    has_more = len(rows) > args.limit
    records = [{"id": row[0], "kind": row[1], "created_at": row[2], "data": json.loads(row[3])}
               for row in rows[:args.limit]]
    return {"task": task, "checkpoints": records, "after_revision": args.after_revision,
            "has_more": has_more,
            "next_revision": records[-1]["data"]["revision"] if has_more else None}


def _required_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ForgeError(f"{label} must be nonempty")
    return scrub_text(value.strip())


def _excluded(relative):
    parts = [part.casefold() for part in relative.parts]
    name = parts[-1]
    return (any(part in _EXCLUDED_DIRECTORIES for part in parts)
            or name in _EXCLUDED_FILES or name == ".env" or name.startswith(".env.")
            or Path(name).suffix in _SECRET_SUFFIXES)


def _file_path(store, value, *, relative_only=False):
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ForgeError("File path must be nonempty")
    normalized = value.replace("\\", "/")
    windows = PureWindowsPath(value)
    path = Path(normalized)
    if ".." in normalized.split("/"):
        raise ForgeError("File traversal is not allowed")
    if relative_only and (path.is_absolute() or windows.drive or windows.root):
        raise ForgeError("Saved file paths must be project-relative")
    if windows.drive and not path.is_absolute():
        raise ForgeError("File path is not project-relative on this platform")
    candidate = path if path.is_absolute() else store.root / path
    try:
        relative = candidate.relative_to(store.root)
    except ValueError as exc:
        raise ForgeError("File must remain inside the project directory") from exc
    if not relative.parts or any(":" in part for part in relative.parts):
        raise ForgeError("File must name a regular project file")
    if _excluded(relative):
        raise ForgeError("Secret, data, or dependency file paths are excluded")
    current = store.root
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ForgeError("Symlinks and reparse points are not allowed in file paths")
    try:
        candidate.resolve().relative_to(store.root)
    except (ValueError, RuntimeError) as exc:
        raise ForgeError("File must remain inside the project directory") from exc
    return relative


@contextmanager
def _regular_file(store, relative):
    descriptors = []
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            descriptor = os.open(store.root, directory_flags)
            descriptors.append(descriptor)
            for component in relative.parts[:-1]:
                descriptor = os.open(component, directory_flags, dir_fd=descriptor)
                descriptors.append(descriptor)
            descriptor = os.open(relative.name, flags | os.O_NOFOLLOW, dir_fd=descriptor)
        else:
            descriptor = os.open(store.root / relative, flags)
        descriptors.append(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ForgeError("File must be a regular file")
        _file_path(store, relative.as_posix(), relative_only=True)
        if not os.path.samestat(info, (store.root / relative).stat()):
            raise ForgeError("File changed while being opened")
        with os.fdopen(descriptors.pop(), "rb") as source:
            yield source
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _file_fact(store, value, *, relative_only=False):
    relative = _file_path(store, value, relative_only=relative_only)
    digest = hashlib.sha256()
    size = 0
    with _regular_file(store, relative) as source:
        before = os.fstat(source.fileno())
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ForgeError("File changed while being hashed")
        _file_path(store, relative.as_posix(), relative_only=True)
        if not os.path.samestat(after, (store.root / relative).stat()) or size != after.st_size:
            raise ForgeError("File changed while being hashed")
    return {"path": relative.as_posix(), "sha256": digest.hexdigest(), "size": size}


def _revision(value):
    try:
        revision = int(value)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("Revision must be a nonnegative integer") from exc
    if revision < 0:
        raise argparse.ArgumentTypeError("Revision must be a nonnegative integer")
    return revision


def checkpoint(args, store):
    expected = getattr(args, "expect_revision", None)
    if type(expected) is not int or expected < 0:
        raise ForgeError("--expect-revision must be a nonnegative integer")
    if args.phase not in PHASES or args.state not in STATES:
        raise ForgeError("Invalid checkpoint phase or state")
    summary = _required_text(args.summary, "--summary")
    next_action = getattr(args, "next_action", None)
    next_action = _required_text(next_action, "--next") if next_action is not None else None
    blockers = [_required_text(value, "--blocker") for value in (getattr(args, "blocker", None) or [])]
    if args.state in {"active", "blocked"} and not next_action:
        raise ForgeError("Active and blocked checkpoints require --next")
    if args.state == "blocked" and not blockers:
        raise ForgeError("Blocked checkpoints require at least one --blocker")
    if args.state == "completed" and (blockers or next_action):
        raise ForgeError("Completed checkpoints cannot have blockers or a pending --next")
    ids = list(dict.fromkeys(getattr(args, "evidence", None) or []))
    connection = store.connection
    if connection.in_transaction:
        raise ForgeError("Checkpoint requires a connection with no pending transaction")
    connection.execute("BEGIN IMMEDIATE")
    try:
        task = _task(store, getattr(args, "task", None))
        if not task:
            raise ForgeError("No task exists; initialize a task first")
        current = _current(store, task["id"])
        revision = _progress(task, current)["revision"]
        if expected != revision:
            raise ForgeError(f"Stale revision: expected {expected}, current revision is {revision}")
        for evidence_id in ids:
            citation = store.get(evidence_id)
            data = citation["data"] if isinstance(citation["data"], dict) else {}
            if ((citation["kind"] == "task" and citation["id"] != task["id"])
                    or (data.get("task_id") is not None and data["task_id"] != task["id"])):
                raise ForgeError("Evidence citation belongs to another task")
        files = {}
        for value in getattr(args, "file", None) or []:
            fact = _file_fact(store, value)
            files[fact["path"]] = fact
        # EvidenceStore.add commits its single insert while this write lock is held.
        return store.add("task_checkpoint", {
            "task_id": task["id"], "revision": revision + 1,
            "phase": args.phase, "state": args.state, "summary": summary,
            "next_action": next_action, "blockers": blockers, "evidence": ids,
            "files": [files[path] for path in sorted(files)], "meaning": _MEANING,
        })
    except BaseException:
        connection.rollback()
        raise


def _integrity(store, fact):
    result = {"path": fact["path"], "expected": {"sha256": fact["sha256"], "size": fact["size"]}, "observed": None}
    try:
        observed = _file_fact(store, fact["path"], relative_only=True)
    except FileNotFoundError:
        result["status"] = "missing"
    except (ForgeError, OSError) as exc:
        result.update(status="unsafe", reason=scrub_text(str(exc)))
    else:
        result["observed"] = {"sha256": observed["sha256"], "size": observed["size"]}
        result["status"] = "unchanged" if result["observed"] == result["expected"] else "changed"
    return result


def resume(args, store):
    connection = store.connection
    if connection.in_transaction:
        raise ForgeError("Resume requires a connection with no pending transaction")
    connection.execute("BEGIN")
    try:
        task = _task(store, getattr(args, "task", None))
        if not task:
            raise ForgeError("No task exists; initialize a task first")
        current = _current(store, task["id"])
        selected = current
        checkpoint_id = getattr(args, "checkpoint", None)
        if checkpoint_id is not None:
            selected = store.get(checkpoint_id)
            if selected["kind"] != "task_checkpoint" or selected["data"].get("task_id") != task["id"]:
                raise ForgeError("--checkpoint must identify a checkpoint belonging to the selected task")
        progress = _progress(task, selected)
        result = {"task": task, "checkpoint": selected, **progress,
                  "current_revision": _progress(task, current)["revision"],
                  "is_current": selected == current}
    finally:
        connection.rollback()
    result["file_integrity"] = [_integrity(store, fact) for fact in progress["files"]]
    return result


def register(subparsers):
    parser = subparsers.add_parser("checkpoint", help="Append agent-reported task progress with an expected revision")
    parser.add_argument("--task", help="Task evidence ID; defaults to the newest task")
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--state", choices=STATES, default="active")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--next", dest="next_action")
    parser.add_argument("--blocker", action="append")
    parser.add_argument("--evidence", action="append")
    parser.add_argument("--file", action="append")
    parser.add_argument("--expect-revision", type=_revision, required=True)
    parser.set_defaults(handler=checkpoint)

    parser = subparsers.add_parser("resume", help="Read saved task progress and current file integrity without executing it")
    parser.add_argument("--task", help="Task evidence ID; defaults to the newest task")
    parser.add_argument("--checkpoint", help="Optional historical checkpoint evidence ID for this task")
    parser.set_defaults(handler=resume)

    parser = subparsers.add_parser("history", help="Read task checkpoints in revision order without rehashing files")
    parser.add_argument("--task", help="Task evidence ID; defaults to the newest task")
    parser.add_argument("--after-revision", type=_revision, default=0, help="Exclusive revision cursor")
    parser.add_argument("--limit", type=int, default=20, help="Page size, between 1 and 1000")
    parser.set_defaults(handler=history)
