"""Bounded execution of explicitly declared, trusted project controls."""

from __future__ import annotations

import base64
import ctypes
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
import uuid

from forge_core import ForgeError, scrub_text
import forge_network
import forge_tasks


_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_BUCKETS = frozenset({"HIT", "FREE", "FAIL", "TERMINAL"})
_LIMITS = [
    "Executed code, bounded process outputs, and declared controls only; this is not a sandbox.",
    "The program reports its bucket; FORGE does not independently attest network/server or authentication behavior.",
    "Client and egress are non-secret declarations, not measured client identity, IP, or egress.",
    "Only explicitly listed source files are hashed; unlisted code, dependencies, interpreter, and environment are not attested.",
]
_MAX_OUTPUT = 16 * 1024 * 1024


def _protect(secrets, value):
    forge_network._add_secret(secrets, value, allow_redacted=True)
    if isinstance(value, str) and value:
        raw = value.encode("utf-8")
        for encoded in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
            secrets.add(encoded.decode("ascii"))
            secrets.add(encoded.decode("ascii").rstrip("="))
        secrets.add(raw.hex())
        # Percent escapes are case-insensitive, but replacement is not.
        for form in tuple(secrets):
            if "%" in form:
                secrets.add(re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match[0].lower(), form))


def _template(value):
    pieces, cursor = [], 0
    for match in _REFERENCE.finditer(value):
        if cursor != match.start():
            pieces.append("[LITERAL REDACTED]")
        pieces.append(match[0])
        cursor = match.end()
    if cursor != len(value):
        pieces.append("[LITERAL REDACTED]")
    return "".join(pieces) if pieces else "[LITERAL REDACTED]"


def _argv(value, label, environment, output_secrets, metadata_secrets, *, nonempty):
    if not isinstance(value, list) or (nonempty and not value):
        raise ForgeError(f"{label} must be {'a nonempty' if nonempty else 'an'} argv array")
    resolved = []
    sensitive_next = False
    for argument in value:
        if not isinstance(argument, str) or "\x00" in argument:
            raise ForgeError(f"{label} entries must be strings without NUL bytes")
        if "${" in _REFERENCE.sub("", argument):
            raise ForgeError("Command arguments contain an invalid environment reference; flow references are not supported")
        # All literal arguments are opaque, including innocently named credential values.
        try:
            _protect(output_secrets, argument)
            forge_network._gather_secrets(argument, metadata_secrets)
            forge_network._url_secrets(argument, metadata_secrets)
        except (UnicodeError, RecursionError):
            raise ForgeError("Command arguments cannot be safely encoded or redacted") from None
        if sensitive_next:
            _protect(metadata_secrets, argument)
        flag, separator, attached = argument.partition("=")
        sensitive_next = flag.startswith("-") and bool(forge_network._SENSITIVE.search(flag)) and not separator
        if flag.startswith("-") and separator:
            _protect(output_secrets, attached)
            if forge_network._SENSITIVE.search(flag):
                _protect(metadata_secrets, attached)

        def replace(match):
            name = match[1]
            if name not in environment:
                if name not in os.environ:
                    raise ForgeError("A referenced environment variable is not defined")
                environment[name] = os.environ[name]
            secret = environment[name]
            if "\x00" in secret:
                raise ForgeError("A referenced environment value contains a NUL byte")
            try:
                _protect(output_secrets, secret)
                _protect(metadata_secrets, secret)
            except UnicodeError:
                raise ForgeError("A referenced environment value cannot be safely encoded") from None
            return secret

        result = _REFERENCE.sub(replace, argument)
        _protect(output_secrets, result)
        resolved.append(result)
    return resolved


def _options(args):
    if (isinstance(args.timeout, bool) or not isinstance(args.timeout, (int, float))
            or not math.isfinite(args.timeout) or not 0 < args.timeout <= 3600):
        raise ForgeError("--timeout must be finite, greater than zero, and at most 3600 seconds")
    if type(args.max_output) is not int or not 0 < args.max_output <= _MAX_OUTPUT:
        raise ForgeError("--max-output must be an integer from 1 to 16777216 bytes")


def _strict_json(text):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("non-JSON number")

    return json.loads(text, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def _hash_files(store, paths):
    try:
        facts = [forge_tasks._file_fact(store, path, relative_only=True) for path in paths]
    except (ForgeError, OSError, RuntimeError, UnicodeError):
        raise ForgeError("Listed source files must be safe, readable, regular project files") from None
    if len({fact["path"] for fact in facts}) != len(facts):
        raise ForgeError("Source files must be distinct explicit project paths")
    return sorted(facts, key=lambda fact: fact["path"])


def _prepare(args, store):
    _options(args)
    path = Path(args.spec).expanduser()
    if not path.is_absolute():
        path = store.root / path
    try:
        spec = _strict_json(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        # Parser errors may quote credentials from the raw spec.
        raise ForgeError("Cannot read target spec as a complete JSON object") from None
    allowed = {"command", "files", "context", "bucket_path", "controls"}
    if not isinstance(spec, dict) or set(spec) - allowed or not {"command", "files", "context", "controls"} <= set(spec):
        raise ForgeError("Target spec requires command, files, context, controls and optional bucket_path only")
    paths = spec["files"]
    if not isinstance(paths, list) or not paths or any(not isinstance(item, str) for item in paths):
        raise ForgeError("files must be a nonempty explicit project-source path array")
    context = spec["context"]
    if (not isinstance(context, dict) or set(context) != {"client", "egress"}
            or any(not isinstance(item, str) or not item.strip() or "\x00" in item
                   or "${" in item for item in context.values())):
        raise ForgeError("context must declare nonempty, non-secret client and egress strings")
    bucket_path = spec.get("bucket_path", "/bucket")
    try:
        parts = forge_network._path_parts(bucket_path)
    except ForgeError:
        raise ForgeError("bucket_path must be a valid JSON pointer or dotted selector") from None
    controls = spec["controls"]
    if not isinstance(controls, list) or len(controls) != 2:
        raise ForgeError("controls must contain exactly one positive and one negative control")
    names = set()
    environment, output_secrets, metadata_secrets = {}, set(), set()
    command = _argv(spec["command"], "command", environment, output_secrets, metadata_secrets, nonempty=True)
    if not command[0].strip():
        raise ForgeError("Command executable must be nonempty after environment resolution")
    if Path(command[0]).suffix.casefold() in {".bat", ".cmd"}:
        raise ForgeError("Batch-file executables are not supported; run a real executable without a shell")
    prepared = []
    for control in controls:
        if not isinstance(control, dict) or set(control) != {"name", "args", "expected_bucket"}:
            raise ForgeError("Each control requires name, args, and expected_bucket only")
        name = control["name"]
        if not isinstance(name, str) or name not in {"positive", "negative"} or name in names:
            raise ForgeError("Control names must be unique positive and negative")
        names.add(name)
        expected = control["expected_bucket"]
        if not isinstance(expected, str) or expected not in ({"HIT", "FREE"} if name == "positive" else {"FAIL"}):
            raise ForgeError("Positive expects HIT or FREE; negative expects FAIL")
        arguments = _argv(control["args"], "control args", environment, output_secrets, metadata_secrets, nonempty=False)
        prepared.append({"name": name, "argv": command + arguments, "expected_bucket": expected,
                         "args_template": [_template(item) for item in control["args"]]})
    facts = _hash_files(store, paths)
    public_arguments = {command[0], "positive", "negative", *_BUCKETS}
    for fact in facts:
        public_arguments.update({fact["path"], "./" + fact["path"], str(store.root / fact["path"])})
    for control in prepared:
        for argument in control["argv"][1:]:
            if argument not in public_arguments and not (argument.startswith("-") and "=" not in argument):
                _protect(metadata_secrets, argument)
    # All controls contribute privacy inputs before validating public metadata.
    for secret in tuple(metadata_secrets):
        _protect(output_secrets, secret)
    safe_context = forge_network._sanitize(context, metadata_secrets)
    for item in context.values():
        forge_network._url_secrets(item, metadata_secrets)
    if (safe_context != context or forge_network._sanitize(context, metadata_secrets) != context
            or forge_network._has_redacted(context)):
        raise ForgeError("context identifiers must be non-secret declarations")
    if any(forge_network._sanitize(fact["path"], metadata_secrets) != fact["path"] for fact in facts):
        raise ForgeError("Source paths must not contain credentials")
    if (not isinstance(bucket_path, str) or "${" in bucket_path
            or forge_network._sanitize(bucket_path, metadata_secrets) != bucket_path):
        raise ForgeError("bucket_path must be a non-secret selector")
    try:
        for value in (*context.values(), bucket_path):
            value.encode("utf-8")
    except UnicodeError:
        raise ForgeError("Public context and selector must be valid Unicode text") from None
    return {"command_template": [_template(item) for item in spec["command"]],
            "context": context, "bucket_path": bucket_path, "parts": parts,
            "controls": prepared, "paths": [fact["path"] for fact in facts], "initial": facts,
            "output_secrets": output_secrets, "metadata_secrets": metadata_secrets}


def _windows_descendants(pid):
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot_fn = kernel.CreateToolhelp32Snapshot
    snapshot_fn.argtypes, snapshot_fn.restype = (wintypes.DWORD, wintypes.DWORD), wintypes.HANDLE
    first, next_entry = kernel.Process32FirstW, kernel.Process32NextW
    for function in (first, next_entry):
        function.argtypes, function.restype = (wintypes.HANDLE, ctypes.POINTER(ProcessEntry)), wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes, close.restype = (wintypes.HANDLE,), wintypes.BOOL
    snapshot = snapshot_fn(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise OSError("process snapshot failed")
    parents = {}
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        available = first(snapshot, ctypes.byref(entry))
        while available:
            parents[entry.th32ProcessID] = entry.th32ParentProcessID
            available = next_entry(snapshot, ctypes.byref(entry))
    finally:
        close(snapshot)
    descendants = {pid}
    while True:
        found = {child for child, parent in parents.items() if parent in descendants}
        if found <= descendants:
            return sorted(descendants)
        descendants.update(found)


def _terminate_tree(process):
    if os.name == "nt":
        try:
            pids = _windows_descendants(process.pid)
        except (OSError, AttributeError):
            pids = [process.pid]
        # Parent PIDs remain in the process snapshot after the leader exits.
        # Kill the discovered children too: taskkill alone cannot find a dead leader.
        utility = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe")
        arguments = [utility, "/F", "/T"]
        for pid in pids:
            arguments.extend(("/PID", str(pid)))
        try:
            subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _capture(argv, root, timeout, max_output):
    started = time.monotonic()
    result = {"exit_code": None, "timed_out": False, "truncated": False, "error": None,
              "stdout_bytes": 0, "stderr_bytes": 0}
    try:
        process = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, bufsize=0,
                                   start_new_session=os.name != "nt",
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
    except (OSError, ValueError, subprocess.SubprocessError):
        result.update(stdout=b"", stderr=b"", elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                      error="launch_error")
        return result
    lock = threading.Lock()
    retained = 0
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    finished = {"stdout": threading.Event(), "stderr": threading.Event()}

    def drain(name, stream):
        nonlocal retained
        try:
            while True:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    break
                with lock:
                    result[name + "_bytes"] += len(chunk)
                    keep = min(len(chunk), max_output - retained)
                    buffers[name].extend(chunk[:keep])
                    retained += keep
                    if keep != len(chunk):
                        result["truncated"] = True
        except OSError:
            with lock:
                result["error"] = "pipe_read_error"
        finally:
            stream.close()
            finished[name].set()

    threads = [threading.Thread(target=drain, args=(name, getattr(process, name)), daemon=True)
               for name in ("stdout", "stderr")]
    for thread in threads:
        thread.start()
    deadline = started + timeout
    try:
        while process.poll() is None or not all(event.is_set() for event in finished.values()):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result["timed_out"] = True
                _terminate_tree(process)
                break
            time.sleep(min(0.01, remaining))
        cleanup_deadline = time.monotonic() + 2
        try:
            process.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            result["error"] = "process_cleanup_error"
        for thread in threads:
            thread.join(timeout=max(0, cleanup_deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            result["error"] = "pipe_cleanup_error"
        result["exit_code"] = process.poll()
        with lock:
            result["stdout"], result["stderr"] = bytes(buffers["stdout"]), bytes(buffers["stderr"])
    except BaseException:
        _terminate_tree(process)
        raise
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def _gather_output(value, secrets, metadata_secrets):
    discovered = set()
    try:
        forge_network._gather_secrets(value, discovered)
    except RecursionError:
        return False
    try:
        for secret in discovered:
            _protect(secrets, secret)
            _protect(metadata_secrets, secret)
    except UnicodeError:
        return False
    return True


def _safe_output(text, secrets, truncated):
    value = forge_network._safe_body(text, secrets, truncated)

    def mask_scalars(item):
        if isinstance(item, dict):
            return {key.encode("utf-8", errors="replace").decode("utf-8"): mask_scalars(child)
                    for key, child in item.items()}
        if isinstance(item, list):
            return [mask_scalars(child) for child in item]
        if isinstance(item, str):
            return item.encode("utf-8", errors="replace").decode("utf-8")
        if item is not None and not isinstance(item, str) and json.dumps(item) in secrets:
            return "[REDACTED]"
        return item

    return mask_scalars(value)


def _reported_error(value):
    if isinstance(value, dict):
        return any((key.casefold() in {"error", "errors"} and child not in (None, False, "", [], {}))
                   or _reported_error(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_reported_error(child) for child in value)
    return False


def _run_control(args, store, prepared, control, invocation, before):
    captured = _capture(control["argv"], store.root, args.timeout, args.max_output)
    error, bucket = captured["error"], None
    decoding = "ignore" if captured["truncated"] else "replace"
    stdout = captured["stdout"].decode("utf-8", errors=decoding)
    stderr = captured["stderr"].decode("utf-8", errors=decoding)
    try:
        parsed = _strict_json(captured["stdout"].decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("stdout is not an object")
        candidate = forge_network._json_at(parsed, prepared["parts"])
        if isinstance(candidate, str) and candidate in _BUCKETS:
            bucket = candidate
        elif error is None:
            error = "missing_bucket" if candidate is forge_network._MISSING else "unknown_bucket"
        if _reported_error(parsed) and error is None:
            error = "reported_error"
    except (ValueError, UnicodeError, RecursionError):
        if error is None:
            error = "invalid_stdout_json"
    try:
        after = _hash_files(store, prepared["paths"])
        source_error = None
    except ForgeError:
        after, source_error = [], "source_unavailable"
    changed = source_error is not None or before != after or before != prepared["initial"]
    if source_error and error is None:
        error = source_error
    success = (captured["exit_code"] == 0 and not captured["timed_out"] and not captured["truncated"]
               and error is None and not changed and bucket == control["expected_bucket"])
    return {"invocation_id": invocation, "control": control["name"],
            "command_template": prepared["command_template"], "args_template": control["args_template"],
            "context": prepared["context"], "bucket_path": prepared["bucket_path"],
            "sources_before": before, "sources_after": after, "source_changed": changed,
            "source_error": source_error, "elapsed_ms": captured["elapsed_ms"],
            "exit_code": captured["exit_code"], "timed_out": captured["timed_out"],
            "truncated": captured["truncated"], "stdout_bytes": captured["stdout_bytes"],
            "stderr_bytes": captured["stderr_bytes"], "stdout": stdout, "stderr": stderr,
            "bucket": bucket, "expected_bucket": control["expected_bucket"], "error": error,
            "success": success, "limits": list(_LIMITS)}


def _valid_run(record, control):
    if record.get("kind") != "target_run":
        raise ForgeError("Controls must cite target_run evidence")
    data = record["data"]
    if not isinstance(data, dict):
        raise ForgeError("Target run evidence must contain a complete run object")
    allowed = {"HIT", "FREE"} if control == "positive" else {"FAIL"}
    if (data.get("control") != control or not isinstance(data.get("bucket"), str) or data["bucket"] not in allowed
            or data.get("bucket") != data.get("expected_bucket") or data.get("success") is not True
            or type(data.get("exit_code")) is not int or data["exit_code"] != 0
            or data.get("timed_out") is not False or data.get("truncated") is not False
            or data.get("source_changed") is not False or data.get("error") is not None
            or data.get("source_error") is not None):
        raise ForgeError("Target controls must be successful, complete, unchanged positive and negative runs")
    facts = data.get("sources_before")
    if (not isinstance(facts, list) or not facts or facts != data.get("sources_after")
            or any(not isinstance(fact, dict) or set(fact) != {"path", "sha256", "size"}
                   or not isinstance(fact["path"], str) or not isinstance(fact["sha256"], str)
                   or not re.fullmatch(r"[a-f0-9]{64}", fact["sha256"])
                   or type(fact["size"]) is not int or fact["size"] < 0 for fact in facts)):
        raise ForgeError("Target controls must contain complete matching source hashes")
    command = data.get("command_template")
    if not isinstance(command, list) or not command or any(not isinstance(value, str) for value in command):
        raise ForgeError("Target controls must contain a command template")
    try:
        forge_network._path_parts(data.get("bucket_path"))
    except ForgeError:
        raise ForgeError("Target controls must contain a valid bucket selector") from None
    return data


def _verify_pair(store, positive, negative):
    if positive["id"] == negative["id"]:
        raise ForgeError("Target controls must cite distinct runs")
    left, right = _valid_run(positive, "positive"), _valid_run(negative, "negative")
    invocation = left.get("invocation_id")
    if not isinstance(invocation, str) or not re.fullmatch(r"run_[a-f0-9]{32}", invocation) or invocation != right.get("invocation_id"):
        raise ForgeError("Target controls must come from the same run-target invocation")
    for field in ("command_template", "context", "bucket_path", "sources_before", "sources_after"):
        if left.get(field) != right.get(field):
            raise ForgeError("Target controls differ in command, context, selector, or source hashes")
    context = left.get("context")
    if (not isinstance(context, dict) or set(context) != {"client", "egress"}
            or any(not isinstance(value, str) or not value.strip() for value in context.values())
            or forge_network._has_redacted(context) or forge_network._sanitize(context, set()) != context):
        raise ForgeError("Target controls require non-secret declared client and egress context")
    current = _hash_files(store, [fact["path"] for fact in left["sources_before"]])
    if current != left["sources_before"]:
        raise ForgeError("Current source files do not match the target runs")
    return store.add("target_verification", {
        "passed": True, "positive": positive["id"], "negative": negative["id"],
        "evidence": [positive["id"], negative["id"]], "invocation_id": invocation,
        "command_template": left["command_template"], "context": context,
        "bucket_path": left["bucket_path"], "sources": current, "limits": list(_LIMITS),
    })


def handle_run_target(args, store):
    prepared = _prepare(args, store)
    invocation = "run_" + uuid.uuid4().hex
    pending, reason = [], None
    for control in prepared["controls"]:
        try:
            before = _hash_files(store, prepared["paths"])
        except ForgeError:
            reason = "source_unavailable"
            break
        if before != prepared["initial"]:
            reason = "source_changed"
            break
        data = _run_control(args, store, prepared, control, invocation, before)
        pending.append(data)
        # Collect both streams before writing either run: later tagged echoes
        # can identify secrets that also appeared in the earlier control.
        gathered = [_gather_output(data[stream], prepared["output_secrets"], prepared["metadata_secrets"])
                    for stream in ("stdout", "stderr")]
        if not all(gathered):
            data["error"], data["success"] = "output_redaction_error", False
        if (data["bucket"] == "TERMINAL" and not data["truncated"] and not data["timed_out"]
                and data["error"] in (None, "reported_error")):
            reason = "TERMINAL"
            break
        if data["source_changed"]:
            reason = data["source_error"] or "source_changed"
            break
    records = []
    for data in pending:
        for stream in ("stdout", "stderr"):
            try:
                data[stream] = _safe_output(data[stream], prepared["output_secrets"], data["truncated"])
            except RecursionError:
                data[stream] = "[OUTPUT OMITTED: nesting exceeds redaction limit]"
                data["error"], data["success"] = "output_redaction_error", False
        for field in ("context", "bucket_path", "sources_before", "sources_after"):
            if field.startswith("sources_"):
                safe = [{**fact, "path": forge_network._sanitize(fact["path"], prepared["metadata_secrets"])}
                        for fact in data[field]]
            else:
                safe = forge_network._sanitize(data[field], prepared["metadata_secrets"])
            if safe != data[field]:
                data["error"], data["success"] = "metadata_redaction_error", False
            data[field] = safe
        # Fixed bucket/control labels are process facts, not credential echoes.
        data["redaction"] = {"applied": True, "raw_streams_stored": False, "resolved_argv_stored": False}
        records.append(store.add("target_run", data))
    verification = None
    if len(records) == 2 and all(record["data"]["success"] for record in records):
        by_control = {record["data"]["control"]: record for record in records}
        try:
            verification = _verify_pair(store, by_control["positive"], by_control["negative"])
        except ForgeError:
            reason = reason or "source_changed_before_verification"
    return {"invocation_id": invocation, "runs": records, "passed": verification is not None,
            "verification": verification, "stopped": reason is not None, "stop_reason": reason,
            "requested": 2, "completed": len(records), "limits": list(_LIMITS)}


def handle_verify_target(args, store):
    # IDs need not be reflected back in error messages if a user supplied a secret.
    try:
        positive, negative = store.get(args.positive), store.get(args.negative)
    except ForgeError:
        raise ForgeError("Unknown target control evidence ID") from None
    return _verify_pair(store, positive, negative)


def register(subparsers):
    run = subparsers.add_parser("run-target", help="Run two declared controls of trusted project code; not a sandbox")
    run.add_argument("spec", help="Explicit target JSON spec file")
    run.add_argument("--timeout", type=float, default=30, help="Wall-clock seconds per control, including pipe EOF (default: 30; maximum: 3600)")
    run.add_argument("--max-output", type=int, default=1048576, help="Combined retained stdout/stderr bytes per control (default: 1048576; maximum: 16777216)")
    run.set_defaults(handler=handle_run_target)
    verify = subparsers.add_parser("verify-target", help="Verify a same-invocation target control pair against current source files")
    verify.add_argument("--positive", required=True, help="Positive target_run evidence ID")
    verify.add_argument("--negative", required=True, help="Negative target_run evidence ID")
    verify.set_defaults(handler=handle_verify_target)
