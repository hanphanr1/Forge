"""Bounded execution of explicitly declared, trusted project controls."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import subprocess
import threading
import time
import uuid

from forge_core import ForgeError, scrub_text
import forge_network
import forge_tasks


_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_BUCKETS = frozenset({"HIT", "FREE", "FAIL", "TERMINAL", "RETRY", "ERROR", "BADFORMAT", "CUSTOM", "RISK"})
_LIMITS = [
    "Executed code, bounded process outputs, and declared controls only; this is not a sandbox.",
    "The program reports its bucket; FORGE does not independently attest network/server or authentication behavior.",
    "Client and egress are non-secret declarations, not measured client identity, IP, or egress.",
    "Listed sources and the resolved executable are hashed; unlisted code, libraries, dependencies, and environment are not attested.",
    "Versions are observed only through an explicitly declared bounded version probe, not inferred from executable names.",
]
_MAX_OUTPUT = 16 * 1024 * 1024
_MAX_STDIN = 1024 * 1024
_MAX_SPEC = 4 * 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 10000
_SCHEMA = "forge.target-run/v2"


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


def _protect_path_variants(secrets, root):
    for value in tuple(secrets):
        try:
            path = Path(value)
            if not path.is_absolute() and "/" not in value and "\\" not in value and not path.suffix:
                continue
            path = path if path.is_absolute() else root / path
            if not path.exists():
                continue
            for variant in (os.path.normcase(value), os.path.normcase(str(path.absolute())),
                            os.path.normcase(str(path.resolve(strict=True)))):
                _protect(secrets, variant)
        except (OSError, ValueError, RuntimeError, UnicodeError):
            continue


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


def _argv(value, label, environment, output_secrets, metadata_secrets, *, nonempty, public_executable=False):
    if not isinstance(value, list) or (nonempty and not value):
        raise ForgeError(f"{label} must be {'a nonempty' if nonempty else 'an'} argv array")
    resolved = []
    sensitive_next = False
    for index, argument in enumerate(value):
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
                raise ForgeError("A referenced environment variable is not defined")
            secret = environment[name]
            if "\x00" in secret:
                raise ForgeError("A referenced environment value contains a NUL byte")
            try:
                _protect(output_secrets, secret)
                if not (public_executable and index == 0) or forge_network._SENSITIVE.search(name):
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

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("nonfinite number")
        return value

    return json.loads(text, object_pairs_hook=object_pairs, parse_constant=invalid_constant, parse_float=finite_float)


def _hash_files(store, paths):
    try:
        facts = [forge_tasks._file_fact(store, path, relative_only=True) for path in paths]
    except (ForgeError, OSError, RuntimeError, UnicodeError):
        raise ForgeError("Listed source files must be safe, readable, regular project files") from None
    if len({fact["path"] for fact in facts}) != len(facts):
        raise ForgeError("Source files must be distinct explicit project paths")
    return sorted(facts, key=lambda fact: fact["path"])


def _stdin_json(value, environment, output_secrets, metadata_secrets):
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if depth > _MAX_JSON_DEPTH or nodes > _MAX_JSON_NODES:
            raise ForgeError("stdin_json exceeds the depth or node limit")
        if isinstance(item, dict):
            resolved, template = {}, {}
            for key, child in item.items():
                if not isinstance(key, str) or "\x00" in key or "${" in key:
                    raise ForgeError("stdin_json keys must be literal strings without NUL or environment references")
                nodes += 1
                if nodes > _MAX_JSON_NODES:
                    raise ForgeError("stdin_json exceeds the node limit")
                resolved[key], template[key] = visit(child, depth + 1)
            return resolved, template
        if isinstance(item, list):
            pairs = [visit(child, depth + 1) for child in item]
            return [pair[0] for pair in pairs], [pair[1] for pair in pairs]
        if isinstance(item, str):
            result = _argv([item], "stdin_json strings", environment, output_secrets,
                           metadata_secrets, nonempty=False)[0]
            _protect(metadata_secrets, result)
            return result, _template(item)
        if item is None or type(item) in {bool, int, float}:
            if isinstance(item, float) and not math.isfinite(item):
                raise ForgeError("stdin_json numbers must be finite")
            scalar = json.dumps(item, allow_nan=False)
            _protect(output_secrets, scalar)
            return item, "[LITERAL REDACTED]"
        raise ForgeError("stdin_json must contain only JSON values")

    try:
        resolved, template = visit(value, 0)
        encoded = json.dumps(resolved, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (UnicodeError, ValueError, RecursionError):
        raise ForgeError("stdin_json cannot be safely encoded or redacted") from None
    if len(encoded) > _MAX_STDIN:
        raise ForgeError("stdin_json exceeds the 1048576 encoded-byte limit")
    return encoded, template


def _resolve_executable(executable, root, environment):
    try:
        if os.path.dirname(executable):
            path = Path(executable)
            path = path if path.is_absolute() else root / path
        else:
            entries = [Path(entry) if Path(entry).is_absolute() else root / entry
                       for entry in os.get_exec_path(environment)]
            if os.name == "nt":
                entries.insert(0, root)
                suffixes = [""] if Path(executable).suffix else environment.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
                path = next((directory / (executable + suffix) for directory in entries for suffix in suffixes
                             if (directory / (executable + suffix)).is_file()), None)
            else:
                found = shutil.which(executable, path=os.pathsep.join(map(str, entries)))
                path = Path(found) if found else None
        if path is None or path.suffix.casefold() in {".bat", ".cmd"}:
            raise ForgeError("Cannot resolve a supported real executable without an implicit batch shell")
        if not path.is_file() or (os.name != "nt" and not os.access(path, os.X_OK)):
            raise ForgeError("Command executable must resolve to a readable executable file")
        # Launch this absolute path, rather than letting Popen repeat a different PATH search.
        return os.path.normcase(str(path.absolute()))
    except (OSError, ValueError, UnicodeError):
        raise ForgeError("Cannot safely resolve the command executable") from None


def _runtime_fact(identity):
    try:
        path = Path(identity)
        if not path.is_absolute() or path.suffix.casefold() in {".bat", ".cmd"}:
            raise ValueError("invalid identity")
        resolved = os.path.normcase(str(path.resolve(strict=True)))
        path_before = path.stat()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("not regular")
            digest = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            # Windows fstat and path stat can expose different ctime semantics.
            # Compare change timestamps within each API, not across the two.
            current = path.stat()
            after = os.fstat(stream.fileno())
        changes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if (any(getattr(before, field) != getattr(after, field)
                or getattr(path_before, field) != getattr(current, field) for field in changes)
                or any(getattr(after, field) != getattr(current, field) for field in identity_fields)
                or resolved != os.path.normcase(str(path.resolve(strict=True)))):
            raise ValueError("changed while hashing")
        return {"identity": identity, "resolved_identity": resolved, "sha256": digest.hexdigest(), "size": after.st_size}
    except (OSError, ValueError, RuntimeError, UnicodeError):
        raise ForgeError("Resolved executable is unavailable or changed while hashing") from None


def _prepare(args, store):
    _options(args)
    path = Path(args.spec).expanduser()
    if not path.is_absolute():
        path = store.root / path
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_SPEC + 1)
        if len(raw) > _MAX_SPEC:
            raise ValueError("spec exceeds byte cap")
        spec = _strict_json(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        # Parser errors may quote credentials from the raw spec.
        raise ForgeError("Cannot read target spec as a complete JSON object") from None
    allowed = {"command", "files", "context", "bucket_path", "controls", "version_argv"}
    if not isinstance(spec, dict) or set(spec) - allowed or not {"command", "files", "context", "controls"} <= set(spec):
        raise ForgeError("Target spec requires command, files, context, controls and optional bucket_path/version_argv only")
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
    environment, output_secrets, metadata_secrets = dict(os.environ), set(), set()
    command = _argv(spec["command"], "command", environment, output_secrets, metadata_secrets,
                    nonempty=True, public_executable=True)
    if not command[0].strip():
        raise ForgeError("Command executable must be nonempty after environment resolution")
    if Path(command[0]).suffix.casefold() in {".bat", ".cmd"}:
        raise ForgeError("Batch-file executables are not supported; run a real executable without a shell")
    executable = _resolve_executable(command[0], store.root, environment)
    _protect(output_secrets, executable)
    command[0] = executable
    version_argv = None
    if "version_argv" in spec:
        version_argv = [executable] + _argv(spec["version_argv"], "version_argv", environment,
                                          output_secrets, metadata_secrets, nonempty=True)
    prepared = []
    for control in controls:
        if (not isinstance(control, dict) or set(control) - {"name", "args", "expected_bucket", "stdin_json"}
                or not {"name", "args", "expected_bucket"} <= set(control)):
            raise ForgeError("Each control requires name, args, expected_bucket and optional stdin_json only")
        name = control["name"]
        if not isinstance(name, str) or name not in {"positive", "negative"} or name in names:
            raise ForgeError("Control names must be unique positive and negative")
        names.add(name)
        expected = control["expected_bucket"]
        if not isinstance(expected, str) or expected not in ({"HIT", "FREE"} if name == "positive" else {"FAIL"}):
            raise ForgeError("Positive expects HIT or FREE; negative expects FAIL")
        arguments = _argv(control["args"], "control args", environment, output_secrets, metadata_secrets, nonempty=False)
        stdin, stdin_template = None, None
        if "stdin_json" in control:
            stdin, stdin_template = _stdin_json(control["stdin_json"], environment, output_secrets, metadata_secrets)
        prepared.append({"name": name, "argv": command + arguments, "expected_bucket": expected,
                         "args_template": [_template(item) for item in control["args"]],
                         "stdin": stdin, "stdin_template": stdin_template})
    facts = _hash_files(store, paths)
    public_arguments = {"positive", "negative", *_BUCKETS}
    for fact in facts:
        public_arguments.update({fact["path"], "./" + fact["path"], str(store.root / fact["path"])})
    for control in prepared:
        for argument in control["argv"][1:]:
            if argument not in public_arguments and not (argument.startswith("-") and "=" not in argument):
                _protect(metadata_secrets, argument)
    if version_argv:
        for argument in version_argv[1:]:
            if argument not in public_arguments and not (argument.startswith("-") and "=" not in argument):
                _protect(metadata_secrets, argument)
    # All controls contribute privacy inputs before validating public metadata.
    _protect_path_variants(metadata_secrets, store.root)
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
    runtime = _runtime_fact(executable)
    if any(scrub_text(runtime[field], secrets=tuple(metadata_secrets)) != runtime[field]
           for field in ("identity", "resolved_identity")):
        raise ForgeError("Executable identity must not contain credentials")
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
            "output_secrets": output_secrets, "metadata_secrets": metadata_secrets,
            "environment": environment, "runtime_initial": runtime, "executable": executable,
            "version_argv": version_argv,
            "version_template": [_template(item) for item in spec["version_argv"]] if version_argv else None}


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


def _capture(argv, root, timeout, max_output, *, stdin_bytes=None, env=None):
    if stdin_bytes is not None and (not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > _MAX_STDIN):
        raise ForgeError("Serialized stdin must be bytes bounded to 1048576 bytes")
    started = time.monotonic()
    result = {"exit_code": None, "timed_out": False, "truncated": False, "error": None,
              "stdout_bytes": 0, "stderr_bytes": 0}
    try:
        process = subprocess.Popen(argv, cwd=root, env=env,
                                   stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, bufsize=0,
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
    if stdin_bytes is not None:
        finished["stdin"] = threading.Event()

        def feed():
            try:
                view = memoryview(stdin_bytes)
                sent = 0
                while sent < len(view):
                    count = os.write(process.stdin.fileno(), view[sent:sent + 65536])
                    if count <= 0:
                        raise OSError("stdin write made no progress")
                    sent += count
            except OSError:
                with lock:
                    result["error"] = "pipe_write_error"
            finally:
                process.stdin.close()
                finished["stdin"].set()

        threads.append(threading.Thread(target=feed, daemon=True))
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
        if not isinstance(item, str) and json.dumps(item) in secrets:
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

def _version_probe(args, store, prepared):
    if prepared["version_argv"] is None:
        return None
    before = prepared["runtime_initial"]
    captured = _capture(prepared["version_argv"], store.root, min(args.timeout, 5), min(args.max_output, 4096),
                        env=prepared["environment"])
    try:
        after = _runtime_fact(prepared["executable"])
    except ForgeError:
        after = None
    for stream in ("stdout", "stderr"):
        _gather_output(captured[stream].decode("utf-8", errors="replace"),
                       prepared["output_secrets"], prepared["metadata_secrets"])
    try:
        stdout = captured["stdout"].decode("utf-8")
    except UnicodeError:
        stdout = "[OUTPUT OMITTED: invalid UTF-8]"
        captured["error"] = "invalid_version_utf8"
    return {"argv_template": prepared["version_template"], "stdout": stdout,
            "exit_code": captured["exit_code"], "timed_out": captured["timed_out"],
            "truncated": captured["truncated"], "error": captured["error"],
            "stdout_bytes": captured["stdout_bytes"], "stderr_bytes": captured["stderr_bytes"],
            "runtime_before": before, "runtime_after": after,
            "runtime_changed": after != before}



def _run_control(args, store, prepared, control, invocation, before, runtime_before):
    captured = _capture(control["argv"], store.root, args.timeout, args.max_output,
                        stdin_bytes=control["stdin"], env=prepared["environment"])
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
    try:
        runtime_after = _runtime_fact(prepared["executable"])
        runtime_error = None
    except ForgeError:
        runtime_after, runtime_error = None, "runtime_unavailable"
    runtime_changed = runtime_error is not None or runtime_before != runtime_after or runtime_before != prepared["runtime_initial"]
    if runtime_changed and error is None:
        error = runtime_error or "runtime_changed"
    version = prepared["version"]
    if (version is not None and (version["error"] is not None or version["exit_code"] != 0
                                or version["timed_out"] or version["truncated"]) and error is None):
        error = "version_probe_error"
    success = (captured["exit_code"] == 0 and not captured["timed_out"] and not captured["truncated"]
               and error is None and not changed and not runtime_changed and bucket == control["expected_bucket"])
    return {"schema": _SCHEMA, "invocation_id": invocation, "control": control["name"],
            "command_template": prepared["command_template"], "args_template": control["args_template"],
            "stdin_template": control["stdin_template"], "stdin_provided": control["stdin"] is not None,
            "runtime_before": runtime_before, "runtime_after": runtime_after,
            "runtime_changed": runtime_changed, "runtime_error": runtime_error, "version": version,
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
    if data.get("schema") != _SCHEMA:
        raise ForgeError("Target controls require v2 executable-fingerprinted evidence; rerun legacy controls")
    allowed = {"HIT", "FREE"} if control == "positive" else {"FAIL"}
    if (data.get("control") != control or not isinstance(data.get("bucket"), str) or data["bucket"] not in allowed
            or data.get("bucket") != data.get("expected_bucket") or data.get("success") is not True
            or type(data.get("exit_code")) is not int or data["exit_code"] != 0
            or data.get("timed_out") is not False or data.get("truncated") is not False
            or data.get("source_changed") is not False or data.get("error") is not None
            or data.get("source_error") is not None
            or data.get("runtime_changed") is not False or data.get("runtime_error") is not None):
        raise ForgeError("Target controls must be successful, complete, unchanged positive and negative runs")
    facts = data.get("sources_before")
    if (not isinstance(facts, list) or not facts or facts != data.get("sources_after")
            or any(not isinstance(fact, dict) or set(fact) != {"path", "sha256", "size"}
                   or not isinstance(fact["path"], str) or not isinstance(fact["sha256"], str)
                   or not re.fullmatch(r"[a-f0-9]{64}", fact["sha256"])
                   or type(fact["size"]) is not int or fact["size"] < 0 for fact in facts)):
        raise ForgeError("Target controls must contain complete matching source hashes")
    runtime = data.get("runtime_before")
    if (not isinstance(runtime, dict) or set(runtime) != {"identity", "resolved_identity", "sha256", "size"}
            or runtime != data.get("runtime_after")
            or any(not isinstance(runtime[field], str) or not Path(runtime[field]).is_absolute()
                   or forge_network._has_redacted(runtime[field]) for field in ("identity", "resolved_identity"))
            or not isinstance(runtime["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", runtime["sha256"])
            or type(runtime["size"]) is not int or runtime["size"] < 0):
        raise ForgeError("Target controls must contain complete matching executable fingerprints")
    version = data.get("version")
    if version is not None and (not isinstance(version, dict) or version.get("exit_code") != 0
                                or version.get("error") is not None or version.get("timed_out") is not False
                                or version.get("truncated") is not False or version.get("runtime_changed") is not False
                                or version.get("runtime_before") != runtime or version.get("runtime_after") != runtime):
        raise ForgeError("Target controls require a complete unchanged successful declared version probe")
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
    for field in ("command_template", "context", "bucket_path", "sources_before", "sources_after",
                  "runtime_before", "runtime_after", "version"):
        if left.get(field) != right.get(field):
            raise ForgeError("Target controls differ in command, context, selector, sources, or executable fingerprint")
    context = left.get("context")
    if (not isinstance(context, dict) or set(context) != {"client", "egress"}
            or any(not isinstance(value, str) or not value.strip() for value in context.values())
            or forge_network._has_redacted(context) or forge_network._sanitize(context, set()) != context):
        raise ForgeError("Target controls require non-secret declared client and egress context")
    current = _hash_files(store, [fact["path"] for fact in left["sources_before"]])
    if current != left["sources_before"]:
        raise ForgeError("Current source files do not match the target runs")
    runtime = _runtime_fact(left["runtime_before"]["identity"])
    if runtime != left["runtime_before"]:
        raise ForgeError("Current executable identity or bytes do not match the target runs")
    return store.add("target_verification", {
        "schema": "forge.target-verification/v2", "passed": True, "positive": positive["id"], "negative": negative["id"],
        "evidence": [positive["id"], negative["id"]], "invocation_id": invocation,
        "command_template": left["command_template"], "context": context,
        "bucket_path": left["bucket_path"], "sources": current, "limits": list(_LIMITS),
        "runtime": runtime, "version": left.get("version"),
    })


def handle_run_target(args, store):
    prepared = _prepare(args, store)
    invocation = "run_" + uuid.uuid4().hex
    pending, reason = [], None
    prepared["version"] = _version_probe(args, store, prepared)
    if prepared["version"] is not None and prepared["version"]["runtime_changed"]:
        reason = "runtime_changed_during_version_probe"
    for control in prepared["controls"]:
        if reason is not None:
            break
        try:
            before = _hash_files(store, prepared["paths"])
        except ForgeError:
            reason = "source_unavailable"
            break
        if before != prepared["initial"]:
            reason = "source_changed"
            break
        try:
            runtime_before = _runtime_fact(prepared["executable"])
        except ForgeError:
            reason = "runtime_unavailable"
            break
        if runtime_before != prepared["runtime_initial"]:
            reason = "runtime_changed"
            break
        data = _run_control(args, store, prepared, control, invocation, before, runtime_before)
        pending.append(data)
        # Collect both streams before writing either run: later tagged echoes
        # can identify secrets that also appeared in the earlier control.
        gathered = [_gather_output(data[stream], prepared["output_secrets"], prepared["metadata_secrets"])
                    for stream in ("stdout", "stderr")]
        if not all(gathered):
            data["error"], data["success"] = "output_redaction_error", False
        if data["bucket"] == "TERMINAL":
            reason = "TERMINAL"
            break
        if data["source_changed"]:
            reason = data["source_error"] or "source_changed"
            break
        if data["runtime_changed"]:
            reason = data["runtime_error"] or "runtime_changed"
            break
    records = []
    _protect_path_variants(prepared["metadata_secrets"], store.root)
    for secret in tuple(prepared["metadata_secrets"]):
        _protect(prepared["output_secrets"], secret)
    version = prepared["version"]
    if version is not None:
        try:
            version["stdout"] = _safe_output(version["stdout"], prepared["output_secrets"], version["truncated"])
        except RecursionError:
            version["stdout"], version["error"] = "[OUTPUT OMITTED: nesting exceeds redaction limit]", "output_redaction_error"
        for field in ("runtime_before", "runtime_after"):
            fact = version[field]
            if fact is not None:
                safe = {**fact, **{key: scrub_text(fact[key], secrets=tuple(prepared["metadata_secrets"]))
                                  for key in ("identity", "resolved_identity")}}
                if safe != fact:
                    version["error"] = "metadata_redaction_error"
                version[field] = safe
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
        for field in ("runtime_before", "runtime_after"):
            fact = data[field]
            if fact is not None:
                safe = {**fact, **{key: scrub_text(fact[key], secrets=tuple(prepared["metadata_secrets"]))
                                  for key in ("identity", "resolved_identity")}}
                if safe != fact:
                    data["error"], data["success"] = "metadata_redaction_error", False
                data[field] = safe
        if data["stdin_template"] is not None:
            def safe_template(item):
                if isinstance(item, dict):
                    return {scrub_text(key, secrets=tuple(prepared["metadata_secrets"])): safe_template(child)
                            for key, child in item.items()}
                if isinstance(item, list):
                    return [safe_template(child) for child in item]
                return item
            data["stdin_template"] = safe_template(data["stdin_template"])
        if version is not None and version["error"] is not None:
            data["error"], data["success"] = "version_probe_error", False
        # Fixed bucket/control labels are process facts, not credential echoes.
        data["redaction"] = {"applied": True, "raw_streams_stored": False, "resolved_argv_stored": False,
                             "raw_stdin_stored": False}
        records.append(store.add("target_run", data))
    verification = None
    if len(records) == 2 and all(record["data"]["success"] for record in records):
        by_control = {record["data"]["control"]: record for record in records}
        try:
            verification = _verify_pair(store, by_control["positive"], by_control["negative"])
        except ForgeError:
            reason = reason or "fingerprint_changed_before_verification"
    return {"invocation_id": invocation, "runs": records, "passed": verification is not None,
            "verification": verification, "stopped": reason is not None, "stop_reason": reason,
            "requested": 2, "completed": len(records), "version": version, "limits": list(_LIMITS)}


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
    verify = subparsers.add_parser("verify-target", help="Verify a same-invocation target pair against current sources and executable")
    verify.add_argument("--positive", required=True, help="Positive target_run evidence ID")
    verify.add_argument("--negative", required=True, help="Negative target_run evidence ID")
    verify.set_defaults(handler=handle_verify_target)
