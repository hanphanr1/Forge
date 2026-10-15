from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from forge_core import ForgeError, scrub_text
from forge_toolchain import TOOLS, executable, find_tool
import forge_tasks

_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
_MAX_PACKAGE_APKS = 128
_MAX_OBSERVE_PIDS = 16


def _input_path(store, value):
    path = Path(value).expanduser()
    return (path if path.is_absolute() else store.root / path).resolve()


def doctor(args, store):
    tools = {name: find_tool(name) for name in TOOLS}
    return {"python": sys.version.split()[0], "python_executable": sys.executable,
            "project": str(store.root), "tools": tools,
            "curl_cffi": {"available": importlib.util.find_spec("curl_cffi") is not None,
                          "setup": "python -m pip install curl_cffi"},
            "mode": "Agent-operated local CLI; no embedded LLM, no model key required"}


def _run(command, timeout):
    if not 0 < timeout <= 3600:
        raise ForgeError("Timeout must be greater than 0 and at most 3600 seconds")
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False)
        return result.returncode, result.stdout, result.stderr, False
    except subprocess.TimeoutExpired as error:
        return None, error.stdout or b"", error.stderr or b"", True
    except OSError as error:
        raise ForgeError(f"Cannot launch runtime tool: {error}") from error


def _devices(adb):
    code, stdout, stderr, expired = _run([adb, "devices", "-l"], 15)
    if code != 0 or expired:
        raise ForgeError("ADB device listing failed: " + scrub_text(stderr.decode("utf-8", "replace")))
    devices = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        fields = line.split()
        if len(fields) >= 2 and not line.startswith(("List of devices", "*")):
            devices.append({"serial": fields[0], "state": fields[1], "details": " ".join(fields[2:])})
    return devices


def _remote_path(value):
    if not value or "\x00" in value or len(value) > 4096:
        raise ForgeError("Provide an explicit absolute device path for --remote")
    if not value.startswith("/"):
        raise ForgeError("Device paths must be absolute, for example /data/local/tmp/sample.bin")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ForgeError("Device path must not contain '.' or '..' segments")
    return value


def _new_destination(store, value):
    if not value:
        raise ForgeError("Provide --path for the project-local destination")
    destination = _input_path(store, value)
    if not destination.is_relative_to(store.root.resolve()):
        raise ForgeError("Destination must stay inside the project")
    if destination.exists():
        raise ForgeError("Destination already exists; choose a new project-local path")
    parent = destination.parent
    for part in (*reversed(parent.parents), parent):
        if part.is_symlink():
            raise ForgeError(f"Symlinked destination directories are not allowed: {part}")
    if not parent.is_dir():
        raise ForgeError("Destination directory does not exist")
    return destination


def _new_directory(store, value):
    if not value:
        raise ForgeError("Provide --path for the project-local APK directory")
    destination = _input_path(store, value)
    if not destination.is_relative_to(store.root.resolve()):
        raise ForgeError("Directory must stay inside the project")
    if destination.exists():
        raise ForgeError("Directory already exists; choose a new project-local path")
    for part in (*reversed(destination.parent.parents), destination.parent):
        if part.is_symlink():
            raise ForgeError(f"Symlinked destination directories are not allowed: {part}")
    if not destination.parent.is_dir():
        raise ForgeError("Destination parent directory does not exist")
    return destination


def _package_processes(adb, serial, package, timeout):
    code, stdout, stderr, expired = _run(
        [adb, "-s", serial, "shell", "ps", "-A", "-o", "PID,NAME"], timeout)
    if code != 0 or expired:
        return [], {"returncode": code, "timed_out": expired,
                    "stderr": scrub_text(stderr.decode("utf-8", "replace"))}
    processes = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2 and fields[0].isdigit():
            name = fields[1].strip()
            if name == package or name.startswith(package + ":"):
                processes.append({"pid": int(fields[0]), "name": name})
    processes.sort(key=lambda item: (item["name"] != package, item["pid"]))
    omitted = max(0, len(processes) - _MAX_OBSERVE_PIDS)
    return processes[:_MAX_OBSERVE_PIDS], {"returncode": code, "timed_out": False, "stderr": "",
                                           "omitted": omitted}


def _filter_android_logcat(output, pids, start_epoch, end_epoch, max_bytes):
    selected = []
    omitted_lines = 0
    retained = 0
    for line in output.decode("utf-8", "replace").splitlines():
        match = re.match(r"\s*(\d+(?:\.\d+)?)\s+(\d+)\s+\d+\s+[VDIWEF]\s+", line)
        if not match or int(match.group(2)) not in pids:
            continue
        timestamp = float(match.group(1))
        if start_epoch is not None and timestamp < start_epoch - 1:
            continue
        if end_epoch is not None and timestamp > end_epoch + 1:
            continue
        clean = scrub_text(line)
        size = len(clean.encode("utf-8")) + 1
        if retained + size > max_bytes:
            omitted_lines += 1
            continue
        selected.append(clean)
        retained += size
    return selected, omitted_lines


def _existing_source(store, value):
    if not value:
        raise ForgeError("Provide --path to an existing project-local file")
    source = _input_path(store, value)
    if not source.is_relative_to(store.root.resolve()):
        raise ForgeError("Source must stay inside the project")
    if source.is_symlink() or not source.is_file():
        raise ForgeError("Source must be one regular project-local file")
    return source


def _relative(store, path):
    return path.relative_to(store.root.resolve()).as_posix()


def _package_facts(text):
    facts = {}
    for key, pattern in (
            ("version_name", r"\bversionName=(\S+)"),
            ("version_code", r"\bversionCode=(\d+)"),
            ("primary_cpu_abi", r"\bprimaryCpuAbi=(\S+)"),
            ("split_names", r"\bsplitNames=\[(.*?)\]")):
        match = re.search(pattern, text)
        facts[key] = ([part.strip() for part in match.group(1).split(",") if part.strip()]
                      if key == "split_names" and match else
                      match.group(1) if match else None)
    return facts


def _pull_installed_package(args, store, adb, serial):
    package = args.package
    if not package or not _PACKAGE_NAME.fullmatch(package):
        raise ForgeError("Provide a valid --package")
    if not 1 <= args.max_bytes <= 1024 * 1024 * 1024:
        raise ForgeError("--max-bytes must be between 1 and 1073741824 for a package pull")
    if not 1 <= args.max_output <= 16 * 1024 * 1024:
        raise ForgeError("--max-output must be between 1 and 16777216 bytes for package metadata")
    output_dir = _new_directory(store, args.path)
    path_result = _run([adb, "-s", serial, "shell", "pm", "path", package], args.timeout)
    detail_result = _run([adb, "-s", serial, "shell", "dumpsys", "package", package], args.timeout)
    if path_result[0] != 0 or path_result[3] or detail_result[0] != 0 or detail_result[3]:
        failure = store.add("runtime", {"tool": "adb", "action": "pull-package", "package": package,
                                        "serial": serial, "success": False, "code_paths": [],
                                        "timed_out": path_result[3] or detail_result[3],
                                        "stderr": scrub_text((path_result[2] + detail_result[2]).decode("utf-8", "replace")),
                                        "scope": "Read-only copy of the installed package; no install or app modification"})
        raise ForgeError(f"ADB could not inspect installed package; evidence {failure['id']}")
    remote_paths = []
    for line in path_result[1].decode("utf-8", "replace").splitlines():
        if line.startswith("package:"):
            remote_paths.append(_remote_path(line.split("package:", 1)[1].strip()))
    if not 1 <= len(remote_paths) <= _MAX_PACKAGE_APKS:
        failure = store.add("runtime", {"tool": "adb", "action": "pull-package", "package": package,
                                        "serial": serial, "success": False, "code_paths": remote_paths,
                                        "error": "Package manager returned no APK paths or too many splits",
                                        "scope": "Read-only copy of the installed package"})
        raise ForgeError(f"ADB returned no usable APK paths; evidence {failure['id']}")
    names = [remote.rsplit("/", 1)[-1] for remote in remote_paths]
    if any(not re.fullmatch(r"[A-Za-z0-9._-]+\.apk", name, re.IGNORECASE) for name in names):
        raise ForgeError("Package manager returned an unsafe APK filename")
    if len({name.casefold() for name in names}) != len(names):
        raise ForgeError("Package manager returned duplicate APK filenames")
    detail = detail_result[1][:args.max_output].decode("utf-8", "replace")
    package_facts = _package_facts(detail)
    staging = Path(tempfile.mkdtemp(prefix="forge-pull-package-", dir=store.directory))
    files, total = [], 0
    try:
        for remote, name in zip(remote_paths, names):
            local = staging / name
            code, stdout, stderr, expired = _run([adb, "-s", serial, "pull", remote, str(local)], args.timeout)
            if code != 0 or expired or not local.is_file():
                raise ForgeError(f"ADB pull failed for installed split {name}: "
                                 + scrub_text(stderr.decode("utf-8", "replace")))
            size = local.stat().st_size
            total += size
            if size <= 0 or total > args.max_bytes:
                raise ForgeError(f"Pulled package exceeds --max-bytes ({args.max_bytes}) or contains an empty APK")
            digest = hashlib.sha256()
            with local.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            manifest = None
            manifest_error = None
            try:
                import forge_android
                manifest = forge_android.inspect_apk(local)
            except (ForgeError, OSError) as error:
                manifest_error = str(error)
            if manifest is not None and manifest["package"] != package:
                raise ForgeError(f"Pulled split {name} declares package {manifest['package']}, expected {package}")
            files.append({"remote": remote, "filename": name, "sha256": digest.hexdigest(),
                          "size": size, "manifest": manifest, "manifest_error": manifest_error})
        if output_dir.exists():
            raise ForgeError("Output directory appeared during the pull; no files were published")
        shutil.move(str(staging), str(output_dir))
        staging = None
    except (ForgeError, OSError, shutil.Error, RuntimeError) as error:
        failure = store.add("runtime", {"tool": "adb", "action": "pull-package", "package": package,
                                        "serial": serial, "success": False, "code_paths": remote_paths,
                                        "files": files, "bytes_pulled": total, "error": str(error),
                                        "scope": "Read-only copy of the installed package; no install or app modification"})
        raise ForgeError(f"{error}; rejection evidence {failure['id']}") from error
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    for item in files:
        item["path"] = _relative(store, output_dir / item["filename"])
    return store.add("runtime", {"tool": "adb", "action": "pull-package", "package": package,
                                 "serial": serial, "success": True, "code_paths": remote_paths,
                                 "package_facts": package_facts, "files": files, "bytes_pulled": total,
                                 "output_dir": _relative(store, output_dir),
                                 "scope": "Read-only copy of the installed package; pulled bytes are locally hashed, "
                                          "not publisher-authenticated. Review before sharing."})


def _ui_tree_snapshot(adb, serial, timeout):
    remote = f"/data/local/tmp/forge-android-lab-{uuid.uuid4().hex}.xml"
    try:
        dump = _run([adb, "-s", serial, "shell", "uiautomator", "dump", remote], timeout)
        if dump[0] != 0 or dump[3] or b"ERROR" in dump[1] + dump[2]:
            return {"error": scrub_text((dump[1] + dump[2]).decode("utf-8", "replace"))[:1024]}
        content = _run([adb, "-s", serial, "exec-out", "cat", remote], timeout)
        if content[0] != 0 or content[3]:
            return {"error": scrub_text(content[2].decode("utf-8", "replace"))[:1024]}
        return {"xml": scrub_text(content[1].decode("utf-8", "replace"))}
    finally:
        _run([adb, "-s", serial, "shell", "rm", "-f", remote], min(timeout, 15))


def _android_logcat_observation(args, store, adb, serial):
    package = args.package
    if not package or not _PACKAGE_NAME.fullmatch(package):
        raise ForgeError("Provide a valid --package")
    if not 1 <= args.seconds <= 3600:
        raise ForgeError("--seconds must be between 1 and 3600")
    if not 1 <= args.lines <= 10000:
        raise ForgeError("--lines must be between 1 and 10000")
    if not 1024 <= args.max_output <= 4 * 1024 * 1024:
        raise ForgeError("--max-output must be between 1024 and 4194304 bytes")
    start_processes, start_ps = _package_processes(adb, serial, package, args.timeout)
    if not start_processes:
        detail = ("ADB could not list processes" if start_ps.get("returncode") != 0 or start_ps.get("timed_out")
                  else "Target app is not running; launch it, then start adb observe")
        failure = store.add("runtime", {"tool": "adb", "action": "observe", "package": package, "serial": serial,
                                        "success": False, "processes_before": [], "processes_after": [],
                                        "error": detail, "ps_call": start_ps})
        raise ForgeError(f"{detail}; evidence {failure['id']}")
    ui = {"before": _ui_tree_snapshot(adb, serial, args.timeout)} if args.ui_snapshots else None
    start_clock = _run([adb, "-s", serial, "shell", "date", "+%s"], args.timeout)
    start_epoch = None
    if start_clock[0] == 0 and not start_clock[3]:
        found = re.fullmatch(r"\s*(\d+)\s*", start_clock[1].decode("utf-8", "replace"))
        start_epoch = int(found.group(1)) if found else None
    started_at = time.time()
    time.sleep(args.seconds)
    duration = time.time() - started_at
    end_clock = _run([adb, "-s", serial, "shell", "date", "+%s"], args.timeout)
    end_epoch = None
    if end_clock[0] == 0 and not end_clock[3]:
        found = re.fullmatch(r"\s*(\d+)\s*", end_clock[1].decode("utf-8", "replace"))
        end_epoch = int(found.group(1)) if found else None
    end_processes, end_ps = _package_processes(adb, serial, package, args.timeout)
    processes = {item["pid"]: item for item in start_processes + end_processes}
    all_process_ids = list(processes)
    process_ids = all_process_ids[:_MAX_OBSERVE_PIDS]
    per_pid_lines = max(1, args.lines // max(1, len(process_ids)))
    log_lines, omitted, log_calls = [], 0, []
    retained_bytes = 0
    logcat_succeeded = False
    for pid in process_ids:
        result = _run([adb, "-s", serial, "logcat", "-d", "-v", "epoch", "--pid", str(pid),
                       "-t", str(per_pid_lines)], args.timeout)
        log_calls.append({"pid": pid, "returncode": result[0], "timed_out": result[3],
                          "stderr": scrub_text(result[2].decode("utf-8", "replace"))})
        if result[0] != 0 or result[3]:
            continue
        logcat_succeeded = True
        selected, omitted_lines = _filter_android_logcat(
            result[1], {pid}, start_epoch, end_epoch, max(0, args.max_output - retained_bytes))
        log_lines.extend(selected)
        retained_bytes += sum(len(line.encode("utf-8")) + 1 for line in selected)
        omitted += omitted_lines
    if len(log_lines) > args.lines:
        omitted += len(log_lines) - args.lines
        log_lines = sorted(log_lines, key=lambda line: float(line.split(None, 1)[0]))[-args.lines:]
    if ui is not None:
        ui["after"] = _ui_tree_snapshot(adb, serial, args.timeout)
    record = store.add("runtime", {"tool": "adb", "action": "observe", "package": package, "serial": serial,
                                  "success": logcat_succeeded, "duration_seconds": round(duration, 3),
                                  "device_epoch_start": start_epoch, "device_epoch_end": end_epoch,
                                  "time_window_filtered": start_epoch is not None and end_epoch is not None,
                                  "processes_before": start_processes, "processes_after": end_processes,
                                  "process_rows_omitted_before": start_ps.get("omitted", 0),
                                  "process_rows_omitted_after": end_ps.get("omitted", 0),
                                  "session_pids_omitted": max(0, len(all_process_ids) - len(process_ids)),
                                  "pid_list_calls": [start_ps, end_ps], "logcat_calls": log_calls,
                                  "logcat_lines": log_lines, "logcat_line_count": len(log_lines),
                                  "logcat_line_cap_per_pid": per_pid_lines,
                                  "logcat_omitted_lines": omitted, "ui_snapshots": ui,
                                  "scope": "Process-scoped logcat only; per-PID line caps can omit earlier rows and "
                                          "redaction is best-effort. UI snapshots are opt-in and may contain private "
                                          "screen text. This does not capture or decrypt HTTP traffic, bypass pinning, "
                                          "or modify the app."})
    if not logcat_succeeded:
        raise ForgeError(f"ADB logcat observation failed; evidence {record['id']}")
    return record


def adb_action(args, store):
    forge_tasks.check_scope(store, f"adb {args.action}", device=True)
    adb = executable("adb")
    devices = _devices(adb)
    if args.action == "devices":
        return store.add("runtime", {"tool": "adb", "action": "devices", "success": True, "returncode": 0,
                                     "timed_out": False, "serial": args.serial, "devices": devices,
                                     "stdout": "", "stderr": "", "blob": None})
    online = [device["serial"] for device in devices if device["state"] == "device"]
    serial = args.serial
    if serial is None:
        if len(online) != 1:
            raise ForgeError("Select --serial for one connected authorized Android device; use adb devices")
        serial = online[0]
    elif serial not in online:
        raise ForgeError(f"Device {serial} is absent, unauthorized or offline")

    if args.action == "pull-package":
        return _pull_installed_package(args, store, adb, serial)
    if args.action == "observe":
        return _android_logcat_observation(args, store, adb, serial)
    command = [adb, "-s", serial]
    blob = None
    remote, destination, digest, size = None, None, None, None
    if args.action == "install":
        if not args.path or not _input_path(store, args.path).is_file():
            raise ForgeError("adb install requires --path to an existing APK; APKS/XAPK require split-aware installation")
        command += ["install", "-r"]
        if getattr(args, "installer", None):
            command += ["-i", args.installer]
        command += [str(_input_path(store, args.path))]
    elif args.action in {"launch", "stop"}:
        if not args.package or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", args.package):
            raise ForgeError("Provide a valid --package")
        if args.action == "launch":
            if not args.component or not re.fullmatch(r"[A-Za-z0-9_.$/]+", args.component):
                raise ForgeError("adb launch requires --component PACKAGE/ACTIVITY from the manifest")
            command += ["shell", "am", "start", "-W", "-n", args.component]
        else:
            command += ["shell", "am", "force-stop", args.package]
    elif args.action == "logcat":
        if not 1 <= args.lines <= 10000:
            raise ForgeError("--lines must be between 1 and 10000")
        command += ["logcat", "-d", "-t", str(args.lines)]
    elif args.action == "screenshot":
        command += ["exec-out", "screencap", "-p"]
    elif args.action == "pull":
        remote = _remote_path(args.remote)
        destination = _new_destination(store, args.path)
        if not 1 <= args.max_bytes <= 512 * 1024 * 1024:
            raise ForgeError("--max-bytes must be between 1 and 536870912")
        with tempfile.TemporaryDirectory(prefix="forge-adb-pull-") as temporary:
            staging = Path(temporary) / "artifact"
            code, stdout, stderr, expired = _run(command + ["pull", remote, str(staging)], args.timeout)
            if code != 0 or expired:
                failure = store.add("runtime", {"tool": "adb", "action": "pull", "serial": serial, "remote": remote,
                                                "success": False, "returncode": code, "timed_out": expired,
                                                "stdout": stdout.decode("utf-8", "replace"),
                                                "stderr": scrub_text(stderr.decode("utf-8", "replace")), "blob": None})
                raise ForgeError(f"ADB pull failed; evidence {failure['id']}")
            if not staging.is_file():
                raise ForgeError("ADB pull did not produce one regular file; directories are not supported")
            size = staging.stat().st_size
            if size > args.max_bytes:
                raise ForgeError(f"Pulled content exceeds --max-bytes ({args.max_bytes})")
            digest = hashlib.sha256()
            try:
                with staging.open("rb") as source, destination.open("xb") as target:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                        target.write(block)
            except OSError:
                destination.unlink(missing_ok=True)
                raise
        digest, size = digest.hexdigest(), size
        return store.add("runtime", {"tool": "adb", "action": "pull", "serial": serial, "remote": remote,
                                     "path": _relative(store, destination), "sha256": digest, "size": size,
                                     "success": True, "returncode": 0, "timed_out": False, "blob": None,
                                     "stdout": "Pulled device file into the project; inspect it before sharing",
                                     "stderr": ""})
    elif args.action == "push":
        remote = _remote_path(args.remote)
        source = _existing_source(store, args.path)
        command += ["push", str(source), remote]
    elif args.action == "packages":
        selector = ["-3"] if args.third_party else (["-s"] if args.system else [])
        command += ["shell", "pm", "list", "packages", *selector]
    elif args.action == "package":
        if not args.package or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", args.package):
            raise ForgeError("Provide a valid --package")
        if not 1 <= args.max_output <= 16 * 1024 * 1024:
            raise ForgeError("--max-output must be between 1 and 16777216")
        paths_call = _run(command + ["shell", "pm", "path", args.package], args.timeout)
        detail_call = _run(command + ["shell", "dumpsys", "package", args.package], args.timeout)
        if paths_call[0] != 0 or detail_call[0] != 0 or paths_call[3] or detail_call[3]:
            failure = store.add("runtime", {"tool": "adb", "action": "package", "serial": serial,
                                            "package": args.package, "success": False,
                                            "stdout": (paths_call[1] + detail_call[1]).decode("utf-8", "replace"),
                                            "stderr": scrub_text((paths_call[2] + detail_call[2]).decode("utf-8", "replace")),
                                            "timed_out": paths_call[3] or detail_call[3], "blob": None})
            raise ForgeError(f"ADB package inspection failed; evidence {failure['id']}")
        detail = detail_call[1]
        truncated = len(detail) > args.max_output
        text = detail[:args.max_output].decode("utf-8", "replace")
        paths = [line.split("package:", 1)[1].strip()
                 for line in paths_call[1].decode("utf-8", "replace").splitlines() if line.startswith("package:")]
        facts = {"code_paths": paths, "truncated": truncated}
        for label, pattern in (("version_name", r"\bversionName=(\S+)"), ("version_code", r"\bversionCode=(\d+)"),
                               ("primary_cpu_abi", r"\bprimaryCpuAbi=(\S+)"),
                               ("split_names", r"\bsplitNames=\[(.*?)\]")):
            found = re.search(pattern, text)
            facts[label] = ([name.strip() for name in found.group(1).split(",") if name.strip()] if label == "split_names"
                            else found.group(1)) if found else None
        return store.add("runtime", {"tool": "adb", "action": "package", "serial": serial,
                                     "package": args.package, "success": True, "returncode": 0, "timed_out": False,
                                     "stdout": text, "stderr": "", "blob": None, "facts": facts})
    elif args.action == "ui-tree":
        remote = "/data/local/tmp/forge-ui.xml"
        _run(command + ["shell", "input", "keyevent", "KEYCODE_WAKEUP"], 15)
        for attempt in range(2):
            code, stdout, stderr, expired = _run(command + ["shell", "uiautomator", "dump", remote], args.timeout)
            if code == 0 and not expired and b"ERROR" not in stdout + stderr:
                break
            if attempt == 0:
                time.sleep(1.5)
        else:
            failure = store.add("runtime", {"tool": "adb", "action": "ui-tree", "serial": serial,
                                            "success": False, "stdout": stdout.decode("utf-8", "replace"),
                                            "stderr": scrub_text(stderr.decode("utf-8", "replace")),
                                            "timed_out": expired,
                                            "limitation": "uiautomator needs a quiescent foreground window; unlock the "
                                                          "screen or stop animations and retry"})
            raise ForgeError(f"UI hierarchy dump failed after retry; evidence {failure['id']}")
        command += ["exec-out", "cat", remote]
    code, stdout, stderr, expired = _run(command, args.timeout)
    success = code == 0 and not expired
    text = stdout.decode("utf-8", "replace")
    if args.action == "launch" and ("Error:" in text or "Exception" in text):
        success = False
    if args.action == "screenshot" and success:
        if not stdout.startswith(b"\x89PNG\r\n\x1a\n"):
            success = False
        else:
            blob = store.put_bytes(stdout)
            text = "PNG screenshot stored locally; may contain private on-screen content"
    if args.action == "packages" and success:
        names = [line.split("package:", 1)[1].strip() for line in text.splitlines() if line.startswith("package:")]
        if args.filter:
            wanted = args.filter.casefold()
            names = [name for name in names if wanted in name.casefold()]
        if len(names) > 5000:
            names = names[:5000]
            text = "Package list truncated to 5000 entries"
        else:
            text = "\n".join(names)
    record = store.add("runtime", {"tool": "adb", "action": args.action, "serial": serial,
                                   "package": args.package, "success": success, "returncode": code,
                                   "timed_out": expired, "stdout": text,
                                   "stderr": scrub_text(stderr.decode("utf-8", "replace")), "blob": blob,
                                   "remote": remote, "path": _relative(store, destination) if destination else None,
                                   "sha256": digest, "size": size,
                                   "declared_installer": getattr(args, "installer", None)})
    if not success:
        raise ForgeError(f"ADB {args.action} failed; see evidence {record['id']}")
    return record


_FRIDA_JAILED = re.compile(r"(?i)(need gadget|jailed android)")
_FRIDA_UNREACHABLE = re.compile(r"(?i)(unable to connect|failed to connect|connection closed|frida-server)")
_FRIDA_LAUNCH_REFUSED = re.compile(r"(?i)(not permitted|permission denied|denied|spawn.*failed|unable to spawn)")


def _frida_companion(launcher, name):
    candidate = Path(launcher).with_name(name + Path(launcher).suffix)
    return str(candidate) if candidate.is_file() else None


def frida_hook(args, store):
    forge_tasks.check_scope(store, "frida", device=True)
    path = _input_path(store, args.script)
    if not path.is_file():
        raise ForgeError("Frida hook script does not exist")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", args.package):
        raise ForgeError("Provide a valid --package, or the Gadget process name (for example Gadget) with --host")
    host = getattr(args, "host", None)
    forward_port = getattr(args, "forward", None)
    if host is not None and not re.fullmatch(r"[A-Za-z0-9.\-]+:[0-9]{1,5}", host):
        raise ForgeError("--host must be HOST:PORT, for example 127.0.0.1:27042")
    if forward_port is not None and host is None:
        raise ForgeError("--forward needs --host: a Gadget listener is reached through the forwarded port")
    if forward_port is not None and not 1 <= forward_port <= 65535:
        raise ForgeError("--forward must be a TCP port between 1 and 65535")
    if host is not None and not args.attach:
        raise ForgeError("--host attaches to a running Gadget, so it requires --attach; spawning needs a device-side "
                         "frida-server")
    launcher = executable("frida")
    device = args.device or "usb"
    transport = {"mode": "gadget-host" if host else "usb", "host": host, "forwarded_port": forward_port,
                 "forward": None}
    if host:
        transport["note"] = ("A Gadget host session has no device-side frida-server: the app carries the Gadget, and "
                             "this host attaches over the forwarded port")
    adb_tool = None
    if forward_port is not None:
        adb_tool = executable("adb")
        code, stdout, stderr, expired = _run([adb_tool, "forward", f"tcp:{forward_port}", f"tcp:{forward_port}"], 30)
        transport["forward"] = {"returncode": code, "timed_out": expired,
                                "stdout": stdout.decode("utf-8", "replace")[:512],
                                "stderr": scrub_text(stderr.decode("utf-8", "replace"))[:512]}
        if code != 0 or expired:
            failure = store.add("runtime", {"tool": "frida", "action": "frida-forward", "package": args.package,
                                            "device": device, "transport": transport, "success": False,
                                            "returncode": code, "timed_out": expired,
                                            "stdout": transport["forward"]["stdout"],
                                            "stderr": transport["forward"]["stderr"]})
            raise ForgeError(f"ADB port forward failed; evidence {failure['id']}")
    try:
        prerequisite = {"checked": False, "available": False, "listing": None}
        listing_tool = _frida_companion(launcher, "frida-ps")
        if listing_tool:
            if host:
                listing = [listing_tool, "-H", host]
                setup = ("Reach the Gadget port on this host first: install the repackaged build, then forward the "
                         "Gadget port with adb")
            else:
                listing = [listing_tool] + (["-D", args.device] if args.device else ["-U"])
                setup = ("Android also needs a reachable frida-server (root) or a repackaged Gadget build "
                         "(`apk-gadget` then `apk-sign`), attached through --host HOST:PORT --forward PORT --attach")
            code, stdout, stderr, expired = _run(listing, min(max(args.duration, 5) + 15, 60))
            prerequisite = {"checked": True, "available": code == 0 and not expired, "returncode": code,
                            "timed_out": expired, "listing": stdout.decode("utf-8", "replace")[:4096],
                            "stderr": scrub_text(stderr.decode("utf-8", "replace"))[:2048], "setup": setup}
            if not prerequisite["available"]:
                record = store.add("runtime", {"tool": "frida", "action": "frida-prerequisite", "package": args.package,
                                               "device": device, "transport": transport, "success": False,
                                               "returncode": code, "timed_out": expired,
                                               "stdout": prerequisite["listing"], "stderr": prerequisite["stderr"],
                                               "prerequisite": prerequisite})
                raise ForgeError("Frida prerequisite missing: no reachable hook transport. "
                                 f"Evidence {record['id']}")
        if host:
            command = [launcher, "-H", host, "-n", args.package, "-l", str(path), "-q", "-t", str(args.duration)]
        else:
            command = [launcher]
            command += ["-D", args.device] if args.device else ["-U"]
            command += ["-n" if args.attach else "-f", args.package, "-l", str(path), "-q", "-t", str(args.duration)]
        code, stdout, stderr, expired = _run(command, args.duration + 15)
        text_out = stderr.decode("utf-8", "replace")
        combined = text_out + stdout.decode("utf-8", "replace")
        success = code == 0 and not expired
        guidance = None
        if not success:
            if _FRIDA_JAILED.search(combined):
                guidance = ("jailed Android cannot be spawned: repackage the APK with `apk-gadget` and a matching "
                            "frida-gadget, sign it with `apk-sign`, or use a rooted device running frida-server")
            elif _FRIDA_UNREACHABLE.search(combined):
                guidance = ("no reachable hook transport: start a frida-server on a rooted target, or forward the "
                            "Gadget port and pass --host HOST:PORT --forward PORT")
            elif _FRIDA_LAUNCH_REFUSED.search(combined):
                guidance = "the target refused the session; check process name, debuggability and signature"
            if guidance:
                prerequisite["available"] = False
                prerequisite["reason"] = guidance
        record = store.add("runtime", {"tool": "frida", "action": "frida-hook", "package": args.package,
                                       "device": device, "attach": args.attach, "transport": transport,
                                       "script_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                       "success": success, "returncode": code, "timed_out": expired,
                                       "stdout": stdout.decode("utf-8", "replace"), "stderr": scrub_text(text_out),
                                       "prerequisite": prerequisite})
    finally:
        if forward_port is not None and adb_tool is not None:
            _run([adb_tool, "forward", "--remove", f"tcp:{forward_port}"], 15)
    if not success:
        if guidance:
            raise ForgeError(f"Frida session did not start: {guidance}; evidence {record['id']}")
        raise ForgeError(f"Frida session did not complete; inspect evidence {record['id']} (partial observations may exist)")
    return record


def native_inspect(args, store):
    if args.action in {"disasm", "xrefs", "callgraph", "decompile"}:
        import forge_native
        return forge_native.inspect(args, store)
    binary = _input_path(store, args.path)
    if not binary.is_file():
        raise ForgeError("Native artifact does not exist")
    commands = {"imports": "iij", "exports": "iEj", "strings": "izj", "functions": "aaa;aflj"}
    code, stdout, stderr, expired = _run([executable("r2"), "-q", "-c", commands[args.action], str(binary)], args.timeout)
    record = store.add("analysis", {"tool": "radare2", "action": args.action, "path": str(binary),
                                    "success": code == 0 and not expired, "returncode": code, "timed_out": expired,
                                    "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace")})
    if code != 0 or expired:
        raise ForgeError(f"radare2 analysis failed; see evidence {record['id']}")
    return record


def register(subparsers):
    parser = subparsers.add_parser("doctor", help="Report installed tools without downloading or changing host settings")
    parser.set_defaults(handler=doctor)
    parser = subparsers.add_parser("adb", help="Run device actions and save local runtime evidence")
    parser.add_argument("action", choices=["devices", "install", "launch", "stop", "logcat", "screenshot", "ui-tree",
                                           "pull", "push", "pull-package", "observe", "packages", "package"])
    parser.add_argument("--serial")
    parser.add_argument("--path")
    parser.add_argument("--package")
    parser.add_argument("--component")
    parser.add_argument("--remote", help="Absolute device path for pull/push")
    parser.add_argument("--filter", help="Case-insensitive package-name substring filter for packages")
    parser.add_argument("--installer", help="Declare the recorded install source with adb -i, for example "
                                            "com.android.vending")
    parser.add_argument("--third-party", action="store_true", help="Restrict packages to third-party apps")
    parser.add_argument("--system", action="store_true", help="Restrict packages to system apps")
    parser.add_argument("--lines", type=int, default=200)
    parser.add_argument("--seconds", type=int, default=60, help="Manual Android observation window in seconds")
    parser.add_argument("--ui-snapshots", action="store_true",
                        help="Capture before/after UI trees; the tree may contain private screen text")
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024,
                        help="Byte cap per pulled file or aggregate installed package")
    parser.add_argument("--max-output", type=int, default=4 * 1024 * 1024,
                        help="Retained byte cap for package details and observation logs")
    parser.add_argument("--timeout", type=float, default=60)
    parser.set_defaults(handler=adb_action)
    parser = subparsers.add_parser("frida", help="Run an explicit Java/native hook script on a configured device")
    parser.add_argument("--package", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--device")
    parser.add_argument("--attach", action="store_true")
    parser.add_argument("--host", help="Attach to a Gadget over HOST:PORT instead of USB, for example 127.0.0.1:27042")
    parser.add_argument("--forward", type=int, help="Forward this TCP port from the selected device before attaching")
    parser.add_argument("--duration", type=int, default=15)
    parser.set_defaults(handler=frida_hook)
    parser = subparsers.add_parser("native", help="Inspect native metadata, disassembly, xrefs or call graphs with radare2")
    parser.add_argument("action", choices=["imports", "exports", "strings", "functions", "disasm", "xrefs", "callgraph",
                                           "decompile"])
    parser.add_argument("path")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--address", help="Explicit unsigned decimal/hex address; no arbitrary radare2 commands")
    parser.add_argument("--max-output", type=int, default=1048576, help="Combined retained bytes for deep native analysis")
    parser.add_argument("--max-items", type=int, default=1000, help="Shared item cap for deep native analysis")
    parser.set_defaults(handler=native_inspect)
