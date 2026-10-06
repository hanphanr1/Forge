from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from forge_core import ForgeError, scrub_text
from forge_toolchain import TOOLS, executable, find_tool
import forge_tasks


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
    command = [adb, "-s", serial]
    blob = None
    remote, destination, digest, size = None, None, None, None
    if args.action == "install":
        if not args.path or not _input_path(store, args.path).is_file():
            raise ForgeError("adb install requires --path to an existing APK; APKS/XAPK require split-aware installation")
        command += ["install", "-r", str(_input_path(store, args.path))]
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
                                   "sha256": digest, "size": size})
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
        raise ForgeError("Provide a valid --package")
    launcher = executable("frida")
    device = args.device or "usb"
    prerequisite = {"checked": False, "available": False, "listing": None}
    listing_tool = _frida_companion(launcher, "frida-ps")
    if listing_tool:
        listing = [listing_tool] + (["-D", args.device] if args.device else ["-U"])
        code, stdout, stderr, expired = _run(listing, min(max(args.duration, 5) + 15, 60))
        prerequisite = {"checked": True, "available": code == 0 and not expired, "returncode": code,
                        "timed_out": expired, "listing": stdout.decode("utf-8", "replace")[:4096],
                        "stderr": scrub_text(stderr.decode("utf-8", "replace"))[:2048],
                        "setup": "Android also needs a reachable frida-server (root) or a repackaged Gadget build; a "
                                 "jailed device cannot be spawned without one"}
        if not prerequisite["available"]:
            record = store.add("runtime", {"tool": "frida", "action": "frida-prerequisite", "package": args.package,
                                           "device": device, "success": False, "returncode": code,
                                           "timed_out": expired, "stdout": prerequisite["listing"],
                                           "stderr": prerequisite["stderr"], "prerequisite": prerequisite})
            raise ForgeError("Frida device prerequisite missing: no reachable frida-server/Gadget on the target "
                             f"device. Evidence {record['id']}")
    command = [launcher]
    command += ["-D", args.device] if args.device else ["-U"]
    command += ["-n" if args.attach else "-f", args.package, "-l", str(path), "-q", "-t", str(args.duration)]
    code, stdout, stderr, expired = _run(command, args.duration + 15)
    text = stderr.decode("utf-8", "replace")
    combined = text + stdout.decode("utf-8", "replace")
    success = code == 0 and not expired
    guidance = None
    if not success:
        if _FRIDA_JAILED.search(combined):
            guidance = ("jailed Android cannot be spawned: repackage the APK with a matching frida-gadget, or use a "
                        "rooted device running frida-server")
        elif _FRIDA_UNREACHABLE.search(combined):
            guidance = "no reachable frida-server on the device; start one on a rooted target or use --device/--attach"
        elif _FRIDA_LAUNCH_REFUSED.search(combined):
            guidance = "the target refused the spawn; check package name, debuggability and signature"
        if guidance:
            prerequisite["available"] = False
            prerequisite["reason"] = guidance
    record = store.add("runtime", {"tool": "frida", "action": "frida-hook", "package": args.package, "device": device,
                                   "attach": args.attach, "script_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                   "success": success, "returncode": code, "timed_out": expired,
                                   "stdout": stdout.decode("utf-8", "replace"), "stderr": scrub_text(text),
                                   "prerequisite": prerequisite})
    if not success:
        if guidance:
            raise ForgeError(f"Frida session did not start: {guidance}; evidence {record['id']}")
        raise ForgeError(f"Frida session did not complete; inspect evidence {record['id']} (partial observations may exist)")
    return record


def native_inspect(args, store):
    if args.action in {"disasm", "xrefs", "callgraph"}:
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
                                           "pull", "push", "packages", "package"])
    parser.add_argument("--serial")
    parser.add_argument("--path")
    parser.add_argument("--package")
    parser.add_argument("--component")
    parser.add_argument("--remote", help="Absolute device path for pull/push")
    parser.add_argument("--filter", help="Case-insensitive package-name substring filter for packages")
    parser.add_argument("--third-party", action="store_true", help="Restrict packages to third-party apps")
    parser.add_argument("--system", action="store_true", help="Restrict packages to system apps")
    parser.add_argument("--lines", type=int, default=200)
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024, help="Byte cap for a pulled file")
    parser.add_argument("--max-output", type=int, default=4 * 1024 * 1024, help="Retained byte cap for package details")
    parser.add_argument("--timeout", type=float, default=60)
    parser.set_defaults(handler=adb_action)
    parser = subparsers.add_parser("frida", help="Run an explicit Java/native hook script on a configured device")
    parser.add_argument("--package", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--device")
    parser.add_argument("--attach", action="store_true")
    parser.add_argument("--duration", type=int, default=15)
    parser.set_defaults(handler=frida_hook)
    parser = subparsers.add_parser("native", help="Inspect native metadata, disassembly, xrefs or call graphs with radare2")
    parser.add_argument("action", choices=["imports", "exports", "strings", "functions", "disasm", "xrefs", "callgraph"])
    parser.add_argument("path")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--address", help="Explicit unsigned decimal/hex address; no arbitrary radare2 commands")
    parser.add_argument("--max-output", type=int, default=1048576, help="Combined retained bytes for deep native analysis")
    parser.add_argument("--max-items", type=int, default=1000, help="Shared item cap for deep native analysis")
    parser.set_defaults(handler=native_inspect)
