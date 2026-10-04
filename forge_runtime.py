from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

from forge_core import ForgeError, scrub_text
from forge_toolchain import TOOLS, executable, find_tool


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


def adb_action(args, store):
    adb = executable("adb")
    devices = _devices(adb)
    if args.action == "devices":
        return {"devices": devices}
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
    elif args.action == "ui-tree":
        remote = "/data/local/tmp/forge-ui.xml"
        code, stdout, stderr, expired = _run(command + ["shell", "uiautomator", "dump", remote], args.timeout)
        if code != 0 or expired or b"ERROR" in stdout + stderr:
            failure = store.add("runtime", {"tool": "adb", "action": "ui-tree", "serial": serial,
                                          "success": False, "stdout": stdout.decode("utf-8", "replace"),
                                          "stderr": stderr.decode("utf-8", "replace"), "timed_out": expired})
            raise ForgeError(f"UI hierarchy dump failed; evidence {failure['id']}")
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
    record = store.add("runtime", {"tool": "adb", "action": args.action, "serial": serial,
                                   "package": args.package, "success": success, "returncode": code,
                                   "timed_out": expired, "stdout": text,
                                   "stderr": stderr.decode("utf-8", "replace"), "blob": blob})
    if not success:
        raise ForgeError(f"ADB {args.action} failed; see evidence {record['id']}")
    return record


def frida_hook(args, store):
    path = _input_path(store, args.script)
    if not path.is_file():
        raise ForgeError("Frida hook script does not exist")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", args.package):
        raise ForgeError("Provide a valid --package")
    command = [executable("frida")]
    command += ["-D", args.device] if args.device else ["-U"]
    command += ["-n" if args.attach else "-f", args.package, "-l", str(path), "-q", "-t", str(args.duration)]
    code, stdout, stderr, expired = _run(command, args.duration + 15)
    record = store.add("runtime", {"tool": "frida", "package": args.package, "device": args.device or "usb",
                                   "attach": args.attach, "script_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                   "success": code == 0 and not expired, "returncode": code, "timed_out": expired,
                                   "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace")})
    if code != 0 or expired:
        raise ForgeError(f"Frida session did not complete; inspect evidence {record['id']} (partial observations may exist)")
    return record


def native_inspect(args, store):
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
    parser.add_argument("action", choices=["devices", "install", "launch", "stop", "logcat", "screenshot", "ui-tree"])
    parser.add_argument("--serial")
    parser.add_argument("--path")
    parser.add_argument("--package")
    parser.add_argument("--component")
    parser.add_argument("--lines", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=60)
    parser.set_defaults(handler=adb_action)
    parser = subparsers.add_parser("frida", help="Run an explicit Java/native hook script on a configured device")
    parser.add_argument("--package", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--device")
    parser.add_argument("--attach", action="store_true")
    parser.add_argument("--duration", type=int, default=15)
    parser.set_defaults(handler=frida_hook)
    parser = subparsers.add_parser("native", help="Inspect native imports, exports, strings or functions with radare2")
    parser.add_argument("action", choices=["imports", "exports", "strings", "functions"])
    parser.add_argument("path")
    parser.add_argument("--timeout", type=float, default=120)
    parser.set_defaults(handler=native_inspect)
