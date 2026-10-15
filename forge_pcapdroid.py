"""Rootless PCAPdroid capture control over ADB: preflight facts and bounded, cited sessions.

The only capture path here is PCAPdroid's documented Intent API driven through the
configured ADB server. An accepted ``am start`` is a dispatch observation: it is not an
Activity result and not capture success. A capture is only reported successful when the
scoped CaptureService observation and the unique dump file were observed to start, the
stop was observed to take that service down, and a new private PCAP file was retrieved
and hashed. No root, emulator or app preference access is used.

Two opt-ins extend that path without changing its guarantees. ``--tls-decryption`` asks
PCAPdroid for its own decryption mode; FORGE installs no CA and decrypts nothing itself.
``--repeat`` runs several bounded windows in one session, each with its own dump file and
its own evidence record, plus one capture-session record over all of them.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

from forge_core import ForgeError, scrub_text
from forge_android import MAX_OUTPUT, _ok, select_device
import forge_tasks
from forge_toolchain import executable


SCHEMA = "forge.pcapdroid/v1"
TOOL = "pcapdroid"
CAPTURE_PACKAGE = "com.emanuelef.remote_capture"
CAPTURE_COMPONENT = "com.emanuelef.remote_capture/.activities.CaptureCtrl"
CAPTURE_SERVICE = "CaptureService"
DEVICE_DIRECTORY = "/sdcard/Download/PCAPdroid"
SNAPLEN = 2048
HEADER_BYTES = 24
MIN_FILE_BYTES = 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_SECONDS = 300
MAX_CONSENT_SECONDS = 120
MAX_TOOL_SECONDS = 120
MAX_REPEATS = 20
MAX_GAP_SECONDS = 60
PREFLIGHT_TIMEOUT = 15
POLL_SECONDS = 0.5
SETTLE_SECONDS = 5
MAX_SERVICE_RECORDS = 16
MAX_KEY_BYTES = 512
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
NANOSECOND_MAGIC = {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
SERIAL_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
CAPTURE_NAME = re.compile(r"forge-[a-f0-9]{32}\.pcap\Z")
DEVICE_PATH = re.compile(r"/sdcard/Download/PCAPdroid/forge-[a-f0-9]{32}\.pcap\Z")
WINDOW_FILE = re.compile(r"window-[0-9]{2}\.pcap\Z")
# The launch component is validated like forge_runtime's `adb launch --component`: one
# PACKAGE/ACTIVITY pair, no shell, whitespace or option characters.
LAUNCH_COMPONENT = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+/[A-Za-z0-9_.$]+\Z")
API_KEY_PLACEHOLDER = "<forge-api-key>"
ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
UNSAFE_FILE_NAME = re.compile(r'[<>:"|?*\x00-\x1f]')
SERVICE_RECORD = re.compile(r"ServiceRecord\{([^}]*)\}")
SERVICE_COMPONENT = re.compile(r"([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)")
SERVICE_ERROR = re.compile(r"(?im)^\s*Error\b")
AM_ERROR = re.compile(r"(?im)^\s*(?:Error|Failure)\b|^\s*Exception\b|Permission Denial|"
                      r"unable to resolve|does not exist|not found")
AM_WARNING = re.compile(r"(?m)^\s*Warning:.*$")
DIGITS = re.compile(r"[0-9]+\Z")
VERSION_NAME = re.compile(r"\bversionName=(\S+)")
VERSION_CODE = re.compile(r"\bversionCode=([0-9]+)")
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
_EMPTY_SERVICE_OUTPUT = "(nothing)"

_DECRYPTION_SCOPE = ("TLS decryption is requested through PCAPdroid's own setting only: FORGE installs no CA, adds no "
                     "trust anchor and edits no app preference. Decryption needs the PCAPdroid CA installed by the "
                     "operator and trusted by the target app, and certificate pinning, QUIC-only paths, non-HTTP "
                     "protocols or an app that ignores user CAs commonly stay undecrypted, so a requested decryption "
                     "is never evidence that a given flow was decrypted.")
_DECRYPTION_LIMIT = ("--tls-decryption is a request, not decryption: without the operator-installed PCAPdroid CA, "
                     "without app trust or with certificate pinning the captured flows stay encrypted")
_SCOPE = ("Rootless PCAPdroid capture control through its documented Intent API only. Recorded evidence covers ADB "
          "dispatch, scoped CaptureService observations and the unique dump file; consent prompts, VPN approval, "
          "packet contents, app-filter correctness and any Activity result extras are not proven here. The retrieved "
          "raw PCAP stays local and may hold secrets.")
_LIMITS = [
    "An accepted ADB `am start` is a dispatch observation, not capture success and not an Activity result",
    "Running/stopped state comes from scoped `dumpsys activity services` observations only; no get_status extras are claimed",
    "Unique dump names bind file observations to the requested session; concurrent external capture replacement is not independently attested",
    "PCAPdroid creates the dump file before it writes packet data: a created file with 0 bytes is start evidence, never traffic, and the PCAP header is validated on the finalized retrieved file",
    "The device max_dump_size may overshoot by the last packet and packet extensions; the host retrieval cap is authoritative",
    "Packet-level hosts, flows and app-filter correctness stay analysis-time claims; dump UID/package metadata is not independent attestation",
    "Raw PCAP bytes are never printed, exported or summarised by this command",
]


def _limits(options):
    return _LIMITS + ([_DECRYPTION_LIMIT] if options["tls_decryption"] else [])


def _run(command, timeout, binary=False):
    """Run one bounded local command without a shell.

    Mirrors forge_android._run, except that stdout can be retained as raw bytes: the
    device PCAP header check must not decode binary header bytes as text.
    """
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=timeout, check=False)
            code, expired, launch_error = result.returncode, False, None
        except subprocess.TimeoutExpired:
            code, expired, launch_error = None, True, None
        except OSError as error:
            code, expired, launch_error = None, False, str(error)
        output = {"returncode": code, "timed_out": expired, "launch_error": launch_error}
        for name, stream in (("stdout", stdout), ("stderr", stderr)):
            size = stream.tell()
            stream.seek(0)
            data = stream.read(MAX_OUTPUT)
            output[name] = data if name == "stdout" and binary else data.decode("utf-8", "replace")
            output[name + "_omitted_bytes"] = max(0, size - len(data))
        return output


def _text(value):
    return value if isinstance(value, str) else ""


def _complete(call):
    return _ok(call) and not call["stdout_omitted_bytes"] and not call["stderr_omitted_bytes"]


def _bounded_call(call, limit=8192):
    """Retain a bounded invocation preview; parsing always happens before this trim."""
    stored = dict(call)
    for name in ("stdout", "stderr"):
        text = _text(stored.get(name))
        if len(text) > limit:
            stored[name] = text[:limit]
            stored[name + "_preview_truncated"] = True
    return stored


# --------------------------------------------------------------------------- facts

def _devices(adb):
    listing = _run([adb, "devices", "-l"], PREFLIGHT_TIMEOUT)
    devices = []
    if _ok(listing) and not listing["stdout_omitted_bytes"]:
        for line in listing["stdout"].splitlines():
            fields = line.split()
            if len(fields) >= 2 and not line.startswith(("List of devices", "*")):
                devices.append({"serial": fields[0], "state": fields[1], "details": " ".join(fields[2:])})
    return listing, devices


def _package_facts(adb, serial, package, timeout=PREFLIGHT_TIMEOUT):
    path_call = _run([adb, "-s", serial, "shell", "pm", "path", package], timeout)
    detail_call = _run([adb, "-s", serial, "shell", "dumpsys", "package", package], timeout)
    uid_call = _run([adb, "-s", serial, "shell", "pm", "list", "packages", "-U", "--user", "current", package], timeout)
    # The scoped `dumpsys package` detail is the authority for installed-ness: `pm path`
    # exit codes vary between Android versions for an absent package.
    observed = _complete(detail_call)
    paths = [line.split("package:", 1)[1].strip() for line in _text(path_call["stdout"]).splitlines()
             if line.startswith("package:")]
    detail = _text(detail_call["stdout"])
    uid = re.search(rf"(?m)^package:{re.escape(package)}\s+uid:([0-9]+)\s*$", _text(uid_call["stdout"])) \
        if _complete(uid_call) else None
    version_name, version_code = VERSION_NAME.search(detail), VERSION_CODE.search(detail)
    return {"package": package, "observed": observed, "path_observed": _complete(path_call),
            "installed": bool(paths) or bool(uid),
            "code_paths": paths[:8], "paths_omitted": max(0, len(paths) - 8),
            "uid": int(uid.group(1)) if uid else None,
            "version_name": version_name.group(1) if version_name else None,
            "version_code": int(version_code.group(1)) if version_code else None,
            "calls": {"package_path": _bounded_call(path_call), "package_detail": _bounded_call(detail_call),
                      "package_uid": _bounded_call(uid_call)}}


def _service_state(call):
    """Classify one scoped service listing without inventing an Activity result."""
    text = _text(call["stdout"])
    records = []
    for match in SERVICE_RECORD.finditer(text):
        component = SERVICE_COMPONENT.search(match.group(1))
        records.append({"package": component.group(1) if component else None,
                        "service": component.group(2) if component else None})
        if len(records) >= MAX_SERVICE_RECORDS:
            break
    state = {"known": False, "running": None, "records": records, "unrelated_services": [],
             "records_omitted": max(0, len(SERVICE_RECORD.findall(text)) - len(records)),
             "reason": None}
    if not _complete(call):
        state["reason"] = "Scoped service state was not observed completely"
        return state
    if records:
        state["known"] = True
        state["running"] = any(record["service"] and CAPTURE_SERVICE in record["service"] for record in records)
        state["unrelated_services"] = [record["service"] for record in records if record["service"]
                                       and CAPTURE_SERVICE not in record["service"]]
        return state
    if SERVICE_ERROR.search(text):
        state["reason"] = "Scoped service listing reported an error"
        return state
    if _EMPTY_SERVICE_OUTPUT in text.casefold() or not text.strip():
        state["known"] = True
        state["running"] = False
        return state
    state["reason"] = "Scoped service listing returned no parseable service record"
    return state


def _service_call(adb, serial, timeout):
    return _service_state(_run([adb, "-s", serial, "shell", "dumpsys", "activity", "services", CAPTURE_PACKAGE],
                               timeout))


def _device_file(adb, serial, remote, timeout):
    """Observe the generated dump file only: size, then the first PCAP header bytes."""
    size_call = _run([adb, "-s", serial, "shell", "stat", "-c", "%s", remote], timeout)
    size = None
    if _complete(size_call) and DIGITS.fullmatch(size_call["stdout"].strip()):
        size = int(size_call["stdout"].strip())
    if size is None:
        listing = _run([adb, "-s", serial, "shell", "ls", "-ln", remote], timeout)
        fields = _text(listing["stdout"]).split()
        if _complete(listing) and len(fields) >= 5 and fields[0].startswith("-") and DIGITS.fullmatch(fields[4]):
            size = int(fields[4])
    if size is None:
        if size_call["timed_out"] or size_call["launch_error"] or size_call["stdout_omitted_bytes"]:
            return {"known": False, "exists": None, "size": None, "header_valid": False, "magic": None,
                    "reason": "Device dump file state was not observed completely"}
        return {"known": True, "exists": False, "size": None, "header_valid": False, "magic": None, "reason": None}
    header_call = _run([adb, "-s", serial, "exec-out", "head", "-c", str(HEADER_BYTES), remote], timeout, binary=True)
    if not _ok(header_call):
        header_call = _run([adb, "-s", serial, "exec-out", "toybox", "head", "-c", str(HEADER_BYTES), remote],
                           timeout, binary=True)
    data = header_call["stdout"] if isinstance(header_call["stdout"], bytes) else b""
    return {"known": True, "exists": True, "size": size, "header_valid": len(data) >= HEADER_BYTES and data[:4] in PCAP_MAGIC,
            "magic": data[:4].hex() if len(data) >= 4 else None,
            "reason": None if len(data) >= HEADER_BYTES else "Device dump file header was not observed completely"}


def _preflight(serial=None, package=None):
    result = {"schema": SCHEMA, "tool": TOOL, "action": "preflight", "success": False, "status": "missing-tool",
              "requested_serial": serial, "requested_package": package, "devices": [], "device": None,
              "capture_package": None, "target_package": None, "service": None, "capture_running": None,
              "scope": "Observed ADB, installed-package and scoped CaptureService facts only; no root, consent, "
                       "permission or capture-control claim"}
    try:
        adb = executable("adb")
    except ForgeError as error:
        result["precondition"] = str(error)
        return result
    result["adb_path"] = adb
    version = _run([adb, "version"], PREFLIGHT_TIMEOUT)
    listing, devices = _devices(adb)
    result["calls"] = {"tool_version": _bounded_call(version), "device_listing": _bounded_call(listing)}
    result["devices"] = devices
    if not _ok(version) or not _ok(listing) or listing["stdout_omitted_bytes"]:
        result["status"] = "adb-failed"
        result["precondition"] = "Configured ADB must report its version and a complete device listing"
        return result
    status, device = select_device(devices, serial)
    result["device"] = device
    if status != "authorized":
        result["status"] = status
        result["precondition"] = ("Connect and authorize an owned Android device; select --serial when selection is "
                                  "ambiguous")
        return result
    adb_serial = device["serial"]
    capture_package = _package_facts(adb, adb_serial, CAPTURE_PACKAGE)
    result["capture_package"] = capture_package
    if not capture_package["observed"]:
        result["status"] = "capture-app-unknown"
        result["precondition"] = "Installed PCAPdroid facts must be observed completely; no root or preference access is used"
        return result
    if not capture_package["installed"]:
        result["status"] = "capture-app-absent"
        result["precondition"] = "Install PCAPdroid from its official distribution; this command never adds a companion APK"
        return result
    service = _service_call(adb, adb_serial, PREFLIGHT_TIMEOUT)
    result["service"] = service
    if not service["known"]:
        result["status"] = "service-unknown"
        result["precondition"] = ("The scoped CaptureService state must be observed completely before a bounded capture "
                                  "can be refused or started")
        return result
    result["capture_running"] = service["running"]
    if package is not None:
        target_package = _package_facts(adb, adb_serial, package)
        result["target_package"] = target_package
        if not target_package["observed"]:
            result["status"] = "target-app-unknown"
            result["precondition"] = f"Installed facts for {package} must be observed completely"
            return result
        if not target_package["installed"]:
            result["status"] = "target-app-absent"
            result["precondition"] = f"{package} is not installed on the selected device"
            return result
    result["success"] = True
    if service["running"]:
        result["status"] = "capture-active"
        result["precondition"] = ("An existing capture is already running; stop it on the device before starting a new "
                                  "bounded session")
    else:
        result["status"] = "ready"
    return result


# --------------------------------------------------------------------------- capture

def _target_uid(facts):
    target = facts.get("target_package") or {}
    return target.get("uid") if isinstance(target.get("uid"), int) else None


def _serial_value(value, label):
    if value is None:
        return None
    if not isinstance(value, str) or not SERIAL_VALUE.fullmatch(value):
        raise ForgeError(f"{label} must be an ADB serial without spaces, options or path characters")
    return value


def _launch_value(value):
    if value is None:
        return None
    if not isinstance(value, str) or not LAUNCH_COMPONENT.fullmatch(value):
        raise ForgeError("--launch must name a PACKAGE/COMPONENT from the manifest, for example ai.x.grok/.MainActivity")
    return value


def _capture_options(args):
    bounds = (("seconds", 1, MAX_SECONDS, "seconds"), ("consent_timeout", 1, MAX_CONSENT_SECONDS, "consent-timeout"),
              ("timeout", 1, MAX_TOOL_SECONDS, "timeout"))
    for name, low, high, label in bounds:
        value = getattr(args, name, None)
        if type(value) is not int or not low <= value <= high:
            raise ForgeError(f"--{label} must be an integer between {low} and {high}")
    if type(getattr(args, "max_bytes", None)) is not int or not MIN_FILE_BYTES <= args.max_bytes <= MAX_FILE_BYTES:
        raise ForgeError(f"--max-bytes must be an integer between {MIN_FILE_BYTES} and {MAX_FILE_BYTES}")
    repeat = getattr(args, "repeat", 1)
    if type(repeat) is not int or not 1 <= repeat <= MAX_REPEATS:
        raise ForgeError(f"--repeat must be an integer between 1 and {MAX_REPEATS}")
    gap = getattr(args, "gap", 0)
    if type(gap) not in (int, float) or not 0 <= gap <= MAX_GAP_SECONDS:
        raise ForgeError(f"--gap must be a number of seconds between 0 and {MAX_GAP_SECONDS}")
    for name, label in (("force_stop", "--force-stop"), ("tls_decryption", "--tls-decryption")):
        if type(getattr(args, name, False)) is not bool:
            raise ForgeError(f"{label} is a flag and takes no value")
    package = getattr(args, "package", None)
    if not isinstance(package, str) or not PACKAGE_NAME.fullmatch(package):
        raise ForgeError("Provide a valid --package name, for example ai.x.grok")
    return {"seconds": args.seconds, "consent_timeout": args.consent_timeout, "timeout": args.timeout,
            "max_bytes": args.max_bytes, "package": package, "repeat": repeat, "gap": gap,
            "launch": _launch_value(getattr(args, "launch", None)), "force_stop": getattr(args, "force_stop", False),
            "tls_decryption": getattr(args, "tls_decryption", False),
            "serial": _serial_value(getattr(args, "serial", None), "--serial")}


def _api_key(environment):
    """Read the optional API key from the environment; the key itself is never persisted."""
    if environment is None:
        return None, None
    if not isinstance(environment, str) or not ENVIRONMENT_NAME.fullmatch(environment):
        raise ForgeError("--api-key-env must name an environment variable such as PCAPDROID_API_KEY")
    key = os.environ.get(environment)
    if key is None or not key.strip():
        raise ForgeError(f"Environment variable {environment} does not provide a PCAPdroid API key")
    if "\x00" in key or len(key.encode("utf-8", "replace")) > MAX_KEY_BYTES:
        raise ForgeError(f"Environment variable {environment} does not hold a plausible PCAPdroid API key")
    return key, environment


def _local_path(value, prompt):
    """Reject device, UNC, alternate-stream and traversing --path values; return the relative path."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ForgeError(prompt)
    text = value.strip()
    if text.startswith("\\\\") or (":" in text and not re.match(r"^[A-Za-z]:[\\/]", text)):
        raise ForgeError("Use a local filesystem path, not a device, UNC or alternate-stream path")
    relative = Path(text)
    if ".." in relative.parts:
        raise ForgeError("Path traversal is not allowed in --path")
    return relative


def _in_project(store, path):
    destination = path if path.is_absolute() else store.root / path
    destination = Path(os.path.abspath(destination))
    if not destination.is_relative_to(store.root.resolve()):
        raise ForgeError("Capture destination must remain inside the project")
    return destination


def _reject_symlink_chain(directory):
    for part in (*reversed(directory.parents), directory):
        try:
            info = part.lstat()
        except OSError as error:
            raise ForgeError(f"Destination directory is not usable: {part}") from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE_POINT:
            raise ForgeError(f"Symlink/reparse destination paths are not allowed: {part}")


def _new_destination(store, value):
    relative = _local_path(value, "Provide a new --path for the retrieved PCAP file")
    if relative.suffix.lower() != ".pcap":
        raise ForgeError("--path must name a new .pcap file")
    if UNSAFE_FILE_NAME.search(relative.name):
        raise ForgeError("--path must name a plain file name")
    destination = _in_project(store, relative)
    if destination.exists() or destination.is_symlink():
        raise ForgeError("Destination already exists; choose a new --path")
    parent = destination.parent
    if not parent.is_dir():
        raise ForgeError("Destination directory does not exist")
    _reject_symlink_chain(parent)
    return destination


def _session_directory(store, value):
    """Existing project directory holding one new window-NN.pcap per window."""
    relative = _local_path(value, "Provide an existing project directory --path when --repeat is greater than 1")
    directory = _in_project(store, relative)
    if not directory.is_dir():
        raise ForgeError("--path must be an existing project directory when --repeat is greater than 1")
    _reject_symlink_chain(directory)
    return directory


def _window_destination(directory, index):
    name = f"window-{index:02d}.pcap"
    if not WINDOW_FILE.fullmatch(name):
        raise ForgeError("Window capture files must stay window-NN.pcap")
    destination = directory / name
    if destination.exists() or destination.is_symlink():
        raise ForgeError(f"Window destination {name} already exists; each capture window requires a new file")
    return destination


def _destinations(store, value, repeat):
    """Every destination is validated before any device call."""
    if repeat > 1:
        directory = _session_directory(store, value)
        return [_window_destination(directory, index) for index in range(1, repeat + 1)]
    return [_new_destination(store, value)]


def _settings(name, options, environment):
    settings = {"root_capture": False, "tls_decryption": False, "socks5_enabled": False, "pcapng_format": False,
                "block_quic": "never", "auto_block_private_dns": False, "dump_extensions": True, "ip_mode": "both",
                "pcap_dump_mode": "pcap_file", "app_filter": options["package"], "pcap_name": name,
                "full_payload": True, "snaplen": SNAPLEN, "max_dump_size": options["max_bytes"],
                "api_env_variable": environment, "key_supplied": environment is not None}
    if options["tls_decryption"]:
        settings["tls_decryption"] = True
        settings["block_quic"] = "to_decrypt"
        settings["decryption_rules"] = json.dumps([{"type": "APP", "value": options["package"]}],
                                                  separators=(",", ":"))
    return settings


def _capture_name():
    """Unique dump name, validated so the remote shell never sees a metacharacter."""
    name = "forge-" + uuid.uuid4().hex + ".pcap"
    if not CAPTURE_NAME.fullmatch(name) or not DEVICE_PATH.fullmatch(DEVICE_DIRECTORY + "/" + name):
        raise ForgeError("Generated capture name is not safe for the device shell")
    return name


def _intent_command(adb, serial, action, key=None, extras=(), component=CAPTURE_COMPONENT):
    """Build the documented CaptureCtrl command with a key placeholder, never the raw key."""
    command = [adb, "-s", serial, "shell", "am", "start", "-e", "action", action]
    if key is not None:
        command += ["-e", "api_key", API_KEY_PLACEHOLDER]
    for extra, value in extras:
        command += ["-e", extra, value]
    return command + ["-n", component]


def _dispatch_command(command, key):
    """Substitute the POSIX-quoted key exactly where the placeholder sits.

    ``adb shell`` re-joins the arguments into one remote shell line, so an arbitrary key
    must arrive quoted. Keeping a placeholder in the template means no retained argv,
    error message or evidence record ever has to scrub a key whose quoted spelling
    differs from the key itself.
    """
    if key is None:
        return list(command)
    quoted = shlex.quote(key)
    return [quoted if item == API_KEY_PLACEHOLDER else item for item in command]


def _start_command(adb, serial, options, name, key):
    settings = _settings(name, options, None)
    names = ["pcap_dump_mode", "pcap_name", "app_filter", "root_capture", "tls_decryption", "socks5_enabled",
             "pcapng_format", "block_quic", "auto_block_private_dns", "dump_extensions", "ip_mode", "full_payload",
             "snaplen", "max_dump_size"]
    extras = [(extra, str(settings[extra]).lower() if isinstance(settings[extra], bool) else str(settings[extra]))
              for extra in names]
    if settings.get("decryption_rules"):
        # `adb shell` re-joins argv into one remote shell line, so the JSON value needs the
        # quoting the device shell strips again; unquoted JSON arrives stripped of its quotes.
        extras.append(("decryption_rules", shlex.quote(settings["decryption_rules"])))
    return _intent_command(adb, serial, "start", key, extras)


def _dispatch(call, secrets=()):
    """Classify one intent dispatch. Acceptance is never capture success."""
    stdout = scrub_text(_text(call["stdout"]), secrets)
    stderr = scrub_text(_text(call["stderr"]), secrets)
    combined = stdout + "\n" + stderr
    if call["launch_error"] is not None:
        reason = "ADB could not be launched"
    elif call["timed_out"]:
        reason = "ADB dispatch did not finish within the tool timeout"
    elif call["returncode"] != 0:
        reason = f"ADB exited with status {call['returncode']}"
    elif not _complete(call):
        reason = "ADB dispatch output was truncated"
    elif AM_ERROR.search(combined):
        reason = "ADB reported that the intent could not be dispatched"
    else:
        reason = None
    return {"accepted": reason is None, "reason": reason, "returncode": call["returncode"],
            "timed_out": call["timed_out"],
            "launch_error": scrub_text(str(call["launch_error"]), secrets) if call["launch_error"] else None,
            "marked_starting": "Starting:" in stdout, "error_line": _error_line(combined),
            "warnings": [warning.strip()[:300] for warning in AM_WARNING.findall(stdout)][:4],
            "stdout": stdout, "stderr": stderr,
            "stdout_omitted_bytes": call["stdout_omitted_bytes"], "stderr_omitted_bytes": call["stderr_omitted_bytes"]}


def _error_line(text):
    """First diagnostic line of a dispatch reply, already scrubbed by the caller."""
    for line in text.splitlines():
        if AM_ERROR.search(line):
            return line.strip()[:300]
    return None


def _await_start(adb, serial, remote, options):
    """Poll boundedly for the scoped service and the unique dump file.

    PCAPdroid creates the dump file when the capture starts but may write the classic
    PCAP global header only with the first packet or at stop, so a created file of any
    size is start evidence and the header is validated on the finalized retrieved file
    instead. Waiting for header bytes here would stall the operator's action window.
    """
    deadline = time.monotonic() + options["consent_timeout"]
    started = time.monotonic()
    polls, service, file_fact = 0, None, None
    while True:
        polls += 1
        service = _service_call(adb, serial, options["timeout"])
        file_fact = _device_file(adb, serial, remote, options["timeout"])
        running = service["known"] and service["running"] is True
        if running and file_fact["exists"]:
            return _start_facts(service, file_fact, polls, started, complete=True)
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    return _start_facts(service, file_fact, polls, started, complete=False)


def _start_facts(service, file_fact, polls, started, complete):
    running = service["known"] and service["running"] is True
    created = bool(file_fact["exists"])
    return {"observed": running and created, "complete": complete, "service_running": running,
            "file_created": created, "file_header_observed": bool(file_fact["header_valid"]),
            "file_size": file_fact["size"], "polls": polls,
            "seconds_waited": round(time.monotonic() - started, 3),
            "consent_pending": not (running and created), "service": service, "file": file_fact}


def _observe(adb, serial, remote, timeout):
    service = _service_call(adb, serial, timeout)
    return {"service": service, "file": _device_file(adb, serial, remote, timeout),
            "still_running": service["known"] and service["running"] is True}


def _stop_session(adb, serial, options, key, secrets):
    """Ask PCAPdroid to stop, then poll boundedly for the observed service termination."""
    command = _intent_command(adb, serial, "stop", key)
    print(f"forge pcapdroid-capture: stopping the capture now; if PCAPdroid asks for stop consent, approve it on the "
          f"device within {options['timeout']}s", file=sys.stderr, flush=True)
    dispatch = _dispatch(_run(_dispatch_command(command, key), options["timeout"]), secrets)
    result = {"requested": True, "dispatch": dispatch, "observed_stopped": False, "polls": 0, "service": None,
              "command": list(command)}
    if not dispatch["accepted"]:
        result["state"] = "stop-not-dispatched"
        return result
    deadline = time.monotonic() + options["timeout"]
    while True:
        result["polls"] += 1
        result["service"] = _service_call(adb, serial, options["timeout"])
        if result["service"]["known"] and result["service"]["running"] is False:
            result["observed_stopped"] = True
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    result["state"] = ("stopped" if result["observed_stopped"]
                       else ("stop-not-observed" if result["service"]["known"] else "stop-unknown"))
    return result


def _settled_file(adb, serial, remote, options):
    """Bounded settle for the finalized dump: PCAPdroid may write the header only at stop."""
    deadline = time.monotonic() + min(options["timeout"], SETTLE_SECONDS)
    observed = _device_file(adb, serial, remote, options["timeout"])
    while not (observed["exists"] and observed["header_valid"]):
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
        observed = _device_file(adb, serial, remote, options["timeout"])
    return observed


def _window(seconds):
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(POLL_SECONDS, remaining))


def _hash_bounded(path, limit):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise ForgeError(f"Retrieved capture exceeds the {limit}-byte retrieval cap")
            digest.update(block)
    return digest.hexdigest(), size


def _pcap_header(data):
    order = PCAP_MAGIC.get(data[:4])
    if order is None:
        raise ForgeError("The retrieved file is not a classic PCAP file (unsupported magic)")
    major, minor, _, _, snaplen, link_type = struct.unpack_from(order + "HHiIII", data, 4)
    if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_FILE_BYTES:
        raise ForgeError("The retrieved PCAP header has an unsupported version or snaplen")
    return {"magic": data[:4].hex(), "byte_order": "little" if order == "<" else "big",
            "version": f"{major}.{minor}", "snaplen": snaplen, "link_type": link_type,
            "ethernet_link_type": link_type == 1, "nanosecond_timestamps": data[:4] in NANOSECOND_MAGIC}


def _retrieve(adb, serial, remote, destination, options, device_size):
    if device_size is None or device_size > options["max_bytes"]:
        raise ForgeError(f"The device dump exceeds --max-bytes ({options['max_bytes']}); nothing was pulled")
    with tempfile.TemporaryDirectory(prefix="forge-pcapdroid-", dir=str(destination.parent)) as staging:
        target = Path(staging) / "capture.pcap"
        call = _run([adb, "-s", serial, "pull", remote, str(target)], options["timeout"])
        if not _complete(call) or call["returncode"] != 0:
            detail = _text(call["stderr"]).strip().splitlines()
            raise ForgeError("ADB could not pull the capture file"
                             + (f": {detail[0][:200]}" if detail else ""))
        if target.is_symlink() or not target.is_file():
            raise ForgeError("ADB pull did not produce one regular capture file")
        digest, size = _hash_bounded(target, options["max_bytes"])
        if size < HEADER_BYTES:
            raise ForgeError("The pulled capture file is shorter than a PCAP header")
        if size != device_size:
            raise ForgeError("Capture size changed after stop; nothing was published")
        with target.open("rb") as stream:
            header = _pcap_header(stream.read(HEADER_BYTES))
        if destination.exists() or destination.is_symlink():
            raise ForgeError("Destination appeared during the capture; nothing was published")
        try:
            os.link(target, destination)
        except FileExistsError as error:
            raise ForgeError("Destination appeared during the capture; nothing was published") from error
        except OSError as error:
            raise ForgeError(f"Atomic PCAP publication requires hard-link support: {error}") from error
        return {"sha256": digest, "size": size, "device_size": device_size, "header": header,
                "empty": size == HEADER_BYTES, "max_dump_size_reached": size >= options["max_bytes"]}


def _stop_detail(stop):
    if not isinstance(stop, dict) or not stop.get("requested"):
        return ("No stop was sent because no own capture start was observed; verify the device state before retrying "
                "and never force-stop the app")
    dispatch = stop.get("dispatch") or {}
    if not dispatch.get("accepted"):
        return (f"Stop was not dispatched ({dispatch.get('reason')}); the capture state on the device is "
                f"{_stop_state(stop)}")
    return (f"The CaptureService was still observed as {_stop_state(stop)} after the stop request and "
            f"{stop.get('polls', 0)} scoped observations")


def _stop_state(stop):
    service = (stop or {}).get("service")
    if not isinstance(service, dict) or not service.get("known"):
        return "unknown (scoped service observations were incomplete)"
    return "running" if service.get("running") else "stopped"


def _required_action(dispatch, start, stop, dump=None):
    if dispatch is None:
        return "Resolve the reported prerequisite before retrying; no capture Intent was sent."
    if not dispatch["accepted"]:
        return ("Confirm PCAPdroid is installed and no other capture prompt is open, then retry; ADB did not dispatch "
                "the start Intent.")
    if not isinstance(start, dict) or not start["observed"]:
        return ("Unlock the device and approve the PCAPdroid consent/VPN prompt. If a capture was approved anyway, "
                "stop it from the PCAPdroid notification, verify no CaptureService remains, then retry.")
    if not isinstance(stop, dict) or not stop.get("requested"):
        return ("No own capture start was observed, so no stop was sent; check the device for a running capture before "
                "retrying.")
    if stop.get("observed_stopped") is not True:
        return ("Open PCAPdroid on the device, approve the stop prompt or stop the capture manually, "
                "then confirm no CaptureService remains before retrying.")
    if not isinstance(dump, dict) or not (dump.get("exists") and dump.get("header_valid")):
        return ("The capture session ran but no readable dump file was observed: exercise the target app while the "
                "command waits for its bounded window so PCAPdroid writes packet data, then retry.")
    return ("Open PCAPdroid on the device, approve the stop/consent prompt or stop the capture manually, then confirm "
            "no CaptureService remains before retrying.")


def pcapdroid_preflight(args, store):
    forge_tasks.check_scope(store, "pcapdroid-preflight", device=True)
    package = getattr(args, "package", None)
    if package is not None and (not isinstance(package, str) or not PACKAGE_NAME.fullmatch(package)):
        raise ForgeError("Provide a valid --package name for the observed target app")
    return store.add("runtime", _preflight(_serial_value(getattr(args, "serial", None), "--serial"), package))


def _gap(seconds):
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(POLL_SECONDS, remaining))


def _action_dispatch(label, command, options, secrets):
    """Dispatch one scripted app action; acceptance stays a dispatch observation."""
    dispatch = _dispatch(_run(command, options["timeout"]), secrets)
    dispatch["action"] = label
    dispatch["command"] = list(command)
    return dispatch


def _scripted_actions(adb, serial, options, secrets):
    """Send the configured per-window app actions: force-stop of the target package first, then the launch."""
    force_stop = launch = None
    if options["force_stop"]:
        force_stop = _action_dispatch("force-stop", [adb, "-s", serial, "shell", "am", "force-stop",
                                                     options["package"]], options, secrets)
    if options["launch"]:
        launch = _action_dispatch("launch", [adb, "-s", serial, "shell", "am", "start", "-W", "-n",
                                            options["launch"]], options, secrets)
    return force_stop, launch


def _action_error(force_stop, launch):
    for label, dispatch in (("force-stop", force_stop), ("launch", launch)):
        if dispatch is not None and not dispatch["accepted"]:
            return f"The scripted {label} action was not dispatched: {dispatch['reason']}"
    return None


def _stop_code(stop):
    """Compact stop outcome for session summaries; the window record keeps the full structure."""
    if not isinstance(stop, dict) or not stop.get("requested"):
        return "not-requested"
    return stop.get("state") or "unknown"


def _window_summary(store, index, destination, *, attempted, success, name=None, evidence_id=None, sha256=None,
                    size=None, empty=None, error=None, stop_state=None):
    return {"index": index, "path": _project_relative(store, destination), "pcap_name": name, "attempted": attempted,
            "success": success, "evidence_id": evidence_id, "sha256": sha256, "size": size, "empty": empty,
            "error": error, "stop_state": stop_state}


def _window_failure(store, options, environment, secrets, index, count, destination, preflight_id, error, name=None,
                    remote=None, settings=None, dispatch=None, start=None, stop=None, window_end=None, dump=None,
                    force_stop=None, launch=None, precheck=None):
    """Store the per-window rejection first, so a mid-session stop keeps the completed windows intact."""
    message = scrub_text(str(error), secrets)
    required = _required_action(dispatch, start, stop, dump)
    decryption = options["tls_decryption"]
    record = store.add("runtime", {
        "schema": SCHEMA, "tool": TOOL, "action": "capture-rejected", "success": False, "error": message,
        "package": options["package"], "serial": options["serial"], "pcap_name": name, "device_path": remote,
        "settings": settings if settings is not None else _settings(None, options, environment),
        "window_index": index, "window_count": count,
        "destination": str(destination), "destination_published": False,
        "dispatch": dispatch, "start": start, "stop": stop, "window_end": window_end, "dump": dump,
        "force_stop_action": force_stop, "launch_action": launch, "service_precheck": precheck,
        "retrieval": {"pulled": False, "published": False}, "preflight_evidence_id": preflight_id,
        "decryption_requested": decryption, "operator_approved_tls_decryption": decryption,
        "decryption_scope": _DECRYPTION_SCOPE if decryption else None,
        "proof": {"activity_result_available": False, "get_status_extras_used": False},
        "required_action": required, "scope": _SCOPE, "limits": _limits(options)})
    summary = _window_summary(store, index, destination, attempted=True, success=False, name=name,
                             evidence_id=record["id"], error=message, stop_state=_stop_code(stop))
    return {"record": None, "summary": summary, "message": message, "error": error,
            "failure": {"index": index, "path": summary["path"], "pcap_name": name, "error": message,
                        "evidence_id": record["id"], "required_action": required}}


def _capture_window(store, options, facts, preflight_id, key, secrets, environment, index, count, destination):
    """Run one bounded window: observed start, scripted app actions, bounded window, observed stop, retrieval.

    The window outcome never decides the session outcome, and any capture this window started is stopped before
    the outcome is returned. A failure stores its own rejection record with whatever this window observed.
    """
    adb, serial = facts["adb_path"], facts["device"]["serial"]
    name = _capture_name()
    remote = DEVICE_DIRECTORY + "/" + name
    settings = _settings(name, options, environment)
    prefix = f"window {index}/{count}: " if count > 1 else ""
    dispatch = start = stop = window_end = dump = precheck = force_stop = launch = None

    def reject(error):
        return _window_failure(store, options, environment, secrets, index, count, destination, preflight_id, error,
                               name=name, remote=remote, settings=settings, dispatch=dispatch, start=start, stop=stop,
                               window_end=window_end, dump=dump, force_stop=force_stop, launch=launch,
                               precheck=precheck)

    try:
        if index > 1:
            # Every window re-checks that no CaptureService is running; a foreign capture is never stopped.
            precheck = _service_call(adb, serial, options["timeout"])
            status = (None if precheck["known"] and precheck["running"] is False
                      else ("capture-active" if precheck["running"] else "service-unknown"))
            if status is not None:
                raise ForgeError(f"Capture prerequisite missing: {status}")
        print(f"forge pcapdroid-capture: {prefix}starting {name}", file=sys.stderr, flush=True)
        command = _start_command(adb, serial, options, name, key)
        try:
            dispatch = _dispatch(_run(_dispatch_command(command, key), options["timeout"]), secrets)
            if not dispatch["accepted"]:
                raise ForgeError(f"Capture start was not dispatched: {dispatch['reason']}")
            start = _await_start(adb, serial, remote, options)
            if not start["observed"]:
                raise ForgeError("Both the capture service and this session's dump file were not observed within the consent timeout")
            print(_ready_message(options, start, index, count), file=sys.stderr, flush=True)
            force_stop, launch = _scripted_actions(adb, serial, options, secrets)
            problem = _action_error(force_stop, launch)
            if problem is not None:
                raise ForgeError(problem)
            _window(options["seconds"])
            window_end = _observe(adb, serial, remote, options["timeout"])
        finally:
            if dispatch is not None and dispatch["accepted"] and start is not None and start["observed"]:
                stop = _stop_session(adb, serial, options, key, secrets)
            else:
                stop = {"requested": False, "observed_stopped": False, "polls": 0, "service": None,
                        "reason": "No own capture start was observed; no stop was sent"}
        if stop.get("observed_stopped") is not True:
            raise ForgeError(_stop_detail(stop))
        dump = _settled_file(adb, serial, remote, options)
        if not (dump["exists"] and dump["header_valid"]):
            detail = ("no dump file at all" if dump["size"] is None
                      else f"a {dump['size']}-byte file without a valid PCAP header")
            raise ForgeError(f"No readable dump file named {name} was observed on the device after the stop: {detail}; "
                             f"a running service or an unwritten dump is not this capture")
        after_stop = _device_file(adb, serial, remote, options["timeout"])
        flushed = dump["size"] == after_stop["size"]
        if not flushed:
            raise ForgeError("Capture dump size was not stable after stop; nothing was published")
        retrieval = _retrieve(adb, serial, remote, destination, options, after_stop["size"])
        print(f"forge pcapdroid-capture: {prefix}capture stopped and {retrieval['size']} bytes retrieved as "
              f"{destination.name}", file=sys.stderr, flush=True)
        decryption = options["tls_decryption"]
        record = store.add("runtime", {
            "schema": SCHEMA, "tool": TOOL, "action": "capture", "success": True,
            "serial": serial, "package": options["package"], "target_uid": _target_uid(facts),
            "window_index": index, "window_count": count,
            "capture": {"path": _project_relative(store, destination),
                        "sha256": retrieval["sha256"], "size": retrieval["size"]},
            "empty": retrieval["empty"],
            "pcap_header": retrieval["header"], "settings": settings,
            "device": {"serial": serial, "adb_path": adb,
                       "capture_package": facts["capture_package"], "target_package": facts["target_package"],
                       "device_path": remote, "device_size": after_stop["size"], "size_stable_after_stop": flushed},
            "dispatch": dispatch,
            "dispatch_command": list(command),
            "start": start, "stop": stop, "window_end": window_end,
            "force_stop_action": force_stop, "launch_action": launch,
            "retrieval": {"pulled": True, "published": True, "device_size": after_stop["size"],
                          "size": retrieval["size"], "sha256": retrieval["sha256"],
                          "max_dump_size_reached": retrieval["max_dump_size_reached"]},
            "max_dump_size_reached": retrieval["max_dump_size_reached"],
            "dump_size_stable_after_stop": flushed,
            "decryption_requested": decryption, "operator_approved_tls_decryption": decryption,
            "decryption_scope": _DECRYPTION_SCOPE if decryption else None,
            "proof": {"dispatch_observed": True, "service_running_observed": start["service_running"],
                      "file_created_observed": start["file_created"],
                      "file_header_observed": start["file_header_observed"],
                      "complete_start_signals": start["complete"], "stop_requested": stop["requested"],
                      "service_stopped_observed": True,
                      "still_running_at_window_end": bool(window_end and window_end["still_running"]),
                      "target_uid_observed": isinstance(_target_uid(facts), int),
                      "retrieved_header_valid": True,
                      "activity_result_available": False, "get_status_extras_used": False,
                      "empty_capture": retrieval["empty"]},
            "preflight_evidence_id": preflight_id, "evidence_ids": [preflight_id],
            "scope": _SCOPE, "limits": _limits(options)})
    except (ForgeError, OSError, ValueError, sqlite3.Error) as error:
        return reject(error)
    return {"record": record,
            "summary": _window_summary(store, index, destination, attempted=True, success=True, name=name,
                                       evidence_id=record["id"], sha256=retrieval["sha256"],
                                       size=retrieval["size"], empty=retrieval["empty"],
                                       stop_state=_stop_code(stop)),
            "failure": None, "error": None, "message": None}


def _session_data(store, options, environment, facts, preflight_id, destination, windows, failures, observed):
    decryption = options["tls_decryption"]
    serial = facts["device"]["serial"] if isinstance(facts.get("device"), dict) else options["serial"]
    running = observed["running"] if isinstance(observed, dict) and observed.get("known") else None
    return {"schema": SCHEMA, "tool": TOOL, "action": "capture-session",
            "success": not failures and bool(windows) and all(entry["success"] for entry in windows),
            "package": options["package"], "serial": serial, "target_uid": _target_uid(facts),
            "repeats": options["repeat"], "attempted_windows": sum(1 for entry in windows if entry["attempted"]),
            "completed_windows": sum(1 for entry in windows if entry["success"]),
            "seconds": options["seconds"], "gap_seconds": options["gap"], "max_bytes": options["max_bytes"],
            "force_stop": options["force_stop"], "launch": options["launch"],
            "destination": _project_relative(store, destination), "settings": _settings(None, options, environment),
            "decryption_requested": decryption, "operator_approved_tls_decryption": decryption,
            "decryption_scope": _DECRYPTION_SCOPE if decryption else None,
            "windows": windows, "failures": failures, "service_after_session": observed,
            "capture_running_after_session": running, "preflight_evidence_id": preflight_id,
            "evidence_ids": [preflight_id] + [entry["evidence_id"] for entry in windows if entry["evidence_id"]],
            "required_action": failures[0]["required_action"] if failures else None,
            "scope": _SCOPE, "limits": _limits(options)}


def pcapdroid_capture(args, store):
    forge_tasks.check_scope(store, "pcapdroid-capture", device=True, network=True)
    options = _capture_options(args)
    destinations = _destinations(store, getattr(args, "path", None), options["repeat"])
    key, environment = _api_key(getattr(args, "api_key_env", None))
    secrets = (key, shlex.quote(key)) if key is not None else ()
    count = len(destinations)
    windows, failures, failed, completed = [], [], None, None
    facts = _preflight(options["serial"], options["package"])
    preflight = store.add("runtime", facts)
    adb = facts.get("adb_path")
    serial = facts["device"]["serial"] if isinstance(facts.get("device"), dict) else None
    try:
        if facts["status"] != "ready":
            raise ForgeError(f"Capture prerequisite missing: {facts['status']}")
        for index, destination in enumerate(destinations, start=1):
            if index > 1:
                _gap(options["gap"])
            outcome = _capture_window(store, options, facts, preflight["id"], key, secrets, environment, index,
                                      count, destination)
            windows.append(outcome["summary"])
            if outcome["error"] is None:
                completed = outcome["record"]
                continue
            failures.append(outcome["failure"])
            failed = outcome
            break
    except (ForgeError, OSError, ValueError, sqlite3.Error) as error:
        # Only a session-level refusal reaches here: window failures record themselves and end the loop.
        failed = _window_failure(store, options, environment, secrets, len(windows) + 1, count,
                                 destinations[len(windows)], preflight["id"], error)
        windows.append(failed["summary"])
        failures.append(failed["failure"])
    attempted = len(windows)
    windows += [_window_summary(store, index, destination, attempted=False, success=False)
                for index, destination in enumerate(destinations[attempted:], start=attempted + 1)]
    observed = _service_call(adb, serial, options["timeout"]) if attempted and adb and serial else None
    session = store.add("runtime", _session_data(store, options, environment, facts, preflight["id"],
                                                 destinations[0].parent if count > 1 else destinations[0],
                                                 windows, failures, observed))
    if failed is not None:
        window = f"window {attempted}/{count} " if count > 1 else ""
        raise ForgeError(f"{failed['message']}; {window}rejection evidence {failed['failure']['evidence_id']}; "
                         f"capture-session evidence {session['id']}") from failed["error"]
    return completed if count == 1 else session


def _project_relative(store, destination):
    try:
        return destination.resolve().relative_to(store.root).as_posix()
    except (ValueError, OSError):
        return None


def _ready_message(options, start, index=1, count=1):
    detail = (f"dump file created ({start['file_size']} bytes so far)" if start["file_created"]
              else "dump file not observed yet")
    prefix = f"window {index}/{count}: " if count > 1 else ""
    if start["complete"]:
        return (f"forge pcapdroid-capture: {prefix}capture service running and {detail} for {options['package']}; "
                f"perform the target action now ({options['seconds']}s)")
    return (f"forge pcapdroid-capture: {prefix}{detail} for {options['package']} but the capture service was not "
            f"observed running yet; perform the target action now ({options['seconds']}s)")


def register(subparsers):
    parser = subparsers.add_parser("pcapdroid-preflight",
                                   help="Observe configured ADB, installed PCAPdroid/target package facts and scoped "
                                        "CaptureService state without starting anything")
    parser.add_argument("--serial", help="Explicit ADB serial when device selection is ambiguous")
    parser.add_argument("--package", help="Optional target app package to observe installed facts for")
    parser.set_defaults(handler=pcapdroid_preflight)
    parser = subparsers.add_parser("pcapdroid-capture",
                                   help="Start one bounded app-filtered rootless PCAPdroid capture and retrieve the "
                                        "new private PCAP file after an observed stop; --repeat runs several scripted "
                                        "windows with one evidence record each")
    parser.add_argument("--package", required=True, help="Target app package to capture, for example ai.x.grok")
    parser.add_argument("--path", required=True,
                        help="New local destination for the retrieved PCAP file, or an existing project directory "
                             "when --repeat is greater than 1 (each window writes window-NN.pcap)")
    parser.add_argument("--serial", help="Explicit ADB serial when device selection is ambiguous")
    parser.add_argument("--seconds", type=int, default=15,
                        help=f"Bounded capture window in seconds (1..{MAX_SECONDS}, default: 15)")
    parser.add_argument("--consent-timeout", type=int, default=30,
                        help=f"Seconds to wait for the capture start observation (1..{MAX_CONSENT_SECONDS}, default: 30)")
    parser.add_argument("--repeat", type=int, default=1,
                        help=f"Scripted capture windows in one session (1..{MAX_REPEATS}, default: 1); each window "
                             f"writes its own window-NN.pcap and evidence record")
    parser.add_argument("--gap", type=float, default=0,
                        help=f"Seconds between capture windows (0..{MAX_GAP_SECONDS}, default: 0)")
    parser.add_argument("--launch", help="Optional PACKAGE/COMPONENT to launch in every window after the capture "
                                         "starts, for example ai.x.grok/.MainActivity")
    parser.add_argument("--force-stop", action="store_true",
                        help="Force-stop the target package before each window's launch")
    parser.add_argument("--tls-decryption", action="store_true",
                        help="Request PCAPdroid TLS decryption for the target package; needs a user-installed "
                             "PCAPdroid CA and app trust, and FORGE installs nothing")
    parser.add_argument("--api-key-env",
                        help="Environment variable holding the PCAPdroid API key; the key is never stored or echoed")
    parser.add_argument("--max-bytes", type=int, default=33554432,
                        help=f"Device dump and host retrieval byte cap ({MIN_FILE_BYTES}..{MAX_FILE_BYTES}, "
                             f"default: 33554432)")
    parser.add_argument("--timeout", type=int, default=15,
                        help=f"Seconds per bounded ADB call, and the window allowed for the stop consent/termination "
                             f"observation (1..{MAX_TOOL_SECONDS}, default: 15)")
    parser.set_defaults(handler=pcapdroid_capture)
