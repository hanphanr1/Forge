"""Tool-gated, read-only iOS boundary observations; FORGE has no iOS runtime adapter.

Both commands only invoke an explicitly configured external libimobiledevice tool and record what that
tool printed. Discovery is shared with `forge doctor` through `forge_toolchain` (`FORGE_IDEVICE_ID` /
`FORGE_IDEVICEPAIR`, then `PATH`). Nothing here captures traffic, hooks a process, injects code,
escalates to jailbreak, installs a certificate or opens a listener/socket. ADB is not an iOS transport.

``success`` means the configured tool ran to completion and its output was parsed; device presence and
pairing state are reported separately in ``status``/``devices``/``pairing_state``.
"""
from __future__ import annotations

import re
import subprocess
import tempfile

from forge_core import ForgeError, scrub_text
from forge_toolchain import find_tool


SCHEMA = "forge.ios.v1"
IDEVICE_ID = "idevice_id"
IDEVICEPAIR = "idevicepair"
MAX_OUTPUT = 256 * 1024
MAX_DEVICES = 128
LIST_TIMEOUT = 15
PAIR_TIMEOUT = 30
UDID = re.compile(r"[0-9A-Fa-f][0-9A-Fa-f-]{7,63}")
PAIRED = re.compile(r"(?i)\b(?:valid pairing|success:\s*paired)\b")
UNPAIRED = re.compile(r"(?i)\b(?:invalid pairing|no valid pairing|not paired with this host|pairing failed|unpaired)\b")

SCOPE = ("Read-only observation of an explicitly configured libimobiledevice tool. FORGE has no iOS runtime "
         "adapter: a jailed (non-jailbroken) device cannot be instrumented, and no capture, hooking, injection, "
         "jailbreak, certificate or trust-modifying action is performed here. ADB does not apply to iOS.")
LIMITS = (
    "FORGE has no iOS runtime adapter; this module only invokes an explicitly configured external tool",
    "A jailed (non-jailbroken) device cannot be instrumented; capture, hooking, injection, jailbreak and certificate capability are not offered or implied",
    "An observed pairing state is host/device trust metadata, not proof of capture, trust or login on the target app",
    "Read-only local invocation: no bind, network, device-write or trust-modifying action",
)


def _run(command, timeout):
    # Bounded local invocation: argv only, no stdin, no shell, no network.
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
            output[name] = stream.read(MAX_OUTPUT).decode("utf-8", "replace")
            output[name + "_omitted_bytes"] = max(0, size - MAX_OUTPUT)
        return output


def _ok(result):
    return result["returncode"] == 0 and not result["timed_out"] and not result["launch_error"]


def _missing(name, found):
    return f"Missing required iOS tool '{name}': {found['setup']}"


def _base(action, name, found):
    return {"schema": SCHEMA, "action": action, "status": "missing-tool", "success": False, "precondition": None,
            "tool": name, "command": name, "tool_path": found["path"], "tool_source": found["source"],
            "setup": found["setup"], "read_only": True, "network_action": False, "device_write": False,
            "scope": SCOPE, "limits": list(LIMITS)}


def _output(command, invocation):
    return {"argv": list(command), "returncode": invocation["returncode"], "timed_out": invocation["timed_out"],
            "launch_error": invocation["launch_error"], "stdout": scrub_text(invocation["stdout"]),
            "stderr": scrub_text(invocation["stderr"]),
            "stdout_omitted_bytes": invocation["stdout_omitted_bytes"],
            "stderr_omitted_bytes": invocation["stderr_omitted_bytes"]}


def _observed_udid(value):
    value = (value or "").strip()
    if not UDID.fullmatch(value):
        raise ForgeError("Provide one observed iOS UDID (8-64 hexadecimal characters with optional dashes) as printed by ios-devices")
    return value


def parse_pairing(text):
    """Classify idevicepair output as paired, not-paired or unknown; never guess from a silent tool."""
    if PAIRED.search(text):
        return "paired"
    if UNPAIRED.search(text):
        return "not-paired"
    return "unknown"


def _devices(found):
    result = _base("ios-devices", IDEVICE_ID, found)
    result.update({"devices": [], "devices_omitted": 0, "malformed_lines": 0, "invocation": None})
    if not found["available"]:
        result["precondition"] = _missing(IDEVICE_ID, found)
        return result
    command = [found["path"], "-l"]
    invocation = _run(command, LIST_TIMEOUT)
    result["invocation"] = _output(command, invocation)
    if not _ok(invocation) or invocation["stdout_omitted_bytes"] or invocation["stderr_omitted_bytes"]:
        result["status"] = "tool-failed"
        result["precondition"] = "The configured idevice_id must enumerate attached devices to completion without omitted output"
        return result
    for line in invocation["stdout"].splitlines():
        value = line.strip()
        if not value:
            continue
        if not UDID.fullmatch(value):
            result["malformed_lines"] += 1
            continue
        if len(result["devices"]) < MAX_DEVICES:
            result["devices"].append(value)
        else:
            result["devices_omitted"] += 1
    result["status"] = "observed" if result["devices"] else "absent"
    result["success"] = True
    return result


def _pair(found, udid):
    result = _base("ios-pair", IDEVICEPAIR, found)
    result.update({"udid": udid, "pairing_state": "unknown", "tool_ok": False, "invocation": None})
    if not found["available"]:
        result["precondition"] = _missing(IDEVICEPAIR, found)
        return result
    command = [found["path"], "validate", "-u", udid]
    invocation = _run(command, PAIR_TIMEOUT)
    result["invocation"] = _output(command, invocation)
    if invocation["launch_error"] or invocation["timed_out"] or invocation["stdout_omitted_bytes"] or invocation["stderr_omitted_bytes"]:
        result["status"] = "tool-failed"
        result["precondition"] = "The configured idevicepair must report a pairing verdict to completion without omitted output"
        return result
    result["tool_ok"] = _ok(invocation)
    verdict = parse_pairing(invocation["stdout"] + "\n" + invocation["stderr"])
    if verdict == "paired" and not result["tool_ok"]:
        verdict = "unknown"
    result["pairing_state"] = verdict
    result["status"] = verdict
    if verdict == "unknown":
        result["precondition"] = ("idevicepair reported success but no recognizable pairing verdict" if result["tool_ok"]
                                  else "idevicepair exit status and pairing verdict disagree")
        return result
    result["success"] = True
    return result


def ios_devices(args, store):
    result = _devices(find_tool(IDEVICE_ID))
    record = store.add("runtime", result)
    if not result["success"]:
        raise ForgeError(f"iOS device enumeration failed ({result['status']}): {result['precondition']}; evidence {record['id']}")
    return record


def ios_pair(args, store):
    udid = _observed_udid(args.udid)
    result = _pair(find_tool(IDEVICEPAIR), udid)
    record = store.add("runtime", result)
    if not result["success"]:
        raise ForgeError(f"iOS pairing state is {result['status']}: {result['precondition']}; evidence {record['id']}")
    return record


def register(subparsers):
    parser = subparsers.add_parser("ios-devices",
                                   help="List attached iOS UDIDs with a configured idevice_id; read-only, no iOS runtime adapter")
    parser.set_defaults(handler=ios_devices)
    parser = subparsers.add_parser("ios-pair",
                                   help="Report the observed pairing state of one explicit iOS UDID with a configured idevicepair")
    parser.add_argument("--udid", required=True, help="Observed device UDID printed by ios-devices")
    parser.set_defaults(handler=ios_pair)
