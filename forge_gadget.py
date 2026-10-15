"""One bounded command from an installed app to imported, decrypted exchanges.

gadget-capture chains the existing stages in one fixed order: repackage the base APK with a Frida
Gadget, sign the base and every split with one identity, uninstall and reinstall the set, preflight
PCAPdroid, capture with TLS decryption and a no-wait launch, attach the shipped trust-bypass script
while the window runs, then pull the flow dump, convert it with the builtin reader and import it.
Each stage writes its own record citing the records it invoked, and the first failure stops the run
with the required operator action. The Gadget route is the only one that works without root, and an
app that loads the Gadget in wait mode stays blocked until the attach happens, which is why the
scripted launch runs without -W. iOS stays out of scope.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import sysconfig
import threading
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

from forge_android import _ok, _run
from forge_core import ForgeError, scrub_text
from forge_toolchain import executable
import forge_android
import forge_apktool
import forge_flows
import forge_network
import forge_pcapdroid
import forge_tasks


SCHEMA = "forge.gadget/v1"
ACTION = "gadget-capture"
STAGES = ("gadget", "sign", "uninstall", "install", "preflight", "capture", "hook", "flows", "summary")
BUILTIN = "builtin"
SCRIPT_NAME = "forge-trust-bypass.js"
SCRIPT_MARKERS = ("forge-trust-bypass-loaded", "ssl-context-init-replaced", "certificate-pinner-check$okhttp",
                  "certificate-pinner-check", "conscrypt-verify-chain", "conscrypt-engine-verify")
DEFAULT_GADGET_CONFIG = ("on_load=resume",)
FRIDA_HOST = "127.0.0.1:27042"
FRIDA_PORT = "27042"
GADGET_PROCESS = "Gadget"
FLOWS_DUMP_NAME = "flows.dump"
HAR_NAME = "capture.har"
PCAP_NAME = "capture.pcap"
GADGET_APK_NAME = "base-gadget.apk"
SIGNED_BASE_NAME = "base-signed.apk"
SIGNED_SPLIT_NAME = "split-{index:02d}-signed.apk"
DEBUG_KEYSTORE_NAME = "forge-debug.keystore"
INSTALLER = "com.android.vending"
POLL_SECONDS = 1.0
POLL_TIMEOUT = 10
MAX_POLL_SECONDS = 10
FORWARD_SECONDS = 15
CONSENT_SECONDS = 30
MAX_LAUNCH_WAIT = 150
MIN_ATTACH_SECONDS = 5
ATTACH_TAIL_SECONDS = 15
MIN_BUDGET = 60
MAX_BUDGET = 7200
MAX_APKS = 128
HAR_LIMIT = 1000
HAR_BODY_BYTES = 1024 * 1024
HOSTS_CAP = 50
EXCHANGE_IDS = 100
STORE_ENV = "FORGE_GADGET_STORE_PASS"
KEY_ENV = "FORGE_GADGET_KEY_PASS"
EVIDENCE_ID = re.compile(r"\bev_[a-f0-9]{32}\b")
FAILURE = re.compile(r"(?im)^\s*(?:Failure|Error)\b")
ABSENT = re.compile(r"not installed", re.I)
MISSING_PIDOF = re.compile(r"(?i)not found|unknown command|inaccessible")
DIGITS = re.compile(r"[0-9]+")
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
SCOPE = ("One bounded Gadget run on the selected device. The repackaged, differently signed build is what was "
         "captured, the trust bypass applies in-process to that build only, and the imported HAR is redacted, "
         "non-replayable evidence rather than proof of authentication.")
LIMITS = [
    "Gadget repackaging sets android:debuggable and replaces the signature: hook output describes this modified "
    "build, not the official one.",
    "TLS decryption depends on the user-installed capture CA and on the trust-bypass script attaching before the app "
    "builds its TLS context.",
    "endpoints_hint counts distinct request host+path pairs in the imported HAR; paths are counted, not stored.",
]
FLOWS_ACTION = ("No mitmproxy flow dump was retrieved from the device. Install the PCAPdroid mitm addon and its CA, "
                "keep --mitm so the capture runs with TLS decryption and its addon check, then rerun")
HOOK_ACTION = ("The app never exposed a Gadget on 127.0.0.1:27042. Confirm the installed base APK is this run's "
               "repackage (adb shell pm path), that --gadget matches the device ABI, and force-stop the app "
               "(adb shell am force-stop PACKAGE) if it is still blocked in Gadget wait mode, then rerun")


# --------------------------------------------------------------------------- inputs

def _local_file(store, value, label, suffix=None):
    """One regular project-local file, resolved before any stage runs."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ForgeError(f"Provide {label} as a project-local path")
    path = Path(value.strip()).expanduser()
    path = (path if path.is_absolute() else store.root / path)
    try:
        path = path.resolve()
    except OSError as error:
        raise ForgeError(f"{label} is not usable: {error}") from error
    if not path.is_relative_to(store.root.resolve()):
        raise ForgeError(f"{label} must stay inside the project")
    if not path.is_file() or path.is_symlink():
        raise ForgeError(f"{label} must be one regular project-local file")
    if suffix and path.suffix.lower() != suffix:
        raise ForgeError(f"{label} must keep the {suffix} suffix")
    return path


def _reject_symlinks(directory):
    for part in (*reversed(directory.parents), directory):
        try:
            info = part.lstat()
        except OSError as error:
            raise ForgeError(f"--path is not usable: {part}") from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE_POINT:
            raise ForgeError(f"Symlinked or reparse-point --path directories are not allowed: {part}")


def _session_directory(store, value):
    """An existing project-local directory that holds this run's build, dump and HAR outputs."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ForgeError("Provide --path as an existing project-local directory for this run's outputs")
    path = Path(value.strip()).expanduser()
    path = (path if path.is_absolute() else store.root / path)
    path = path.resolve()
    if not path.is_relative_to(store.root.resolve()):
        raise ForgeError("--path must stay inside the project")
    if not path.is_dir() or path.is_symlink():
        raise ForgeError("--path must name an existing project-local directory, not a file")
    _reject_symlinks(path)
    return path


def _planned(directory, name, label):
    destination = directory / name
    if destination.exists() or destination.is_symlink():
        raise ForgeError(f"{label} already exists ({name}); give each run a new --path directory")
    return destination


def _builtin_script():
    """The shipped trust-bypass script: next to the module, or in the installed data directory."""
    candidates = []
    try:
        import importlib.resources as resources

        candidates.append(Path(str(resources.files(__name__))) / "scripts" / SCRIPT_NAME)
    except (ImportError, AttributeError, TypeError, OSError):
        pass
    candidates.append(Path(__file__).resolve().parent / "scripts" / SCRIPT_NAME)
    data = sysconfig.get_paths().get("data")
    if data:
        candidates.append(Path(data) / "share" / "forge" / "scripts" / SCRIPT_NAME)
    for candidate in candidates:
        if candidate.is_file():
            return candidate, candidates
    return None, candidates


def _script(store, value):
    if value in (None, "", BUILTIN):
        path, candidates = _builtin_script()
        if path is None:
            tried = ", ".join(str(item) for item in candidates) or "no candidate path"
            raise ForgeError(f"The shipped {SCRIPT_NAME} was not found ({tried}); pass --script with a project-local "
                             f"Frida script instead")
        return path, BUILTIN
    return _local_file(store, value, "--script", ".js"), "caller"


def _target(args):
    package = args.package
    if not isinstance(package, str) or not forge_pcapdroid.PACKAGE_NAME.fullmatch(package):
        raise ForgeError("Provide a valid --package name, for example ai.x.grok")
    component = args.component
    if not isinstance(component, str) or not forge_pcapdroid.LAUNCH_COMPONENT.fullmatch(component):
        raise ForgeError("--component must be PACKAGE/ACTIVITY from the manifest, for example ai.x.grok/.MainActivity")
    if component.partition("/")[0] != package:
        raise ForgeError(f"--component must launch --package {package}; {component!r} starts another package")
    serial = args.serial
    if serial is not None and (not isinstance(serial, str) or not forge_pcapdroid.SERIAL_VALUE.fullmatch(serial)):
        raise ForgeError("--serial must be an ADB serial without spaces, options or path characters")
    return {"package": package, "component": component, "serial": serial}


def _limits(args):
    if type(args.seconds) is not int or not 1 <= args.seconds <= forge_pcapdroid.MAX_SECONDS:
        raise ForgeError(f"--seconds must be an integer between 1 and {forge_pcapdroid.MAX_SECONDS}")
    if type(args.max_bytes) is not int or not forge_pcapdroid.MIN_FILE_BYTES <= args.max_bytes <= forge_pcapdroid.MAX_FILE_BYTES:
        raise ForgeError(f"--max-bytes must be an integer between {forge_pcapdroid.MIN_FILE_BYTES} and "
                         f"{forge_pcapdroid.MAX_FILE_BYTES}")
    if type(args.poll_seconds) is not int or not 1 <= args.poll_seconds <= MAX_POLL_SECONDS:
        raise ForgeError(f"--poll-seconds must be an integer between 1 and {MAX_POLL_SECONDS}")
    if type(args.timeout) is not int or not 1 <= args.timeout <= 3600:
        raise ForgeError("--timeout must be an integer between 1 and 3600")
    if type(args.budget) is not int or not MIN_BUDGET <= args.budget <= MAX_BUDGET:
        raise ForgeError(f"--budget must be an integer between {MIN_BUDGET} and {MAX_BUDGET}")
    if type(args.mitm) is not bool:
        raise ForgeError("--mitm is a flag and takes no value")
    config = list(args.gadget_config or [])
    for item in config:
        key, separator, value = item.partition("=")
        if not separator or not key.strip() or not value.strip():
            raise ForgeError("--gadget-config expects KEY=VALUE, for example on_load=wait")
    return {"seconds": args.seconds, "max_bytes": args.max_bytes, "poll_seconds": args.poll_seconds,
            "timeout": args.timeout, "budget": args.budget, "mitm": args.mitm,
            "gadget_config": config or list(DEFAULT_GADGET_CONFIG)}


def _paths(args, store):
    apks = list(args.apk or [])
    if not 1 <= len(apks) <= MAX_APKS:
        raise ForgeError(f"--apk must name between 1 and {MAX_APKS} project-local APKs: the base first, then every split")
    base = _local_file(store, apks[0], "the base APK (first --apk)", ".apk")
    splits = [_local_file(store, value, f"split APK {value!r}", ".apk") for value in apks[1:]]
    gadget = _local_file(store, args.gadget, "--gadget", ".so")
    session = _session_directory(store, args.path)
    script, script_source = _script(store, args.script)
    return {"base": base, "splits": splits, "gadget": gadget, "session": session, "script": script,
            "script_source": script_source, "script_sha256": _hash_file(script),
            "gadget_apk": _planned(session, GADGET_APK_NAME, "The Gadget APK"),
            "signed_base": _planned(session, SIGNED_BASE_NAME, "The signed base APK"),
            "signed_splits": [_planned(session, SIGNED_SPLIT_NAME.format(index=index), "The signed split APK")
                              for index in range(1, len(splits) + 1)],
            "pcap": _planned(session, PCAP_NAME, "The captured PCAP"),
            "dump": _planned(session, FLOWS_DUMP_NAME, "The pulled flow dump"),
            "har": _planned(session, HAR_NAME, "The converted HAR")}


def _debug_identity(store, session, alias):
    """Materialise the one throwaway key the whole run signs with.

    apk-sign creates and deletes a debug key per invocation, which would give every APK a different
    certificate and break install-multiple, so the single key is kept for the run instead.
    """
    destination = _planned(session, DEBUG_KEYSTORE_NAME, "The throwaway debug keystore")
    request = SimpleNamespace(debug_keystore=True, keystore=str(destination), alias=alias)
    keystore, resolved_alias, store_pass, key_pass, generated = forge_apktool._keystore_arguments(request, store)
    return keystore, resolved_alias, store_pass, key_pass, generated


def _signing(args, store, session):
    if args.keystore and args.debug_keystore:
        raise ForgeError("Pass either --keystore for an existing identity or --debug-keystore for one throwaway key, "
                         "not both: gadget-capture keeps its debug key inside --path")
    if args.debug_keystore:
        keystore, alias, store_pass, key_pass, generated = _debug_identity(store, session, args.alias)
        if not generated:
            raise ForgeError("The requested debug identity was not created; pass --keystore with --alias instead")
        return {"keystore": keystore, "alias": alias, "store_env": STORE_ENV, "key_env": KEY_ENV,
                "environment": {STORE_ENV: store_pass, KEY_ENV: key_pass}, "generated": True}
    if not args.keystore:
        raise ForgeError("Provide --keystore with --alias and --store-pass-env, or pass --debug-keystore to create one "
                         "throwaway key for this run")
    keystore = _local_file(store, args.keystore, "--keystore")
    if not args.alias:
        raise ForgeError("Provide --alias for the supplied keystore")
    if not os.environ.get(args.store_pass_env or ""):
        raise ForgeError(f"Environment variable {args.store_pass_env!r} does not hold the keystore password; set it "
                         f"before running gadget-capture")
    return {"keystore": keystore, "alias": args.alias, "store_env": args.store_pass_env, "key_env": args.key_pass_env,
            "environment": {}, "generated": False}


def _tools():
    """Resolve every host tool the run needs before the first device call."""
    adb = executable("adb")
    frida = executable("frida")
    sibling = Path(frida).with_name("frida-ps.exe" if os.name == "nt" else "frida-ps")
    return {"adb": adb, "frida": frida, "frida_ps": str(sibling) if sibling.is_file() else "frida-ps"}


def _options(args, store):
    paths = _paths(args, store)
    return {**_target(args), **_limits(args), **paths, "identity": _signing(args, store, paths["session"]),
            **_tools()}


@contextmanager
def _environment(pairs):
    """Set temporary password environment variables around the signing calls, then restore them."""
    previous = {name: os.environ.get(name) for name in pairs}
    os.environ.update(pairs)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sleep(seconds):
    time.sleep(seconds)


# --------------------------------------------------------------------------- evidence helpers

class _Pipeline:
    """Ordered stage records for one run: each cites what it invoked and stops with an action."""

    def __init__(self, store, options):
        self.store = store
        self.options = options
        self.entries = []
        self.evidence = []
        self.worker = None
        self.state = None
        self.facts = None
        self.capture_id = None
        self.hook_observed = False
        self.hook_markers = []
        self.started = time.monotonic()
        self.deadline = self.started + options["budget"]

    def stage(self, name, data, *, kind, tool="frida", success=True, action=None, cited=()):
        if name not in STAGES:
            raise ForgeError(f"Unknown gadget-capture stage: {name}")
        cited = list(cited)
        payload = {"schema": SCHEMA, "tool": tool, "action": ACTION, "stage": name, "success": success,
                   "required_action": action, "scope": SCOPE, "limits": LIMITS, "evidence": cited,
                   "evidence_ids": sorted(set(self.evidence) | set(cited))}
        payload.update(data)
        record = self.store.add(kind, payload)
        self.entries.append({"stage": name, "success": success, "evidence": record["id"], "cited": cited,
                             "required_action": action})
        self.evidence.append(record["id"])
        return record

    def stop(self, stage, detail, action, *, data=None, kind="runtime", tool="frida", cited=()):
        """Record a failed stage, then stop the run with the required operator action."""
        record = self.stage(stage, {"error": detail, **(data or {})}, kind=kind, tool=tool, success=False,
                            action=action, cited=cited)
        self.raise_stop(record, detail, action, cited)
        return record

    def raise_stop(self, record, detail, action, cited=()):
        citation = f"; cited {', '.join(cited)}" if cited else ""
        raise ForgeError(f"gadget-capture stopped at the {record['data']['stage']} stage: {detail} "
                         f"Next: {action} Stage evidence {record['id']}{citation}")

    def check(self, stage):
        if time.monotonic() >= self.deadline:
            self.stop(stage, f"the whole-run budget of {self.options['budget']}s was already spent before this stage "
                             f"started", f"raise --budget (at most {MAX_BUDGET}s) or shorten --seconds, then rerun")

    # -- Frida side of the capture window ---------------------------------
    def start_hook(self, facts):
        self.state = {"stop": threading.Event(), "started": time.monotonic(),
                      "serial": _observed_serial(facts) or self.options["serial"]}
        self.worker = threading.Thread(target=self._hook_window, name="forge-gadget-hook", daemon=True)
        self.worker.start()

    def _hook_window(self):
        self.facts = _hook_window(self.state, self.options)

    def stop_hook(self, abort=False):
        """Wait for the Frida side, or abort it early when the window failed before the probe."""
        if self.worker is None:
            return self.facts
        if abort:
            self.state["stop"].set()
        self.worker.join(timeout=self.options["seconds"] + ATTACH_TAIL_SECONDS + FORWARD_SECONDS + POLL_TIMEOUT)
        if self.worker.is_alive():
            self.facts = {**(self.facts or {}), "abandoned": True}
        self.worker = None
        return self.facts


def _detail(error, limit=400):
    text = scrub_text(str(error)).strip() or "stage failed without a message"
    return text if len(text) <= limit else text[:limit] + "…"


def _cited_ids(error):
    return list(dict.fromkeys(EVIDENCE_ID.findall(str(error))))


def _cited_action(store, cited, fallback):
    """Reuse the invoked stage's own guidance as the next operator action."""
    for identifier in cited:
        try:
            data = store.get(identifier)["data"]
        except ForgeError:
            continue
        for key in ("required_action", "precondition", "error", "failure"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return fallback


def _call_text(call):
    value = call.get("stdout")
    return value if isinstance(value, str) else (value or b"").decode("utf-8", "replace")


def _call_summary(call):
    return {key: call.get(key) for key in ("returncode", "timed_out", "launch_error", "stdout", "stderr",
                                          "stdout_omitted_bytes", "stderr_omitted_bytes")}


def _first_line(text):
    for line in text.splitlines():
        if line.strip():
            return scrub_text(line.strip())[:300]
    return ""


def _observed_serial(facts):
    device = (facts or {}).get("device") or {}
    serial = device.get("serial")
    return serial if isinstance(serial, str) and serial else None


def _adb_prefix(options, serial=None):
    serial = serial or options["serial"]
    return [options["adb"], "-s", serial] if serial else [options["adb"]]


def _discard(path):
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


# --------------------------------------------------------------------------- stages

def _repackage(run):
    run.check("gadget")
    options = run.options
    request = SimpleNamespace(path=str(options["base"]), gadget=str(options["gadget"]),
                              output=str(options["gadget_apk"]), gadget_config=options["gadget_config"],
                              timeout=options["timeout"])
    try:
        record = forge_apktool.gadget(request, run.store)
    except ForgeError as error:
        cited = _cited_ids(error)
        run.stop("gadget", _detail(error), _cited_action(run.store, cited, "Fix the reported frida-apk repackaging "
                     "failure, then rerun with a new --path directory"), data={"apk_gadget_evidence": cited},
                 kind="analysis", cited=cited)
    data = record["data"]
    run.stage("gadget", {"apk_gadget_evidence": [record["id"]], "extract_native_libs_enabled":
                         data.get("extract_native_libs_enabled"), "gadget_abi": data.get("gadget_abi"),
                         "config_keys": data.get("config_keys"), "output_sha256": data.get("sha256")},
              kind="analysis", cited=[record["id"]])
    return record


def _sign(run):
    run.check("sign")
    options = run.options
    identity = options["identity"]
    sources = [options["gadget_apk"], *options["splits"]]
    destinations = [options["signed_base"], *options["signed_splits"]]
    records, digests = [], []
    with _environment(identity["environment"]):
        for source, destination in zip(sources, destinations):
            request = SimpleNamespace(path=str(source), output=str(destination), keystore=str(identity["keystore"]),
                                      alias=identity["alias"], store_pass_env=identity["store_env"],
                                      key_pass_env=identity["key_env"], debug_keystore=False,
                                      timeout=options["timeout"])
            try:
                record = forge_apktool.sign(request, run.store)
            except ForgeError as error:
                cited = _cited_ids(error)
                run.stop("sign", _detail(error), _cited_action(run.store, cited, "Fix the reported apk-sign failure, "
                             "then rerun with a new --path directory"), data={"apk_sign_evidence": cited},
                         kind="analysis", tool="apksigner", cited=cited)
            records.append(record["id"])
            digests.append(record["data"].get("sha256"))
    run.stage("sign", {"apk_sign_evidence": records, "signed": len(records), "identity_generated":
                       identity["generated"], "alias": identity["alias"], "output_sha256": digests},
              kind="analysis", tool="apksigner", cited=records)
    return [options["signed_base"], *options["signed_splits"]]


def _uninstall(run):
    run.check("uninstall")
    options = run.options
    call = _run([*_adb_prefix(options), "shell", "pm", "uninstall", options["package"]], options["timeout"])
    text = _call_text(call)
    absent = bool(ABSENT.search(text))
    if not absent and (not _ok(call) or FAILURE.search(text)):
        # MIUI reports DELETE_FAILED_INTERNAL_ERROR for a package that is already gone;
        # the goal is "no installed copy", so ask the package manager instead of the error text.
        path_call = _run([*_adb_prefix(options), "shell", "pm", "path", options["package"]], options["timeout"])
        # `pm path` exits 1 with empty output for an absent package on several Android builds.
        absent = "package:" not in _call_text(path_call)
        data_extra = {"pm_path_check": _call_summary(path_call)}
    else:
        data_extra = {}
    data = {"pm_uninstall": _call_summary(call), "absent": absent, **data_extra}
    if (not _ok(call) or FAILURE.search(text)) and not absent:
        run.stop("uninstall", _first_line(text) or "adb could not run pm uninstall", "Remove the installed copy before "
                 "reinstalling a differently signed build: fix the reported error, or pass --serial when more than one "
                 "device is attached, then rerun", data=data, tool="adb")
    run.stage("uninstall", data, kind="runtime", tool="adb")


def _install(run, signed):
    run.check("install")
    options = run.options
    request = SimpleNamespace(apk=[str(path) for path in signed], archive=None, member=[], serial=options["serial"],
                              timeout=options["timeout"], installer=INSTALLER)
    try:
        record = forge_android.adb_install_splits(request, run.store)
    except ForgeError as error:
        cited = _cited_ids(error)
        run.stop("install", _detail(error), _cited_action(run.store, cited, "Fix the reported installer failure and "
                     "retry: the whole set must be signed with one identity and match the observed API and ABI"),
                 data={"install_evidence": cited, "installer": INSTALLER}, tool="adb", cited=cited)
    run.stage("install", {"install_evidence": [record["id"]], "installer": INSTALLER, "apks": len(signed)},
              kind="runtime", tool="adb", cited=[record["id"]])


def _preflight(run):
    run.check("preflight")
    options = run.options
    request = SimpleNamespace(serial=options["serial"], package=options["package"])
    record = forge_pcapdroid.pcapdroid_preflight(request, run.store)
    data = record["data"]
    detail = {"preflight_evidence": [record["id"]], "status": data.get("status"),
              "capture_running": data.get("capture_running"),
              "mitm_addon_installed": (data.get("mitm_addon") or {}).get("installed"),
              "device": data.get("device")}
    if not data.get("success"):
        run.stop("preflight", f"PCAPdroid preflight reported {data.get('status')}", data.get("precondition") or
                 "Resolve the reported device and PCAPdroid prerequisite, then rerun", data=detail, tool="pcapdroid",
                 cited=[record["id"]])
    if data.get("capture_running"):
        run.stop("preflight", "a capture is already running on the device", "Stop the running PCAPdroid capture on the "
                 "device, then rerun", data=detail, tool="pcapdroid", cited=[record["id"]])
    if options["mitm"] and not detail["mitm_addon_installed"]:
        run.stop("preflight", "the PCAPdroid mitm addon is not installed", f"Install the PCAPdroid mitm addon "
                 f"({forge_pcapdroid.MITM_PACKAGE}) and its CA on the device, then rerun with --mitm", data=detail,
                 tool="pcapdroid", cited=[record["id"]])
    run.stage("preflight", detail, kind="runtime", tool="pcapdroid", cited=[record["id"]])
    return data


def _capture(run, facts):
    run.check("capture")
    options = run.options
    serial = _observed_serial(facts)
    remote = f"{forge_pcapdroid.DEVICE_DIRECTORY}/{FLOWS_DUMP_NAME}"
    removed = _run([*_adb_prefix(options, serial), "shell", "rm", "-f", remote], FORWARD_SECONDS)
    data = {"capture_name": options["pcap"].name, "remote": remote, "flows_dump_cleared": bool(_ok(removed)),
            "tls_decryption_requested": True, "launch_no_wait": True, "mitmproxy_opts": f"-w {remote}"}
    run.start_hook(facts)
    request = SimpleNamespace(package=options["package"], path=str(options["pcap"]),
                              serial=options["serial"] or serial, seconds=options["seconds"],
                              consent_timeout=CONSENT_SECONDS, repeat=1, gap=0, launch=options["component"],
                              force_stop=True, tls_decryption=True, continue_on_error=False,
                              mitmproxy_opts=f"-w {remote}", ssl_keylog=None, api_key_env=None,
                              max_bytes=options["max_bytes"], timeout=options["timeout"], launch_no_wait=True)
    try:
        record = forge_pcapdroid.pcapdroid_capture(request, run.store)
    except ForgeError as error:
        cited = _cited_ids(error)
        hook = _hook_stage(run, run.stop_hook(abort=True), stop=False)
        run.stop("capture", _detail(error), _cited_action(run.store, cited, "Resolve the reported capture "
                     "prerequisite, unlock the device, approve the PCAPdroid consent prompt, then rerun"),
                 data={**data, "capture_evidence": cited, "hook_evidence": [hook["id"]]}, tool="pcapdroid",
                 cited=[*cited, hook["id"]])
    run.capture_id = record["id"]
    hook_facts = run.stop_hook()
    run.stage("capture", {**data, "capture_evidence": [record["id"]]}, kind="runtime", tool="pcapdroid",
              cited=[record["id"]])
    return _hook_stage(run, hook_facts)


def _hook_stage(run, facts, *, stop=True):
    options = run.options
    facts = facts or {}
    observed = bool(facts.get("gadget_observed"))
    run.hook_observed = observed
    run.hook_markers = list(facts.get("markers") or [])
    attach = facts.get("attach") or {}
    data = {"gadget_observed": observed, "gadget_polls": facts.get("polls"), "markers": run.hook_markers,
            "script_loaded": bool(facts.get("script_loaded")), "script_source": options["script_source"],
            "script_sha256": options["script_sha256"], "attach_seconds": facts.get("attach_seconds"),
            "window_seconds": options["seconds"], "launch_wait": facts.get("launch_wait"),
            "hook_abandoned": bool(facts.get("abandoned")), "hook_error": facts.get("error"),
            "hook_output_omitted_bytes": attach.get("stdout_omitted_bytes"), "forward": facts.get("forward"),
            "gadget_probe": facts.get("gadget_probe"), "attach": attach}
    action = None if observed else HOOK_ACTION
    record = run.stage("hook", data, kind="runtime", success=observed, action=action)
    if stop and not observed:
        detail = f"the Gadget was not reachable after {facts.get('polls') or 0} probe(s)"
        if facts.get("error"):
            detail = f"{detail}: {facts['error']}"
        run.raise_stop(record, detail, HOOK_ACTION)
    return record


def _hook_window(state, options):
    """Runs on its own thread while the capture window is open; touches no evidence store."""
    facts = {"forward": None, "polls": 0, "gadget_observed": False, "markers": [], "script_loaded": False,
             "attach_seconds": None, "launch_wait": None, "error": None}
    prefix = _adb_prefix(options, state.get("serial"))
    try:
        facts["forward"] = _call_summary(_run([*prefix, "forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}"],
                                              FORWARD_SECONDS))
        facts["launch_wait"] = _await_launch(state, options, prefix)
        if state["stop"].is_set():
            return facts
        detection = _await_gadget(state, options)
        facts.update(detection)
        if not detection["gadget_observed"]:
            return facts
        remaining = options["seconds"] - max(0.0, time.monotonic() - detection["detected_at"])
        seconds = int(max(MIN_ATTACH_SECONDS, min(options["seconds"], remaining)))
        facts["attach_seconds"] = seconds
        call = _run([options["frida"], "-H", FRIDA_HOST, "-n", GADGET_PROCESS, "-l", str(options["script"]), "-q",
                     "-t", str(seconds), "--exit-on-error"], seconds + ATTACH_TAIL_SECONDS)
        text = _call_text(call)
        facts["attach"] = _call_summary(call)
        facts["markers"] = [marker for marker in SCRIPT_MARKERS if marker in text]
        facts["script_loaded"] = "forge-trust-bypass-loaded" in text
    except (ForgeError, OSError, ValueError) as error:
        facts["error"] = _detail(error)
    finally:
        if facts.get("forward"):
            _run([*prefix, "forward", "--remove", f"tcp:{FRIDA_PORT}"], FORWARD_SECONDS)
    return facts


def _await_launch(state, options, prefix):
    """Wait for this run's app process.

    The scripted launch happens inside the capture call, and stage (c) uninstalled the package first,
    so every observed process belongs to this run's launch.
    """
    deadline = time.monotonic() + min(MAX_LAUNCH_WAIT, CONSENT_SECONDS + options["seconds"] + 60)
    polls = 0
    while True:
        call = _run([*prefix, "shell", "pidof", options["package"]], FORWARD_SECONDS)
        text = _call_text(call)
        polls += 1
        if _ok(call) and DIGITS.search(text):
            return {"observed": True, "polls": polls}
        if not _ok(call) and MISSING_PIDOF.search(text):
            return {"observed": False, "polls": polls, "probe_unsupported": True}
        if state["stop"].is_set() or time.monotonic() >= deadline:
            return {"observed": False, "polls": polls}
        _sleep(POLL_SECONDS)


def _await_gadget(state, options):
    deadline = time.monotonic() + options["poll_seconds"]
    polls = 0
    while True:
        call = _run([options["frida_ps"], "-H", FRIDA_HOST], POLL_TIMEOUT)
        polls += 1
        if _ok(call) and GADGET_PROCESS in _call_text(call):
            return {"gadget_observed": True, "polls": polls, "detected_at": time.monotonic(),
                    "gadget_probe": _call_summary(call)}
        probe = _call_summary(call)
        if state["stop"].is_set() or time.monotonic() >= deadline:
            return {"gadget_observed": False, "polls": polls, "gadget_probe": probe}
        _sleep(POLL_SECONDS)


def _endpoints(exchanges):
    """Distinct request host+path pairs: host names only, paths counted and never stored."""
    pairs, hosts = set(), {}
    for record in exchanges:
        url = ((record.get("data") or {}).get("request") or {}).get("url")
        if not isinstance(url, str):
            continue
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        pairs.add((host, parts.path or "/"))
        hosts[host] = None
    names = sorted(hosts)
    return {"pairs": len(pairs), "hosts": names[:HOSTS_CAP], "omitted": max(0, len(names) - HOSTS_CAP)}


def _harvest(run, serial):
    run.check("flows")
    options = run.options
    remote = f"{forge_pcapdroid.DEVICE_DIRECTORY}/{FLOWS_DUMP_NAME}"
    call = _run([*_adb_prefix(options, serial), "pull", remote, str(options["dump"])], options["timeout"])
    size = options["dump"].stat().st_size if options["dump"].is_file() else 0
    data = {"pull": _call_summary(call), "remote": remote, "dump_size": size}
    if not _ok(call):
        run.stop("flows", f"adb could not pull {remote}: {_first_line(_call_text(call)) or 'no output'}", FLOWS_ACTION,
                 data=data, tool="mitmproxy")
    if size == 0:
        run.stop("flows", f"the retrieved flow dump is empty ({remote})", FLOWS_ACTION, data=data, tool="mitmproxy")
    request = SimpleNamespace(path=str(options["dump"]), output=str(options["har"]), limit=HAR_LIMIT,
                              max_body_bytes=HAR_BODY_BYTES, reader="builtin")
    try:
        flows_record = forge_flows.flow_to_har(request, run.store)
    except ForgeError as error:
        cited = _cited_ids(error)
        run.stop("flows", _detail(error), _cited_action(run.store, cited, "Fix the reported flow-to-har rejection "
                     "or capture a fresh window, then rerun"),
                 data={**data, "flow_to_har_evidence": cited}, tool="mitmproxy", cited=cited)
    try:
        imported = forge_network.handle_har_import(SimpleNamespace(har=str(options["har"]), limit=HAR_LIMIT,
                                                                  max_body=HAR_BODY_BYTES, rules=None), run.store)
    except ForgeError as error:
        run.stop("flows", _detail(error), "Inspect the converted HAR and the flow-to-har evidence, then fix the "
                 "reported import rejection and rerun",
                 data={**data, "flow_to_har_evidence": [flows_record["id"]], "har_import_evidence":
                       _cited_ids(error)}, tool="mitmproxy", cited=[flows_record["id"], *_cited_ids(error)])
    exchanges = imported["exchanges"]
    endpoints = _endpoints(exchanges)
    ids = [record["id"] for record in exchanges[:EXCHANGE_IDS]]
    data.update({"flow_to_har_evidence": [flows_record["id"]], "har_name": options["har"].name,
                 "flows": flows_record["data"].get("flows"), "flows_skipped": flows_record["data"].get("flows_skipped"),
                 "bodies_truncated": flows_record["data"].get("bodies_truncated"),
                 "har_reader": flows_record["data"].get("reader"), "har_imported": imported["imported"],
                 "har_available": imported["available"], "har_omitted": imported["omitted"],
                 "endpoints_hint": endpoints["pairs"], "hosts": endpoints["hosts"],
                 "hosts_omitted": endpoints["omitted"], "exchanges": ids,
                 "exchanges_omitted": max(0, len(exchanges) - len(ids))})
    run.stage("flows", data, kind="runtime", tool="mitmproxy", cited=[flows_record["id"], *ids])
    return {"flows": flows_record["data"].get("flows") or 0, "imported": imported["imported"],
            "flows_skipped": flows_record["data"].get("flows_skipped") or 0,
            "bodies_truncated": flows_record["data"].get("bodies_truncated") or 0,
            "endpoints_hint": endpoints["pairs"], "hosts": endpoints["hosts"], "hosts_omitted": endpoints["omitted"],
            "exchanges": ids, "exchanges_omitted": max(0, len(exchanges) - len(ids))}


def _summary(run, harvest):
    installed = any(entry["stage"] == "install" and entry["success"] for entry in run.entries)
    action = None
    if harvest["flows"] == 0:
        action = ("No decrypted exchange reached the HAR. Read the capture evidence for TLS client rejections, confirm "
                  "the app made requests inside the window, then rerun with a longer --seconds")
    stage_evidence = {entry["stage"]: [entry["evidence"], *entry["cited"]] for entry in run.entries}
    cited = list(dict.fromkeys([entry["evidence"] for entry in run.entries]
                               + [identifier for entry in run.entries for identifier in entry["cited"]]))
    data = {"installed": installed, "capture_id": run.capture_id, "flows": harvest["flows"],
            "har_imported": harvest["imported"], "endpoints_hint": harvest["endpoints_hint"],
            "hosts": harvest["hosts"], "hosts_omitted": harvest["hosts_omitted"],
            "gadget_observed": run.hook_observed, "hooks_observed": run.hook_markers,
            "flows_skipped": harvest["flows_skipped"], "bodies_truncated": harvest["bodies_truncated"],
            "exchanges": harvest["exchanges"], "exchanges_omitted": harvest["exchanges_omitted"],
            "stage_evidence": stage_evidence, "budget_seconds": run.options["budget"],
            "elapsed_seconds": round(time.monotonic() - run.started, 2), "required_action": action}
    return run.stage("summary", data, kind="analysis", action=action, cited=cited)


# --------------------------------------------------------------------------- command

def gadget_capture(args, store):
    forge_tasks.check_scope(store, "gadget-capture", device=True, network=True)
    options = _options(args, store)
    run = _Pipeline(store, options)
    try:
        _repackage(run)
        signed = _sign(run)
        _uninstall(run)
        _install(run, signed)
        facts = _preflight(run)
        _capture(run, facts)
        return _summary(run, _harvest(run, _observed_serial(facts) or options["serial"]))
    finally:
        run.stop_hook(abort=True)
        if options["identity"]["generated"]:
            _discard(options["identity"]["keystore"])


def register(subparsers):
    parser = subparsers.add_parser("gadget-capture",
                                   help="Run the whole Gadget route in one bounded pipeline: repackage, sign, install, "
                                        "capture with TLS decryption, attach the trust bypass, then pull, convert and "
                                        "import the decrypted flows")
    parser.add_argument("--package", required=True, help="Installed app package, for example ai.x.grok")
    parser.add_argument("--component", required=True,
                        help="PACKAGE/ACTIVITY to launch without -W, for example ai.x.grok/.MainActivity")
    parser.add_argument("--apk", action="append", required=True, metavar="APK",
                        help="Project-local base APK first, then each split APK; repeatable")
    parser.add_argument("--gadget", required=True, help="Project-local frida-gadget .so matching the device ABI")
    parser.add_argument("--gadget-config", action="append", metavar="KEY=VALUE",
                        help="Gadget interaction option passed to apk-gadget; default: on_load=wait so the script "
                             "attaches before the app builds its TLS context")
    parser.add_argument("--path", required=True,
                        help="Existing project-local directory for this run's Gadget APK, signed APKs, PCAP, flow dump "
                             "and HAR; each run needs a fresh directory")
    parser.add_argument("--script", default=BUILTIN,
                        help="Project-local Frida script, or 'builtin' for the shipped trust bypass (default)")
    parser.add_argument("--seconds", type=int, default=15,
                        help=f"Bounded capture window in seconds (1..{forge_pcapdroid.MAX_SECONDS}, default: 15)")
    parser.add_argument("--serial", help="Explicit ADB serial when device selection is ambiguous")
    parser.add_argument("--mitm", action="store_true",
                        help="Also require the PCAPdroid mitm addon at preflight; the capture itself always runs with "
                             "TLS decryption and the addon flow dump")
    parser.add_argument("--keystore", help="Existing project-local keystore used for every APK in the run")
    parser.add_argument("--alias", help="Key alias inside --keystore, or the debug key alias")
    parser.add_argument("--store-pass-env", default="FORGE_KEYSTORE_PASS",
                        help="Environment variable holding the store password; never stored in evidence")
    parser.add_argument("--key-pass-env", default="FORGE_KEY_PASS", help="Environment variable holding the key password")
    parser.add_argument("--debug-keystore", action="store_true",
                        help="Create one throwaway key for this run instead of using --keystore")
    parser.add_argument("--max-bytes", type=int, default=33554432,
                        help=f"Device dump and retrieval byte cap ({forge_pcapdroid.MIN_FILE_BYTES}.."
                             f"{forge_pcapdroid.MAX_FILE_BYTES}, default: 33554432)")
    parser.add_argument("--poll-seconds", type=int, default=MAX_POLL_SECONDS,
                        help=f"Seconds to wait for the Gadget once the app process is up (1..{MAX_POLL_SECONDS}, "
                             f"default: {MAX_POLL_SECONDS})")
    parser.add_argument("--timeout", type=int, default=120, help="Seconds per bounded stage call (1..3600)")
    parser.add_argument("--budget", type=int, default=1800,
                        help=f"Whole-run timeout budget in seconds ({MIN_BUDGET}..{MAX_BUDGET}, default: 1800)")
    parser.set_defaults(handler=gadget_capture)
