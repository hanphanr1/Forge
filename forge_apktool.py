"""APK decode, manifest summary, rebuild, signing and Gadget repackaging for authorized patch work.

Every command here works on explicitly supplied project-local inputs, refuses to
overwrite existing outputs and records what actually ran. Nothing is downloaded,
and no signing identity is invented silently: the caller either supplies a
keystore or explicitly asks for a local debug key. Gadget repackaging is the only
Frida route that works on a device without root, and it records the changes that
route forces on the build (debuggable flag, replaced signature) instead of
presenting the result as the original app.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
import zipfile

from forge_core import ForgeError, scrub_text
from forge_toolchain import find_tool

SCHEMA = "forge.apk/v1"
ANDROID = "http://schemas.android.com/apk/res/android"
MAX_OUTPUT = 256 * 1024
MAX_COMPONENTS = 500
MAX_VALIDITY_DAYS = 3650
DEBUG_ALIAS = "androiddebugkey"
DEBUG_PASSWORD = "android"
COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
GADGET_NAME = "libfridagadget.so"
GADGET_CONFIG_NAME = "libfridagadget.config.so"
WRAP_NAME = "wrap.sh"
MAX_GADGET = 64 * 1024 * 1024
GADGET_ABIS = {3: "x86", 40: "armeabi-v7a", 62: "x86_64", 183: "arm64-v8a", 243: "riscv64"}
_GADGET_SCOPE = ("Gadget repackaging sets android:debuggable=true, adds lib/<abi>/wrap.sh, libfridagadget.so and its "
                 "config, and replaces the original signature. Installing it needs a signed APK and removing any "
                 "installed copy of the same package, which deletes that app's data. The debuggable flag and the new "
                 "signature are visible to the app, so integrity, tamper and anti-fraud checks may refuse or answer "
                 "differently: hook output from this build is evidence about a modified build, not about the official "
                 "one.")


def _input(store, value, suffix=None):
    if not value:
        raise ForgeError("Provide a project-local input path")
    path = Path(value).expanduser()
    path = (path if path.is_absolute() else store.root / path).resolve()
    if not path.is_relative_to(store.root.resolve()):
        raise ForgeError("Input must stay inside the project")
    if path.is_symlink():
        raise ForgeError("Symlinked inputs are not allowed")
    if suffix and not path.is_file():
        raise ForgeError(f"Input must be one regular file ({suffix})")
    return path


def _new_output(store, value, suffix=None, label="Output"):
    if not value:
        raise ForgeError(f"Provide --output for the {label.lower()}")
    path = Path(value).expanduser()
    path = (path if path.is_absolute() else store.root / path).resolve()
    if not path.is_relative_to(store.root.resolve()):
        raise ForgeError(f"{label} must stay inside the project")
    if path.exists():
        raise ForgeError(f"{label} already exists; choose a new project-local path")
    if suffix and path.suffix.lower() != suffix:
        raise ForgeError(f"{label} must keep the {suffix} suffix")
    for part in (*reversed(path.parent.parents), path.parent):
        if part.is_symlink():
            raise ForgeError(f"Symlinked output directories are not allowed: {part}")
    if not path.parent.is_dir():
        raise ForgeError("Output directory does not exist")
    return path


def _relative(store, path):
    return path.relative_to(store.root.resolve()).as_posix()


def _run(command, timeout, cwd=None):
    if not 0 < timeout <= 3600:
        raise ForgeError("Timeout must be greater than 0 and at most 3600 seconds")
    try:
        completed = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        return None, (error.stdout or b"")[:MAX_OUTPUT], (error.stderr or b"")[:MAX_OUTPUT], True
    except OSError as error:
        raise ForgeError(f"Cannot launch patching tool: {error}") from error
    return (completed.returncode, completed.stdout[:MAX_OUTPUT], completed.stderr[:MAX_OUTPUT], False)


def _tool(name):
    tool = find_tool(name)
    if not tool["available"]:
        raise ForgeError(f"Missing {name} ({tool['source']}): {tool['setup']}")
    return tool


def _copy_bounded(source, destination):
    digest, size = hashlib.sha256(), 0
    with source.open("rb") as reader, destination.open("xb") as writer:
        while True:
            block = reader.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
            writer.write(block)
    return digest.hexdigest(), size


def _staged(store, source):
    directory = Path(tempfile.mkdtemp(prefix="forge-apk-", dir=store.directory))
    staged = directory / source.name
    digest, size = _copy_bounded(source, staged)
    return directory, staged, digest, size


def _hash_file(path):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as reader:
        for block in iter(lambda: reader.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _gadget_abi(path, size):
    if size > MAX_GADGET:
        raise ForgeError(f"Gadget exceeds the {MAX_GADGET} byte cap; supply one frida-gadget shared object")
    with path.open("rb") as reader:
        header = reader.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ForgeError("Gadget must be an ELF shared object such as frida-gadget-<version>-android-arm64.so")
    elf_class = header[4]
    kind = struct.unpack_from("<H", header, 16)[0]
    machine = struct.unpack_from("<H", header, 18)[0]
    if elf_class not in (1, 2):
        raise ForgeError("Gadget has an invalid ELF class byte")
    if kind != 3:
        raise ForgeError("Gadget must be a shared object (ET_DYN); an executable will not load as a gadget")
    abi = GADGET_ABIS.get(machine)
    if abi is None:
        raise ForgeError(f"Gadget targets machine 0x{machine:02x}, which is not a supported Android ABI")
    return abi, 64 if elf_class == 2 else 32


def _member_digest(archive, name):
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _package_name(path):
    try:
        import forge_android
        return forge_android.inspect_apk(path)["package"]
    except (ForgeError, OSError, KeyError):
        return None


def _inspect_gadget_output(path, abi):
    required = [f"lib/{abi}/{GADGET_NAME}", f"lib/{abi}/{WRAP_NAME}", f"lib/{abi}/{GADGET_CONFIG_NAME}"]
    try:
        with zipfile.ZipFile(path) as archive:
            names = {entry.filename for entry in archive.infolist()}
            missing = [name for name in required if name not in names]
            if "AndroidManifest.xml" not in names:
                missing.append("AndroidManifest.xml")
            if missing:
                raise ForgeError("Repackaged APK is missing " + ", ".join(sorted(missing)))
            embedded = _member_digest(archive, f"lib/{abi}/{GADGET_NAME}")
            count = len(names)
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ForgeError(f"Repackaged APK is not a readable archive: {error}") from error
    return embedded, count, _package_name(path)


def decode(args, store):
    source = _input(store, args.path)
    if not source.is_file():
        raise ForgeError("apk-decode requires one regular project-local APK/APKS/JAR input")
    destination = _new_output(store, args.output, label="Output directory")
    destination.mkdir()
    tool = _tool("apktool")
    command = [tool["path"], "d", "--force", "-o", str(destination)]
    if args.no_sources:
        command.append("--no-src")
    if args.no_resources:
        command.append("--no-res")
    command.append(str(source))
    code, stdout, stderr, expired = _run(command, args.timeout)
    manifest = destination / "AndroidManifest.xml"
    success = code == 0 and not expired and manifest.is_file()
    record = store.add("analysis", {"schema": SCHEMA, "tool": "apktool", "action": "decode",
                                    "input": _relative(store, source), "output_path": _relative(store, destination),
                                    "executable": tool["path"], "tool_source": tool["source"],
                                    "success": success, "returncode": code, "timed_out": expired,
                                    "stdout": scrub_text(stdout.decode("utf-8", "replace")),
                                    "stderr": scrub_text(stderr.decode("utf-8", "replace")),
                                    "scope": "Decoded sources and resources only; no rebuild, signing or install "
                                             "is implied"})
    if not success:
        raise ForgeError(f"apktool decode failed; evidence {record['id']}")
    return record


def _attributes(element):
    values = {}
    for name, value in element.attrib.items():
        key = tuple(name[1:].split("}", 1)) if name.startswith("{") else (None, name)
        values[key] = value
    return values


def _summarize(element):
    root_attrs = _attributes(element)
    if (None, "package") not in root_attrs:
        raise ForgeError("Manifest has no package attribute")
    permissions, features, components, deeplinks = [], [], [], []
    application = element.find("application")
    if application is not None:
        permissions = sorted({value for key, value in _attributes(application).items()
                              if key == (ANDROID, "permission") or key[1] == "permission"})
    for child in element.findall("uses-permission"):
        name = _attributes(child).get((ANDROID, "name"))
        if name:
            permissions.append(name)
    for child in element.findall("uses-feature"):
        name = _attributes(child).get((ANDROID, "name"))
        if name:
            features.append(name)
    launcher = None
    for parent in ([application] if application is not None else []):
        for component in parent:
            tag = component.tag
            if tag not in COMPONENT_TAGS:
                continue
            attrs = _attributes(component)
            name = attrs.get((ANDROID, "name"))
            if not name:
                continue
            exported = attrs.get((ANDROID, "exported"))
            actions, categories, schemes, hosts = [], [], [], []
            for group in component.findall("intent-filter"):
                group_attrs = _attributes(group)
                if group_attrs.get((ANDROID, "autoVerify")) == "true":
                    pass
                for item in group:
                    item_attrs = _attributes(item)
                    if item.tag == "action" and item_attrs.get((ANDROID, "name")):
                        actions.append(item_attrs[(ANDROID, "name")])
                    elif item.tag == "category" and item_attrs.get((ANDROID, "name")):
                        categories.append(item_attrs[(ANDROID, "name")])
                    elif item.tag == "data":
                        if item_attrs.get((ANDROID, "scheme")):
                            schemes.append(item_attrs[(ANDROID, "scheme")])
                        if item_attrs.get((ANDROID, "host")):
                            hosts.append(item_attrs[(ANDROID, "host")])
            is_launcher = ("android.intent.action.MAIN" in actions
                           and "android.intent.category.LAUNCHER" in categories)
            if is_launcher and launcher is None:
                launcher = f"{root_attrs[(None, 'package')]}/{name}"
            entry = {"tag": tag, "name": name, "exported": exported if exported in {"true", "false"} else None,
                     "exported_declared": exported in {"true", "false"},
                     "has_intent_filter": any(True for _ in component.findall("intent-filter")),
                     "actions": sorted(set(actions)), "categories": sorted(set(categories)),
                     "schemes": sorted(set(schemes)), "hosts": sorted(set(hosts)),
                     "permission": attrs.get((ANDROID, "permission"))}
            if entry["has_intent_filter"] and entry["exported"] is None:
                entry["note"] = "intent filter without an explicit android:exported declaration"
            components.append(entry)
            for scheme in sorted(set(schemes)):
                if scheme not in {"http", "https"} or hosts:
                    deeplinks.append({"component": name, "scheme": scheme, "hosts": sorted(set(hosts))})
    omitted = max(0, len(components) - MAX_COMPONENTS)
    components = components[:MAX_COMPONENTS]
    return {"package": root_attrs[(None, "package")], "launcher": launcher,
            "permissions": sorted(set(permissions)), "features": sorted(set(features)),
            "components": components, "components_omitted": omitted, "deeplinks": deeplinks}


def _decoded_manifest(path):
    try:
        return ET.fromstring(path.read_bytes())
    except ET.ParseError as error:
        raise ForgeError(f"Decoded AndroidManifest.xml is not plain XML: {error}") from error


def manifest(args, store):
    target = _input(store, args.path)
    if target.is_dir():
        candidate = target / "AndroidManifest.xml"
        if not candidate.is_file():
            raise ForgeError("Directory has no decoded AndroidManifest.xml at its root")
        target = candidate
    if not target.is_file():
        raise ForgeError("apk-manifest requires a decoded AndroidManifest.xml, a decoded directory, or an APK")
    if target.suffix.lower() in {".apk", ".apks", ".xapk"}:
        import forge_android
        metadata = forge_android.inspect_apk(target)
        summary = {"package": metadata["package"], "launcher": None, "permissions": [], "features": [],
                   "components": [], "components_omitted": 0, "deeplinks": [],
                   "note": "Compiled manifest: only literal values readable by the bounded parser are shown. "
                           "Decode the APK to read permissions, components and intent filters."}
    else:
        summary = _summarize(_decoded_manifest(target))
    record = store.add("analysis", {"schema": SCHEMA, "tool": "apktool", "action": "manifest",
                                    "input": _relative(store, target), "success": True,
                                    "summary": summary,
                                    "scope": "Observed declaration only. A declared component, permission or "
                                             "deeplink is not proof of a reachable or exploitable path."})
    return record


def rebuild(args, store):
    directory = _input(store, args.path)
    if not directory.is_dir():
        raise ForgeError("apk-rebuild requires a decoded project-local directory")
    if not (directory / "AndroidManifest.xml").is_file():
        raise ForgeError("Directory has no AndroidManifest.xml at its root")
    output = _new_output(store, args.output, suffix=".apk", label="Rebuilt APK")
    tool = _tool("apktool")
    staging = Path(tempfile.mkdtemp(prefix="forge-apk-build-", dir=store.directory))
    built = staging / "rebuilt.apk"
    command = [tool["path"], "b", str(directory), "-o", str(built)]
    if args.use_aapt2:
        command.append("--use-aapt2")
    if args.debug:
        command.append("--debug")
    try:
        code, stdout, stderr, expired = _run(command, args.timeout)
        success = code == 0 and not expired and built.is_file()
        digest = size = None
        if success:
            digest, size = _copy_bounded(built, output)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    record = store.add("analysis", {"schema": SCHEMA, "tool": "apktool", "action": "rebuild",
                                    "input": _relative(store, directory), "output_path": _relative(store, output),
                                    "executable": tool["path"], "tool_source": tool["source"],
                                    "success": success, "returncode": code, "timed_out": expired,
                                    "sha256": digest, "size": size,
                                    "stdout": scrub_text(stdout.decode("utf-8", "replace")),
                                    "stderr": scrub_text(stderr.decode("utf-8", "replace")),
                                    "scope": "Rebuilt bytes are not signed and not installable until apk-sign "
                                             "succeeds; content changes are not attributed to FORGE"})
    if not success:
        raise ForgeError(f"apktool rebuild failed; evidence {record['id']}")
    return record


def _keystore_arguments(args, store):
    if args.debug_keystore:
        keystore = _new_output(store, args.keystore or f"debug-{args.alias or DEBUG_ALIAS}.keystore",
                               suffix=".keystore", label="Debug keystore")
        keytool = _tool("java")
        java_home = Path(keytool["path"]).parent
        keytool_path = java_home / ("keytool.exe" if os.name == "nt" else "keytool")
        if not keytool_path.is_file():
            keytool_path = Path(shutil.which("keytool") or keytool_path)
        command = [str(keytool_path), "-genkeypair", "-keystore", str(keystore), "-alias", args.alias or DEBUG_ALIAS,
                   "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000", "-storepass", DEBUG_PASSWORD,
                   "-keypass", DEBUG_PASSWORD, "-dname", "CN=FORGE Debug, OU=Authorized testing, O=Local, C=NA"]
        code, stdout, stderr, expired = _run(command, 120)
        if code != 0 or expired or not keystore.is_file():
            keystore.unlink(missing_ok=True)
            raise ForgeError("Could not create the local debug keystore; supply --keystore instead")
        return keystore, args.alias or DEBUG_ALIAS, DEBUG_PASSWORD, DEBUG_PASSWORD, True
    if not args.keystore:
        raise ForgeError("Provide --keystore, or pass --debug-keystore to create a local throwaway key")
    keystore = _input(store, args.keystore)
    if not keystore.is_file():
        raise ForgeError("Keystore file does not exist")
    alias = args.alias
    if not alias:
        raise ForgeError("Provide --alias for the supplied keystore")
    return keystore, alias, os.environ.get(args.store_pass_env or "", None), os.environ.get(args.key_pass_env or "", None), False


def sign(args, store):
    source = _input(store, args.path)
    if not source.is_file() or source.suffix.lower() != ".apk":
        raise ForgeError("apk-sign requires one regular project-local .apk input")
    output = _new_output(store, args.output, suffix=".apk", label="Signed APK")
    keystore, alias, store_password, key_password, generated = _keystore_arguments(args, store)
    if not generated and not store_password:
        raise ForgeError(f"Store password environment {args.store_pass_env!r} is empty or unset")
    align_tool, signer_tool = _tool("zipalign"), _tool("apksigner")
    staging = Path(tempfile.mkdtemp(prefix="forge-apk-sign-", dir=store.directory))
    aligned = staging / "aligned.apk"
    signed = staging / "signed.apk"
    steps = {}
    try:
        code, stdout, stderr, expired = _run([align_tool["path"], "-f", "-p", "4", str(source), str(aligned)], args.timeout)
        steps["zipalign"] = {"returncode": code, "timed_out": expired,
                             "stdout": scrub_text(stdout.decode("utf-8", "replace")),
                             "stderr": scrub_text(stderr.decode("utf-8", "replace"))}
        if code != 0 or expired:
            raise ForgeError("zipalign failed; no signed output was produced")
        command = [signer_tool["path"], "sign", "--ks", str(keystore), "--ks-key-alias", alias,
                   "--ks-pass", f"pass:{store_password}", "--key-pass", f"pass:{key_password}",
                   "--out", str(signed), str(aligned)]
        code, stdout, stderr, expired = _run(command, args.timeout)
        steps["apksigner"] = {"returncode": code, "timed_out": expired,
                              "stdout": scrub_text(stdout.decode("utf-8", "replace")),
                              "stderr": scrub_text(stderr.decode("utf-8", "replace"))}
        if code != 0 or expired or not signed.is_file():
            raise ForgeError("apksigner failed; no signed output was produced")
        verify = [signer_tool["path"], "verify", "--verbose", "--print-certs", str(signed)]
        code, stdout, stderr, expired = _run(verify, args.timeout)
        steps["verify"] = {"returncode": code, "timed_out": expired,
                           "stdout": scrub_text(stdout.decode("utf-8", "replace")),
                           "stderr": scrub_text(stderr.decode("utf-8", "replace"))}
        verified = code == 0 and not expired
        if not verified:
            raise ForgeError("apksigner verify did not accept the produced signature")
        digest, size = _copy_bounded(signed, output)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        if generated:
            keystore.unlink(missing_ok=True)
    record = store.add("analysis", {"schema": SCHEMA, "tool": "apksigner", "action": "sign",
                                    "input": _relative(store, source), "output_path": _relative(store, output),
                                    "sha256": digest, "size": size, "verified": verified,
                                    "debug_identity": generated, "alias": alias,
                                    "steps": {name: {key: value for key, value in step.items() if key != "stdout"}
                                              for name, step in steps.items()},
                                    "scope": "Signing proves key possession for these bytes only. A debug identity is "
                                             "not a release identity and does not authorize distribution."})
    return record


def gadget(args, store):
    source = _input(store, args.path)
    if not source.is_file() or source.suffix.lower() != ".apk":
        raise ForgeError("apk-gadget requires one regular project-local .apk input")
    shared_object = _input(store, args.gadget)
    if not shared_object.is_file() or shared_object.suffix.lower() != ".so":
        raise ForgeError("Provide one project-local frida-gadget shared object with --gadget")
    gadget_digest, gadget_size = _hash_file(shared_object)
    abi, bitness = _gadget_abi(shared_object, gadget_size)
    config = []
    for item in args.gadget_config or []:
        key, separator, value = item.partition("=")
        key = key.strip()
        if not separator or not key or not value:
            raise ForgeError("--gadget-config expects KEY=VALUE, for example on_load=wait")
        config.append((key, value))
    output = _new_output(store, args.output, suffix=".apk", label="Gadget APK")
    tool = _tool("frida_apk")
    package_before = _package_name(source)
    staging = Path(tempfile.mkdtemp(prefix="forge-apk-gadget-", dir=store.directory))
    staged = staging / "gadget.apk"
    command = [tool["path"], "-g", str(shared_object), "-o", str(staged)]
    for key, value in config:
        command += ["-c", f"{key}={value}"]
    command.append(str(source))
    embedded = package_after = None
    entry_count = 0
    failure = None
    digest = size = None
    try:
        code, stdout, stderr, expired = _run(command, args.timeout)
        produced = code == 0 and not expired and staged.is_file()
        if not produced:
            failure = "frida-apk did not produce an APK"
        else:
            try:
                embedded, entry_count, package_after = _inspect_gadget_output(staged, abi)
            except ForgeError as error:
                failure = str(error)
        if failure is None and embedded != gadget_digest:
            failure = "The gadget inside the repackaged APK does not match the supplied shared object"
        if failure is None and package_before and package_after and package_before != package_after:
            failure = f"Repackaging changed the package name ({package_before} -> {package_after})"
        success = failure is None
        if success:
            digest, size = _copy_bounded(staged, output)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    record = store.add("analysis", {"schema": SCHEMA, "tool": "frida-apk", "action": "apk-gadget",
                                    "input": _relative(store, source), "gadget": _relative(store, shared_object),
                                    "output_path": _relative(store, output), "executable": tool["path"],
                                    "tool_source": tool["source"], "success": success, "failure": failure,
                                    "returncode": code, "timed_out": expired,
                                    "gadget_sha256": gadget_digest, "gadget_size": gadget_size, "gadget_abi": abi,
                                    "gadget_bitness": bitness, "config_keys": [key for key, _ in config],
                                    "package_before": package_before, "package_after": package_after,
                                    "embedded_gadget_matches": embedded == gadget_digest,
                                    "injected_members": [f"lib/{abi}/{GADGET_NAME}", f"lib/{abi}/{WRAP_NAME}",
                                                         f"lib/{abi}/{GADGET_CONFIG_NAME}"],
                                    "archive_entries": entry_count,
                                    "sha256": digest, "size": size,
                                    "stdout": scrub_text(stdout.decode("utf-8", "replace")),
                                    "stderr": scrub_text(stderr.decode("utf-8", "replace")),
                                    "scope": _GADGET_SCOPE})
    if not success:
        raise ForgeError(f"apk-gadget failed: {failure}; evidence {record['id']}")
    return record


def register(subparsers):
    parser = subparsers.add_parser("apk-decode", help="Decode an APK into project-local sources and resources with apktool")
    parser.add_argument("path")
    parser.add_argument("--output", required=True)
    parser.add_argument("--no-sources", action="store_true", help="Skip dex disassembly")
    parser.add_argument("--no-resources", action="store_true", help="Skip resource decoding")
    parser.add_argument("--timeout", type=float, default=900)
    parser.set_defaults(handler=decode)

    parser = subparsers.add_parser("apk-manifest", help="Summarize declared permissions, components and deeplinks")
    parser.add_argument("path")
    parser.set_defaults(handler=manifest)

    parser = subparsers.add_parser("apk-rebuild", help="Rebuild a decoded directory into an unsigned APK")
    parser.add_argument("path")
    parser.add_argument("--output", required=True)
    parser.add_argument("--use-aapt2", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--timeout", type=float, default=900)
    parser.set_defaults(handler=rebuild)

    parser = subparsers.add_parser("apk-gadget", help="Repackage an APK with a Frida Gadget for hooking without root")
    parser.add_argument("path")
    parser.add_argument("--gadget", required=True, help="Project-local frida-gadget .so matching the device ABI")
    parser.add_argument("--output", required=True)
    parser.add_argument("--gadget-config", action="append", default=[], metavar="KEY=VALUE",
                        help="Gadget interaction option; values stay in the APK and out of evidence")
    parser.add_argument("--timeout", type=float, default=600)
    parser.set_defaults(handler=gadget)

    parser = subparsers.add_parser("apk-sign", help="Zipalign and sign a rebuilt APK, then verify the signature")
    parser.add_argument("path")
    parser.add_argument("--output", required=True)
    parser.add_argument("--keystore", help="Existing project-local keystore")
    parser.add_argument("--alias")
    parser.add_argument("--store-pass-env", default="FORGE_KEYSTORE_PASS")
    parser.add_argument("--key-pass-env", default="FORGE_KEY_PASS")
    parser.add_argument("--debug-keystore", action="store_true",
                        help="Create and delete a throwaway local debug key for this run")
    parser.add_argument("--timeout", type=float, default=600)
    parser.set_defaults(handler=sign)
