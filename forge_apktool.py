"""APK decode, manifest summary, rebuild and signing for authorized patch work.

Every command here works on explicitly supplied project-local inputs, refuses to
overwrite existing outputs and records what actually ran. Nothing is downloaded,
and no signing identity is invented silently: the caller either supplies a
keystore or explicitly asks for a local debug key.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET

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
