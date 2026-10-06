from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from forge_core import ForgeError
from forge_toolchain import executable


SCHEMA = "forge.android.v1"
ANDROID = "http://schemas.android.com/apk/res/android"
MAX_INPUT = 512 * 1024 * 1024
MAX_UNCOMPRESSED = 1024 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_MANIFEST = 4 * 1024 * 1024
MAX_OUTPUT = 256 * 1024
MAX_APKS = 128
NO_INDEX = 0xffffffff


def _regular_path(root, value):
    path = Path(value).expanduser()
    if path.drive and not path.is_absolute():
        raise ForgeError("Drive-relative input paths are not allowed")
    path = Path(os.path.abspath(path if path.is_absolute() else root / path))
    if os.name == "nt" and (str(path).startswith("\\\\") or ":" in str(path)[2:]):
        raise ForgeError("Use local regular files, not device, UNC or alternate-stream paths")
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except OSError as error:
            raise ForgeError(f"Cannot access input {path}: {error}") from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ForgeError(f"Symlink/reparse input paths are not allowed: {part}")
    if not stat.S_ISREG(info.st_mode):
        raise ForgeError(f"Input is not a regular file: {path}")
    if not 0 < info.st_size <= MAX_INPUT:
        raise ForgeError("Input byte cap exceeded or input is empty")
    return path


def _member_name(name):
    if not name or "\\" in name or ":" in name or any(ord(c) < 32 for c in name):
        raise ForgeError(f"Unsafe ZIP member name: {name!r}")
    parts = (name[:-1] if name.endswith("/") else name).split("/")
    if name.startswith("/") or any(p in {"", ".", ".."} for p in parts):
        raise ForgeError(f"Unsafe ZIP member name: {name!r}")
    return name


def _zip_index(path):
    # Bound the central directory before ZipFile allocates its entry objects.
    with path.open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - 65557))
        footer = stream.read(65557)
    offset = footer.rfind(b"PK\x05\x06")
    if offset < 0 or offset + 22 > len(footer):
        raise ForgeError("Missing ZIP end-of-directory record")
    disk, cd_disk, disk_count, count, cd_size, cd_offset, comment_size = struct.unpack_from("<4H2IH", footer, offset + 4)
    if offset + 22 + comment_size != len(footer) or disk or cd_disk or disk_count != count:
        raise ForgeError("Multi-disk or malformed ZIP is not supported")
    if count > MAX_ENTRIES or cd_size > 8 * 1024 * 1024 or cd_offset + cd_size > size:
        raise ForgeError("ZIP entry/central-directory cap exceeded (ZIP64 is not supported)")
    if cd_offset + cd_size != max(0, size - 65557) + offset:
        raise ForgeError("Malformed ZIP central-directory extent")
    with path.open("rb") as stream:
        stream.seek(cd_offset)
        directory = stream.read(cd_size)
    position, actual_count = 0, 0
    while position < len(directory):
        if position + 46 > len(directory) or directory[position:position + 4] != b"PK\x01\x02":
            raise ForgeError("Malformed ZIP central-directory entry")
        name_size, extra_size, comment_length = struct.unpack_from("<3H", directory, position + 28)
        position += 46 + name_size + extra_size + comment_length
        actual_count += 1
        if actual_count > MAX_ENTRIES or position > len(directory):
            raise ForgeError("ZIP entry/central-directory cap exceeded")
    if actual_count != count:
        raise ForgeError("ZIP entry count mismatch")
    try:
        archive = zipfile.ZipFile(path)
        entries = archive.infolist()
        if len(entries) != count:
            raise ForgeError("ZIP entry count mismatch")
        seen, total = set(), 0
        for entry in entries:
            name = _member_name(entry.orig_filename)
            key = name.rstrip("/").casefold()
            if key in seen:
                raise ForgeError("Duplicate ZIP member names are not allowed")
            seen.add(key)
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind not in {0, stat.S_IFREG, stat.S_IFDIR} or entry.external_attr & 0x400:
                raise ForgeError("ZIP symlink, reparse or special-file entries are not allowed")
            if entry.flag_bits & (1 | 0x40):
                raise ForgeError("Encrypted ZIP entries are not allowed")
            if entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise ForgeError("Only stored/deflated ZIP members are supported")
            total += entry.file_size
            if total > MAX_UNCOMPRESSED or entry.file_size > MAX_INPUT:
                raise ForgeError("ZIP uncompressed byte cap exceeded")
            if entry.file_size > max(1, entry.compress_size) * 200:
                raise ForgeError("ZIP compression-ratio cap exceeded")
        return archive
    except (OSError, zipfile.BadZipFile, NotImplementedError) as error:
        if "archive" in locals():
            archive.close()
        raise ForgeError(f"Cannot read ZIP: {error}") from error
    except ForgeError:
        if "archive" in locals():
            archive.close()
        raise


def _hash_file(path):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _copy_bounded(source, destination, limit=MAX_INPUT):
    digest, size = hashlib.sha256(), 0
    while True:
        block = source.read(min(1024 * 1024, limit - size + 1))
        if not block:
            break
        size += len(block)
        if size > limit:
            raise ForgeError("Input/extracted byte cap exceeded")
        digest.update(block)
        destination.write(block)
    return digest.hexdigest(), size


def _pool(data, start, header, size):
    if header < 28:
        raise ForgeError("Malformed binary XML string pool")
    count, styles, flags, strings_start, styles_start = struct.unpack_from("<5I", data, start + 8)
    if count > 65536 or header + (count + styles) * 4 > size or not header <= strings_start <= size:
        raise ForgeError("Binary XML string pool bounds exceeded")
    end = start + (styles_start or size)
    if not start + strings_start <= end <= start + size:
        raise ForgeError("Malformed binary XML styles offset")
    strings = []
    for i in range(count):
        pos = start + strings_start + struct.unpack_from("<I", data, start + header + 4 * i)[0]

        def length(width):
            nonlocal pos
            if pos + width > end:
                raise ForgeError("Truncated binary XML string length")
            value = int.from_bytes(data[pos:pos + width], "little")
            pos += width
            mask = 0x80 if width == 1 else 0x8000
            if value & mask:
                if pos + width > end:
                    raise ForgeError("Truncated binary XML string length")
                value = ((value & (mask - 1)) << (width * 8)) | int.from_bytes(data[pos:pos + width], "little")
                pos += width
            return value

        if flags & 0x100:
            units, byte_count = length(1), length(1)
            width, encoding = 1, "utf-8"
        else:
            units = length(2)
            byte_count, width, encoding = units * 2, 2, "utf-16-le"
        if pos + byte_count + width > end or data[pos + byte_count:pos + byte_count + width] != bytes(width):
            raise ForgeError("Truncated/unterminated binary XML string")
        value = data[pos:pos + byte_count].decode(encoding)
        if len(value.encode("utf-16-le")) // 2 != units:
            raise ForgeError("Binary XML string length mismatch")
        strings.append(value)
    return strings


def _binary_elements(data):
    if len(data) < 8 or struct.unpack_from("<HHI", data) != (3, 8, len(data)):
        raise ForgeError("Unsupported or malformed Android binary XML header")
    strings, stack, root_seen, root_closed = None, [], False, False
    elements = []
    pos = 8
    while pos < len(data):
        if pos + 8 > len(data):
            raise ForgeError("Truncated binary XML chunk")
        kind, header, size = struct.unpack_from("<HHI", data, pos)
        if header < 8 or size < header or pos + size > len(data):
            raise ForgeError("Invalid binary XML chunk bounds")

        def string(index):
            if index == NO_INDEX:
                return None
            if strings is None or index >= len(strings):
                raise ForgeError("Invalid binary XML string index")
            return strings[index]

        if kind == 1:
            if strings is not None or root_seen:
                raise ForgeError("Duplicate/misplaced binary XML string pool")
            strings = _pool(data, pos, header, size)
        elif kind == 0x180:
            if root_seen or header != 8 or (size - header) % 4:
                raise ForgeError("Malformed binary XML resource map")
        elif kind in {0x100, 0x101}:
            if header != 16 or size != 24:
                raise ForgeError("Malformed binary XML namespace")
            string(struct.unpack_from("<I", data, pos + 16)[0])
            string(struct.unpack_from("<I", data, pos + 20)[0])
        elif kind == 0x102:
            if header != 16 or size < 36 or root_closed:
                raise ForgeError("Malformed binary XML start element")
            ns, name, attr_start, attr_size, count = struct.unpack_from("<IIHHH", data, pos + header)
            tag = (string(ns), string(name))
            if not tag[1] or attr_size < 20 or attr_start < 20 or header + attr_start + count * attr_size > size:
                raise ForgeError("Invalid binary XML attributes")
            attrs = {}
            for i in range(count):
                a = pos + header + attr_start + i * attr_size
                namespace, attribute, raw = struct.unpack_from("<III", data, a)
                value_size, reserved, value_type, value = struct.unpack_from("<HBBI", data, a + 12)
                if value_size != 8 or reserved:
                    raise ForgeError("Malformed binary XML typed value")
                key = (string(namespace), string(attribute))
                if not key[1] or key in attrs:
                    raise ForgeError("Duplicate/invalid binary XML attribute")
                if value_type == 3:
                    decoded = string(value)
                elif value_type in {0x10, 0x11}:
                    decoded = value
                elif value_type == 0x12:
                    decoded = bool(value)
                else:
                    decoded = {"unresolved_type": value_type, "data": value}
                # Resource references must not be mistaken for their raw spelling.
                if raw != NO_INDEX:
                    string(raw)
                attrs[key] = decoded
            if not stack:
                if root_seen:
                    raise ForgeError("Multiple binary XML roots")
                root_seen = True
            if len(stack) >= 128:
                raise ForgeError("Manifest nesting cap exceeded")
            elements.append((len(stack), tag, attrs))
            stack.append(tag)
        elif kind == 0x103:
            if header != 16 or size != 24:
                raise ForgeError("Malformed binary XML end element")
            ns, name = struct.unpack_from("<II", data, pos + header)
            if not stack or stack.pop() != (string(ns), string(name)):
                raise ForgeError("Unbalanced binary XML elements")
            if not stack:
                root_closed = True
        elif kind == 0x104:
            if not stack or header != 16 or size != 28:
                raise ForgeError("Malformed binary XML text")
        else:
            raise ForgeError(f"Unsupported binary XML chunk: 0x{kind:x}")
        pos += size
    if stack or not root_closed:
        raise ForgeError("Incomplete binary XML document")
    return elements


def parse_manifest(data):
    """Read relevant literal attributes from compiled Android XML or plain XML."""
    if not 0 < len(data) <= MAX_MANIFEST:
        raise ForgeError("Manifest byte cap exceeded or manifest is empty")
    try:
        if data.lstrip().startswith(b"<"):
            if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
                raise ForgeError("Manifest DTD/entities are not allowed")
            root = ET.fromstring(data)
            elements = []

            def qualified(name):
                return tuple(name[1:].split("}", 1)) if name.startswith("{") else (None, name)

            def visit(element, depth):
                if depth > 128:
                    raise ForgeError("Manifest nesting cap exceeded")
                elements.append((depth, qualified(element.tag), {qualified(k): v for k, v in element.attrib.items()}))
                for child in element:
                    visit(child, depth + 1)
            visit(root, 0)
        else:
            elements = _binary_elements(data)
        if elements[0][1] != (None, "manifest"):
            raise ForgeError("APK manifest root must be manifest")
        attrs = elements[0][2]

        def text(value, label, required=False):
            if (value is None or value == "") and not required:
                return None
            if not isinstance(value, str) or not value:
                raise ForgeError(f"Missing or unresolved manifest {label}; compiled literal metadata is required")
            return value

        def number(value, label, required=False):
            if value is None and not required:
                return None
            if isinstance(value, bool):
                raise ForgeError(f"Unresolved/invalid manifest {label}")
            if isinstance(value, str) and re.fullmatch(r"(?:[0-9]+|0x[0-9a-fA-F]+)", value):
                value = int(value, 16 if value.startswith("0x") else 10)
            if not isinstance(value, int) or not 0 <= value <= 0xffffffff:
                raise ForgeError(f"Missing or unresolved manifest {label}; numeric literal metadata is required")
            return value

        package = text(attrs.get((None, "package")), "package", True)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package):
            raise ForgeError("Invalid manifest package")
        split = text(attrs.get((None, "split")), "split")
        if split and not re.fullmatch(r"[A-Za-z0-9_.]+", split):
            raise ForgeError("Invalid manifest split name")
        code = number(attrs.get((ANDROID, "versionCode")), "versionCode", True)
        major = number(attrs.get((ANDROID, "versionCodeMajor")), "versionCodeMajor")
        min_sdk, dependencies, sdk_seen = None, [], False
        for depth, tag, child in elements[1:]:
            if depth != 1:
                continue
            if tag == (None, "uses-sdk"):
                if sdk_seen:
                    raise ForgeError("Duplicate uses-sdk element")
                sdk_seen = True
                min_sdk = number(child.get((ANDROID, "minSdkVersion")), "minSdkVersion")
                if min_sdk is not None and min_sdk < 1:
                    raise ForgeError("Invalid manifest minSdkVersion")
            elif tag == (None, "uses-split"):
                dependencies.append(text(child.get((ANDROID, "name")), "uses-split name", True))
        config_for = text(attrs.get((None, "configForSplit")), "configForSplit")
        required_splits = attrs.get((ANDROID, "isSplitRequired"), False)
        if isinstance(required_splits, str) and required_splits in {"true", "false"}:
            required_splits = required_splits == "true"
        if not isinstance(required_splits, bool):
            raise ForgeError("Unresolved manifest isSplitRequired")

        def split_types(label):
            value = text(attrs.get((ANDROID, label)), label)
            if value is None:
                return []
            types = [item.strip() for item in value.split(",")]
            if any(not re.fullmatch(r"[A-Za-z0-9_.]+", item) for item in types):
                raise ForgeError(f"Invalid manifest {label}")
            return sorted(set(types))
        return {"package": package, "split": split, "version_code": code,
                "version_code_major": major, "long_version_code": ((major or 0) << 32) | code,
                "min_sdk": min_sdk, "dependencies": dependencies, "config_for_split": config_for,
                "requires_splits": required_splits, "required_split_types": split_types("requiredSplitTypes"),
                "split_types": split_types("splitTypes")}
    except (ET.ParseError, UnicodeError, struct.error, RecursionError, ValueError, IndexError) as error:
        raise ForgeError(f"Malformed Android manifest: {error}") from error


def inspect_apk(path):
    try:
        with _zip_index(path) as archive:
            try:
                manifest = archive.getinfo("AndroidManifest.xml")
            except KeyError as error:
                raise ForgeError("APK has no AndroidManifest.xml") from error
            if manifest.file_size > MAX_MANIFEST:
                raise ForgeError("Manifest byte cap exceeded")
            with archive.open(manifest) as stream:
                data = stream.read(MAX_MANIFEST + 1)
            metadata = parse_manifest(data)
            abis = set()
            for entry in archive.infolist():
                parts = entry.filename.split("/")
                if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so") and not entry.is_dir():
                    abis.add(parts[1])
            metadata["native_abis"] = sorted(abis)
            return metadata
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ForgeError(f"Cannot inspect APK: {error}") from error


@contextmanager
def prepare_apks(root, paths=(), archive_path=None, members=()):
    if bool(paths) == bool(archive_path):
        raise ForgeError("Provide ordered --apk paths OR one --archive with explicit --member selection")
    if paths and members or archive_path and not members:
        raise ForgeError("--member is required only with --archive; variant selection is never automatic")
    selected = list(paths or members)
    if not 1 <= len(selected) <= MAX_APKS:
        raise ForgeError("Select between 1 and 128 APKs")
    inputs = [_regular_path(root, value) for value in (paths or [archive_path])]
    if len({os.path.normcase(str(p)) for p in inputs}) != len(inputs):
        raise ForgeError("Duplicate input paths are not allowed")
    if sum(p.stat().st_size for p in inputs) > MAX_INPUT:
        raise ForgeError("Aggregate input byte cap exceeded")
    suffix = ".apk" if paths else None
    if suffix and any(p.suffix.lower() != suffix for p in inputs):
        raise ForgeError("Explicit APK inputs must have .apk suffix")
    if archive_path and inputs[0].suffix.lower() not in {".apks", ".xapk"}:
        raise ForgeError("Archive must be an explicit .apks or .xapk file")
    with tempfile.TemporaryDirectory(prefix="forge-android-") as temporary:
        directory, staged, sources = Path(temporary), [], []
        archive_hash = None
        if archive_path:
            copied = directory / "source.zip"
            with inputs[0].open("rb") as source, copied.open("wb") as target:
                archive_hash, _ = _copy_bounded(source, target)
            with _zip_index(copied) as archive:
                names = [_member_name(name) for name in members]
                if len(set(name.casefold() for name in names)) != len(names):
                    raise ForgeError("Duplicate selected members are not allowed")
                entries = []
                for name in names:
                    if not name.lower().endswith(".apk"):
                        raise ForgeError("Selected archive members must be APK files")
                    try:
                        entry = archive.getinfo(name)
                    except KeyError as error:
                        raise ForgeError(f"Selected APK member is absent: {name}") from error
                    if entry.is_dir():
                        raise ForgeError("Selected APK member is a directory")
                    entries.append(entry)
                if sum(e.file_size for e in entries) > MAX_INPUT:
                    raise ForgeError("Selected APK aggregate byte cap exceeded")
                for index, entry in enumerate(entries):
                    destination = directory / f"{index:03d}.apk"
                    with archive.open(entry) as source, destination.open("wb") as target:
                        digest, size = _copy_bounded(source, target)
                    staged.append(destination)
                    sources.append({"path": str(inputs[0]), "member": entry.filename, "sha256": digest, "size": size})
        else:
            for index, path in enumerate(inputs):
                destination = directory / f"{index:03d}.apk"
                with path.open("rb") as source, destination.open("wb") as target:
                    digest, size = _copy_bounded(source, target)
                staged.append(destination)
                sources.append({"path": str(path), "member": None, "sha256": digest, "size": size})
        if sum(source["size"] for source in sources) > MAX_INPUT:
            raise ForgeError("Staged APK aggregate byte cap exceeded")
        try:
            metadata = [inspect_apk(path) for path in staged]
            validate_apks(metadata)
            yield staged, [{**source, "manifest": meta} for source, meta in zip(sources, metadata)], archive_hash
        except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
            raise ForgeError(f"Cannot prepare selected APKs: {error}") from error


def validate_apks(metadata, device=None):
    bases = [apk for apk in metadata if apk["split"] is None]
    if len(bases) != 1:
        raise ForgeError("Selection must contain exactly one base APK")
    base = bases[0]
    splits = [apk["split"] for apk in metadata if apk["split"] is not None]
    if len(splits) != len(set(splits)):
        raise ForgeError("Duplicate manifest split names")
    if base["requires_splits"] and not splits:
        raise ForgeError("Base manifest requires split APKs; select the explicit required splits")
    available_types = {kind for apk in metadata for kind in apk["split_types"]}
    for apk in metadata:
        if (apk["package"], apk["long_version_code"]) != (base["package"], base["long_version_code"]):
            raise ForgeError("Selected APKs must share package and versionCode/versionCodeMajor")
        required = list(apk["dependencies"])
        if apk["config_for_split"]:
            required.append(apk["config_for_split"])
        if any(name not in splits for name in required):
            raise ForgeError("Selected APKs are missing a declared split dependency")
        if not set(apk["required_split_types"]).issubset(available_types):
            raise ForgeError("Selected APKs are missing a declared requiredSplitTypes member")
    if base["min_sdk"] is None:
        raise ForgeError("Base APK has no literal minSdkVersion; compatible installation cannot be established")
    if device is not None:
        api, abis = device.get("api"), device.get("abis")
        if not isinstance(api, int) or not abis:
            raise ForgeError("Missing observed device API/ABI facts; installation is not permitted")
        if splits and api < 21:
            raise ForgeError("Split APK installation requires observed device API 21 or later")
        for apk in metadata:
            if max(base["min_sdk"], apk["min_sdk"] or 0) > api:
                raise ForgeError("APK minSdkVersion exceeds observed device API")
            if apk["native_abis"] and not set(apk["native_abis"]).intersection(abis):
                raise ForgeError("APK native ABIs are incompatible with observed device ABI list")
    return base


def _run(command, timeout):
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


def select_device(devices, serial=None):
    if serial is not None:
        matches = [device for device in devices if device["serial"] == serial]
        if not matches:
            return "absent", None
        if len(matches) != 1:
            return "multiple", None
        device = matches[0]
        return ("authorized" if device["state"] == "device" else device["state"], device)
    online = [device for device in devices if device["state"] == "device"]
    if len(online) == 1:
        return "authorized", online[0]
    if len(online) > 1 or len(devices) > 1:
        return "multiple", None
    if not devices:
        return "absent", None
    return devices[0]["state"], devices[0]


def _preflight(serial=None):
    result = {"schema": SCHEMA, "action": "preflight", "success": False,
              "status": "missing-tool", "requested_serial": serial, "devices": [], "device": None,
              "scope": "Observed ADB/OS/API/ABI facts only; no installation, root or injection proof"}
    try:
        adb = executable("adb")
    except ForgeError as error:
        result["precondition"] = str(error)
        return result
    result["adb_path"] = adb
    result["tool_version"] = _run([adb, "version"], 15)
    listing = _run([adb, "devices", "-l"], 15)
    result["device_listing"] = listing
    if not _ok(result["tool_version"]) or not _ok(listing) or listing["stdout_omitted_bytes"]:
        result["status"] = "adb-failed"
        result["precondition"] = "Configured ADB must successfully report version and complete device listing"
        return result
    for line in listing["stdout"].splitlines():
        fields = line.split()
        if len(fields) >= 2 and not line.startswith(("List of devices", "*")):
            result["devices"].append({"serial": fields[0], "state": fields[1], "details": " ".join(fields[2:])})
    status, device = select_device(result["devices"], serial)
    result["status"], result["device"] = status, device
    if status != "authorized":
        result["precondition"] = "Connect and authorize an owned Android device; select --serial when selection is ambiguous"
        return result
    properties, calls = {}, {}
    for prop in ("ro.build.version.release", "ro.build.version.sdk", "ro.product.cpu.abilist",
                 "ro.product.cpu.abi", "ro.product.cpu.abi2"):
        call = _run([adb, "-s", device["serial"], "shell", "getprop", prop], 15)
        calls[prop] = call
        properties[prop] = call["stdout"].strip() if _ok(call) and not call["stdout_omitted_bytes"] else None
    sdk = properties["ro.build.version.sdk"]
    abilist = properties["ro.product.cpu.abilist"]
    abis = (abilist.split(",") if abilist else [properties["ro.product.cpu.abi"], properties["ro.product.cpu.abi2"]])
    device.update({"os_release": properties["ro.build.version.release"],
                   "api": int(sdk) if sdk and re.fullmatch(r"[0-9]{1,5}", sdk) else None,
                   "abis": list(dict.fromkeys(abi.strip() for abi in abis if abi and abi.strip())),
                   "properties": properties, "property_calls": calls})
    if not device["os_release"] or device["api"] is None or device["api"] < 1 or not device["abis"]:
        result["status"] = "incomplete-device-facts"
        result["precondition"] = "Authorized device must expose OS release, numeric API and ABI properties via configured ADB"
        return result
    result["success"] = True
    return result


def adb_preflight(args, store):
    return store.add("runtime", _preflight(args.serial))


def adb_install_splits(args, store):
    if not 0 < args.timeout <= 3600:
        raise ForgeError("Timeout must be greater than 0 and at most 3600 seconds")
    inputs, archive_hash, facts, preflight = [], None, None, None
    try:
        with prepare_apks(store.root, args.apk, args.archive, args.member) as (paths, inputs, archive_hash):
            facts = _preflight(args.serial)
            preflight = store.add("runtime", facts)
            if not facts["success"]:
                raise ForgeError(f"Installation prerequisite missing: {facts['status']}; evidence {preflight['id']}")
            validate_apks([item["manifest"] for item in inputs], facts["device"])
            action = "install" if len(paths) == 1 else "install-multiple"
            command = [facts["adb_path"], "-s", facts["device"]["serial"], action, *map(str, paths)]
            installer = _run(command, args.timeout)
            complete_output = not installer["stdout_omitted_bytes"] and not installer["stderr_omitted_bytes"]
            success = bool(_ok(installer) and complete_output and not re.search(
                r"(?im)^\s*(?:Failure\b|Error\b)", installer["stdout"] + "\n" + installer["stderr"]))
            record = store.add("runtime", {"schema": SCHEMA, "action": "install-splits", "installer_action": action,
                                           "success": success, "inputs": inputs, "archive_sha256": archive_hash,
                                           "device": facts["device"], "preflight_evidence_id": preflight["id"],
                                           "tool_version": facts["tool_version"], "adb_path": facts["adb_path"],
                                           "policy": "new-install-only; no replace, downgrade or permission grant flags",
                                           "installer": installer})
            if not success:
                raise ForgeError(f"ADB installer failed; evidence {record['id']}")
            return record
    except (ForgeError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        failure = store.add("runtime", {"schema": SCHEMA, "action": "install-splits-rejected",
                                       "success": False, "error": str(error), "inputs": inputs,
                                       "archive_sha256": archive_hash,
                                       "device": facts["device"] if facts else None,
                                       "preflight_evidence_id": preflight["id"] if preflight else None})
        raise ForgeError(f"{error}; rejection evidence {failure['id']}") from error


def apk_info(args, store):
    if bool(args.paths) == bool(args.archive):
        raise ForgeError("Provide ordered APK paths OR one --archive with explicit --member selection")
    if args.paths and args.member or args.archive and not args.member:
        raise ForgeError("--member is required only with --archive; variant selection is never automatic")
    selected = list(args.paths or args.member)
    if not 1 <= len(selected) <= MAX_APKS:
        raise ForgeError("Select between 1 and 128 APKs")
    inputs = [_regular_path(store.root, value) for value in (args.paths or [args.archive])]
    if len({os.path.normcase(str(path)) for path in inputs}) != len(inputs):
        raise ForgeError("Duplicate input paths are not allowed")
    if args.paths and any(path.suffix.lower() != ".apk" for path in inputs):
        raise ForgeError("Explicit APK inputs must have .apk suffix")
    if args.archive and inputs[0].suffix.lower() not in {".apks", ".xapk"}:
        raise ForgeError("Archive must be an explicit .apks or .xapk file")
    inspected, archive_hash = [], None
    try:
        with tempfile.TemporaryDirectory(prefix="forge-apk-info-") as temporary:
            directory = Path(temporary)
            if args.archive:
                copied = directory / "source.zip"
                with inputs[0].open("rb") as source, copied.open("wb") as target:
                    archive_hash, _ = _copy_bounded(source, target)
                with _zip_index(copied) as archive:
                    names = [_member_name(name) for name in args.member]
                    if len(set(name.casefold() for name in names)) != len(names):
                        raise ForgeError("Duplicate selected members are not allowed")
                    for name in names:
                        if not name.lower().endswith(".apk"):
                            raise ForgeError("Selected archive members must be APK files")
                        try:
                            entry = archive.getinfo(name)
                        except KeyError:
                            raise ForgeError(f"Selected APK member is absent: {name}") from None
                        if entry.is_dir():
                            raise ForgeError("Selected APK member is a directory")
                        if entry.file_size > MAX_INPUT:
                            raise ForgeError(f"Selected member exceeds the input byte cap: {name}")
                        staged = directory / f"member-{len(inspected)}.apk"
                        digest = hashlib.sha256()
                        size = 0
                        with archive.open(entry) as source, staged.open("xb") as target:
                            while True:
                                block = source.read(1024 * 1024)
                                if not block:
                                    break
                                size += len(block)
                                if size > MAX_INPUT:
                                    raise ForgeError(f"Selected member exceeds the input byte cap: {name}")
                                digest.update(block)
                                target.write(block)
                        metadata = inspect_apk(staged)
                        inspected.append({"path": str(inputs[0]), "member": name, "sha256": digest.hexdigest(),
                                          "size": size, "manifest": metadata})
            else:
                for path in inputs:
                    digest, size = _hash_file(path)
                    inspected.append({"path": str(path), "member": None, "sha256": digest, "size": size,
                                      "manifest": inspect_apk(path)})
    except (ForgeError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        failure = store.add("analysis", {"schema": SCHEMA, "tool": "android", "action": "apk-info", "success": False,
                                         "error": str(error), "archive_sha256": archive_hash, "inputs": inspected})
        raise ForgeError(f"{error}; rejection evidence {failure['id']}") from error
    record = store.add("analysis", {"schema": SCHEMA, "tool": "android", "action": "apk-info", "success": True,
                                    "archive_sha256": archive_hash, "inputs": inspected,
                                    "scope": "Observed manifest metadata only; not an install, signature or "
                                             "functionality check"})
    if args.validate_selection:
        validate_apks([item["manifest"] for item in inspected])
    return record


def register(subparsers):
    parser = subparsers.add_parser("apk-info", help="Read compiled manifest metadata from explicit APKs or archive members")
    parser.add_argument("paths", nargs="*", help="Ordered APK paths")
    parser.add_argument("--archive", help="Explicit APKS/XAPK archive")
    parser.add_argument("--member", action="append", default=[], help="Exact APK archive member; repeat in order")
    parser.add_argument("--validate-selection", action="store_true",
                        help="Also check the set as one installable split selection")
    parser.set_defaults(handler=apk_info)
    parser = subparsers.add_parser("adb-preflight", help="Observe configured ADB and authorized device OS/API/ABI facts")
    parser.add_argument("--serial")
    parser.set_defaults(handler=adb_preflight)
    parser = subparsers.add_parser("adb-install-splits", help="Install an explicitly selected, compatible APK set without replacing apps")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--apk", action="append", default=[], help="Ordered APK path; repeat for splits")
    source.add_argument("--archive", help="Explicit APKS/XAPK archive")
    parser.add_argument("--member", action="append", default=[], help="Exact APK archive member; repeat in install order")
    parser.add_argument("--serial")
    parser.add_argument("--timeout", type=float, default=120)
    parser.set_defaults(handler=adb_install_splits)
