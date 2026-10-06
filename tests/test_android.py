import argparse
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import forge_android as android
from forge_core import EvidenceStore, ForgeError


def manifest(package="org.forge.fixture", split=None, version=7, minimum=23, extra="", dependencies=()):
    split_attr = f' split="{split}"' if split is not None else ""
    sdk = f'<uses-sdk android:minSdkVersion="{minimum}"/>' if minimum is not None else ""
    uses = "".join(f'<uses-split android:name="{name}"/>' for name in dependencies)
    return (f'<manifest xmlns:android="{android.ANDROID}" package="{package}"{split_attr} '
            f'android:versionCode="{version}" {extra}>{sdk}{uses}<application/></manifest>').encode()


def binary_manifest(utf8=True, sdk_type=0x10, split=None, major=0):
    # Android ResXMLTree with string pool, namespace/resource-map chunks and typed attrs.
    strings = [android.ANDROID, "android", "manifest", "package", "org.forge.fixture", "versionCode",
               "uses-sdk", "minSdkVersion", "application", "split", "config.arm64_v8a", "versionCodeMajor"]
    encoded, offsets = bytearray(), []
    for value in strings:
        offsets.append(len(encoded))
        if utf8:
            raw = value.encode()
            encoded += bytes([len(value), len(raw)]) + raw + b"\0"
        else:
            raw = value.encode("utf-16-le")
            encoded += struct.pack("<H", len(raw) // 2) + raw + b"\0\0"
    encoded += b"\0" * (-len(encoded) % 4)
    start = 28 + len(strings) * 4
    pool = (struct.pack("<HHI5I", 1, 28, start + len(encoded), len(strings), 0, 0x100 if utf8 else 0, start, 0)
            + struct.pack(f"<{len(offsets)}I", *offsets) + encoded)
    null = android.NO_INDEX

    def attribute(ns, name, kind, value):
        return struct.pack("<IIIHBBI", ns, name, null, 8, 0, kind, value)

    def begin(name, attrs=()):
        return (struct.pack("<HHIII", 0x102, 16, 36 + len(attrs) * 20, 1, null)
                + struct.pack("<II6H", null, name, 20, 20, len(attrs), 0, 0, 0) + b"".join(attrs))

    def end(name):
        return struct.pack("<HHIIIII", 0x103, 16, 24, 1, null, null, name)

    def namespace(kind):
        return struct.pack("<HHIIIII", kind, 16, 24, 1, null, 1, 0)

    attrs = [attribute(null, 3, 3, 4), attribute(0, 5, 0x10, 7), attribute(0, 11, 0x10, major)]
    if split is not None:
        attrs.append(attribute(null, 9, 3, 10))
    resources = struct.pack("<HHI", 0x180, 8, 8 + len(strings) * 4) + bytes(len(strings) * 4)
    content = (pool + resources + namespace(0x100) + begin(2, attrs)
               + begin(6, [attribute(0, 7, sdk_type, 23)]) + end(6)
               + begin(8) + end(8) + end(2) + namespace(0x101))
    return struct.pack("<HHI", 3, 8, 8 + len(content)) + content


def apk_bytes(xml=None, abis=()):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", xml if xml is not None else manifest())
        for abi in abis:
            archive.writestr(f"lib/{abi}/libfixture.so", b"\x7fELF" + bytes(32))
    return buffer.getvalue()


def run_result(stdout="", code=0, stderr="", expired=False):
    return {"returncode": code, "timed_out": expired, "launch_error": None,
            "stdout": stdout, "stderr": stderr, "stdout_omitted_bytes": 0, "stderr_omitted_bytes": 0}


class ManifestTests(unittest.TestCase):
    def test_compiled_binary_manifest_both_string_encodings(self):
        for utf8 in (True, False):
            with self.subTest(utf8=utf8):
                meta = android.parse_manifest(binary_manifest(utf8, major=2))
                self.assertEqual(meta["package"], "org.forge.fixture")
                self.assertEqual(meta["version_code"], 7)
                self.assertEqual(meta["long_version_code"], (2 << 32) | 7)
                self.assertEqual(meta["min_sdk"], 23)
                self.assertIsNone(meta["split"])

    def test_compiled_split_name(self):
        self.assertEqual(android.parse_manifest(binary_manifest(split=True))["split"], "config.arm64_v8a")

    def test_binary_resource_reference_not_treated_as_literal(self):
        with self.assertRaisesRegex(ForgeError, "unresolved.*minSdkVersion"):
            android.parse_manifest(binary_manifest(sdk_type=1))

    def test_truncated_corrupt_and_unsupported_binary_rejected(self):
        data = binary_manifest()
        for malformed in (data[:-1], data[:7], b"not XML", data[:8] + struct.pack("<HHI", 1, 28, 0)):
            with self.subTest(malformed=malformed[:20]), self.assertRaises(ForgeError):
                android.parse_manifest(malformed)
        corrupt = bytearray(data)
        struct.pack_into("<I", corrupt, 36, 0xffffffff)
        with self.assertRaises(ForgeError):
            android.parse_manifest(bytes(corrupt))

    def test_plain_manifest_requires_correct_android_namespace(self):
        self.assertEqual(android.parse_manifest(manifest())["min_sdk"], 23)
        with self.assertRaisesRegex(ForgeError, "versionCode"):
            android.parse_manifest(manifest().replace(android.ANDROID.encode(), b"urn:not-android"))

    def test_non_numeric_sdk_and_missing_version_rejected(self):
        for xml in (manifest(minimum="VanillaIceCream"), manifest(version="@integer/version"),
                    manifest().replace(b'android:versionCode="7"', b"")):
            with self.subTest(xml=xml), self.assertRaises(ForgeError):
                android.parse_manifest(xml)

    def test_duplicate_uses_sdk_and_entities_rejected(self):
        for xml in (manifest().replace(b"<application/>", b'<uses-sdk android:minSdkVersion="24"/>'),
                    b'<!DOCTYPE manifest [<!ENTITY x "org.forge.fixture">]>' + manifest()):
            with self.assertRaises(ForgeError):
                android.parse_manifest(xml)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def write_apk(self, name="base.apk", xml=None, abis=()):
        path = self.root / name
        path.write_bytes(apk_bytes(xml, abis))
        return path

    def write_archive(self, entries):
        path = self.root / "fixture.apks"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in entries:
                archive.writestr(name, data)
        return path

    def test_binary_apk_metadata_and_native_abis(self):
        path = self.write_apk(xml=binary_manifest(), abis=("arm64-v8a", "x86_64"))
        meta = android.inspect_apk(path)
        self.assertEqual(meta["native_abis"], ["arm64-v8a", "x86_64"])
        self.assertEqual(meta["min_sdk"], 23)

    def test_explicit_archive_order_extracts_only_selected_and_cleans(self):
        path = self.write_archive([("chosen/base.apk", apk_bytes()),
                                   ("chosen/config.apk", apk_bytes(manifest(split="config.en", minimum=None))),
                                   ("other/base.apk", b"not selected, not an APK")])
        original = path.read_bytes()
        with android.prepare_apks(self.root, archive_path=path, members=["chosen/config.apk", "chosen/base.apk"]) as (paths, sources, digest):
            owned = paths[0].parent
            self.assertEqual([x["member"] for x in sources], ["chosen/config.apk", "chosen/base.apk"])
            self.assertEqual(len(list(owned.glob("*.apk"))), 2)
            self.assertTrue(all(x.exists() for x in paths))
            self.assertEqual(len(digest), 64)
        self.assertFalse(owned.exists())
        self.assertEqual(path.read_bytes(), original)

    def test_explicit_apks_preserved_and_staged_in_order(self):
        base = self.write_apk()
        split = self.write_apk("config.apk", manifest(split="config.en", minimum=None))
        original = [p.read_bytes() for p in (base, split)]
        with android.prepare_apks(self.root, [split, base]) as (paths, sources, digest):
            self.assertEqual([x["path"] for x in sources], [str(split), str(base)])
            self.assertIsNone(digest)
            self.assertNotEqual(paths[0], split)
        self.assertEqual([p.read_bytes() for p in (base, split)], original)

    def test_archive_selection_is_never_automatic(self):
        path = self.write_archive([("base.apk", apk_bytes())])
        for members in ([], ["missing.apk"], ["base.apk", "base.apk"], ["../base.apk"]):
            with self.subTest(members=members), self.assertRaises(ForgeError):
                with android.prepare_apks(self.root, archive_path=path, members=members):
                    self.fail("Invalid selection reached prepared state")

    def test_unselected_unsafe_zip_members_rejected(self):
        for name in ("../escape", "/absolute", "C:/drive", "folder\\file", "a//b", "./relative"):
            with self.subTest(name=name):
                path = self.write_archive([("base.apk", apk_bytes()), (name, b"unsafe")])
                if "\\" in name:
                    # The Windows ZIP writer normalizes separators before emitting headers.
                    safe = name.replace("\\", "/").encode("ascii")
                    path.write_bytes(path.read_bytes().replace(safe, name.encode("ascii")))
                with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("Unsafe archive must reject before extraction")), self.assertRaises(ForgeError):
                    with android.prepare_apks(self.root, archive_path=path, members=["base.apk"]):
                        self.fail("Unsafe ZIP was accepted")

    def test_zip_duplicate_and_symlink_entries_rejected(self):
        path = self.write_archive([("base.apk", apk_bytes()), ("BASE.apk", b"duplicate")])
        with self.assertRaisesRegex(ForgeError, "Duplicate"):
            android._zip_index(path)
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("base.apk", apk_bytes())
            archive.writestr(link, "base.apk")
        with self.assertRaisesRegex(ForgeError, "symlink"):
            android._zip_index(path)

    def test_encrypted_flag_rejected_before_read(self):
        path = self.write_archive([("base.apk", apk_bytes())])
        data = bytearray(path.read_bytes())
        footer = data.rfind(b"PK\x05\x06")
        central = struct.unpack_from("<I", data, footer + 16)[0]
        local = struct.unpack_from("<I", data, central + 42)[0]
        struct.pack_into("<H", data, central + 8, 1)
        struct.pack_into("<H", data, local + 6, 1)
        path.write_bytes(data)
        with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("Encrypted payload must not be read")), self.assertRaisesRegex(ForgeError, "Encrypted"):
            android._zip_index(path)

    def test_compression_bomb_and_entry_caps_rejected(self):
        path = self.root / "bomb.apks"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bomb", bytes(1024 * 1024))
        with self.assertRaisesRegex(ForgeError, "compression-ratio"):
            android._zip_index(path)
        path = self.write_archive([("base.apk", apk_bytes()), ("extra", b"1")])
        with patch.object(android, "MAX_ENTRIES", 1), self.assertRaisesRegex(ForgeError, "entry"):
            android._zip_index(path)
        with patch.object(android, "MAX_UNCOMPRESSED", 10), self.assertRaisesRegex(ForgeError, "uncompressed"):
            android._zip_index(path)

    def test_input_and_manifest_caps_rejected(self):
        path = self.write_apk()
        with patch.object(android, "MAX_INPUT", 10), self.assertRaisesRegex(ForgeError, "byte cap"):
            with android.prepare_apks(self.root, [path]):
                self.fail("Oversize input accepted")
        with patch.object(android, "MAX_MANIFEST", 10), self.assertRaisesRegex(ForgeError, "Manifest byte cap"):
            android.inspect_apk(path)

    def test_duplicate_regular_inputs_and_directories_rejected(self):
        path = self.write_apk()
        for paths in ([path, path], [self.root]):
            with self.assertRaises(ForgeError):
                with android.prepare_apks(self.root, paths):
                    self.fail("Invalid inputs accepted")

    def test_symlink_input_rejected_when_platform_allows_creation(self):
        base = self.write_apk()
        link = self.root / "link.apk"
        try:
            link.symlink_to(base)
        except OSError:
            self.skipTest("Host does not permit creating symlinks")
        with self.assertRaisesRegex(ForgeError, "Symlink/reparse"):
            with android.prepare_apks(self.root, [link]):
                self.fail("Symlink accepted")

    def test_temporary_files_clean_after_exception(self):
        path = self.write_apk()
        with self.assertRaisesRegex(ForgeError, "fixture failure"):
            with android.prepare_apks(self.root, [path]) as (paths, _, _):
                directory = paths[0].parent
                raise ForgeError("fixture failure")
        self.assertFalse(directory.exists())

    def test_forged_zip_entry_count_rejected_before_zipfile_allocates(self):
        path = self.write_archive([("base.apk", apk_bytes()), ("extra", b"1")])
        data = bytearray(path.read_bytes())
        footer = data.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", data, footer + 8, 1, 1)
        path.write_bytes(data)
        with patch.object(android.zipfile, "ZipFile") as allocator:
            with self.assertRaisesRegex(ForgeError, "entry count mismatch"):
                android._zip_index(path)
        allocator.assert_not_called()

    def test_reparse_input_attribute_rejected_without_opening_source(self):
        path = self.write_apk()
        original_lstat = Path.lstat

        def reparse(candidate, *args, **kwargs):
            info = original_lstat(candidate, *args, **kwargs)
            if candidate == path:
                return SimpleNamespace(st_mode=info.st_mode, st_size=info.st_size, st_file_attributes=0x400)
            return info

        with patch.object(Path, "lstat", new=reparse), self.assertRaisesRegex(ForgeError, "Symlink/reparse"):
            with android.prepare_apks(self.root, [path]):
                self.fail("Reparse input accepted")


class CompatibilityTests(unittest.TestCase):
    def metadata(self, xml=None, abis=()):
        return {**android.parse_manifest(xml if xml is not None else manifest()), "native_abis": list(abis)}

    def test_compatible_base_and_split_with_inherited_sdk(self):
        base = self.metadata()
        split = self.metadata(manifest(split="config.arm64", minimum=None), ["arm64-v8a"])
        self.assertEqual(android.validate_apks([split, base], {"api": 23, "abis": ["arm64-v8a"]}), base)

    def test_package_version_and_major_mismatch_rejected(self):
        for xml in (manifest(package="org.other.fixture", split="feature"),
                    manifest(version=8, split="feature"),
                    manifest(split="feature", extra='android:versionCodeMajor="1"')):
            with self.subTest(xml=xml), self.assertRaisesRegex(ForgeError, "share package"):
                android.validate_apks([self.metadata(), self.metadata(xml)])

    def test_missing_or_duplicate_base_and_duplicate_split_rejected(self):
        base, split = self.metadata(), self.metadata(manifest(split="feature"))
        for selection in ([], [split], [base, base], [base, split, split]):
            with self.subTest(count=len(selection)), self.assertRaises(ForgeError):
                android.validate_apks(selection)

    def test_min_sdk_abi_and_missing_device_facts_rejected(self):
        selection = [self.metadata(abis=["arm64-v8a"])]
        for device in ({"api": 22, "abis": ["arm64-v8a"]}, {"api": 35, "abis": ["x86_64"]},
                       {"api": None, "abis": ["arm64-v8a"]}, {"api": 35, "abis": []}):
            with self.subTest(device=device), self.assertRaises(ForgeError):
                android.validate_apks(selection, device)
        split = self.metadata(manifest(split="feature", minimum=36))
        with self.assertRaisesRegex(ForgeError, "minSdkVersion"):
            android.validate_apks([self.metadata(), split], {"api": 35, "abis": ["arm64-v8a"]})

    def test_missing_literal_base_sdk_fails_safe(self):
        with self.assertRaisesRegex(ForgeError, "no literal minSdkVersion"):
            android.validate_apks([self.metadata(manifest(minimum=None))])

    def test_declared_dependency_and_required_split_selection(self):
        base = self.metadata(manifest(extra='android:isSplitRequired="true"'))
        dependent = self.metadata(manifest(split="config.feature", dependencies=["feature"]))
        with self.assertRaisesRegex(ForgeError, "requires split"):
            android.validate_apks([base])
        with self.assertRaisesRegex(ForgeError, "dependency"):
            android.validate_apks([base, dependent])
        feature = self.metadata(manifest(split="feature"))
        android.validate_apks([base, dependent, feature])

    def test_config_target_and_required_split_types_checked(self):
        base = self.metadata(manifest(extra='android:requiredSplitTypes="abi,density"'))
        abi = self.metadata(manifest(split="config.arm64", extra='android:splitTypes="abi"'))
        density = self.metadata(manifest(split="config.hdpi", extra='android:splitTypes="density"'))
        with self.assertRaisesRegex(ForgeError, "requiredSplitTypes"):
            android.validate_apks([base, abi])
        android.validate_apks([base, abi, density])
        targeted = self.metadata(manifest(split="config.feature", extra='configForSplit="feature"'))
        with self.assertRaisesRegex(ForgeError, "dependency"):
            android.validate_apks([self.metadata(), targeted])

    def test_split_install_requires_api_21_even_for_low_min_sdk(self):
        base = self.metadata(manifest(minimum=19))
        split = self.metadata(manifest(split="config.en", minimum=None))
        with self.assertRaisesRegex(ForgeError, "API 21"):
            android.validate_apks([base, split], {"api": 19, "abis": ["arm64-v8a"]})

    def test_empty_split_and_config_target_are_android_base_semantics(self):
        meta = self.metadata(manifest(split="", extra='configForSplit=""'))
        self.assertIsNone(meta["split"])
        self.assertIsNone(meta["config_for_split"])


class CommandBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.base = self.root / "base.apk"
        self.base.write_bytes(apk_bytes())
        self.args = argparse.Namespace(apk=[str(self.base)], archive=None, member=[], serial=None, timeout=30)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def backend(self, command, timeout):
        if command[1:] == ["version"]:
            return run_result("Android Debug Bridge version 1.0.41\nVersion fixture-test-only\n")
        if command[1:] == ["devices", "-l"]:
            return run_result("List of devices attached\nowned-fixture device product:fixture\n")
        if "getprop" in command:
            values = {"ro.build.version.release": "14", "ro.build.version.sdk": "34",
                      "ro.product.cpu.abilist": "arm64-v8a,armeabi-v7a", "ro.product.cpu.abi": "arm64-v8a",
                      "ro.product.cpu.abi2": "armeabi-v7a"}
            return run_result(values[command[-1]] + "\n")
        return run_result("Success\n")

    def test_device_selection_classifies_observed_states(self):
        for state in ("unauthorized", "offline"):
            self.assertEqual(android.select_device([{"serial": "a", "state": state}])[0], state)
        self.assertEqual(android.select_device([])[0], "absent")
        devices = [{"serial": "a", "state": "device"}, {"serial": "b", "state": "device"}]
        self.assertEqual(android.select_device(devices)[0], "multiple")
        self.assertEqual(android.select_device(devices, "a")[0], "authorized")
        self.assertEqual(android.select_device(devices, "missing")[0], "absent")
        self.assertEqual(android.select_device([devices[0], {"serial": "b", "state": "offline"}])[0], "authorized")

    def test_preflight_observes_properties_and_tool_version_without_install(self):
        with patch.object(android, "executable", return_value="configured-adb"), patch.object(android, "_run", side_effect=self.backend) as calls:
            record = android.adb_preflight(self.args, self.store)
        self.assertEqual(record["data"]["status"], "authorized")
        self.assertEqual(record["data"]["device"]["api"], 34)
        self.assertEqual(record["data"]["device"]["abis"], ["arm64-v8a", "armeabi-v7a"])
        self.assertFalse(any("install" in call.args[0] for call in calls.call_args_list))
        self.assertEqual(self.store.get(record["id"]), record)

    def test_missing_tool_and_incomplete_device_properties_report_preconditions(self):
        with patch.object(android, "executable", side_effect=ForgeError("Missing configured ADB")):
            self.assertEqual(android._preflight()["status"], "missing-tool")

        def incomplete(command, timeout):
            return run_result("") if "getprop" in command else self.backend(command, timeout)
        with patch.object(android, "executable", return_value="configured-adb"), patch.object(android, "_run", side_effect=incomplete):
            self.assertEqual(android._preflight()["status"], "incomplete-device-facts")

    def test_single_and_multiple_dispatch_new_install_only_and_cleanup(self):
        for multiple in (False, True):
            if multiple:
                split = self.root / "config.apk"
                split.write_bytes(apk_bytes(manifest(split="config.en", minimum=None)))
                self.args.apk = [str(self.base), str(split)]
            with patch.object(android, "executable", return_value="configured-adb"), patch.object(android, "_run", side_effect=self.backend) as calls:
                record = android.adb_install_splits(self.args, self.store)
            command = calls.call_args_list[-1].args[0]
            self.assertEqual(command[:4], ["configured-adb", "-s", "owned-fixture", "install-multiple" if multiple else "install"])
            self.assertFalse(any(flag in command for flag in ("-r", "-d", "-g")))
            self.assertFalse(Path(command[4]).exists())
            self.assertTrue(record["data"]["success"])
            self.assertEqual(record["data"]["installer"]["stdout"], "Success\n")
            self.assertEqual(len(record["data"]["inputs"][0]["sha256"]), 64)
            self.assertTrue(self.base.exists())

    def test_invalid_metadata_rejected_before_any_adb_dispatch(self):
        self.base.write_bytes(apk_bytes(manifest(version="@integer/version")))
        with patch.object(android, "_run") as calls, self.assertRaises(ForgeError):
            android.adb_install_splits(self.args, self.store)
        calls.assert_not_called()
        self.assertEqual(self.store.list()[0]["data"]["action"], "install-splits-rejected")

    def test_incompatible_device_never_dispatches_installer(self):
        self.base.write_bytes(apk_bytes(manifest(minimum=35)))
        with patch.object(android, "executable", return_value="configured-adb"), patch.object(android, "_run", side_effect=self.backend) as calls:
            with self.assertRaisesRegex(ForgeError, "minSdkVersion"):
                android.adb_install_splits(self.args, self.store)
        self.assertFalse(any("install" in call.args[0] for call in calls.call_args_list))

    def test_absent_hardware_is_prerequisite_not_install_success(self):
        def absent(command, timeout):
            return run_result("List of devices attached\n") if command[1:] == ["devices", "-l"] else self.backend(command, timeout)
        with patch.object(android, "executable", return_value="configured-adb"), patch.object(android, "_run", side_effect=absent) as calls:
            with self.assertRaisesRegex(ForgeError, "prerequisite missing: absent"):
                android.adb_install_splits(self.args, self.store)
        self.assertFalse(any("install" in call.args[0] for call in calls.call_args_list))

    def test_installer_failure_records_body_and_exit_and_cleans(self):
        commands = []

        def failure(command, timeout):
            commands.append(command)
            if "install" in command:
                return run_result("Failure [INSTALL_FAILED_ALREADY_EXISTS]\n", 1, "fixture stderr")
            return self.backend(command, timeout)
        with patch.object(android, "executable", return_value="configured-adb"), patch.object(android, "_run", side_effect=failure):
            with self.assertRaisesRegex(ForgeError, "installer failed"):
                android.adb_install_splits(self.args, self.store)
        installed = next(record for record in self.store.list() if record["data"]["action"] == "install-splits")
        self.assertFalse(installed["data"]["success"])
        self.assertEqual(installed["data"]["installer"]["returncode"], 1)
        self.assertIn("INSTALL_FAILED_ALREADY_EXISTS", installed["data"]["installer"]["stdout"])
        self.assertFalse(Path(commands[-1][-1]).exists())

    def test_timeout_or_omitted_installer_output_never_claims_success(self):
        for expired, omitted in ((True, 0), (False, 1)):
            def incomplete(command, timeout):
                if "install" in command:
                    result = run_result("Success\n", expired=expired)
                    result["stdout_omitted_bytes"] = omitted
                    return result
                return self.backend(command, timeout)
            with self.subTest(expired=expired, omitted=omitted):
                with patch.object(android, "executable", return_value="configured-adb"), patch.object(android, "_run", side_effect=incomplete):
                    with self.assertRaisesRegex(ForgeError, "installer failed"):
                        android.adb_install_splits(self.args, self.store)


class ApkInfoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = EvidenceStore(self.root)
        self.base = self.root / "base.apk"
        self.base.write_bytes(apk_bytes(manifest(split=None, minimum=23, extra='android:requiredSplitTypes="config.en"')))
        self.split = self.root / "config.en.apk"
        self.split.write_bytes(apk_bytes(manifest(split="config.en", minimum=23,
                                                 extra='android:splitTypes="config.en"')))

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def info(self, *paths, archive=None, members=(), validate=False):
        args = argparse.Namespace(paths=list(paths), archive=archive, member=list(members),
                                  validate_selection=validate)
        return android.apk_info(args, self.store)

    def test_reports_manifest_facts_without_installing_or_validating(self):
        record = self.info(str(self.base))
        item = record["data"]["inputs"][0]
        self.assertEqual(item["manifest"]["package"], "org.forge.fixture")
        self.assertEqual(item["manifest"]["min_sdk"], 23)
        self.assertEqual(item["manifest"]["required_split_types"], ["config.en"])
        self.assertEqual(item["sha256"], hashlib.sha256(self.base.read_bytes()).hexdigest())
        self.assertEqual(record["data"]["action"], "apk-info")
        self.assertEqual([record["data"]["inputs"][0]["member"]], [None])
        self.assertNotIn("installer", record["data"])

    def test_selection_validation_is_opt_in(self):
        self.info(str(self.base))  # an incomplete split set must not be rejected by default
        with self.assertRaisesRegex(ForgeError, "requiredSplitTypes"):
            self.info(str(self.base), validate=True)
        self.info(str(self.base), str(self.split), validate=True)

    def test_explicit_apks_must_exist_and_keep_supplied_order(self):
        with self.assertRaisesRegex(ForgeError, "Cannot access input"):
            self.info(str(self.base), str(self.root / "absent.apk"))
        record = self.info(str(self.split), str(self.base))
        self.assertEqual([item["manifest"]["split"] for item in record["data"]["inputs"]], ["config.en", None])

    def test_archive_members_require_exact_names_and_stay_bounded(self):
        archive = self.root / "bundle.apks"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("base.apk", apk_bytes(manifest(split=None, minimum=23)))
            output.writestr("config.en.apk", apk_bytes(manifest(split="config.en", minimum=23)))
            output.writestr("icon.png", b"\x89PNG")
        record = self.info(archive=str(archive), members=["config.en.apk", "base.apk"])
        self.assertEqual([item["member"] for item in record["data"]["inputs"]], ["config.en.apk", "base.apk"])
        with self.assertRaisesRegex(ForgeError, "member is absent"):
            self.info(archive=str(archive), members=["missing.apk"])
        with self.assertRaisesRegex(ForgeError, "must be APK files"):
            self.info(archive=str(archive), members=["icon.png"])
        with self.assertRaisesRegex(ForgeError, "Unsafe ZIP member name"):
            self.info(archive=str(archive), members=["../escape.js"])
        with self.assertRaisesRegex(ForgeError, "Duplicate selected members"):
            self.info(archive=str(archive), members=["base.apk", "base.apk"])
        with self.assertRaisesRegex(ForgeError, "ordered APK paths OR one --archive"):
            self.info(str(self.base), archive=str(archive), members=["base.apk"])
        with self.assertRaisesRegex(ForgeError, "member is required only with --archive"):
            self.info(archive=str(archive))


if __name__ == "__main__":
    unittest.main()
