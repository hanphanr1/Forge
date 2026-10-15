import argparse
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_apktool


def elf_header(machine=183, kind=3, elf_class=2, magic=b"\x7fELF"):
    header = bytearray(20)
    header[0:4] = magic
    header[4] = elf_class
    struct.pack_into("<H", header, 16, kind)
    struct.pack_into("<H", header, 18, machine)
    return bytes(header) + b"\0" * 32


def apk_bytes(extra=()):
    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\0" * 8)
        archive.writestr("classes.dex", b"dex\n035\0fixture")
        for name, data in extra:
            archive.writestr(name, data)
    return buffer.getvalue()


EXTRACT_NATIVE_LIBS_ID = 0x010104EA


def binary_manifest(extract_native_libs=False, other_id=0x0101000F, other_value=0xFFFFFFFF):
    """Minimal compiled manifest: XML header, string pool, resource map, one element with two attrs."""
    def chunk(kind, header, body):
        # body is everything after the 8-byte common chunk header
        return struct.pack("<HHI", kind, header, 8 + len(body)) + body

    resources = [other_id, EXTRACT_NATIVE_LIBS_ID]
    string_pool = chunk(0x0001, 28, b"\0" * 20)
    resource_map = chunk(0x0180, 8, struct.pack("<%dI" % len(resources), *resources))
    ext = struct.pack("<IIHHH", 20, 1, 20, 20, 2)          # ns, name, attrStart, attrSize, attrCount
    ext += struct.pack("<HHH", 0, 0, 0)                     # idIndex, classIndex, styleIndex
    first = struct.pack("<IIIHBBI", 0, 0, 0xFFFFFFFF, 8, 0, 0x10, other_value & 0xFFFFFFFF)
    second = struct.pack("<IIIHBBI", 0, 1, 0xFFFFFFFF, 8, 0, 0x12, 1 if extract_native_libs else 0)
    element_body = b"\0" * 8 + ext + first + second         # lineNumber + comment, then ext block
    element = struct.pack("<HHI", 0x0102, 16, 8 + len(element_body)) + element_body
    payload = string_pool + resource_map + element
    return chunk(0x0003, 8, payload)


class GadgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.gadget = self.root / "frida-gadget-arm64.so"
        self.gadget.write_bytes(elf_header())
        (self.root / "app.apk").write_bytes(apk_bytes())

    def tearDown(self):
        self.store.connection.close()
        self.temp.cleanup()

    def args(self, **changes):
        values = dict(path="app.apk", gadget="frida-gadget-arm64.so", output="app-gadget.apk",
                      gadget_config=[], timeout=60)
        values.update(changes)
        return argparse.Namespace(**values)

    def injecting(self, member=None, names=None, package=("com.fixture", "com.fixture"), code=0):
        """Fake frida-apk: writes a repackaged APK at the -o path of the launched command."""
        members = list(names) if names is not None else ["lib/arm64-v8a/libfridagadget.so", "lib/arm64-v8a/wrap.sh",
                                                        "lib/arm64-v8a/libfridagadget.config.so"]
        gadget_data = member if member is not None else self.gadget.read_bytes()

        def run(command, timeout, cwd=None):
            staged = Path(command[command.index("-o") + 1])
            with zipfile.ZipFile(staged, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\0" * 8)
                for name in members:
                    archive.writestr(name, gadget_data if name.endswith("libfridagadget.so") else b"fixture\n")
            return code, b"stdout fixture", b"", False

        packages = iter(package)
        return patch.object(forge_apktool, "_run", side_effect=run), \
            patch.object(forge_apktool, "_tool", return_value={"path": "frida-apk", "source": "fixture",
                                                              "available": True}), \
            patch.object(forge_apktool, "_package_name", side_effect=lambda path: next(packages))

    def test_invalid_inputs_never_spawn(self):
        (self.root / "notes.txt").write_text("not a gadget", encoding="utf-8")
        bad_elf = self.root / "executable.so"
        bad_elf.write_bytes(elf_header(kind=2))
        unknown = self.root / "other-arch.so"
        unknown.write_bytes(elf_header(machine=8))
        self.gadget.with_suffix(".bin").write_bytes(elf_header())
        invalid = [
            {"path": "missing.apk"}, {"path": "notes.txt"}, {"path": "../app.apk"},
            {"gadget": "missing.so"}, {"gadget": "notes.txt"}, {"gadget": "other-arch.so"},
            {"gadget": "executable.so"}, {"gadget": "frida-gadget-arm64.bin"}, {"gadget": "../frida-gadget-arm64.so"},
            {"output": "../escaped.apk"}, {"output": "app.apk"}, {"output": "no-suffix"},
            {"gadget_config": ["on_load"]}, {"gadget_config": ["=resume"]}, {"gadget_config": ["on_load="]},
        ]
        with patch.object(forge_apktool, "_run") as run, patch.object(forge_apktool, "_tool") as tool:
            for changes in invalid:
                with self.subTest(changes=changes), self.assertRaises(ForgeError):
                    forge_apktool.gadget(self.args(**changes), self.store)
            run.assert_not_called()
            tool.assert_not_called()

    def test_run_rejects_an_invalid_timeout_before_spawning(self):
        for timeout in (0, -1, 3601, float("nan")):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ForgeError, "Timeout must be greater than 0"):
                forge_apktool._run(["frida-apk"], timeout)

    def test_gadget_rejects_oversized_and_unreadable_shared_objects(self):
        oversized = self.root / "huge.so"
        with patch.object(forge_apktool, "MAX_GADGET", 4):
            oversized.write_bytes(elf_header())
            with self.assertRaisesRegex(ForgeError, "exceeds"):
                forge_apktool.gadget(self.args(gadget="huge.so"), self.store)
        short = self.root / "short.so"
        short.write_bytes(b"\x7fELF")
        with self.assertRaisesRegex(ForgeError, "ELF shared object"):
            forge_apktool.gadget(self.args(gadget="short.so"), self.store)

    def test_abi_and_bitness_come_from_the_gadget_bytes(self):
        cases = [(183, 2, "arm64-v8a", 64), (40, 1, "armeabi-v7a", 32), (62, 2, "x86_64", 64), (243, 2, "riscv64", 64)]
        for machine, elf_class, abi, bitness in cases:
            with self.subTest(machine=machine):
                path = self.root / f"gadget-{abi}.so"
                path.write_bytes(elf_header(machine=machine, elf_class=elf_class))
                self.assertEqual(forge_apktool._gadget_abi(path, path.stat().st_size), (abi, bitness))

    def test_successful_injection_records_verified_members_and_keeps_config_values_out(self):
        run, tool, packages = self.injecting()
        with run as run_mock, tool, packages:
            record = forge_apktool.gadget(self.args(gadget_config=["on_load=resume"]), self.store)
        data = record["data"]
        self.assertTrue(data["success"], data["failure"])
        self.assertIsNone(data["failure"])
        self.assertEqual(record["kind"], "analysis")
        self.assertEqual(data["gadget_abi"], "arm64-v8a")
        self.assertEqual(data["gadget_bitness"], 64)
        self.assertEqual(data["gadget_sha256"], hashlib.sha256(self.gadget.read_bytes()).hexdigest())
        self.assertTrue(data["embedded_gadget_matches"])
        self.assertEqual(data["config_keys"], ["on_load"])
        self.assertNotIn("resume", json_repr(data))
        self.assertEqual(data["injected_members"], ["lib/arm64-v8a/libfridagadget.so", "lib/arm64-v8a/wrap.sh",
                                                   "lib/arm64-v8a/libfridagadget.config.so"])
        self.assertIn("debuggable", data["scope"])
        command = run_mock.call_args.args[0]
        self.assertEqual(command[0], "frida-apk")
        self.assertEqual(command[1:3], ["-g", str(self.gadget)])
        self.assertEqual(command[command.index("-c"):command.index("-c") + 2], ["-c", "on_load=resume"])
        self.assertEqual(command[-1], str(self.root / "app.apk"))
        output = self.root / "app-gadget.apk"
        self.assertEqual(data["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(data["size"], output.stat().st_size)

    def test_differing_embedded_gadget_fails_with_evidence(self):
        run, tool, packages = self.injecting(member=b"\x7fELF" + b"different gadget bytes" * 4)
        with run, tool, packages, self.assertRaisesRegex(ForgeError, "does not match"):
            forge_apktool.gadget(self.args(), self.store)
        data = self.store.list(kind="analysis")[0]["data"]
        self.assertFalse(data["success"])
        self.assertFalse(data["embedded_gadget_matches"])
        self.assertFalse((self.root / "app-gadget.apk").exists())

    def test_missing_injected_members_fail(self):
        run, tool, packages = self.injecting(names=["lib/arm64-v8a/libfridagadget.so"])
        with run, tool, packages, self.assertRaisesRegex(ForgeError, r"missing .*wrap\.sh"):
            forge_apktool.gadget(self.args(), self.store)

    def test_changed_package_name_fails(self):
        run, tool, packages = self.injecting(package=("com.fixture", "com.tampered"))
        with run, tool, packages, self.assertRaisesRegex(ForgeError, "changed the package name"):
            forge_apktool.gadget(self.args(), self.store)

    def test_tool_failure_is_recorded_not_invented(self):
        run, tool, packages = self.injecting(code=1)
        with run, tool, packages, self.assertRaisesRegex(ForgeError, "did not produce an APK"):
            forge_apktool.gadget(self.args(), self.store)
        data = self.store.list(kind="analysis")[0]["data"]
        self.assertFalse(data["success"])
        self.assertEqual(data["returncode"], 1)
        self.assertIsNone(data["sha256"])

    def test_staging_is_removed_after_failure(self):
        run, tool, packages = self.injecting(names=[])
        with run, tool, packages, self.assertRaises(ForgeError):
            forge_apktool.gadget(self.args(), self.store)
        leftovers = [path.name for path in self.store.directory.iterdir() if path.name.startswith("forge-apk-gadget-")]
        self.assertEqual(leftovers, [])


def json_repr(value):
    import json
    return json.dumps(value)


class NativeLibraryPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)

    def tearDown(self):
        self.store.connection.close()
        self.temp.cleanup()

    def write_apk(self, name, *, lib_align=None, manifest=None):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest if manifest is not None else b"\x03\x00\x08\x00" + b"\0" * 8)
            if lib_align is not None:
                with archive.open("lib/arm64-v8a/libfixture.so", "w") as entry:
                    pass
        return path

    def test_elf_load_alignment_selects_the_zipalign_page_flag(self):
        def elf(p_align):
            header = bytearray(64)
            header[0:4] = b"\x7fELF"
            header[4] = 2
            struct.pack_into("<Q", header, 32, 64)          # e_phoff
            struct.pack_into("<HH", header, 54, 56, 1)      # e_phentsize, e_phnum
            program = bytearray(56)
            struct.pack_into("<I", program, 0, 1)           # PT_LOAD
            struct.pack_into("<Q", program, 48, p_align)
            return bytes(header) + bytes(program)

        for align, expected in ((4096, ["-p"]), (16384, ["-P", "16"]), (65536, ["-P", "64"])):
            with self.subTest(align=align):
                path = self.root / f"libs-{align}.apk"
                with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
                    archive.writestr("lib/arm64-v8a/libfixture.so", elf(align))
                self.assertEqual(forge_apktool._so_page_alignment(path), expected)

        plain = self.root / "no-libs.apk"
        with zipfile.ZipFile(plain, "w") as archive:
            archive.writestr("classes.dex", b"dex")
        self.assertEqual(forge_apktool._so_page_alignment(plain), ["-p"])

    def test_extract_native_libs_is_flipped_once_and_stays_a_valid_manifest(self):
        path = self.root / "manifest.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", binary_manifest(extract_native_libs=False))
            archive.writestr("classes.dex", b"dex")
        self.assertTrue(forge_apktool._enable_extract_native_libs(path))
        with zipfile.ZipFile(path) as archive:
            patched = archive.read("AndroidManifest.xml")
        self.assertIn(struct.pack("<i", -1), patched[-8:])
        self.assertFalse(forge_apktool._enable_extract_native_libs(path),
                         "a manifest that already allows extraction must not be rewritten again")
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(archive.read("classes.dex"), b"dex")

    def test_extract_native_libs_left_alone_when_already_true(self):
        path = self.root / "already.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", binary_manifest(extract_native_libs=True))
        self.assertFalse(forge_apktool._enable_extract_native_libs(path))

    def test_missing_manifest_is_refused(self):
        path = self.root / "no-manifest.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("classes.dex", b"dex")
        with self.assertRaisesRegex(ForgeError, "no AndroidManifest.xml"):
            forge_apktool._enable_extract_native_libs(path)


if __name__ == "__main__":
    unittest.main()
