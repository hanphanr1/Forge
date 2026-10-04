import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import ForgeError
import forge_toolchain


class ToolSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.previous_root = forge_toolchain.TOOLS_ROOT
        self.previous_override = os.environ.pop("FORGE_ADB", None)
        forge_toolchain.TOOLS_ROOT = self.root / "tools"
        self.local = forge_toolchain.TOOLS_ROOT / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
        self.local.parent.mkdir(parents=True)
        self.local.write_bytes(b"discovery fixture, never executed")
        if os.name != "nt":
            self.local.chmod(0o755)

    def tearDown(self):
        forge_toolchain.TOOLS_ROOT = self.previous_root
        os.environ.pop("FORGE_ADB", None)
        if self.previous_override is not None:
            os.environ["FORGE_ADB"] = self.previous_override
        self.temp.cleanup()

    def test_invalid_explicit_override_never_falls_back_to_local(self):
        os.environ["FORGE_ADB"] = str(self.root / "missing-adb.exe")
        result = forge_toolchain.find_tool("adb")
        self.assertFalse(result["available"])
        self.assertEqual(result["source"], "FORGE_ADB")
        with self.assertRaisesRegex(ForgeError, "Missing adb.*FORGE_ADB"):
            forge_toolchain.executable("adb")

    def test_local_tool_selection_does_not_depend_on_target_cwd(self):
        target = self.root / "unrelated-target"
        target.mkdir()
        previous = Path.cwd()
        try:
            os.chdir(target)
            result = forge_toolchain.find_tool("adb")
        finally:
            os.chdir(previous)
        self.assertEqual(Path(result["path"]), self.local.resolve())
        self.assertEqual(result["source"], "FORGE/tools")


    @unittest.skipIf(os.name == "nt", "POSIX executable selection")
    def test_windows_candidate_does_not_shadow_native_tool(self):
        foreign = self.local.with_name("adb.exe")
        foreign.write_bytes(b"Windows-only discovery fixture")
        self.assertEqual(Path(forge_toolchain.find_tool("adb")["path"]), self.local.resolve())

    @unittest.skipIf(os.name == "nt", "POSIX executable permissions")
    def test_nonexecutable_local_candidate_is_not_reported_available(self):
        self.local.chmod(0o644)
        result = forge_toolchain.find_tool("adb")
        self.assertNotEqual(result["source"], "FORGE/tools")
        self.assertNotEqual(result["path"], str(self.local.resolve()))


if __name__ == "__main__":
    unittest.main()
