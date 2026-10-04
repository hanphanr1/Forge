import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError


class EvidenceIsolationTests(unittest.TestCase):
    def link_directory(self, link, destination):
        if os.name == "nt":
            result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(destination)],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            link.symlink_to(destination, target_is_directory=True)

    def test_external_evidence_directory_is_rejected_before_database_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, outside = root / "project", root / "outside"
            project.mkdir()
            outside.mkdir()
            self.link_directory(project / ".forge", outside)
            with self.assertRaisesRegex(ForgeError, "inside the project"):
                EvidenceStore(project)
            self.assertFalse((outside / "evidence.sqlite3").exists())

    def test_external_blob_directory_is_rejected_before_writing_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, outside = root / "project", root / "outside"
            project.mkdir()
            outside.mkdir()
            store = EvidenceStore(project)
            try:
                self.link_directory(store.directory / "blobs", outside)
                content = b"owned screenshot fixture"
                with self.assertRaisesRegex(ForgeError, "inside the project"):
                    store.put_bytes(content)
                self.assertFalse((outside / hashlib.sha256(content).hexdigest()).exists())
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
