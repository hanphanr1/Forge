import argparse
import gzip
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_artifacts


class ArtifactBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_artifacts.register(self.parser.add_subparsers())

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def test_gzip_blob_is_indexed_without_changing_original_bytes(self):
        content = gzip.compress(b'fetch("https://example.com/api/login")')
        source = self.root / "compressed-blob"
        source.write_bytes(content)
        record = self.command("artifact-index", str(source))
        login = next(item for item in record["data"]["endpoint_candidates"]
                     if item["value"] == "https://example.com/api/login")
        self.assertEqual(login["location"]["compression"], "gzip")
        self.assertEqual(login["location"]["offset_space"], "decompressed")
        self.assertEqual(source.read_bytes(), content)

    def test_gzip_expansion_limit_prevents_indexing_over_limit_payload(self):
        source = self.root / "compressed-blob"
        source.write_bytes(gzip.compress(b"A" * 1024 + b"https://example.com/api/login"))
        record = self.command("artifact-index", str(source), "--max-file-bytes", "128")
        self.assertTrue(record["data"]["truncated"])
        self.assertEqual(record["data"]["endpoint_candidates"], [])
        self.assertEqual(record["data"]["skipped"][0]["reason"], "exceeds --max-file-bytes")

    def test_apk_dex_strings_are_observations_not_verified_endpoints(self):
        archive = self.root / "client.apk"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("classes.dex", b"dex\n035\x00\x00https://example.com/api/login\x00")
            output.writestr("../escape.js", "https://unsafe.example/api/login")
        record = self.command("artifact-index", str(archive))
        candidates = record["data"]["endpoint_candidates"]
        login = next(item for item in candidates if item["value"] == "https://example.com/api/login")
        self.assertFalse(login["proven_live"])
        self.assertFalse(login["proven_auth_path"])
        self.assertEqual(login["location"]["member"], "classes.dex")
        self.assertNotIn("https://unsafe.example/api/login", [item["value"] for item in candidates])

    def test_member_limit_does_not_discard_entire_large_archive(self):
        archive = self.root / "client.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as output:
            output.writestr("small.js", 'fetch("https://example.com/api/profile")')
            output.writestr("large.bin", b"\x00" * 4096)
        record = self.command("artifact-index", str(archive), "--max-file-bytes", "256")
        self.assertIn("https://example.com/api/profile", [item["value"] for item in record["data"]["endpoint_candidates"]])
        self.assertTrue(record["data"]["truncated"])
        self.assertTrue(any(item["source"].get("member") == "large.bin" for item in record["data"]["skipped"] if isinstance(item["source"], dict)))

    def test_directory_scan_does_not_index_account_or_result_data(self):
        source = self.root / "analysis"
        source.mkdir()
        (source / "client.js").write_text('fetch("https://example.com/api/login")')
        (source / "accounts.txt").write_text("must-not-index-credential")
        (source / "results").mkdir()
        (source / "results" / "hits.txt").write_text("must-not-index-result")
        record = self.command("artifact-index", str(source))
        output = (self.root / record["data"]["path"]).read_text()
        self.assertNotIn("must-not-index-credential", output)
        self.assertNotIn("must-not-index-result", output)
        self.assertIn("https://example.com/api/login", output)

    def test_hash_mismatch_publishes_no_artifact_and_preserves_original(self):
        source = self.root / "source.js"
        content = b"observed client bytes"
        source.write_bytes(content)
        with self.assertRaisesRegex(ForgeError, "SHA256 mismatch"):
            self.command("artifact-add", str(source), "--sha256", "0" * 64)
        self.assertEqual(source.read_bytes(), content)
        self.assertEqual(list((self.store.directory / "blobs").glob("*")) if (self.store.directory / "blobs").exists() else [], [])


class JadxOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_artifacts.register(self.parser.add_subparsers())
        self.source = self.root / "client.apk"
        self.source.write_bytes(b"PK\x03\x04fixture")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def run_jadx(self, returncode, produced, log="INFO - loading\n"):
        def popen(command, **kwargs):
            target = Path(command[command.index("-d") + 1])
            target.mkdir(parents=True, exist_ok=True)
            for index in range(produced):
                (target / f"C{index}.java").write_text(f"class C{index} {{}}\n")
            process = type("FakeProcess", (), {})()
            process.stdout = io.BytesIO(log.encode())
            process.pid = 4242
            process.wait = lambda timeout=None: returncode
            process.poll = lambda: returncode
            process.kill = lambda: None
            return process
        tool = {"available": True, "path": str(self.source), "source": "fixture", "setup": ""}
        args = self.parser.parse_args(["jadx", str(self.source)])
        with patch.object(forge_artifacts, "find_tool", return_value=tool), \
                patch.object(forge_artifacts.subprocess, "Popen", side_effect=popen):
            return args.handler(args, self.store)

    def test_partial_output_is_kept_and_counted(self):
        record = self.run_jadx(1, 3, log="ERROR - finished with errors, count: 12\n")
        data = record["data"]
        self.assertEqual(data["status"], "partial")
        self.assertEqual(data["java_files"], 3)
        self.assertEqual(data["error_count"], 12)
        self.assertTrue(data["partial"])
        self.assertIsNone(data["error"])
        self.assertIn("3 source files are still usable", data["warning"])
        self.assertTrue((self.store.root / data["log_path"]).is_file())
        self.assertEqual(len(list((self.store.root / data["output_path"]).glob("*.java"))), 3)

    def test_failure_without_sources_is_still_an_error(self):
        with self.assertRaisesRegex(ForgeError, "JADX failed"):
            self.run_jadx(1, 0)
        record = next(item for item in self.store.list() if item["data"].get("tool") == "jadx")
        self.assertEqual(record["data"]["status"], "failed")
        self.assertFalse(record["data"]["partial"])
        self.assertIsNone(record["data"]["warning"])

    def test_clean_run_reports_success(self):
        record = self.run_jadx(0, 2)
        self.assertEqual(record["data"]["status"], "success")
        self.assertFalse(record["data"]["partial"])
        self.assertIsNone(record["data"]["warning"])


if __name__ == "__main__":
    unittest.main()
