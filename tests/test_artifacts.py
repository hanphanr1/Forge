import argparse
import gzip
from pathlib import Path
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
