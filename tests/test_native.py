import argparse
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_native
import forge_toolchain


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.binary = self.root / "owned.bin"
        self.binary.write_bytes(b"owned nonsecret test input")

    def tearDown(self):
        self.store.connection.close()
        self.temp.cleanup()

    def args(self, **changes):
        values = dict(action="disasm", path="owned.bin", address="0x10", timeout=30,
                      max_output=65536, max_items=10)
        values.update(changes)
        return argparse.Namespace(**values)

    def capture(self, output, **changes):
        result = dict(stdout=output, stderr=b"", stdout_bytes=len(output), stderr_bytes=0,
                      exit_code=0, timed_out=False, truncated=False, error=None, elapsed_ms=1)
        result.update(changes)
        return result

    def test_invalid_parameters_never_spawn(self):
        invalid = [{"address": value} for value in ("0x10;!whoami", "1\nq", "-1", "main", "", True, 2**64)]
        invalid += [{"max_output": value} for value in (0, -1, True, 16777217, 1.5)]
        invalid += [{"max_items": value} for value in (0, -1, True, 100001, 1.5)]
        invalid += [{"timeout": value} for value in (0, float("nan"), float("inf"), 3601, True)]
        with patch.object(forge_native, "_capture") as capture:
            for changes in invalid:
                with self.subTest(changes=changes), self.assertRaises(ForgeError):
                    forge_native.inspect(self.args(**changes), self.store)
            capture.assert_not_called()

    def test_unsafe_paths_never_spawn(self):
        (self.root / "accounts.txt").write_text("not a binary", encoding="utf-8")
        (self.root / "credentials").mkdir()
        (self.root / "credentials" / "input.bin").write_bytes(b"excluded")
        with patch.object(forge_native, "_capture") as capture:
            for path in ("missing.bin", ".", "../owned.bin", "accounts.txt", "credentials/input.bin", "owned.bin\0"):
                with self.subTest(path=path), self.assertRaises(ForgeError):
                    forge_native.inspect(self.args(path=path), self.store)
            capture.assert_not_called()

    def test_symlink_never_spawn(self):
        link = self.root / "link.bin"
        try:
            link.symlink_to(self.binary)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable")
        with patch.object(forge_native, "_capture") as capture, self.assertRaises(ForgeError):
            forge_native.inspect(self.args(path="link.bin"), self.store)
        capture.assert_not_called()

    def test_disassembly_preserves_observations_and_normalizes_address(self):
        outputs = [self.capture(b"radare2 unit fixture\n"), self.capture(
            b'[{"offset":16,"size":1,"opcode":"ret","bytes":"c3","type":"ret","extra":"omitted"}]')]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(
                forge_native, "_capture", side_effect=outputs) as capture:
            record = forge_native.inspect(self.args(address="00016"), self.store)
        data = record["data"]
        self.assertTrue(data["success"])
        self.assertTrue(data["binary_unchanged"])
        self.assertEqual(data["binary_before"]["sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(data["instructions"], [{"offset": 16, "size": 1, "opcode": "ret", "bytes": "c3", "type": "ret"}])
        self.assertEqual(capture.call_args_list[1].args[0][-2], "aaa;pdj 10 @ 0x10")
        self.assertEqual(len(capture.call_args_list[1].args), 4)

    def test_entrypoint_selection_uses_observed_virtual_address(self):
        outputs = [self.capture(b"r2 unit fixture"), self.capture(b'[{"vaddr":4096,"paddr":64}]'),
                   self.capture(b'[{"offset":4096,"size":1,"opcode":"ret"}]')]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(forge_native, "_capture", side_effect=outputs):
            data = forge_native.inspect(self.args(address=None), self.store)["data"]
        self.assertEqual(data["parameters"]["selected_address"], 4096)
        self.assertEqual(data["parameters"]["address_source"], "first_backend_entrypoint")

    def test_missing_entrypoint_records_failure(self):
        outputs = [self.capture(b"r2 unit fixture"), self.capture(b"[]")]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(forge_native, "_capture", side_effect=outputs):
            with self.assertRaisesRegex(ForgeError, "No observed.*entrypoint"):
                forge_native.inspect(self.args(address=None), self.store)
        data = self.store.list(kind="analysis")[0]["data"]
        self.assertFalse(data["success"])
        self.assertTrue(data["binary_unchanged"])

    def test_decompile_keeps_bounded_pseudo_c_and_records_the_cut(self):
        pseudo = b"void entry0 (void) {\n    eax = 1\n    ebx = 2\n    ret\n}\n"
        outputs = [self.capture(b"r2 unit fixture"), self.capture(pseudo, truncated=True)]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(
                forge_native, "_capture", side_effect=outputs) as capture:
            record = forge_native.inspect(self.args(action="decompile", address="0x10", max_items=2), self.store)
        data = record["data"]
        self.assertTrue(data["success"], data["errors"])
        self.assertEqual(capture.call_args_list[1].args[0][-2], "aaa;pdc @ 0x10")
        self.assertEqual(data["pseudo_c_lines"], 2)
        self.assertEqual(data["pseudo_c"], "void entry0 (void) {\n    eax = 1")
        self.assertEqual(data["caps"]["items_omitted"], 3)
        self.assertTrue(data["caps"]["items_limit_reached"])
        # A cut text view stays usable, but the cut must be recorded, not hidden.
        self.assertTrue(data["caps"]["pseudo_c_truncated"])
        self.assertTrue(data["caps"]["output_truncated"])
        self.assertEqual(data["parameters"]["decompiler"], "radare2 pdc (register-level pseudo-C)")
        self.assertTrue(any("register-level" in item for item in data["limitations"]))
        self.assertEqual(data["instructions"], [])

    def test_decompile_resolves_the_entrypoint_and_reports_clean_text(self):
        pseudo = b"void entry0 (void) {\n    ret\n}\n"
        outputs = [self.capture(b"r2 unit fixture"), self.capture(b'[{"vaddr":4096,"paddr":64}]'), self.capture(pseudo)]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(
                forge_native, "_capture", side_effect=outputs) as capture:
            data = forge_native.inspect(self.args(action="decompile", address=None), self.store)["data"]
        self.assertEqual(data["parameters"]["selected_address"], 4096)
        self.assertEqual(data["parameters"]["address_source"], "first_backend_entrypoint")
        self.assertEqual(capture.call_args_list[2].args[0][-2], "aaa;pdc @ 0x1000")
        self.assertEqual(data["pseudo_c_lines"], 3)
        self.assertFalse(data["caps"]["pseudo_c_truncated"])
        self.assertEqual(data["caps"]["items_omitted"], 0)

    def test_decompile_still_fails_on_a_backend_error(self):
        outputs = [self.capture(b"r2 unit fixture"), self.capture(b"", exit_code=1, error="boom")]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(
                forge_native, "_capture", side_effect=outputs):
            with self.assertRaisesRegex(ForgeError, "decompile failed"):
                forge_native.inspect(self.args(action="decompile", address="0x10"), self.store)
        data = self.store.list(kind="analysis")[0]["data"]
        self.assertFalse(data["success"])
        self.assertTrue(data["binary_unchanged"])

    def test_xrefs_share_item_budget_and_keep_direction(self):
        row = b'[{"from":1,"to":16,"type":"CALL"},{"from":2,"to":16,"type":"DATA"}]'
        outputs = [self.capture(b"r2 unit fixture"), self.capture(row), self.capture(row)]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(forge_native, "_capture", side_effect=outputs):
            data = forge_native.inspect(self.args(action="xrefs", max_items=3), self.store)["data"]
        self.assertEqual(len(data["xrefs"]), 3)
        self.assertEqual([row["direction"] for row in data["xrefs"]], ["incoming", "incoming", "outgoing"])
        self.assertEqual(data["caps"]["items_omitted"], 1)

    def test_incoming_endpoint_can_be_observed_from_query_context(self):
        rows = forge_native._xrefs([{"from": 1, "type": "CALL"}], "incoming", address=16)
        self.assertEqual(rows, [{"from": 1, "to": 16, "type": "CALL", "direction": "incoming",
                                "endpoint_from_query": "to"}])
        with self.assertRaises(ForgeError):
            forge_native._xrefs([{"from": 1, "type": "CALL"}], calls_only=True)

    def test_callgraph_only_retains_backend_call_edges(self):
        rows = b'[{"from":1,"addr":2,"type":"CALL"},{"from":2,"addr":3,"type":"DATA"}]'
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(
                forge_native, "_capture", side_effect=[self.capture(b"r2 unit fixture"), self.capture(rows),
                    self.capture(b'[{"addr":0,"size":2,"name":"observed_caller"},{"addr":2,"size":1,"name":"observed_target"}]'),
                    self.capture(b'[{"addr":0,"size":2}]\n[{"addr":2,"size":1}]')]) as capture:
            data = forge_native.inspect(self.args(action="callgraph", address=None), self.store)["data"]
        self.assertEqual(data["call_edges"][0]["from"], 1)
        self.assertEqual(data["call_edges"][0]["caller_function"], 0)
        self.assertEqual(data["call_edges"][0]["target_function"], 2)
        self.assertEqual(data["function_edges"][0]["caller_function"], 0)
        self.assertEqual(data["function_edges"][0]["target_function"], 2)
        self.assertEqual(data["function_edges"][0]["observed_calls"], 1)
        self.assertEqual(len(data["call_edges"]), 1)
        self.assertEqual(capture.call_args_list[1].args[0][-2], "aaa;axlj")
        self.assertEqual(data["call_edges"][0]["backend_target_field"], "addr")
        self.assertEqual(len(capture.call_args_list), 4)

    def test_function_membership_uses_blocks_not_guessed_size_ranges(self):
        nodes = [{"offset": 0, "size": 100}, {"offset": 200, "size": 10}]
        blocks = [{"function": 0, "address": 0, "size": 2}]
        calls, edges = forge_native._function_graph(
            [{"from": 50, "to": 200, "type": "CALL"}, {"from": 1, "to": 999, "type": "CALL"}],
            nodes, blocks)
        self.assertIsNone(calls[0]["caller_function"])
        self.assertEqual(calls[0]["caller_basis"], "unresolved_in_observed_scope")
        self.assertEqual(calls[0]["target_function"], 200)
        self.assertEqual(calls[1]["caller_function"], 0)
        self.assertIsNone(edges[1]["target_function"])
        self.assertEqual(edges[1]["unresolved_target"], 999)

    def test_overlapping_backend_blocks_do_not_guess_caller(self):
        blocks = [{"function": 0, "address": 10, "size": 5},
                  {"function": 8, "address": 10, "size": 5}]
        calls, _ = forge_native._function_graph([{"from": 11, "to": 50, "type": "CALL"}], [], blocks)
        self.assertIsNone(calls[0]["caller_function"])
        self.assertEqual(calls[0]["caller_basis"], "ambiguous_blocks")

    def test_block_batch_requires_exact_strict_json_documents(self):
        self.assertEqual(forge_native._json_documents(b"[]\n[]\n", 2), [[], []])
        for output in (b"[]", b"[] [] []", b"[] noise []", b"[] [NaN]", b'[] [{"addr":1,"addr":2}]'):
            with self.subTest(output=output), self.assertRaises(ForgeError):
                forge_native._json_documents(output, 2)

    def test_observed_addr_schema_is_normalized_without_guessing(self):
        rows = forge_native._instructions([{"addr": 16, "size": 1, "opcode": "ret"}])
        self.assertEqual(rows[0]["offset"], 16)
        self.assertEqual(rows[0]["backend_address_field"], "addr")
        for row in ({"addr": 1, "offset": 2, "size": 1, "opcode": "ret"},
                    {"addr": True, "size": 1, "opcode": "ret"}):
            with self.assertRaises(ForgeError):
                forge_native._instructions([row])

    def test_invalid_json_and_schema_record_failure(self):
        for output in (b'[{"offset":1,"offset":2}]', b"[NaN]", b"noise\n[]", b"{}", b"[{}]", b"\xff"):
            with self.subTest(output=output), patch.object(forge_native, "executable", return_value="r2"), patch.object(
                    forge_native, "_capture", side_effect=[self.capture(b"r2 unit fixture"), self.capture(output)]):
                with self.assertRaisesRegex(ForgeError, "see evidence"):
                    forge_native.inspect(self.args(), self.store)

    def test_truncated_output_is_not_parsed_as_complete_evidence(self):
        outputs = [self.capture(b"r2 unit fixture"), self.capture(b"[]", truncated=True)]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(forge_native, "_capture", side_effect=outputs):
            with self.assertRaisesRegex(ForgeError, "capture cap"):
                forge_native.inspect(self.args(), self.store)
        data = self.store.list(kind="analysis")[0]["data"]
        self.assertEqual(data["instructions"], [])
        self.assertTrue(data["caps"]["output_truncated"])

    def test_output_budget_is_shared_between_processes(self):
        outputs = [self.capture(b"r2 fixture"), self.capture(b"[]")]
        with patch.object(forge_native, "executable", return_value="r2"), patch.object(
                forge_native, "_capture", side_effect=outputs) as capture:
            forge_native.inspect(self.args(max_output=100), self.store)
        self.assertEqual(capture.call_args_list[0].args[3], 100)
        self.assertEqual(capture.call_args_list[1].args[3], 90)

    def test_changed_binary_produces_failed_evidence(self):
        def capture(argv, root, timeout, max_output):
            if "-v" in argv:
                return self.capture(b"r2 fixture")
            self.binary.write_bytes(b"changed input")
            return self.capture(b'[{"offset":16,"size":1,"opcode":"ret"}]')

        with patch.object(forge_native, "executable", return_value="r2"), patch.object(
                forge_native, "_capture", side_effect=capture):
            with self.assertRaisesRegex(ForgeError, "changed during analysis"):
                forge_native.inspect(self.args(), self.store)
        data = self.store.list(kind="analysis")[0]["data"]
        self.assertFalse(data["binary_unchanged"])
        self.assertNotEqual(data["binary_before"]["sha256"], data["binary_after"]["sha256"])

    def test_real_installed_r2_on_owned_binary_copy(self):
        if not forge_toolchain.find_tool("r2")["available"]:
            self.skipTest("Installed radare2 unavailable")
        shutil.copyfile(sys.executable, self.binary)
        for action in ("disasm", "xrefs", "callgraph"):
            with self.subTest(action=action):
                data = forge_native.inspect(self.args(action=action, address=None, timeout=120,
                    max_output=16777216, max_items=10), self.store)["data"]
                self.assertTrue(data["success"])
                self.assertTrue(data["binary_unchanged"])
                self.assertTrue(data["tool"]["version"])
                if action == "disasm":
                    self.assertTrue(data["instructions"])


if __name__ == "__main__":
    unittest.main()
