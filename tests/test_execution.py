import argparse
import base64
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import quote, quote_plus

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from demo_server import DemoServer
from forge_core import EvidenceStore, ForgeError
import forge_execution


DEFAULT_SOURCE = '''import json, sys
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL"}))
'''


class TargetExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        forge_execution.register(self.parser.add_subparsers())
        self.source(DEFAULT_SOURCE)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def source(self, content, name="checker.py"):
        (self.root / name).write_text(content, encoding="utf-8")
        return name

    def spec(self, **overrides):
        return {"command": [sys.executable, "-u", "checker.py"], "files": ["checker.py"],
                "context": {"client": "owned-python-checker", "egress": "declared-loopback"},
                "controls": [{"name": "positive", "args": ["positive"], "expected_bucket": "HIT"},
                             {"name": "negative", "args": ["negative"], "expected_bucket": "FAIL"}],
                **overrides}

    def save_spec(self, spec):
        (self.root / "target.json").write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
        return "target.json"

    def run_target(self, spec=None, *options):
        args = self.parser.parse_args(["run-target", self.save_spec(spec or self.spec()), *options])
        return args.handler(args, self.store)

    def verify(self, positive, negative):
        args = self.parser.parse_args(["verify-target", "--positive", positive, "--negative", negative])
        return args.handler(args, self.store)

    def ids(self, result):
        return {record["data"]["control"]: record["id"] for record in result["runs"]}

    def assert_private(self, result, secrets):
        serialized = json.dumps(result, ensure_ascii=False)
        stored = json.dumps(self.store.list(limit=1000), ensure_ascii=False)
        files = [path.read_bytes() for path in self.store.directory.iterdir() if path.is_file()]
        for secret in secrets:
            forms = {secret, quote(secret, safe=""), quote_plus(secret, safe=""),
                     json.dumps(secret, ensure_ascii=False)[1:-1], json.dumps(secret)[1:-1],
                     base64.b64encode(secret.encode()).decode(),
                     base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="), secret.encode().hex()}
            for form in forms:
                self.assertNotIn(form, serialized)
                self.assertNotIn(form, stored)
                for content in files:
                    self.assertNotIn(form.encode(), content)

    def test_actual_execution_current_hashes_and_explicit_verification(self):
        self.source('''import json, pathlib, sys
with pathlib.Path("calls.txt").open("a") as output:
    output.write(sys.argv[1] + "\\n")
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL",
                  "stdin_closed": sys.stdin.read() == "", "cwd": pathlib.Path.cwd().name}))
''')
        result = self.run_target()
        self.assertTrue(result["passed"])
        self.assertFalse(result["stopped"])
        self.assertEqual((self.root / "calls.txt").read_text().splitlines(), ["positive", "negative"])
        self.assertEqual([record["kind"] for record in result["runs"]], ["target_run", "target_run"])
        for record in result["runs"]:
            data = record["data"]
            self.assertTrue(data["success"])
            self.assertTrue(data["stdout"]["stdin_closed"])
            self.assertEqual(data["sources_before"], data["sources_after"])
            self.assertFalse(data["source_changed"])
            self.assertEqual(data["exit_code"], 0)
            self.assertIn("[LITERAL REDACTED]", data["command_template"])
        ids = self.ids(result)
        verification = self.verify(ids["positive"], ids["negative"])
        self.assertEqual(verification["kind"], "target_verification")
        self.assertEqual(verification["data"]["evidence"], [ids["positive"], ids["negative"]])
        self.assertEqual(verification["data"]["sources"], result["runs"][0]["data"]["sources_before"])
        self.assertEqual(len(self.store.list("control_verification")), 0)

    def test_control_order_and_free_positive(self):
        self.source(DEFAULT_SOURCE.replace('"HIT"', '"FREE"'))
        spec = self.spec()
        spec["controls"][0]["expected_bucket"] = "FREE"
        spec["controls"].reverse()
        result = self.run_target(spec)
        self.assertTrue(result["passed"])
        self.assertEqual([record["data"]["control"] for record in result["runs"]], ["negative", "positive"])

    def test_exit_zero_opposite_branch_does_not_pass(self):
        spec = self.spec()
        spec["controls"][0]["args"] = ["negative"]
        result = self.run_target(spec)
        self.assertFalse(result["passed"])
        self.assertFalse(result["runs"][0]["data"]["success"])
        self.assertEqual(result["runs"][0]["data"]["exit_code"], 0)
        self.assertEqual(result["runs"][0]["data"]["bucket"], "FAIL")
        self.assertEqual(self.store.list("target_verification"), [])
        ids = self.ids(result)
        with self.assertRaises(ForgeError):
            self.verify(ids["positive"], ids["negative"])

    def test_complete_json_known_bucket_and_no_reported_errors_required(self):
        examples = [
            'print("startup log\\n{\\\"bucket\\\":\\\"HIT\\\"}")',
            'print(\'{"bucket":"HIT"} trailing\')',
            'print(\'[{"bucket":"HIT"}]\')',
            'print(\'{"result":"HIT"}\')',
            'print(\'{"bucket":"UNKNOWN"}\')',
            'print(\'{"bucket":"HIT","bucket":"HIT"}\')',
            'print(\'{"bucket":"HIT","extra":NaN}\')',
            'print(\'{"bucket":"HIT","error":"child failed"}\')',
            'print(\'{"bucket":"HIT","nested":{"errors":["child failed"]}}\')',
            'print(\'{"bucket":"HIT"}\'); sys.exit(3)',
            'sys.stdout.buffer.write(b\'{"bucket":"HIT","bad":"\\xff"}\')',
        ]
        for expression in examples:
            with self.subTest(expression=expression):
                self.source("import sys\n" + expression + "\n")
                result = self.run_target()
                self.assertFalse(result["passed"])
                self.assertFalse(result["runs"][0]["data"]["success"])
        self.assertEqual(self.store.list("target_verification"), [])

    def test_valid_dotted_and_pointer_selectors(self):
        self.source('''import json, sys
print(json.dumps({"nested": [{"value": "HIT" if sys.argv[1] == "positive" else "FAIL"}]}))
''')
        for selector in ("/nested/0/value", "nested[0].value", "$.nested[0].value"):
            with self.subTest(selector=selector):
                self.assertTrue(self.run_target(self.spec(bucket_path=selector))["passed"])
        self.source('''import json, sys
print(json.dumps({"a/b": {"~bucket": "HIT" if sys.argv[1] == "positive" else "FAIL"}}))
''')
        self.assertTrue(self.run_target(self.spec(bucket_path="/a~1b/~0bucket"))["passed"])

    def test_invalid_selectors_fail_before_any_execution(self):
        self.source('''import pathlib
pathlib.Path("unexpected.txt").write_text("ran")
print('{"bucket":"HIT"}')
''')
        for selector in (None, "", "/bucket~2", "bucket..value", "bucket[bad]", "$..bucket", "${ENV}"):
            with self.subTest(selector=selector), self.assertRaises(ForgeError):
                self.run_target(self.spec(bucket_path=selector))
        self.assertFalse((self.root / "unexpected.txt").exists())
        self.assertEqual(self.store.list("target_run"), [])

    def test_negative_undefined_environment_has_zero_positive_side_effects(self):
        self.source('''import pathlib
pathlib.Path("unexpected.txt").write_text("ran")
print('{"bucket":"HIT"}')
''')
        spec = self.spec()
        spec["controls"][1]["args"] = ["${FORGE_TEST_MISSING_NEGATIVE}"]
        environment = dict(os.environ)
        environment.pop("FORGE_TEST_MISSING_NEGATIVE", None)
        with patch.dict(os.environ, environment, clear=True), self.assertRaises(ForgeError):
            self.run_target(spec)
        self.assertFalse((self.root / "unexpected.txt").exists())
        self.assertEqual(self.store.list("target_run"), [])

    def test_all_source_paths_and_control_schemas_preflight_before_spawn(self):
        self.source('''import pathlib
pathlib.Path("unexpected.txt").write_text("ran")
print('{"bucket":"HIT"}')
''')
        (self.root / "accounts.txt").write_text("synthetic excluded fixture")
        (self.root / "node_modules").mkdir()
        (self.root / "node_modules" / "lib.py").write_text("print('not a project source')")
        for paths in (["checker.py", "missing.py"], ["checker.py", "../outside.py"],
                      ["checker.py", "accounts.txt"], ["checker.py", "node_modules/lib.py"],
                      ["checker.py", "./checker.py"], ["checker.py", str(self.root / "checker.py")]):
            with self.subTest(paths=paths), self.assertRaises(ForgeError):
                self.run_target(self.spec(files=paths))
        spec = self.spec()
        spec["controls"][1]["name"] = "positive"
        with self.assertRaises(ForgeError):
            self.run_target(spec)
        self.assertFalse((self.root / "unexpected.txt").exists())

    def test_symlink_and_fifo_source_paths_rejected(self):
        link = self.root / "linked.py"
        try:
            link.symlink_to(self.root / "checker.py")
        except OSError:
            pass
        else:
            with self.assertRaises(ForgeError):
                self.run_target(self.spec(files=["checker.py", "linked.py"]))
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "pipe.py")
            with self.assertRaises(ForgeError):
                self.run_target(self.spec(files=["checker.py", "pipe.py"]))
        self.assertEqual(self.store.list("target_run"), [])

    def test_invalid_references_empty_executable_and_bounds_preflight(self):
        for argument in ("${flow.AUTH}", "${UNFINISHED", "${BAD-NAME}", "${}"):
            spec = self.spec()
            spec["controls"][1]["args"] = [argument]
            with self.subTest(argument=argument), self.assertRaises(ForgeError):
                self.run_target(spec)
        with patch.dict(os.environ, {"FORGE_TEST_EMPTY": ""}), self.assertRaises(ForgeError):
            self.run_target(self.spec(command=["${FORGE_TEST_EMPTY}", "checker.py"]))
        for options in (("--timeout", "nan"), ("--timeout", "inf"), ("--timeout", "0"),
                        ("--timeout", "3601"), ("--max-output", "0"), ("--max-output", "16777217")):
            with self.subTest(options=options), self.assertRaises(ForgeError):
                self.run_target(self.spec(), *options)
        with self.assertRaises(ForgeError):
            self.run_target(self.spec(command=["script.cmd"]))
        self.assertEqual(self.store.list("target_run"), [])

    def test_stderr_flood_is_drained_and_retention_is_bounded(self):
        self.source('''import json, os, sys
if sys.argv[1] == "positive":
    for _ in range(256):
        os.write(2, b"x" * 8192)
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL"}))
''')
        result = self.run_target(self.spec(), "--timeout", "5", "--max-output", "4096")
        data = result["runs"][0]["data"]
        self.assertFalse(result["passed"])
        self.assertFalse(data["timed_out"])
        self.assertTrue(data["truncated"])
        self.assertEqual(data["stderr_bytes"], 256 * 8192)
        self.assertLessEqual(len(data["stderr"].encode()) + len(data["stdout"].encode()), 4096)
        self.assertEqual(data["exit_code"], 0)

    def test_timeout_flood_is_bounded_and_terminated(self):
        self.source('''import json, os, sys, time
if sys.argv[1] == "positive":
    for _ in range(256):
        os.write(2, b"x" * 8192)
    time.sleep(120)
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL"}))
''')
        started = time.monotonic()
        result = self.run_target(self.spec(), "--timeout", "0.5", "--max-output", "2048")
        self.assertLess(time.monotonic() - started, 10)
        data = result["runs"][0]["data"]
        self.assertTrue(data["timed_out"])
        self.assertTrue(data["truncated"])
        self.assertFalse(result["passed"])
        self.assertLessEqual(len(data["stderr"].encode()) + len(data["stdout"].encode()), 2048)
        self.assertIsNotNone(data["exit_code"])

    def test_descendant_inherited_pipes_are_included_in_timeout_and_killed(self):
        self.source('''import json, pathlib, subprocess, sys, time
if sys.argv[1] == "positive":
    child = "import pathlib, time; pathlib.Path('child-ready.txt').write_text('ready'); time.sleep(1.5); pathlib.Path('child-survived.txt').write_text('alive'); time.sleep(120)"
    subprocess.Popen([sys.executable, "-c", child])
    while not pathlib.Path("child-ready.txt").exists():
        time.sleep(0.005)
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL"}))
''')
        started = time.monotonic()
        result = self.run_target(self.spec(), "--timeout", "0.6")
        self.assertLess(time.monotonic() - started, 10)
        data = result["runs"][0]["data"]
        self.assertTrue((self.root / "child-ready.txt").exists())
        self.assertEqual(data["exit_code"], 0)
        self.assertTrue(data["timed_out"])
        self.assertFalse(data["success"])
        self.assertIsNone(data["error"])
        time.sleep(1.6)
        self.assertFalse((self.root / "child-survived.txt").exists())

    def test_terminal_stops_negative_without_retry(self):
        self.source('''import json, pathlib, sys
with pathlib.Path("calls.txt").open("a") as output:
    output.write(sys.argv[1] + "\\n")
print(json.dumps({"bucket": "TERMINAL"}))
''')
        result = self.run_target()
        self.assertEqual((self.root / "calls.txt").read_text().splitlines(), ["positive"])
        self.assertEqual(result["completed"], 1)
        self.assertTrue(result["stopped"])
        self.assertEqual(result["stop_reason"], "TERMINAL")
        self.assertFalse(result["passed"])
        self.assertEqual(self.store.list("target_verification"), [])

    def test_terminal_stops_even_when_control_also_reports_process_failure(self):
        self.source('''import json, pathlib, sys
with pathlib.Path("calls.txt").open("a") as output:
    output.write(sys.argv[1] + "\\n")
print(json.dumps({"bucket": "TERMINAL", "error": "deterministic stop"}))
sys.exit(2)
''')
        result = self.run_target()
        self.assertEqual(result["stop_reason"], "TERMINAL")
        self.assertEqual(result["completed"], 1)
        self.assertFalse(result["passed"])
        self.assertEqual((self.root / "calls.txt").read_text().splitlines(), ["positive"])

    def test_changed_source_during_execution_invalidates_and_stops(self):
        self.source('''import json, pathlib, sys
with pathlib.Path(__file__).open("a") as output:
    output.write("\\n# changed by owned fixture\\n")
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL"}))
''')
        result = self.run_target()
        data = result["runs"][0]["data"]
        self.assertTrue(data["source_changed"])
        self.assertNotEqual(data["sources_before"], data["sources_after"])
        self.assertFalse(data["success"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["stop_reason"], "source_changed")
        self.assertEqual(result["completed"], 1)

    def test_stale_source_cross_invocation_same_ids_reversed_and_wrong_kind_rejected(self):
        first = self.ids(self.run_target())
        second = self.ids(self.run_target())
        wrong = self.store.add("http_probe", {"bucket": "HIT"})
        for positive, negative in ((first["positive"], second["negative"]),
                                   (first["negative"], first["positive"]),
                                   (first["positive"], first["positive"]),
                                   (wrong["id"], first["negative"])):
            with self.subTest(positive=positive, negative=negative), self.assertRaises(ForgeError):
                self.verify(positive, negative)
        self.source(DEFAULT_SOURCE + "\n# newer source\n")
        with self.assertRaises(ForgeError):
            self.verify(first["positive"], first["negative"])
        self.source(DEFAULT_SOURCE)
        self.assertTrue(self.verify(first["positive"], first["negative"])["data"]["passed"])
        (self.root / "checker.py").unlink()
        with self.assertRaises(ForgeError):
            self.verify(first["positive"], first["negative"])

    def test_verification_rejects_incomplete_error_or_changed_records(self):
        result = self.run_target()
        ids = self.ids(result)
        original = result["runs"][0]["data"]
        for change in ({"success": False}, {"timed_out": True}, {"truncated": True},
                       {"error": "child_error"}, {"source_changed": True}, {"exit_code": 1},
                       {"source_error": "source_unavailable"}, {"sources_after": []},
                       {"context": {"client": "different-client", "egress": "declared-loopback"}},
                       {"command_template": ["different-command"]},
                       {"schema": "forge.target-run/v1"}, {"runtime_before": None},
                       {"runtime_changed": True}, {"runtime_error": "runtime_unavailable"}, {"runtime_after": None}):
            with self.subTest(change=change):
                invalid = self.store.add("target_run", {**original, **change})
                with self.assertRaises(ForgeError):
                    self.verify(invalid["id"], ids["negative"])

    def test_later_tagged_child_secret_redacts_earlier_opaque_echo_before_storage(self):
        secret = "owned-generated-future-opaque-41b2"
        self.source(f'''import json, sys
value = {secret!r}
key = "echo" if sys.argv[1] == "positive" else "password"
print(json.dumps({{"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL", key: value}}))
''')
        result = self.run_target()
        self.assertTrue(result["passed"])
        self.assertEqual(result["runs"][0]["data"]["stdout"]["echo"], "[REDACTED]")
        self.assert_private(result, [secret])

    def test_numeric_literal_echo_is_redacted_without_corrupting_source_hashes(self):
        secret = "734892163"
        self.source('''import json, sys
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL", "echo": int(sys.argv[2])}))
''')
        spec = self.spec()
        for control in spec["controls"]:
            control["args"].append(secret)
        result = self.run_target(spec)
        self.assertTrue(result["passed"])
        self.assertEqual(result["runs"][0]["data"]["stdout"]["echo"], "[REDACTED]")
        self.assert_private(result, [secret])

    def test_truncated_literal_secret_prefix_is_not_saved(self):
        secret = "opaque-truncation-fixture-734ac"
        self.source('''import os, sys
os.write(1, sys.argv[2].encode())
''')
        spec = self.spec()
        for control in spec["controls"]:
            control["args"].append(secret)
        result = self.run_target(spec, "--max-output", "8")
        self.assertFalse(result["passed"])
        self.assertTrue(result["runs"][0]["data"]["truncated"])
        self.assertNotIn(secret[:8], json.dumps(result))
        self.assert_private(result, [secret])

    def test_literal_credential_cannot_be_repeated_as_declared_context(self):
        secret = "opaque-declared-context-76d2"
        spec = self.spec(context={"client": secret, "egress": "declared-loopback"})
        spec["controls"][0]["args"].append(secret)
        with self.assertRaises(ForgeError):
            self.run_target(spec)
        self.assertEqual(self.store.list("target_run"), [])

    def test_secret_literals_environment_encoded_echoes_and_child_errors_stay_private(self):
        self.source('''import base64, json, sys, urllib.parse
values = sys.argv[2:]
echoes = []
for value in values:
    echoes.extend([value, urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value),
                   base64.b64encode(value.encode()).decode(), base64.urlsafe_b64encode(value.encode()).decode().rstrip("="),
                   value.encode().hex(), json.dumps(value)[1:-1]])
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL", "echoes": echoes}))
print("child detail " + " ".join(values), file=sys.stderr)
''')
        literal = 'opaque literal-64 /"雪'
        environment = "opaque-environment-927 /+="
        password = "explicit-password-c03 /+="
        attached = "attached-secret-b58 /+="
        spec = self.spec()
        for control in spec["controls"]:
            control["args"] += [literal, "${FORGE_TEST_OPAQUE}", "--password", password, "--opaque=" + attached]
        output = io.StringIO()
        with patch.dict(os.environ, {"FORGE_TEST_OPAQUE": environment}), redirect_stdout(output):
            result = self.run_target(spec)
            print(json.dumps(result, ensure_ascii=False))
        self.assertTrue(result["passed"])
        self.assert_private(result, [literal, environment, password, attached])
        for secret in (literal, environment, password, attached):
            self.assertNotIn(secret, output.getvalue())
        self.assertIn("${FORGE_TEST_OPAQUE}", result["runs"][0]["data"]["args_template"])

    def test_actual_cli_does_not_print_secret_echo_or_executable_preflight_error(self):
        self.source('''import json, sys
print(json.dumps({"bucket": "HIT" if sys.argv[1] == "positive" else "FAIL", "opaque": sys.argv[2]}))
print(sys.argv[2], file=sys.stderr)
''')
        secret = "owned-cli-secret-372d"
        spec = self.spec()
        for control in spec["controls"]:
            control["args"].append("${FORGE_TEST_CLI_SECRET}")
        self.save_spec(spec)
        cli = Path(__file__).resolve().parents[1] / "forge.py"
        environment = {**os.environ, "FORGE_TEST_CLI_SECRET": secret}
        completed = subprocess.run([sys.executable, str(cli), "--project", str(self.root), "run-target", "target.json"],
                                   capture_output=True, text=True, encoding="utf-8", env=environment, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn(secret, completed.stdout + completed.stderr)
        self.assert_private(json.loads(completed.stdout), [secret])
        run_count = len(self.store.list("target_run"))
        self.save_spec(self.spec(command=["${FORGE_TEST_CLI_SECRET}"]))
        failed_launch = subprocess.run([sys.executable, str(cli), "--project", str(self.root), "run-target", "target.json"],
                                      capture_output=True, text=True, encoding="utf-8", env=environment, timeout=15)
        self.assertNotIn(secret, failed_launch.stdout + failed_launch.stderr)
        self.assertEqual(failed_launch.returncode, 2)
        failure = json.loads(failed_launch.stderr)
        self.assertFalse(failure["ok"])
        self.assertEqual(len(self.store.list("target_run")), run_count)
        self.assert_private(failure, [secret])


    def test_standard_nonpassing_buckets_are_preserved_without_retry(self):
        for bucket in ("RETRY", "ERROR", "BADFORMAT", "CUSTOM", "RISK"):
            with self.subTest(bucket=bucket):
                self.source(f'''import json, pathlib, sys
with pathlib.Path("calls.txt").open("a") as output:
    output.write(sys.argv[1] + "\\n")
print(json.dumps({{"bucket": {bucket!r}}}))
''')
                calls = self.root / "calls.txt"
                calls.unlink(missing_ok=True)
                result = self.run_target()
                self.assertEqual(calls.read_text().splitlines(), ["positive", "negative"])
                self.assertEqual([run["data"]["bucket"] for run in result["runs"]], [bucket, bucket])
                self.assertTrue(all(run["data"]["error"] is None for run in result["runs"]))
                self.assertFalse(result["passed"])
                self.assertFalse(result["stopped"])

    def test_structured_stdin_is_read_and_credentials_never_enter_argv_or_evidence(self):
        secret = "owned-stdin-secret-64b7"
        self.source('''import json, pathlib, sys
value = json.load(sys.stdin)
assert value["nested"] == [1, True, None, {"value": 734892163}]
assert sys.argv[1:] == ["--declared-mode"]
pathlib.Path(value["mode"] + ".read").write_text("validated")
print(json.dumps({"bucket": "HIT" if value["mode"] == "positive" else "FAIL",
                  "opaque": value["credential"], "nested": value["nested"], "argv": sys.argv[1:]}))
''')
        spec = self.spec()
        for control in spec["controls"]:
            control["args"] = ["--declared-mode"]
            control["stdin_json"] = {"mode": control["name"], "credential": "${FORGE_TEST_STDIN}",
                                     "nested": [1, True, None, {"value": 734892163}]}
        with patch.dict(os.environ, {"FORGE_TEST_STDIN": secret}):
            result = self.run_target(spec)
        self.assertTrue(result["passed"])
        self.assertTrue((self.root / "positive.read").exists())
        self.assertTrue((self.root / "negative.read").exists())
        for run in result["runs"]:
            data = run["data"]
            self.assertTrue(data["stdin_provided"])
            self.assertFalse(data["redaction"]["raw_stdin_stored"])
            self.assertEqual(data["stdout"]["opaque"], "[REDACTED]")
            self.assertEqual(data["stdout"]["nested"][:3], ["[REDACTED]"] * 3)
        self.assert_private(result, [secret, "734892163"])

    def test_environment_executable_is_public_identity_with_private_stdin(self):
        secret = "owned-env-runtime-stdin-3f9c"
        self.source('''import json, pathlib, sys
value = json.load(sys.stdin)
assert sys.argv[1:] == []
pathlib.Path(value["mode"] + ".read").write_text("validated")
print(json.dumps({"bucket": "HIT" if value["mode"] == "positive" else "FAIL",
                  "opaque": value["credential"], "runtime_echo": sys.executable}))
''')
        spec = self.spec(command=["${FORGE_TEST_RUNTIME}", "-u", "checker.py"])
        for control in spec["controls"]:
            control["args"] = []
            control["stdin_json"] = {"mode": control["name"], "credential": "${FORGE_TEST_STDIN}"}
        with patch.dict(os.environ, {"FORGE_TEST_RUNTIME": sys.executable, "FORGE_TEST_STDIN": secret}):
            result = self.run_target(spec)
        self.assertTrue(result["passed"])
        for run in result["runs"]:
            data = run["data"]
            self.assertEqual(data["command_template"][0], "${FORGE_TEST_RUNTIME}")
            self.assertEqual(data["runtime_before"]["identity"], os.path.normcase(str(Path(sys.executable).absolute())))
            self.assertEqual(data["stdout"]["runtime_echo"], "[REDACTED]")
        self.assertTrue((self.root / "positive.read").exists())
        self.assertTrue((self.root / "negative.read").exists())
        self.assert_private(result, [secret])
        ids = self.ids(result)
        self.assertTrue(self.verify(ids["positive"], ids["negative"])["data"]["passed"])

    def test_environment_executable_does_not_exempt_credential_identity_guards(self):
        self.source('''import pathlib
pathlib.Path("unexpected.txt").touch()
print('{"bucket":"HIT"}')
''')
        with patch.dict(os.environ, {"FORGE_TEST_PASSWORD": sys.executable}), self.assertRaises(ForgeError):
            self.run_target(self.spec(command=["${FORGE_TEST_PASSWORD}", "checker.py"]))
        spec = self.spec(command=["${FORGE_TEST_RUNTIME}", "checker.py"])
        spec["controls"][1]["stdin_json"] = {"credential": "${FORGE_TEST_PASSWORD}"}
        with patch.dict(os.environ, {"FORGE_TEST_RUNTIME": sys.executable, "FORGE_TEST_PASSWORD": sys.executable}):
            with self.assertRaises(ForgeError):
                self.run_target(spec)
        spec = self.spec(command=["${FORGE_TEST_RUNTIME}", "checker.py"])
        spec["controls"][1]["args"].append("${FORGE_TEST_PASSWORD}")
        with patch.dict(os.environ, {"FORGE_TEST_RUNTIME": sys.executable, "FORGE_TEST_PASSWORD": sys.executable}):
            with self.assertRaises(ForgeError):
                self.run_target(spec)
        variants = {sys.executable, os.path.normcase(sys.executable)}
        if os.name == "nt":
            variants.add(sys.executable.swapcase())
        for value in variants:
            for location in ("stdin", "argv"):
                spec = self.spec(command=["${FORGE_TEST_RUNTIME}", "checker.py"])
                if location == "stdin":
                    spec["controls"][1]["stdin_json"] = {"credential": value}
                else:
                    spec["controls"][1]["args"].append(value)
                with self.subTest(location=location, value=value):
                    with patch.dict(os.environ, {"FORGE_TEST_RUNTIME": sys.executable}), self.assertRaises(ForgeError):
                        self.run_target(spec)
        self.assertFalse((self.root / "unexpected.txt").exists())
        self.assertEqual(self.store.list("target_run"), [])

    def test_second_stdin_preflight_rejects_bounds_references_and_nonfinite_before_any_process(self):
        self.source('''import pathlib
pathlib.Path("unexpected.txt").write_text("ran")
print('{"bucket":"HIT"}')
''')
        nested = "leaf"
        for _ in range(34):
            nested = [nested]
        invalid = [float("nan"), float("inf"), nested, [None] * 10000,
                   "x" * 1048576, "${FORGE_TEST_MISSING_STDIN}", "${flow.AUTH}", "nul\x00value",
                   "${FORGE_TEST_BIG_STDIN}" * 40]
        environment = dict(os.environ)
        environment.pop("FORGE_TEST_MISSING_STDIN", None)
        environment["FORGE_TEST_BIG_STDIN"] = "bounded-environment-value-" + "z" * 30000
        for value in invalid:
            spec = self.spec(version_argv=["-c", "import pathlib; pathlib.Path('version-ran.txt').touch()"])
            spec["controls"][1]["stdin_json"] = value
            with self.subTest(value_type=type(value).__name__), patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ForgeError):
                    self.run_target(spec)
        self.assertFalse((self.root / "unexpected.txt").exists())
        self.assertFalse((self.root / "version-ran.txt").exists())
        self.assertEqual(self.store.list("target_run"), [])

    def test_duplicate_stdin_keys_and_overflow_number_fail_before_positive(self):
        self.source('''import pathlib
pathlib.Path("unexpected.txt").touch()
print('{"bucket":"HIT"}')
''')
        for raw in ('{"credential":"first","credential":"second"}', '{"count":1e999}'):
            spec = self.spec()
            spec["controls"][1]["stdin_json"] = "REPLACE_WITH_RAW_JSON"
            text = json.dumps(spec).replace('"REPLACE_WITH_RAW_JSON"', raw)
            (self.root / "target.json").write_text(text, encoding="utf-8")
            args = self.parser.parse_args(["run-target", "target.json"])
            with self.subTest(raw=raw), self.assertRaises(ForgeError):
                args.handler(args, self.store)
        self.assertFalse((self.root / "unexpected.txt").exists())

    def test_stdin_writer_and_output_drainers_run_concurrently(self):
        self.source('''import json, os, sys
os.write(2, b"x" * 131072)
value = json.load(sys.stdin)
print(json.dumps({"bucket": "HIT" if value["mode"] == "positive" else "FAIL"}))
''')
        spec = self.spec()
        for control in spec["controls"]:
            control["args"] = []
            control["stdin_json"] = {"mode": control["name"], "credential": "z" * 262144}
        result = self.run_target(spec, "--timeout", "5", "--max-output", "200000")
        self.assertTrue(result["passed"])
        self.assertTrue(all(run["data"]["stderr_bytes"] == 131072 for run in result["runs"]))

    def test_blocked_stdin_writer_obeys_deadline_and_kills_inherited_pipe_holder(self):
        self.source('''import json, pathlib, subprocess, sys, time
child = "import pathlib, time; pathlib.Path('stdin-child-ready.txt').touch(); time.sleep(1.5); pathlib.Path('stdin-child-survived.txt').touch(); time.sleep(120)"
subprocess.Popen([sys.executable, "-c", child], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
while not pathlib.Path("stdin-child-ready.txt").exists():
    time.sleep(0.005)
print('{"bucket":"HIT"}')
''')
        spec = self.spec()
        spec["controls"][0]["stdin_json"] = {"credential": "z" * 262144}
        started = time.monotonic()
        result = self.run_target(spec, "--timeout", "0.6")
        self.assertLess(time.monotonic() - started, 10)
        self.assertTrue(result["runs"][0]["data"]["timed_out"])
        self.assertFalse(result["passed"])
        time.sleep(1.6)
        self.assertFalse((self.root / "stdin-child-survived.txt").exists())

    def copied_runtime(self):
        executable = self.root / ("owned-runtime.exe" if os.name == "nt" else "owned-runtime")
        shutil.copy2(sys.executable, executable)
        return executable, {**os.environ, "PYTHONHOME": sys.prefix,
                            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")}

    def test_actual_runtime_fingerprint_accepts_platform_stat_timestamp_semantics(self):
        executable = Path(sys.executable).absolute()
        content = executable.read_bytes()
        fact = forge_execution._runtime_fact(os.path.normcase(str(executable)))
        self.assertEqual(fact["identity"], os.path.normcase(str(executable)))
        self.assertEqual(fact["resolved_identity"], os.path.normcase(str(executable.resolve(strict=True))))
        self.assertEqual(fact["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(fact["size"], len(content))

    def test_runtime_current_bytes_are_required_for_verification(self):
        executable, environment = self.copied_runtime()
        original = executable.read_bytes()
        with patch.dict(os.environ, environment, clear=True):
            result = self.run_target(self.spec(command=[str(executable), "-u", "checker.py"]))
        self.assertTrue(result["passed"])
        runtime = result["runs"][0]["data"]["runtime_before"]
        self.assertEqual(runtime["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(runtime["size"], len(original))
        self.assertEqual(runtime["identity"], os.path.normcase(str(executable)))
        self.assertEqual(runtime, result["runs"][0]["data"]["runtime_after"])
        self.assertEqual(runtime, result["verification"]["data"]["runtime"])
        ids = self.ids(result)
        with executable.open("ab") as stream:
            stream.write(b"owned-byte-change")
        with self.assertRaisesRegex(ForgeError, "executable"):
            self.verify(ids["positive"], ids["negative"])
        executable.write_bytes(original)
        self.assertTrue(self.verify(ids["positive"], ids["negative"])["data"]["passed"])
        executable.unlink()
        with self.assertRaises(ForgeError):
            self.verify(ids["positive"], ids["negative"])

    @unittest.skipIf(os.name == "nt", "Windows locks mapped executable images against byte modification")
    def test_actual_runtime_byte_change_during_control_invalidates_and_stops(self):
        executable, environment = self.copied_runtime()
        self.source('''import json, os, shutil, sys
from pathlib import Path
current = Path(sys.executable)
replacement = current.with_name("replacement-owned-runtime")
shutil.copy2(current, replacement)
with replacement.open("ab") as output:
    output.write(b"owned-byte-change")
os.replace(replacement, current)
print('{"bucket":"HIT"}')
''')
        with patch.dict(os.environ, environment, clear=True):
            result = self.run_target(self.spec(command=[str(executable), "-u", "checker.py"]))
        data = result["runs"][0]["data"]
        self.assertTrue(data["runtime_changed"])
        self.assertNotEqual(data["runtime_before"], data["runtime_after"])
        self.assertEqual(data["error"], "runtime_changed")
        self.assertEqual(result["stop_reason"], "runtime_changed")
        self.assertEqual(result["completed"], 1)
        self.assertFalse(result["passed"])

    def test_path_resolution_uses_child_cwd_and_environment_and_rejects_batch(self):
        executable, environment = self.copied_runtime()
        environment["PATH"] = "." + os.pathsep + environment["PATH"]
        with patch.dict(os.environ, environment, clear=True):
            result = self.run_target(self.spec(command=[executable.name, "-u", "checker.py"]))
        self.assertTrue(result["passed"])
        self.assertEqual(result["runs"][0]["data"]["runtime_before"]["identity"], os.path.normcase(str(executable)))
        self.source("@echo off", "implicit.cmd")
        with patch.dict(os.environ, environment, clear=True), self.assertRaises(ForgeError):
            self.run_target(self.spec(command=["implicit.cmd"]))

    def test_version_probe_is_explicit_bounded_and_sanitized(self):
        self.assertIsNone(self.run_target()["runs"][0]["data"]["version"])
        secret = "owned-version-secret-612a"
        probe = ["-c", "import sys; print('Owned runtime release 7'); print(sys.argv[1])", "${FORGE_TEST_VERSION}"]
        with patch.dict(os.environ, {"FORGE_TEST_VERSION": secret}):
            result = self.run_target(self.spec(version_argv=probe))
        self.assertTrue(result["passed"])
        self.assertIn("Owned runtime release 7", result["version"]["stdout"])
        self.assertIn("[REDACTED]", result["version"]["stdout"])
        self.assert_private(result, [secret])
        for probe in (["-c", "import time; time.sleep(120)"], ["-c", "print('x' * 10000)"]):
            with self.subTest(probe=probe):
                result = self.run_target(self.spec(version_argv=probe), "--timeout", "0.5")
                self.assertFalse(result["passed"])
                self.assertTrue(result["version"]["timed_out"] or result["version"]["truncated"])
                self.assertTrue(all(run["data"]["error"] == "version_probe_error" for run in result["runs"]))

    def test_owned_demo_checker_json_stdin_performs_real_login_without_secret_output(self):
        checker = Path(__file__).resolve().parents[1] / "examples" / "demo_checker.py"
        self.source(checker.read_text(encoding="utf-8"))
        server = DemoServer(0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            spec = self.spec(command=[sys.executable, "checker.py", "--stdin-json"],
                             context={"client": "fixture-client", "egress": "loopback"})
            for control, password in zip(spec["controls"], ("demo-password", "wrong-demo-password")):
                control["args"] = []
                control["stdin_json"] = {"url": f"http://127.0.0.1:{server.server_port}",
                                         "login": "demo", "password": password}
            result = self.run_target(spec)
            self.assertTrue(result["passed"])
            self.assertEqual([run["data"]["bucket"] for run in result["runs"]], ["HIT", "FAIL"])
            self.assertEqual(len(server.sessions), 1)
            self.assert_private(result, ["demo-password", "wrong-demo-password"])
            for password in ("demo-password", "wrong-demo-password"):
                completed = subprocess.run([sys.executable, str(checker), "--url", f"http://127.0.0.1:{server.server_port}",
                                            "--login", "demo", "--password", password],
                                           capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 0)
                self.assertNotIn(password, completed.stdout + completed.stderr)
            for raw in ('{"password":"private-stdin-credential","password":"second-value"}',
                        '{"url":"http://127.0.0.1","login":"demo","password":42}'):
                completed = subprocess.run([sys.executable, str(checker), "--stdin-json"], input=raw,
                                           capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(json.loads(completed.stdout)["bucket"], "BADFORMAT")
                self.assertNotIn("private-stdin-credential", completed.stdout + completed.stderr)
            secret = "private-unrecognized-argument-73ae"
            completed = subprocess.run([sys.executable, str(checker), "--unexpected", secret],
                                       capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 2)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_project_source_really_calls_loopback_positive_and_negative(self):
        received = []
        authorized = "owned-loopback-positive-41ce"
        unauthorized = "owned-loopback-negative-824f"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                supplied = self.headers.get("Authorization")
                received.append(supplied)
                positive = supplied == "Bearer " + authorized
                raw = json.dumps({"bucket": "HIT" if positive else "FAIL", "echo": supplied}).encode()
                self.send_response(200 if positive else 403)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.source('''import json, sys, urllib.error, urllib.request
request = urllib.request.Request(sys.argv[1], headers={"Authorization": "Bearer " + sys.argv[2]})
try:
    response = urllib.request.urlopen(request, timeout=3)
except urllib.error.HTTPError as error:
    response = error
with response:
    body = json.loads(response.read())
print(json.dumps({"result": {"bucket": body["bucket"]}, "echo": body["echo"]}))
''')
            spec = self.spec(bucket_path="result.bucket")
            base = f"http://127.0.0.1:{server.server_port}/owned-check"
            spec["controls"][0]["args"] = [base, "${FORGE_TEST_AUTHORIZED}"]
            spec["controls"][1]["args"] = [base, "${FORGE_TEST_UNAUTHORIZED}"]
            with patch.dict(os.environ, {"FORGE_TEST_AUTHORIZED": authorized, "FORGE_TEST_UNAUTHORIZED": unauthorized}):
                result = self.run_target(spec)
            self.assertTrue(result["passed"])
            self.assertEqual(received, ["Bearer " + authorized, "Bearer " + unauthorized])
            self.assertEqual([record["data"]["bucket"] for record in result["runs"]], ["HIT", "FAIL"])
            self.assert_private(result, [authorized, unauthorized])
            self.assertTrue(any("independently attest" in limit for limit in result["verification"]["data"]["limits"]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
