import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CliEncodingTests(unittest.TestCase):
    def test_console_entrypoint_persists_unicode_task_under_ascii_stdio(self):
        root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "ascii"
        prefix = [sys.executable, "-c", "from forge import main; raise SystemExit(main())"]
        goal = "Xác minh phiên bàn giao"
        with tempfile.TemporaryDirectory() as project:
            created = subprocess.run([*prefix, "--project", project, "init", "--target", "https://example.invalid", "--goal", goal],
                                     cwd=root, env=environment, capture_output=True, timeout=30)
            self.assertEqual(created.returncode, 0, created.stderr)
            task = json.loads(created.stdout.decode("utf-8"))["result"]["task"]
            resumed = subprocess.run([*prefix, "--project", project, "resume", "--task", task["id"]],
                                     cwd=root, env=environment, capture_output=True, timeout=30)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            data = json.loads(resumed.stdout.decode("utf-8"))["result"]
            self.assertEqual(data["task"]["id"], task["id"])
            self.assertEqual(data["task"]["data"]["goal"], goal)
            self.assertIn(goal.encode("utf-8"), resumed.stdout)


if __name__ == "__main__":
    unittest.main()
