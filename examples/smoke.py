"""Exercise the actual CLI against disposable local HTTP and task fixtures."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

from demo_server import DemoServer


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def invoke(cli, project, *arguments, expected_exit=0):
    result = subprocess.run([*cli, "--project", str(project), *arguments], cwd=project.parent,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    require(result.returncode == expected_exit,
            f"CLI exit {result.returncode}, expected {expected_exit}: {result.stderr.decode('utf-8', 'replace')}")
    payload = json.loads((result.stdout if expected_exit == 0 else result.stderr).decode("utf-8"))
    require(payload["ok"] == (expected_exit == 0), "CLI result disagrees with exit status")
    return payload["result"] if expected_exit == 0 else payload


def run(cli, transport):
    with tempfile.TemporaryDirectory(prefix="forge-demo-") as directory, DemoServer(0) as server:
        project = Path(directory)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            flow = json.loads((ROOT / "examples/login-flow.json").read_text(encoding="utf-8"))
            negative = json.loads((ROOT / "examples/negative-login.json").read_text(encoding="utf-8"))
            for request in [*flow, negative]:
                request["url"] = request["url"].replace("http://127.0.0.1:8765", base)
            (project / "flow.json").write_text(json.dumps(flow), encoding="utf-8")
            (project / "negative.json").write_text(json.dumps(negative), encoding="utf-8")
            source = project / "fixture_auth.py"
            source.write_text("version = 1\n", encoding="utf-8")

            task = invoke(cli, project, "init", "--target", base, "--goal", "Verify the disposable local fixture")["task"]
            positive = invoke(cli, project, "probe-run", "flow.json", "--transport", transport)
            require(not positive["stopped"] and positive["completed"] == 2, "Dependent HTTP flow did not finish")
            buckets = [record["data"]["bucket"] for record in positive["exchanges"]]
            require(buckets == ["HIT", "HIT"], f"Unexpected flow classification: {buckets}")
            require(positive["exchanges"][1]["data"]["response"]["body"]["opaque_echo"] == "[REDACTED]",
                    "Opaque token echo reached CLI output")
            failed = invoke(cli, project, "probe", "negative.json", "--transport", transport)
            require(failed["data"]["bucket"] == "FAIL", "Negative control was not classified FAIL")
            citations = [record["id"] for record in positive["exchanges"]] + [failed["id"]]
            (project / "protocol.json").write_text(json.dumps({"evidence": citations, "flow": "local demo"}), encoding="utf-8")
            gate = invoke(cli, project, "verify", "--positive", citations[0], "--negative", failed["id"],
                          "--protocol", "protocol.json")
            require(gate["data"]["passed"], "Live local control gate failed")

            saved = invoke(cli, project, "checkpoint", "--task", task["id"], "--phase", "verify", "--state", "blocked",
                           "--summary", "Local controls passed; awaiting fixture review", "--next", "Review the fixture protocol",
                           "--blocker", "Fixture review pending", "--evidence", gate["id"], "--file", "fixture_auth.py",
                           "--file", "protocol.json", "--expect-revision", "0")
            source.write_text("version = 2\n", encoding="utf-8")
            resumed = invoke(cli, project, "resume", "--task", task["id"])
            require(resumed["state"] == "blocked" and resumed["blockers"] == ["Fixture review pending"],
                    "Process handoff lost its blocker")
            integrity = {fact["path"]: fact["status"] for fact in resumed["file_integrity"]}
            require(integrity == {"fixture_auth.py": "changed", "protocol.json": "unchanged"},
                    f"Unexpected file integrity: {integrity}")
            stale = invoke(cli, project, "checkpoint", "--task", task["id"], "--phase", "verify", "--state", "completed",
                           "--summary", "Stale session", "--expect-revision", "0", expected_exit=2)
            require("Stale revision" in stale["error"], "Stale checkpoint was not rejected")
            completed = invoke(cli, project, "checkpoint", "--task", task["id"], "--phase", "verify", "--state", "completed",
                               "--summary", "Local fixture verified; no vendor login was tested", "--evidence", gate["id"],
                               "--expect-revision", "1")
            first = invoke(cli, project, "history", "--task", task["id"], "--limit", "1")
            second = invoke(cli, project, "history", "--task", task["id"], "--after-revision", str(first["next_revision"]), "--limit", "1")
            require([first["checkpoints"][0]["id"], second["checkpoints"][0]["id"]] == [saved["id"], completed["id"]],
                    "Task history pagination lost checkpoint identity")
            require(first["has_more"] and not second["has_more"], "History cursor did not terminate")
            states = [first["checkpoints"][0]["data"]["state"], second["checkpoints"][0]["data"]["state"]]
            historical = invoke(cli, project, "resume", "--task", task["id"], "--checkpoint", saved["id"])
            require(not historical["is_current"] and historical["current_revision"] == 2 and historical["state"] == "blocked",
                    "Historical resume incorrectly became current")

            with server.session_lock:
                issued = [value for pair in server.sessions.items() for value in pair]
            for path in (project / ".forge").glob("evidence.sqlite3*"):
                content = path.read_bytes()
                require(all(secret.encode("utf-8") not in content for secret in issued),
                        "Issued local token/cookie reached SQLite evidence")
            return {"ok": True, "source": "local-fixture", "transport": transport, "flow": buckets,
                    "negative": failed["data"]["bucket"], "control_gate": True, "checkpoint_revision": 2,
                    "stale_rejected": True, "file_integrity": integrity, "history_states": states,
                    "historical_resume": True, "no_issued_secret_in_store": True}
        finally:
            server.shutdown()
            thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=("urllib", "curl_cffi"), default="urllib")
    parser.add_argument("--cli", nargs=argparse.REMAINDER, help="CLI executable and prefix arguments; place last")
    args = parser.parse_args()
    if args.cli == []:
        parser.error("--cli requires an executable")
    cli = args.cli or [sys.executable, str(ROOT / "forge.py")]
    print(json.dumps(run(cli, args.transport)))


if __name__ == "__main__":
    main()
