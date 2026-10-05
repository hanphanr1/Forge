"""Exercise the actual CLI against disposable local HTTP and task fixtures."""

import argparse
import hashlib
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import zipfile

from demo_server import DemoServer


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def invoke(cli, project, *arguments, expected_exit=0, env=None):
    result = subprocess.run([*cli, "--project", str(project), *arguments], cwd=project.parent,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=60, env=env)
    require(result.returncode == expected_exit,
            f"CLI exit {result.returncode}, expected {expected_exit}: {result.stderr.decode('utf-8', 'replace')}")
    payload = json.loads((result.stdout if expected_exit == 0 else result.stderr).decode("utf-8"))
    require(payload["ok"] == (expected_exit == 0), "CLI result disagrees with exit status")
    return payload["result"] if expected_exit == 0 else payload


def run(cli, transport):
    with tempfile.TemporaryDirectory(prefix="forge-fixture-") as directory, DemoServer(0) as server:
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

            with server.session_lock:
                captured_cookie, captured_token = next(iter(server.sessions.items()))
            har = {"log": {"entries": [
                {"request": {"url": base + "/login", "method": "POST",
                             "headers": [{"name": "Content-Type", "value": "application/json"}],
                             "postData": {"mimeType": "application/json", "text": json.dumps(flow[0]["json"])}},
                 "response": {"status": 200, "headers": [], "content": {"text": json.dumps({"message": "SIGNED_IN"})}}},
                {"request": {"url": base + "/profile", "method": "GET", "headers": [
                    {"name": "Authorization", "value": "Bearer " + captured_token},
                    {"name": "Cookie", "value": "demo_session=" + captured_cookie}]},
                 "response": {"status": 200, "headers": [], "content": {"text": json.dumps({"message": "PROFILE_READY"})}}}
            ]}}
            (project / "owned.har").write_text(json.dumps(har), encoding="utf-8")
            exported = invoke(cli, project, "har-to-flow", "owned.har", "--output", "exported-flow.json")
            require(not exported["replayed"], "HAR conversion replayed requests")
            environment = os.environ.copy()
            for binding in exported["variables"]:
                pointer, separator, nested = binding["pointer"].partition("#")
                value = har
                for part in pointer[1:].split("/"):
                    part = part.replace("~1", "/").replace("~0", "~")
                    value = value[int(part)] if isinstance(value, list) else value[part]
                if separator:
                    value = json.loads(value)
                    for part in nested[1:].split("/") if nested else []:
                        part = part.replace("~1", "/").replace("~0", "~")
                        value = value[int(part)] if isinstance(value, list) else value[part]
                environment[binding["variable"]] = value
            reviewed = json.loads((project / "exported-flow.json").read_text(encoding="utf-8"))
            reviewed[0]["extract"] = flow[0]["extract"]
            reviewed[1]["headers"] = {"Authorization": "Bearer ${flow.AUTH}"}
            for request, original in zip(reviewed, flow):
                request["rules"] = original["rules"]
            (project / "reviewed-flow.json").write_text(json.dumps(reviewed), encoding="utf-8")
            replay = invoke(cli, project, "probe-run", "reviewed-flow.json", "--transport", transport, env=environment)
            require(not replay["stopped"] and [item["data"]["bucket"] for item in replay["exchanges"]] == ["HIT", "HIT"],
                    "Reviewed HAR flow did not run against the actual fixture")

            captured = invoke(cli, project, "har-import", "owned.har")
            (project / "client_routes.js").write_text(f'const LOGIN = "{base}/login";', encoding="utf-8")
            indexed = invoke(cli, project, "artifact-index", "client_routes.js")
            mapped = invoke(cli, project, "protocol-map")
            categories = {observation["category"] for endpoint in mapped["endpoints"] for observation in endpoint["observations"]}
            require(categories == {"static_candidate", "captured_http", "live_http"}, "Protocol map lost provenance categories")
            require(not mapped["authentication_verified"] and all(not endpoint["proven_live"] for endpoint in mapped["endpoints"] if "method" not in endpoint),
                    "Protocol map promoted static observations")
            map_citations = {citation["evidence_id"] for endpoint in mapped["endpoints"]
                             for observation in endpoint["observations"] for citation in observation["citations"]}
            require(indexed["id"] in map_citations and all(item["id"] in map_citations for item in captured["exchanges"]),
                    "Protocol map lost capture/source citations")

            before_snapshot = invoke(cli, project, "protocol-snapshot", "--evidence", captured["exchanges"][1]["id"])
            revised_har = json.loads(json.dumps(har))
            revised_har["log"]["entries"][1]["response"]["status"] = 202
            revised_har["log"]["entries"][1]["response"]["content"]["text"] = json.dumps({"message": "PROFILE_READY", "quota_remaining": 7})
            (project / "revision.har").write_text(json.dumps(revised_har), encoding="utf-8")
            revision = invoke(cli, project, "har-import", "revision.har")
            after_snapshot = invoke(cli, project, "protocol-snapshot", "--evidence", revision["exchanges"][1]["id"])
            protocol_changes = invoke(cli, project, "protocol-diff", "--before", before_snapshot["id"], "--after", after_snapshot["id"])
            profile_change = next(item for item in protocol_changes["data"]["changed"] if item["identity"]["method"] == "GET")
            require(profile_change["changes"]["response_status"] == {"before": [200], "after": [202]}
                    and "/quota_remaining" in profile_change["changes"]["response_body.json_field_paths"]["after"],
                    "Cited capture comparison lost field/status changes")
            require(not protocol_changes["data"]["authentication_verified"], "Capture diff claimed authentication")

            client_versions = []
            for version, endpoint in [("1.0", "/login"), ("2.0", "/profile")]:
                archive_path = project / ("client-" + version + ".zip")
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("routes.js", 'const endpoint = "' + base + endpoint + '";\n')
                    archive.writestr("old.js" if version == "1.0" else "new.js", "const revision = true;\n")
                artifact = invoke(cli, project, "artifact-add", archive_path.name, "--version", version)
                version_index = invoke(cli, project, "artifact-index", artifact["data"]["path"])
                archive_path.unlink()
                client_versions.append((artifact, version_index))
            client_changes = invoke(cli, project, "client-diff", "--before", client_versions[0][0]["id"],
                                    "--after", client_versions[1][0]["id"], "--before-index", client_versions[0][1]["id"],
                                    "--after-index", client_versions[1][1]["id"])
            require([item["file"] for item in client_changes["data"]["files"]["added"]] == ["new.js"]
                    and [item["file"] for item in client_changes["data"]["files"]["removed"]] == ["old.js"]
                    and [item["file"] for item in client_changes["data"]["files"]["changed"]] == ["routes.js"],
                    "Stored client-version comparison lost byte inventory changes")
            require(not client_changes["data"]["server_changes_verified"], "Static client diff claimed server changes")

            document = 'query OwnedProfile($id: ID!) { viewer(id: $id) { id plan } }\nmutation OwnedMutation { update(value: "privateGraphQLLiteral91") { ok } }\n'
            (project / "owned.graphql").write_text(document, encoding="utf-8")
            graphql = invoke(cli, project, "graphql-analyze", "owned.graphql")
            operations = graphql["data"]["documents"][0]["operations"]
            require([operation["name"] for operation in operations] == ["OwnedProfile", "OwnedMutation"]
                    and operations[0]["variables"][0]["type"] == "ID!"
                    and "privateGraphQLLiteral91" not in json.dumps(graphql), "GraphQL analysis lost structure or copied values")

            (project / "target_impl.py").write_bytes((ROOT / "examples/demo_checker.py").read_bytes())
            implementation = {"command": ["${FORGE_DEMO_PYTHON}", "target_impl.py", "--stdin-json"], "files": ["target_impl.py"],
                              "version_argv": ["--version"], "context": {"client": "fixture-client", "egress": "loopback"},
                              "controls": [
                                  {"name": "positive", "args": [], "stdin_json": {"url": "${FORGE_DEMO_URL}", "login": "demo",
                                   "password": "${FORGE_DEMO_POSITIVE}"}, "expected_bucket": "HIT"},
                                  {"name": "negative", "args": [], "stdin_json": {"url": "${FORGE_DEMO_URL}", "login": "demo",
                                   "password": "${FORGE_DEMO_NEGATIVE}"}, "expected_bucket": "FAIL"}]}
            (project / "implementation.json").write_text(json.dumps(implementation), encoding="utf-8")
            environment.update(FORGE_DEMO_PYTHON=sys.executable, FORGE_DEMO_URL=base,
                               FORGE_DEMO_POSITIVE="demo-password", FORGE_DEMO_NEGATIVE="wrong-demo-password")
            executed = invoke(cli, project, "run-target", "implementation.json", env=environment)
            require(executed["passed"] and len(executed["runs"]) == 2 and executed["verification"],
                    "Actual target implementation controls did not pass")
            run_ids = {item["data"]["control"]: item["id"] for item in executed["runs"]}
            checked = invoke(cli, project, "verify-target", "--positive", run_ids["positive"], "--negative", run_ids["negative"])
            require(checked["data"]["passed"], "Saved target controls failed current-source verification")
            runtime_hash = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            require(executed["version"]["exit_code"] == 0 and executed["version"]["error"] is None
                    and executed["version"]["stdout"].strip() == "Python " + ".".join(map(str, sys.version_info[:3]))
                    and all(item["data"]["runtime_before"]["sha256"] == runtime_hash for item in executed["runs"]),
                    "Target executable/version fingerprint was not observed")
            shared = invoke(cli, project, "bundle", "--evidence", checked["id"], "--evidence", protocol_changes["id"],
                            "--evidence", client_changes["id"], "--evidence", graphql["id"], "--output", "handoff.zip")
            with zipfile.ZipFile(project / "handoff.zip") as archive:
                manifest = json.loads(archive.read("manifest.json"))
                exported_members = {name: archive.read(name) for name in archive.namelist()}
                for fact in manifest["members"]:
                    require(hashlib.sha256(exported_members[fact["name"]]).hexdigest() == fact["sha256"], "Handoff member hash mismatch")
                packed = b"\n".join(exported_members.values())
                require(b"demo-password" not in packed and b"privateGraphQLLiteral91" not in packed,
                        "Handoff bundle copied private control/document values")
            require(shared["manifest"]["closure_complete"] and not manifest["raw_materials_included"],
                    "Handoff falsely declared incomplete citations or raw material disclosure")
            with (project / "target_impl.py").open("a", encoding="utf-8") as output:
                output.write("\n# owned smoke revision\n")
            changed_target = invoke(cli, project, "verify-target", "--positive", run_ids["positive"],
                                    "--negative", run_ids["negative"], expected_exit=2)
            require(not changed_target["ok"], "Changed implementation remained verified")

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
                    "historical_resume": True, "no_issued_secret_in_store": True,
                    "har_flow": ["HIT", "HIT"], "protocol_categories": sorted(categories),
                    "target_controls": True, "changed_target_rejected": True,
                    "stdin_controls": True, "runtime_fingerprinted": True, "cited_protocol_diff": True,
                    "client_version_diff": True, "graphql_values_withheld": True, "handoff_hashes_verified": True}
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
