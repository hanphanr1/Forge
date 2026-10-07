<div align="center">

# FORGE

**Give the agent evidence, not screenshots.**

</div>

[![CI](https://github.com/hanphanr1/Forge/actions/workflows/ci.yml/badge.svg)](https://github.com/hanphanr1/Forge/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-555)](pyproject.toml)
[![MIT License](https://img.shields.io/badge/License-MIT-555)](LICENSE)
[![No model, no cloud](https://img.shields.io/badge/runs-100%25%20local-555)](docs/scope-and-retention.md)

FORGE is a local workbench for reverse-engineering protocol clients: Android, iOS, desktop and web. It imports the artifact, indexes source-located strings, drives the tools you already installed (JADX, radare2, ADB, Frida), probes real endpoints, and keeps every observation in a target-local evidence store. Checkpoints carry the next experiment across sessions. Response extraction moves tokens between requests without turning the evidence database into a credential store.

Use it directly or from a coding agent with shell access. FORGE does not call a model, require a model API key, or register an MCP server. Your agent still reads request builders, chooses experiments, and writes the target implementation.

What that buys the agent:

- Every result is a record: input SHA-256, the exact command, observed stdout/stderr sizes, raw bytes and the limits of what was actually checked. Cite an evidence ID or leave the claim out.
- Gaps stay visible. An unmatched response is `UNKNOWN`, a truncated output is flagged as truncated, and a field nobody observed never reaches the store.
- Work resumes. `checkpoint` and `resume` return the saved state, cited findings, file-integrity hashes and next action, and every write carries an expected revision.
- FORGE calls no model and needs no account. The whole store lives in `.forge/` inside the target folder.

[CLI reference](docs/cli.md) · [Agent workflow](WORKFLOW.md) · [HTTP flows](docs/http-flows.md) · [HAR templates](docs/har-flows.md) · [Capture ingest](docs/capture-ingest.md) · [Target controls](docs/target-runs.md) · [Comparisons](docs/comparisons.md) · [GraphQL](docs/graphql.md) · [Native](docs/native.md) · [Android](docs/android.md) · [APK patching](docs/apk-patching.md) · [iOS boundary](docs/ios.md) · [Scope and retention](docs/scope-and-retention.md) · [Bundles](docs/bundles.md) · [Task handoff](docs/checkpoints.md)

## See it work

This runs on loopback with disposable fixture credentials. The first command starts the demo server; the second replays a two-request flow: log in, extract a token from the response, spend it with the session cookie.

```sh
python examples/demo_server.py
forge --project . probe-run examples/login-flow.json
```

Below is a real run of that command, reformatted for width. The token and cookie are stored redacted, which is why the flow works without FORGE ever keeping a usable credential:

```text
ok: true    requested: 2    completed: 2    session_reused: true    stopped: false
ev_b0e7a3c1a04a4d16a2ec8edf978b80f2   POST http://127.0.0.1:8765/login    200  {"message": "SIGNED_IN", "data": {"opaque": "[REDACTED]"}}
ev_f41f38f76787487f8ddb661e0c4e272a   GET  http://127.0.0.1:8765/profile  200  {"message": "PROFILE_READY", "plan": "demo", "opaque_echo": "[REDACTED]"}
cookie: [REDACTED]
```

Full walkthrough and the flow syntax: [Try a complete local flow](#try-a-complete-local-flow).

## The workflow

```mermaid
flowchart LR
    Operator["You or your coding agent"] --> CLI["FORGE CLI"]
    CLI --> Artifacts["Artifacts and indexes"]
    CLI --> Capture["HTTP and runtime observations"]
    CLI --> Tasks["Checkpoint / resume / history"]
    Artifacts --> Store["Target-local evidence"]
    Capture --> Store
    Tasks <--> Store
```

The evidence store is local to each target. A resumed task carries its cited findings and next experiment; it does not start an autonomous agent.

## Install

Python 3.10 or newer. The core uses the standard library; runtime tools and the curl transport are optional.

```sh
git clone https://github.com/hanphanr1/Forge.git
cd Forge
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```sh
# Linux / macOS
. .venv/bin/activate
```

Then install from this checkout:

```sh
python -m pip install -e .
forge --version
forge --help
```

If PowerShell blocks activation, invoke `.\.venv\Scripts\python.exe -m pip install -e .` and use `.\.venv\Scripts\forge.exe`; changing machine-wide execution policy is unnecessary.

For explicit curl impersonation support:

```sh
python -m pip install -e ".[http]"
```

You can also run `python forge.py` without installing the package. Third-party binaries, virtual environments and captures are not distributed in this repository.

## Start an investigation

Create a dedicated folder for the target. `--project` selects that existing folder and goes **before** the command. Relative input paths resolve there, not against the shell's current directory.

```sh
mkdir investigation
forge --project investigation doctor
forge --project investigation init --target https://example.invalid --goal "Trace and verify the client login flow"
forge --project investigation status
```

`example.invalid` is an illustrative target, not a supported service. Replace it with the official site identified during your investigation.

Save progress before changing sessions or waiting for a device:

```sh
forge --project investigation checkpoint --phase analyze --state blocked --summary "Located the request builder; runtime capture is still needed" --next "Capture one authorized login on Android" --blocker "Awaiting a connected device" --expect-revision 0
forge --project investigation resume
```

`resume` reports the saved state and file integrity. It does not execute the next action or silently clear blockers. Each checkpoint uses an expected revision to prevent a stale session from overwriting newer work.

## Try a complete local flow

The demo binds to loopback and uses disposable fixture credentials. It does not contact a vendor or accept production credentials. Run the two commands from [See it work](#see-it-work) in two terminals.

The flow logs in, extracts a token from the JSON response, and sends it with the session cookie to the profile endpoint. Inspect the final exchange's `bucket` and the top-level `stopped` / `stop_reason`; `ok: true` alone does not mean an entire flow succeeded. Stop the demo server when finished.

The flow syntax is explicit:

```json
[
  {
    "url": "http://127.0.0.1:8765/login",
    "method": "POST",
    "json": {"login": "demo", "password": "demo-password"},
    "extract": {"AUTH": {"json_path": "/data/opaque"}}
  },
  {
    "url": "http://127.0.0.1:8765/profile",
    "headers": {"Authorization": "Bearer ${flow.AUTH}"}
  }
]
```

`${ENV_VAR}` reads an explicit environment value. `${flow.AUTH}` reads an earlier extraction within this command. Extraction values remain in command memory and are scrubbed from stored exchanges, including opaque echoes. Missing, malformed or truncated extraction stops the flow before a dependent request. See [HTTP flows](docs/http-flows.md) for selectors, stop precedence and limitations.

## From capture to executed controls

```sh
forge --project investigation har-to-flow capture.har --output flows/from-capture.json
forge --project investigation protocol-map --limit 100
forge --project investigation run-target target-controls.json
forge --project investigation verify-target --positive "<positive-target-run-id>" --negative "<negative-target-run-id>"
```

HAR conversion writes editable request templates and source/output hashes without sending traffic or copying captured URL/header/string values. Fill the returned environment variables and add only selectors/rules supported by observed protocol evidence. See [HAR templates](docs/har-flows.md).

`run-target` executes trusted project code for two explicit controls with bounded stdout/stderr, process deadlines, source hashes and actual executable fingerprints. Optional `stdin_json` keeps credentials out of argv; optional declared `version_argv` records a bounded version probe. All standard buckets remain visible, but only expected HIT/FREE and FAIL controls can pass. `verify-target` rechecks sources and executable bytes. The program reports its bucket; FORGE does not independently attest authentication or IP. See [target controls](docs/target-runs.md).

`protocol-map` summarizes stored URLs, methods, header/field names and source citations. Static candidates, imported captures and live HTTP observations stay separate; it neither opens raw captures nor probes endpoints. See [protocol map](docs/protocol-map.md).

## Compare versions and hand off evidence

```sh
forge --project investigation protocol-snapshot --evidence "<observed-exchange-id>"
forge --project investigation protocol-diff --before "<snapshot-id>" --after "<snapshot-id>"
forge --project investigation client-diff --before "<artifact-or-index-id>" --after "<artifact-or-index-id>"
forge --project investigation graphql-analyze client.graphql
forge --project investigation bundle --evidence "<finding-or-verification-id>" --output handoff/review.zip
```

Protocol snapshots retain citations and omission flags; their diffs distinguish field/status/provenance changes from server claims. Client comparisons inspect stored artifact bytes or explicitly labeled redacted-index projections. GraphQL analysis extracts operations, variables, fields and fragments without exporting literals or contacting a schema endpoint. Bundles follow bounded citation closure and withhold capture payloads, process streams, paths, blobs and free-text findings by default. Review metadata before disclosure. See [comparisons](docs/comparisons.md), [GraphQL](docs/graphql.md) and [bundles](docs/bundles.md).


## What is included

| Area | Commands | Boundary |
|---|---|---|
| Task handoff | `init`, `status`, `checkpoint`, `resume`, `history` | Agent-reported progress, not automatic verification |
| Artifacts | `artifact-add`, `artifact-fetch`, `artifact-index`, `search` | Bounded readers; strings are candidates, not live protocol proof |
| Runtime | `jadx`, `native`, `adb`, `adb-preflight`, `adb-install-splits`, `apk-info`, `frida`, `doctor` | Actual installed tools; split selection and compatible authorized hardware are explicit |
| APK patching | `apk-decode`, `apk-manifest`, `apk-rebuild`, `apk-sign`, `apk-gadget` | Unsigned rebuilds stay unsigned; signing never publishes output that fails verification; a Gadget repackage is recorded as a debuggable build with a replaced signature |
| iOS boundary | `ios-devices`, `ios-pair` | Read-only external tool observations; no capture, hooking or injection capability |
| Maintenance | `storage-report`, `evidence-prune` | Read-only inventory; pruning is opt-in and breaks the append-only citation guarantee |
| HTTP | `probe`, `probe-run`, `har-import`, `har-to-flow`, `diff` | Explicit requests and editable capture templates; no automatic retries or replay |
| Capture ingest | `capture-ingest`, `websocket-analyze`, `api-shape` | Loopback-only bounded listener and read-only name-level analysis; pushed traffic is never live proof |
| Implementation | `run-target`, `verify-target` | Trusted-code execution and declared controls; not a sandbox or independent authentication proof |
| Protocol | `protocol-map`, `protocol-snapshot`, `protocol-diff`, `graphql-analyze` | Cited provenance and local structural analysis, not schema/authentication inference |
| Client versions | `client-diff` | Stored artifact bytes or labeled index-projection differences, not server-change proof |
| Evidence | `claim`, `evidence`, `show`, `verify`, `report`, `bundle` | Scoped gates and explicit lossy metadata handoffs |

Artifacts keep SHA-256, origin and source locations. HTTP rules classify observed response bodies rather than guessing from a status code. The first matching rule wins; an unmatched response is `UNKNOWN`. `TERMINAL` stops deterministic refusals instead of retrying them.

## Runtime tools

Install only what the investigation needs:

- [JADX](https://github.com/skylot/jadx) and a compatible Java runtime for Android decompilation.
- [Android Platform Tools](https://developer.android.com/tools/releases/platform-tools) for ADB.
- [Frida](https://frida.re/docs/installation/) for an explicit hook script and compatible target setup. `frida-apk`, which ships with frida-tools, is what `apk-gadget` runs, and the matching `frida-gadget-<version>-android-<abi>.so.xz` comes from the same Frida release.
- [radare2](https://github.com/radareorg/radare2) for native inspection.

Tool discovery checks an explicit `FORGE_*` override, a portable tool directory beside the source modules, then `PATH`. A broken override fails rather than selecting a different executable. `doctor` reports the actual resolution. See [toolchain setup](docs/toolchain.md).

Android requires an authorized device or an environment you have deliberately configured. `apk-info` reads compiled manifest metadata from explicit APKs or exact archive members without installing. `adb-preflight` observes serial/OS/API/ABI and classifies missing prerequisites; `adb packages`/`adb package` locate an installed app and `adb pull`/`adb push` move one explicit artifact in or out of a new project-local path. `adb-install-splits` validates explicitly selected APKs/APKS/XAPK members and uses new-install-only dispatch; it does not replace apps or grant permissions. `jadx` keeps usable source when an obfuscated APK finishes with per-class errors. `apk-decode`/`apk-manifest`/`apk-rebuild`/`apk-sign`/`apk-gadget` cover the authorized patch loop: a decode you can read, a declared-surface summary, a rebuild that stays unsigned, a signing step that verifies before publishing, and a Frida Gadget repackage for a device without root, recorded as a debuggable build with a replaced signature rather than as the original app. Deep native actions expose bounded disassembly, xrefs, register-level `pdc` pseudo-C and function-level call-reference graphs backed by observed radare2 data; `pdc` is a readable view of the disassembly, not recovered source, and FORGE bundles no real decompiler. `frida` checks device reachability first and names the missing prerequisite: a jailed Android needs a repackaged Gadget, otherwise a reachable device-side `frida-server`. There is no iOS runtime adapter; `ios-devices`/`ios-pair` only report what a configured external tool says so prerequisites are known before asking for device-side work. None of this downloads SDKs, changes device security or supplies an iOS adapter. See [Android](docs/android.md), [APK patching](docs/apk-patching.md), [iOS](docs/ios.md) and [native analysis](docs/native.md).

## Evidence and privacy

Each target stores data under `.forge/`:

```text
.forge/
  evidence.sqlite3   # cited task, analysis and exchange records
  blobs/             # original artifact bytes and explicit runtime captures
  indexes/           # bounded static indexes
  analysis/          # tool output such as JADX decompilation
```

The database is not a source for replaying credentials. Redaction is best-effort: unknown unlabeled secrets, raw artifacts and screenshots may still contain private data. Keep the store local, inspect exports, and do not commit captures or credentials. Checkpoint file entries contain paths and hashes, not file contents.

`verify` requires distinct live positive and negative exchanges with complete responses, matching endpoint/transport and matching declared client/egress identifiers. It **does not** execute an implementation. Use `run-target` and `verify-target` for declared process controls; these still do not independently measure egress or verify every server branch.

## Development

```sh
python -m unittest discover -s tests -v
python -m pip wheel . --no-deps --wheel-dir dist
python examples/smoke.py
python examples/smoke.py --transport curl_cffi
```

CI runs the regression suite and actual CLI smoke on Windows, Linux and macOS: reviewed HAR replay, JSON-stdin implementation controls, executable/version fingerprints, changed-source rejection, cited protocol/client diffs, GraphQL value exclusion and bundle member hashes. It then builds and exercises the installed wheel. Native/device checks require their actual dependencies and hardware; parser/dispatch fixtures are not installation proof. See [CONTRIBUTING.md](CONTRIBUTING.md) for the change and release procedure.

## Author and license

Created and maintained by [hanphanr1](https://github.com/hanphanr1).

[MIT License](LICENSE). Optional third-party tools retain their own licenses.
