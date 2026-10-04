# CLI reference

Run `forge --help` or `forge <command> --help` for executable option definitions. Source checkout execution is `python forge.py ...`; Windows also has `forge.cmd`.

Global options:

- `--version`: print the FORGE version without opening an evidence store.
- `--project PATH`: an existing target folder; place before the command.

Relative input paths resolve against that project. Operational single-command failures return exit 2 and sanitized JSON stderr. Help/argument parsing follows argparse's normal CLI output. Successful command output is JSON `{ "ok": true, "result": ... }`; `probe-run` and `run-target` can still describe failed/stopped operations. Inspect their result fields.

## Tasks

| Command | Inputs | Result |
|---|---|---|
| `init` | `--target URL`, optional `--goal TEXT` | New immutable task and workflow location |
| `status` | None | Latest task/progress, historical HTTP/target verification records and recent evidence; no file rehash |
| `checkpoint` | Required `--phase`, `--summary`, `--expect-revision`; optional task/state/next/blocker/evidence/file | New task-specific progress revision |
| `resume` | Optional `--task ID`, `--checkpoint ID` | Selected state and current integrity of checkpointed files |
| `history` | Optional task, `--after-revision N`, `--limit N` | Ascending checkpoint page, `has_more` and cursor |

See [checkpoints](checkpoints.md) for lifecycle and state invariants. `--blocker`, `--evidence` and `--file` repeat. History page size is 1 to 1000. The default selected task is the newest; use its ID to avoid ambiguity in a multi-task project.

## Artifacts and analysis

```sh
forge --project target artifact-add client.apk --source-url "<observed-publication-url>" --platform android --version "<observed-version>"
forge --project target artifact-fetch "<observed-download-url>" --sha256 "<expected-hash>"
forge --project target artifact-index ".forge/blobs/<returned-sha256>"
forge --project target search "/api/" ".forge/indexes/<returned-index-id>/index.jsonl"
```

Use returned paths and IDs, not guessed ones. `artifact-add` preserves the supplied original. SHA-256 identifies content, not publisher authenticity.

Artifact import/download options: `--version`, `--platform`, `--sha256`, `--max-bytes` (default 256 MiB). Fetch also has `--timeout` and `--max-redirects`; artifact downloads may follow redirects, unlike live HTTP probes.

Index/search reader limits: `--max-file-bytes`, `--max-total-bytes`, `--max-entries`, `--max-records`, `--min-string-length`. Index adds `--max-index-bytes`. Search accepts one or more explicitly scoped paths, `--regex`, `--ignore-case`, `--max-matches`.

Index/search output includes source locations and truncation/skip facts. ZIP members are read without extracting their paths. Gzip indexing is bounded and marks offsets as decompressed-space locations. The bounded ZIP reader does not support ZIP64 or multi-disk archives. Directory indexing excludes known account/proxy/key data, results and dependency/cache directories.

`jadx PATH` requires installed JADX and Java. Options: `--timeout`, `--jobs` (default 2), `--max-log-bytes`. Output/log/evidence remain in the target. Explicit input and output containment rules apply; no universal signing or endpoint extraction is inferred from strings.

## HTTP

```sh
forge --project target probe request.json --rules rules.json
forge --project target probe-run flow.json --transport curl_cffi --impersonate chrome124
forge --project target har-import capture.har --limit 50
forge --project target diff "<left-evidence-id>" "<right-evidence-id>"
```

Probe options: `--rules`, `--transport urllib|curl_cffi`, `--impersonate` (alias `--fingerprint`), `--timeout`, `--max-body`.

`probe-run` adds repeated `--stop-bucket`. Default stop bucket is `TERMINAL`; explicit values replace the default. Response extraction and `${flow.NAME}` syntax are documented in [HTTP flows](http-flows.md).

HAR import adds `--limit`, `--max-body`, `--rules` and never replays traffic. Imported entries do not qualify as live controls. `diff` compares normalized redacted exchanges, not private raw values.

`har-to-flow HAR --output NEW_PATH` converts a selected capture prefix into an editable `probe-run` array without requests or captured URL/header/string values. Options: `--limit` (1..1000, default 50) and `--max-input-bytes` (up to 128 MiB, default 16 MiB). It returns required environment descriptors, hashes and omissions/warnings. Existing or unsafe output paths and unsupported bodies fail. See [HAR templates](har-flows.md).

## Target implementation controls

```sh
forge --project target run-target target-controls.json --timeout 30 --max-output 1048576
forge --project target verify-target --positive "<positive-target-run-id>" --negative "<negative-target-run-id>"
```

The spec declares one argv command, source files, client/egress context, a bucket selector and exactly one positive/negative control. No shell is used. Timeout is per control (finite, >0, at most 3600 seconds); output cap is combined retained stdout/stderr per control (1 byte..16 MiB). Deadlines include inherited pipe EOF; timeout cleanup targets the process tree/group.

Controls need complete stdout JSON, the expected HIT/FREE or FAIL bucket, exit zero, no reported error, no truncation/timeout and unchanged listed sources. `TERMINAL` stops later controls. Results contain `runs`, `passed`, `verification`, `stopped`, `stop_reason`, `requested` and `completed`. `verify-target` requires distinct, same-invocation runs and hashes the current sources again. It rejects stale or failed controls. See [target controls](target-runs.md) for schema and privacy limits. Trusted programs retain your permissions and environment access; this is not a sandbox.

## Protocol map

```sh
forge --project target protocol-map --limit 100 --max-endpoints 200
forge --project target protocol-map --evidence "<capture-id>" --evidence "<live-probe-id>"
```

Read-only metadata summary of relevant static indexes/searches, HAR exchanges and live probes. Explicit IDs take precedence over the newest-record window. Bounds: `--limit` 1..1000, `--max-endpoints` 1..5000. Output preserves citations and distinct provenance categories, reports sampling/truncation, and never promotes imported/static evidence to live authentication. No raw-file scanning or network calls. See [protocol map](protocol-map.md).

## Runtime

```sh
forge --project target doctor
forge --project target adb devices
forge --project target adb install --serial "<observed-serial>" --path client.apk
forge --project target adb launch --serial "<observed-serial>" --package "<observed-package>" --component "<observed-package/activity>"
forge --project target frida --package "<observed-package>" --script hook.js --duration 10
forge --project target native imports client.exe
```

- `doctor` reports dependencies; it does not install them or verify device/login success.
- `adb` actions: `devices`, `install`, `launch`, `stop`, `logcat`, `screenshot`, `ui-tree`. Options: serial/path/package/component/lines/timeout. APK install is not split-APK-aware. Screenshot stores a PNG blob that may contain private on-screen content.
- `frida` requires package/script; optional `--device`, `--attach`, `--duration`. The supplied hook and target setup are the investigator's responsibility.
- `native` actions: `imports`, `exports`, `strings`, `functions`; accepts a binary and timeout. Function analysis invokes radare2 analysis.

See [toolchain setup](toolchain.md) for overrides and platform/device prerequisites. Portable candidates must suit the host; on POSIX Windows launchers are skipped and local executables need execution permission.

## Evidence and controls

```sh
forge --project target evidence --kind http_probe --limit 20
forge --project target show "<evidence-id>"
forge --project target claim "Observed request path in this client version" --state OBSERVED --scope "<artifact/version>" --evidence "<evidence-id>"
forge --project target verify --positive "<live-positive-id>" --negative "<live-negative-id>" --protocol protocol.json
forge --project target report
```

Claims support `OBSERVED`, `INFERRED`, `UNKNOWN`, `CONTRADICTED`; OBSERVED needs a citation. The store checks existence, not the reasoning behind a claim. Evidence/exports are best-effort redacted.

The protocol file must be a nonempty JSON object with an `evidence` array of real IDs. `verify` requires distinct live HIT/FREE and FAIL exchanges, complete responses, identical method/URL/transport and matching declared client/egress. It does not independently measure those identifiers or execute a target checker.

`report` creates a new Markdown note rather than overwriting a previous one. Inspect it before sharing; original artifact blobs and screenshots are outside the database's redaction boundary.
