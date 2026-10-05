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

Index/search output includes source locations and truncation/skip facts. New static indexes record creation-time JSONL SHA-256 and size. ZIP members are read without extracting their paths. Gzip indexing is bounded and marks offsets as decompressed-space locations. The bounded ZIP reader does not support ZIP64 or multi-disk archives. Directory indexing excludes known account/proxy/key data, results and dependency/cache directories.

`jadx PATH` requires installed JADX and Java. Options: `--timeout`, `--jobs` (default 2), `--max-log-bytes`. Output/log/evidence remain in the target. Explicit input and output containment rules apply; no universal signing or endpoint extraction is inferred from strings.

`client-diff --before ID --after ID` compares stored artifacts or static indexes. Pair artifacts with `--before-index/--after-index`, or indexes with `--before-artifact/--after-artifact`; pairing must reference the stored blob. Index-only hashes identify redacted projections, not original file bytes. `graphql-analyze [SOURCE] --evidence ID` (repeatable) parses explicit source/request observations, exports structural names/positions and withholds literals; no introspection or traffic. See [comparisons](comparisons.md) and [GraphQL](graphql.md) for limits and provenance.

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

The spec declares one argv command, source files, client/egress context, a bucket selector and exactly one positive/negative control. Per-control `stdin_json` resolves bounded JSON privately and delivers it concurrently; absent input preserves closed stdin. Optional `version_argv` is explicitly supplied for the resolved executable. No shell is used. Timeout is per control (finite, >0, at most 3600 seconds); output cap is combined retained stdout/stderr (1 byte..16 MiB). Deadlines include inherited pipes/input delivery and process-tree cleanup.

Complete stdout JSON may report HIT/FREE/FAIL/TERMINAL/RETRY/ERROR/BADFORMAT/CUSTOM/RISK. Only expected positive HIT/FREE or negative FAIL with exit zero, no reported error/truncation/timeout and unchanged sources/executable can pass. TERMINAL stops later controls; no retries. Results expose `runs`, `passed`, `verification`, `stopped`, `stop_reason`, `requested`, `completed` and optional version facts. `verify-target` requires distinct same-invocation v2 runs and rehashes sources/executable; legacy records remain readable but need fresh execution for v2 verification. See [target controls](target-runs.md). This is not a sandbox.

## Protocol map

```sh
forge --project target protocol-map --limit 100 --max-endpoints 200
forge --project target protocol-map --evidence "<capture-id>" --evidence "<live-probe-id>"
```

Read-only metadata summary of relevant static indexes/searches, HAR exchanges and live probes. Explicit IDs take precedence over the newest-record window. Bounds: `--limit` 1..1000, `--max-endpoints` 1..5000. Output preserves citations and distinct provenance categories, reports sampling/truncation, and never promotes imported/static evidence to live authentication. No raw-file scanning or network calls. See [protocol map](protocol-map.md).

`protocol-snapshot` accepts the same selection/bounds and stores an immutable cited map. `protocol-diff --before SNAPSHOT_ID --after SNAPSHOT_ID` compares endpoint/method identities, field/header names, statuses, selector metadata and provenance with explicit omissions/ambiguities. Query/fragment values are not identity dimensions; static method-unknown candidates remain separate. Neither a missing observation nor a changed field proves a server change. See [comparisons](comparisons.md).

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
- `adb` actions: `devices`, `install`, `launch`, `stop`, `logcat`, `screenshot`, `ui-tree`; existing single-APK behavior is unchanged. `adb-preflight` adds actual authorized-device OS/API/ABI observations. `adb-install-splits` accepts repeatable `--apk`, or `--archive` with repeatable exact `--member`, optional `--serial` and bounded timeout; compiled manifests, package/version/dependencies and compatibility are checked before new-install-only dispatch. No hardware means no install proof. See [Android](android.md).
- `frida` requires package/script; optional `--device`, `--attach`, `--duration`. The supplied hook and target setup are the investigator's responsibility.
- `native` actions: `imports`, `exports`, `strings`, `functions`, `disasm`, `xrefs`, `callgraph`. Deep actions add `--address`, `--max-output` and `--max-items` with strict project input and bounded backend results; observed function/basic-block membership supports graph edges, unresolved memberships stay labeled. No decompiler/source-recovery guarantee. See [native](native.md).

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

`bundle --evidence ID --output NEW_ZIP` follows bounded citation closure and exports metadata projections with member/ZIP hashes. Repeat `--evidence`; options `--limit`, `--max-bytes`, `--max-record-bytes`. Default excludes bodies/streams/argv/stdin/paths/blobs/screenshots and free-text findings. `--include-findings` explicitly includes reviewed scrubbed claim prose; it cannot discover every unlabelled secret. Closure completeness and projection loss are separate. See [bundles](bundles.md).
