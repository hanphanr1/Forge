# CLI reference

Run `forge --help` or `forge <command> --help` for executable option definitions. Source checkout execution is `python forge.py ...`; Windows also has `forge.cmd`.

Global options:

- `--version`: print the FORGE version without opening an evidence store.
- `--project PATH`: an existing target folder; place before the command.

Relative input paths resolve against that project. Operational single-command failures return exit 2 and sanitized JSON stderr. Help/argument parsing follows argparse's normal CLI output. Successful command output is JSON `{ "ok": true, "result": ... }`; `probe-run` and `run-target` can still describe failed/stopped operations. Inspect their result fields.

## Tasks

| Command | Inputs | Result |
|---|---|---|
| `init` | `--target URL`, optional `--goal TEXT`, scope flags | New immutable task and workflow location |
| `status` | None | Latest task/progress including declared scope, historical HTTP/target verification records and recent evidence; no file rehash |
| `checkpoint` | Required `--phase`, `--summary`, `--expect-revision`; optional task/state/next/blocker/evidence/file | New task-specific progress revision |
| `resume` | Optional `--task ID`, `--checkpoint ID` | Selected state and current integrity of checkpointed files |
| `history` | Optional task, `--after-revision N`, `--limit N` | Ascending checkpoint page, `has_more` and cursor |
| `claim` | `TEXT`, required `--scope`; optional `--state`, `--evidence` | Scoped agent statement with retained citations |
| `hook-evidence` | `TEXT`, `--package`, `--static-location`/`--static-evidence`, `--dynamic-proof`/`--dynamic-evidence`; optional state pair and `--scope` | One claim holding a hook evidence triple |
| `storage-report` | Optional `--max-scan-rows N` | Read-only evidence/blob/database inventory |
| `evidence-prune` | `--unreferenced-blobs` or `--older-than DAYS`; `--apply` to delete | Plan by default; guarded deletion with an audit row |

See [checkpoints](checkpoints.md) for lifecycle and state invariants. `--blocker`, `--evidence` and `--file` repeat. History page size is 1 to 1000. The default selected task is the newest; use its ID to avoid ambiguity in a multi-task project.

`init` also records caller-declared scope: `--authorization` (`unspecified`, `granted`, `pending`, `denied`), `--basis`, `--network-profile` (`unspecified`, `offline`, `lab_only`, `authorized_target_only`, `unrestricted_lab`), and repeatable `--in-scope`/`--out-of-scope`. `--authorization granted` requires an explicit `--basis`. A denied scope blocks active steps (`probe`, `probe-run`, `adb *`, `frida`), an `offline` profile blocks network and device steps, and local analysis of already-obtained artifacts stays available either way. See [scope and retention](scope-and-retention.md).

`hook-evidence` keeps a hook boundary together: where it is, what proved it at runtime, and which local state it needs. Each part cites its own record; an omitted state dependency is stored as `not-established` instead of being assumed, and `--state-dependency` without `--state-evidence` is rejected.

## Artifacts and analysis

```sh
forge --project target artifact-add client.apk --source-url "<observed-publication-url>" --platform android --version "<observed-version>"
forge --project target artifact-fetch "<observed-download-url>" --sha256 "<expected-hash>"
forge --project target artifact-index ".forge/blobs/<returned-sha256>"
forge --project target artifact-index pulled/app/base.apk --dex --max-records 500000 --max-index-bytes 268435456
forge --project target search "grok.com" ".forge/indexes/<returned-index-id>/index.jsonl" --max-records 500000
forge --project target android-api-map --index-evidence "<dex-index-id>" --jadx-evidence "<jadx-id>" --class-filter "<observed-class>"
```

Use returned paths and IDs, not guessed ones. `artifact-add` preserves the supplied original. SHA-256 identifies content, not publisher authenticity.

Artifact import/download options: `--version`, `--platform`, `--sha256`, `--max-bytes` (default 256 MiB). Fetch also has `--timeout` and `--max-redirects`; artifact downloads may follow redirects, unlike live HTTP probes.

Index/search reader limits: `--max-file-bytes`, `--max-total-bytes`, `--max-entries`, `--max-records`, `--min-string-length`. Index adds `--max-index-bytes`. Search accepts one or more explicitly scoped paths, `--regex`, `--ignore-case`, `--max-matches`.

`artifact-index APK --dex` selects only root `classes*.dex` members of an APK/ZIP. It skips resources and metadata before they consume the record cap, while each string citation still names the DEX member and byte offset. The mode is explicit; it does not infer application behavior from a string.

`android-api-map` consumes a cited static DEX index and cited successful/partial JADX output. It verifies the index hash, then finds exact URL literal occurrences in bounded Java/Kotlin/smali source. `--class-filter` narrows the source scan, for example to `e5.c`. Each candidate keeps DEX-member byte offsets and source class/line/hash. Java occurrences also include `source_traces`: enclosing methods, direct String field initializers, unambiguous same-arity constructor argument/parameter/field assignments, field reads, and one-hop same-class caller candidates.

`--max-trace-items` (default 10,000; maximum 100,000) is shared across files and counts trace roots, field links, field reads, callers and markers. Inspect `trace_items`, `trace_items_omitted`, and `trace_truncated`; omitted counts are lower bounds when traversal stops. Other source/index/occurrence caps still apply. Source hashes identify the bytes read now, not an immutable snapshot of every file from the earlier JADX run.

These are syntactic candidates, not resolved calls or value propagation. Caller matches retain `overload_count`, without selecting an overload. Markers such as `url(...)`, `newCall(...)`, `execute(...)`, `enqueue(...)`, `performRequest(...)` and HTTP annotations only co-occur in an enclosing method; no client type or network dispatch is proven. Only the first top-level Java type is traced. Nested/local/anonymous classes, malformed Java, Kotlin and smali retain literal citations without Java method resolution. Qualified constructor names are not bound by their last name. Cross-file callers, inheritance, reflection and generated URLs remain unresolved. Pair candidates with captured/live HTTP before treating them as an API flow. Bundles withhold local paths and method/field/parameter names, retaining bounded structural metadata.


`android-caller-map --jadx-evidence ID --method NAME [--class OWNER] [--path-filter SUBSTRING]` scans a cited
JADX output for call sites of one method name: bare calls list possible owner classes from imports and the same
package, `this.`/owner-class/named-receiver/expression/constructor receivers are classified, declarations and
annotation uses are skipped, and `--class` filters by attribution. Repeatable `--path-filter` scopes the walk to
a path/class substring (recorded in the evidence), so following one package does not tokenize the whole tree.
Results are cross-file **name candidates** (`cross_file_name_candidate`): overload resolution, inheritance,
reflection and generated call sites are not resolved, caps and omissions are reported, and each candidate keeps
the calling file's class/line and hash.

`search` reads generated `index.jsonl` files under `--max-total-bytes`; `--max-file-bytes` applies to ordinary source files and archive members, while each index JSON record has a fixed 128 KiB cap. This lets a bounded index larger than one source-file cap remain searchable. `--max-records` can still truncate a large index; check `truncated` and `records_scanned` before treating a no-match result as meaningful.

Index/search output includes source locations and truncation/skip facts. New static indexes record creation-time JSONL SHA-256 and size. ZIP members are read without extracting their paths. Gzip indexing is bounded and marks offsets as decompressed-space locations. The bounded ZIP reader does not support ZIP64 or multi-disk archives. Directory indexing excludes known account/proxy/key data, results and dependency/cache directories.

`jadx PATH` requires installed JADX and Java. Options: `--timeout`, `--jobs` (default 2), `--deobf`, `--single-class`, `--max-log-bytes`. Output/log/evidence remain in the target. Explicit input and output containment rules apply; no universal signing or endpoint extraction is inferred from strings. Real-world obfuscated APKs often finish with per-class decompile errors while still producing thousands of usable sources, so a nonzero exit with saved sources is recorded as `status: partial` (with `java_files` and `error_count`) and returned successfully; a run that produced no sources, or that timed out, still fails. Read `--single-class` or the saved output rather than re-running the whole APK.

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

Read-only metadata summary of relevant static indexes/searches, cited `api-map` candidates, HAR exchanges, live probes and `pcap-analyze` packet hosts. A packet host is a host-only identity that never merges with a URL, and a `static_host_match` joins an observed host to a cited `api-map` candidate by `static_candidate_sha256` without proving the candidate's path or body. Explicit IDs take precedence over the newest-record window, which accepts a `static_index`, `api-map`, or `pcap-analyze` analysis but not a `pcapdroid` capture record. Bounds: `--limit` 1..1000, `--max-endpoints` 1..5000. Output preserves citations and distinct provenance categories, reports sampling/truncation, and never promotes imported/static/packet evidence to live authentication. No raw-file scanning or network calls. See [protocol map](protocol-map.md).

`protocol-snapshot` accepts the same selection/bounds and stores an immutable cited map. `protocol-diff --before SNAPSHOT_ID --after SNAPSHOT_ID` compares endpoint/method identities, field/header names, statuses, selector metadata and provenance with explicit omissions/ambiguities. Query/fragment values are not identity dimensions; static method-unknown candidates remain separate, and a packet-level host is a host-only identity that carries no method or path. Neither a missing observation nor a changed field proves a server change. See [comparisons](comparisons.md).

## Runtime

```sh
forge --project target doctor
forge --project target apk-info client.apk
forge --project target adb devices
forge --project target adb packages --third-party --filter "<observed-name-part>"
forge --project target adb package --serial "<observed-serial>" --package "<observed-package>"
mkdir target/pulled
forge --project target adb pull-package --serial "<observed-serial>" --package "<observed-package>" --path pulled/app
forge --project target adb observe --serial "<observed-serial>" --package "<observed-package>" --seconds 90 --lines 3000
forge --project target adb launch --serial "<observed-serial>" --package "<observed-package>" --component "<observed-package/activity>"
forge --project target frida --package "<observed-package>" --script hook.js --duration 10
forge --project target native imports client.exe
```

- `doctor` reports dependencies; it does not install them or verify device/login success.
- `apk-info` reads compiled manifest metadata (package, split, version code, minSdk, declared split dependencies/types, native ABIs) from explicit APK paths or exact archive members, without installing anything. Add `--validate-selection` to also check the set as one installable split selection.
- `adb` actions: `devices`, `install`, `launch`, `stop`, `logcat`, `screenshot`, `ui-tree`, `pull`, `pull-package`, `push`, `packages`, `package`, `observe`. `pull` copies one explicit absolute device file and refuses overwrite. `pull-package` reads the installed package's `pm path` entries and copies its base/splits into a new project-local directory with hashes and parsed metadata; it does not install or modify the app. `observe` requires the app already running, waits for an interaction, then filters the device log buffer to PIDs sampled at the window edges and epoch timestamps in the window. `--lines` caps recent log rows across PIDs; the Android ring buffer and that cap can omit earlier rows. It can miss short-lived processes. `--ui-snapshots` is opt-in and may capture private screen text. Neither action captures or decrypts HTTP.
- `adb-preflight` records authorized-device OS/API/ABI facts. `adb-install-splits` accepts repeatable `--apk`, or `--archive` with exact repeatable `--member`, plus optional `--serial` and `--installer PACKAGE`; the installer flag only declares the recorded source. The command checks package/version/split compatibility before new-install-only dispatch. See [Android](android.md).
- `frida` requires package/script; optional `--device`, `--attach`, `--duration`, `--host HOST:PORT` and `--forward PORT`. `--host` attaches to a Gadget instead of a device-side `frida-server` and therefore requires `--attach`; `--forward` sets that port up with `adb forward` and removes it afterwards, which is the no-root route. It first checks device reachability with `frida-ps` and classifies a refused spawn (jailed Android needs a repackaged Gadget; otherwise a reachable device-side `frida-server`). The supplied hook and target setup remain the investigator's responsibility.
- `native` actions: `imports`, `exports`, `strings`, `functions`, `disasm`, `xrefs`, `callgraph`, `decompile`. Deep actions add `--address`, `--max-output` and `--max-items` with strict project input and bounded backend results; observed function/basic-block membership supports graph edges, unresolved memberships stay labeled. `decompile` retains radare2 `pdc` pseudo-C bounded by `--max-items` lines and the shared output budget, reporting any cut instead of discarding a usable view; it is register-level pseudo-C, not recovered source, and FORGE bundles no real decompiler. See [native](native.md).

See [toolchain setup](toolchain.md) for overrides and platform/device prerequisites. Portable candidates must suit the host; on POSIX Windows launchers are skipped and local executables need execution permission.

## Capture ingest and shape analysis

```sh
forge --project target pcapdroid-preflight --serial "<observed-serial>" --package "<observed-package>"
forge --project target pcapdroid-capture --serial "<observed-serial>" --package "<observed-package>" --path captures/run.pcap --seconds 20
forge --project target pcap-analyze captures/run.pcap --capture-evidence "<capture-id>" --map-evidence "<api-map-id>"
forge --project target capture-ingest --port 0 --seconds 60
forge --project target websocket-analyze capture.har
forge --project target api-shape --domain "<observed-host>"
```

`pcapdroid-preflight` observes the configured ADB device, the installed capture app and target package, the current-user UID and the scoped `CaptureService` state. `pcapdroid-capture` starts one bounded, app-filtered rootless capture through the installed PCAPdroid app's documented Intent API, with root capture, TLS decryption, SOCKS5, PCAPNG, private-DNS blocking and remote exporters all explicitly off, then waits for an observed stop and retrieves the generated dump to a required new project-local `.pcap` path. `--max-bytes` (default 33554432) caps both the requested device dump and host retrieval; a dump above the cap is refused before anything is pulled. The command records dispatch, service, file and stop observations separately, and `success` requires the generated dump name, the observed service, an observed stop and a hash-verified retrieval — an accepted `am start` is never capture success. Consent still happens on the device, PCAPdroid may need approval for both start and stop, and a consent dialog left open is a reported blocker rather than a retry loop. Set `--api-key-env` to an environment variable to authenticate the control Intent without a prompt; the key is passed quoted and never stored.

`pcap-analyze` reads one local classic PCAP under `--max-bytes`, `--max-packets`, `--max-hosts` and `--max-flows`, and reports bounded connection metadata: per-direction flows, DNS question/answer names, TLS ClientHello SNI, plaintext HTTP `Host`, and optional PCAPdroid trailer UID/app-name claims. Payload bytes, request targets, headers and bodies are never retained, printed or exported. Nothing is decrypted, so HTTPS paths, methods, bodies and authentication are not observed, and QUIC/ECH/pinned traffic yields metadata only. TCP payloads are placed by sequence number, so retransmissions are not double-counted and a gap is reported as `tcp_reassembly_gaps` instead of a guessed name. `--capture-evidence` verifies the cited capture record's hash, size and path, then splits names and packets by the trailer UID claim: observations without a claim are counted as unknown, never as target traffic. `--map-evidence` re-hashes the cited static index and reports exact hostname matches, which ties an APK URL candidate to an observed host without proving a path, method, body or authenticated call. The raw capture stays local and may contain secrets.
`pcap-analyze` also decodes plaintext HTTP request lines: a host entry can carry bounded `http_methods` and
`http_paths` (origin-form, query stripped entirely), and `decryption_performed` is computed, not assumed — true
only when the cited capture record declared a decryption request and this analysis decoded at least one request
line, with the rule recorded in `decryption_basis`. `pcapdroid-capture` adds `--tls-decryption` (an opt-in
request: FORGE installs no CA, adds no trust anchor and edits nothing, so a pinned or CA-distrusting app stays
encrypted and the request is never claimed as performed), `--repeat N` with `--gap SECONDS`, and per-window
`--launch PACKAGE/ACTIVITY` / `--force-stop`: each window writes its own `window-NN.pcap` and evidence record
under one `capture-session` record, and a window failure stops further windows while completed files, hashes
and records stay intact. `pcapdroid-preflight` also observes the PCAPdroid MITM addon (`com.pcapdroid.mitm`) as
its own scoped fact, and `--tls-decryption` refuses with `mitm-addon-absent` before any Intent is sent when
that addon is missing — the hardware failure mode otherwise looks like a consent timeout that never resolves.
`--continue-on-error` keeps later windows running after one fails while the session record still reports
`success: false`; the default is stop-at-first-failure.

Decrypted traffic is **not** written into the PCAP file: PCAPdroid hands it to mitmproxy. Pass
`--mitmproxy-opts "-w /sdcard/Download/PCAPdroid/flows.dump"` together with `--tls-decryption`, pull that dump
from the device, then convert and import it:

```sh
forge --project target flow-to-har captures/flows.dump --output captures/flows.har --limit 500
forge --project target har-import captures/flows.har --limit 50
forge --project target api-shape --domain "<observed-host>"
```

`flow-to-har` needs the optional `flows` extra (`pip install 'forge-protocol[flows]'`), caps every body with
`--max-body-bytes`, records truncation and flow counts, and makes no network calls. `--ssl-keylog NAME` instead
asks PCAPdroid for an SSLKEYLOGFILE for offline decryption of captured TLS.

`capture-ingest` runs a bounded loopback listener so a capture tool can push HAR directly instead of a manual export/import. It binds `127.0.0.1` only, stops at `--seconds` (1..3600), `--max-records` or an error, and accepts a HAR document, an entries array or one entry object. Each exchange is stored through the same normalization as `har-import`, so pushed traffic stays `captured_http` and is never promoted to live proof. With `--port 0` the chosen port is announced once on stderr; stdout stays `{ok, result}`. `--token` requires a matching `X-Forge-Token` or `Authorization: Bearer` header. Oversized bodies, wrong method/route, a bad token and malformed JSON are rejected with per-reason counters and never echo request data.

`websocket-analyze` parses frames from HAR entries carrying `_webSocketMessages`/`_webSocketFrames` or from explicit `{"url", "frames"}` documents: per session it reports frame counts, direction (or `unknown` when the document cannot establish it), opcode/type counts, payload byte stats, close codes and JSON field-name paths only. `api-shape` summarizes stored HTTP evidence per domain: method/path identities, status distribution, and request/response header, JSON field-path, form and query *names*. Both are read-only, export names rather than values, and report their caps. See [capture ingest](capture-ingest.md).

## APK patching

```sh
forge --project target apk-decode client.apk --output decoded
forge --project target apk-manifest decoded
forge --project target apk-rebuild decoded --output rebuilt.apk
forge --project target apk-sign rebuilt.apk --output signed.apk --debug-keystore
forge --project target apk-gadget client.apk --gadget frida-gadget-17.22.1-android-arm64.so --output gadget.apk
forge --project target adb install --serial "<observed-serial>" --path signed.apk
```

`apk-decode` runs apktool into a new project-local directory and only reports success when the decoded `AndroidManifest.xml` exists. `apk-manifest` summarizes declared permissions, components with their `android:exported` value, intent filters and deeplinks from a decoded directory, a decoded manifest, or a raw APK. `apk-rebuild` produces unsigned bytes that are not installable until `apk-sign` succeeds. `apk-sign` runs zipalign, apksigner and a verification pass, requires either `--keystore`/`--alias` with password environment variables or an explicit `--debug-keystore`, and never publishes output that fails verification. Its zip page alignment is read from the ELF `PT_LOAD` alignment of the APK's stored native libraries (`-p`, `-P 16`, `-P 64`): release builds that link 16 KiB-page libraries are refused by the installer when they are only 4 KiB-aligned. `apk-gadget` repackages an APK with a Frida Gadget for a device without root: it reads the ABI from the Gadget's ELF header, requires the injected members and the embedded Gadget hash to match, refuses a changed package name, and records that the result is debuggable with a replaced signature. It also sets `android:extractNativeLibs="true"` in the repackaged manifest, because the Gadget route depends on `wrap.sh` + `LD_PRELOAD` and release builds ship that flag false, which otherwise fails installation. Gadget config values stay out of evidence. See [APK patching](apk-patching.md).

## iOS boundary

```sh
forge --project target ios-devices
forge --project target ios-pair --udid "<observed-udid>"
```

Both commands only invoke an explicitly configured `idevice_id`/`idevicepair` and record what the tool printed. FORGE has no iOS runtime adapter: no capture, hooking, injection, jailbreak or certificate capability, and ADB does not apply. Pairing state is host/device trust metadata, not proof of capture or of an application-layer session. See [iOS](ios.md).

## Maintenance

```sh
forge --project target storage-report
forge --project target evidence-prune --unreferenced-blobs
forge --project target evidence-prune --older-than 30 --kind http_probe --apply
```

`storage-report` is read-only. `evidence-prune` plans by default and only deletes with `--apply`; cited evidence, audit rows and post-checkpoint records are protected unless `--force` lifts that. Pruning breaks the append-only citation guarantee. See [scope and retention](scope-and-retention.md).

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
