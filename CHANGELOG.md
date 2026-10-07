# Changelog

## 0.8.0 - 2026-10-07

- `frida` gains `--host HOST:PORT` and `--forward PORT`: the first attaches to a Gadget instead of a device-side `frida-server` and requires `--attach`, the second sets the port up with `adb forward` and removes it afterwards. This is the no-root transport, and it is now a first-class command instead of ad-hoc host tooling.
- `adb-install-splits` and `adb install` gain `--installer PACKAGE`, which passes `adb -i` and records `declared_installer`. Apps that refuse to run unless their recorded install source is the store are satisfied by this, without touching the byte signature, and the evidence policy text states that the flag only declared the source.
- Evidence records the transport mode, host, forwarded port and forward result for every hook session, and a failed forward is recorded before anything attaches.
- Verified on a real Android 14 device with a locked bootloader, `ro.debuggable=0` and no `su`: the Gadget loaded from the base APK of a split install through `wrap.sh`/`LD_PRELOAD`, listened on its port, and Frida 17.22.1 attached over a forwarded port and ran a live hook inside the app. The same build was refused by the app itself until the install source was declared, which is the honest limit of the route.
- Tests cover the Gadget attach path, forward setup and cleanup, the validation that rejects a host without `--attach`, the installer flag, and rejection of an invalid installer value.

## 0.7.0 - 2026-10-07

- New `apk-gadget` action: repackages an APK with a Frida Gadget through `frida-apk`, which is the only Frida route on a device without root. `frida-server` needs root, so a jailed target has no other dynamic option.
- ABI, bitness and Gadget identity come from bytes: FORGE reads `e_machine`/`e_class` from the Gadget's ELF header, refuses an executable or an unknown machine, and after the run requires the injected members, the embedded Gadget hash and an unchanged package name. A mismatch fails the run and is recorded with its reason.
- The repackaged build is described honestly in evidence and docs: `android:debuggable=true` is forced, the original signature is replaced, the default interaction blocks at launch until a client connects, and integrity, tamper and anti-fraud checks can see all of it. Hook output from such a build describes a modified build.
- Gadget config values stay in the APK and out of evidence; only the keys are recorded.
- `frida-apk` joins the toolchain resolution (`FORGE_FRIDA_APK`), bundle projections carry the new action, and the `frida` prerequisite guidance now points at `apk-gadget` plus `apk-sign` instead of describing the work without naming it.
- First tests for the APK patch loop: `tests/test_apktool.py` covers Gadget validation, injection verification, failure recording and staging cleanup.

## 0.6.0 - 2026-10-07

- New `native decompile` action: retains radare2 `pdc` output as bounded register-level pseudo-C in evidence, with `--address`/entrypoint selection like `disasm`.
- Decompile keeps a usable partial view: output truncation and the `--max-items` line cap are recorded (`caps.pseudo_c_truncated`, `caps.items_omitted`, `caps.items_limit_reached`) instead of failing the run, while a backend error, timeout or non-zero exit still fails. Structured JSON actions keep failing on truncation.
- Decompile evidence states the limit explicitly: `pdc` is a readable view of the disassembly, not recovered source, and FORGE bundles no real decompiler.
- Bundle projections carry the `decompile` action plus `pseudo_c_lines`/`pseudo_c_truncated`; the pseudo-C text itself stays out of bundles by default.

## 0.5.0 - 2026-10-06

- New APK patch loop: `apk-decode` (apktool into a new project directory, success requires the decoded manifest), `apk-manifest` (declared permissions, components with `android:exported`, intent filters and deeplinks from a decoded tree, a decoded manifest or a raw APK), `apk-rebuild` (unsigned bytes that stay unsigned), and `apk-sign` (zipalign, apksigner and a verification pass that must pass before any output is published).
- Signing accepts an explicit project-local keystore with password environment variables, or `--debug-keystore` for a throwaway identity that is recorded as `debug_identity: true` and deleted afterwards. No signing identity is ever invented silently.
- Tool discovery adds apktool, apksigner and zipalign, including selection of the newest numeric `build-tools/*/` under a caller-configured `ANDROID_HOME`/`ANDROID_SDK_ROOT`. `doctor` reports the resolved source.
- New `capture-ingest`: a bounded loopback listener that accepts a pushed HAR document, entries array or single entry and stores each exchange through the same normalization as `har-import`, so pushed traffic stays `captured_http` and is never promoted to live proof. Optional token, per-reason rejection counters, no echoed request data.
- New `websocket-analyze`: frames from HAR `_webSocketMessages`/`_webSocketFrames` or explicit `{"url","frames"}` documents, reported as direction, opcode/type counts, payload byte stats, close codes and JSON field-name paths only.
- New `api-shape`: per-domain method/path identities, status distribution and request/response header, JSON field-path, form and query names from stored HTTP evidence. Names only, never values.
- New `storage-report` and `evidence-prune`: read-only inventory, and opt-in deletion of unreferenced blobs or aged evidence with cited-evidence, audit-row and post-checkpoint protection plus a `maintenance` audit record.
- `init` now records caller-declared scope: authorization status and basis, network profile, and in-scope/out-of-scope assets. A denied status blocks active steps and an `offline` profile blocks network and device steps; local analysis of already-obtained artifacts stays available. Stored keys avoid the credential-redaction words.
- New `hook-evidence`: one claim carrying a hook evidence triple with a citation per part, an omitted state dependency recorded as `not-established`, and paired state arguments enforced.
- New `ios-devices` and `ios-pair`: read-only observations from a configured `idevice_id`/`idevicepair`, with an explicit statement that FORGE has no iOS runtime adapter and no capture, hooking or injection capability.
- Bundle projections carry the new APK, iOS, maintenance and scope fields and no longer drop the added action/tool/status values.

## 0.4.0 - 2026-10-06

- `jadx` keeps usable decompiled sources when an obfuscated APK finishes with per-class errors: a nonzero exit with saved sources is recorded as `status: partial` with `java_files` and `error_count` instead of being discarded. Added `--deobf` and `--single-class`.
- New read-only `apk-info` command reporting compiled manifest metadata (package, split, version code, literal minSdk, declared split dependencies/types, native ABIs) from explicit APK paths or exact archive members, with opt-in `--validate-selection`.
- New `adb pull`/`adb push` for one explicit artifact, restricted to absolute device paths and new project-local destinations, with byte caps, no overwrite and no partial file on failure.
- New `adb packages` and `adb package` for installed-package discovery and observed `pm path`/`dumpsys` facts (version, ABI, split names) with bounded detail.
- `adb ui-tree` wakes the screen and retries once, and names the quiescent-window limitation instead of failing on the first `could not get idle state`.
- `adb devices` now records the same evidence shape (tool/action/serial/success/returncode) as other device actions.
- `frida` checks device reachability with `frida-ps` and classifies a refused spawn: jailed Android needs a repackaged Gadget, otherwise a reachable device-side `frida-server`, or a launch/signing problem.
- Bundle projections carry the new Android actions, the `partial` flag and `java_files`/`error_count`, and no longer drop generic jadx/frida lifecycle statuses.
- Documentation and workflow now describe the no-root Android reverse order (triage → discover → pull → jadx → search → native) and the real Frida prerequisites.

## 0.3.0 - 2026-10-05

- Preserve all standard target buckets while retaining narrow positive/negative passing gates and deterministic TERMINAL stop behavior.
- Bounded per-control JSON stdin with complete preflight and private evidence; owned demo sends actual login controls without credential argv.
- Before/after/current resolved executable fingerprints and optional explicitly declared bounded version probes; v2 target verification rejects stale runtime bytes.
- Immutable cited protocol snapshots and diffs, including field/status/provenance changes, omission flags and redacted-identity ambiguity.
- Stored client artifact/member byte inventories and source-index projection diffs with endpoint/string citations; new indexes record creation-time hashes.
- Bounded GraphQL operation, variable, selection, alias and fragment analysis from explicit sources/request evidence without exported values or network introspection.
- Actual radare2 disassembly, xrefs and observed function-level call-reference graphs, with backend schema normalization and unresolved/capped memberships visible.
- Android ADB preflight and explicit APK/APKS/XAPK split selection, compiled-manifest/package/version/dependency/ABI/API checks and new-install-only dispatch.
- Metadata-only evidence ZIP handoffs with bounded citation closure, disclosure exclusions and content hashes; optional reviewed claim prose.
- Correct Windows executable race checks for differing descriptor/path ctime semantics without dropping same-API change detection.

## 0.2.0 - 2026-10-05

- HAR-to-flow conversion with environment-backed URL/header/body templates, source/output hashes, visible omissions and no automatic replay or captured credential assignments.
- Actual trusted target execution with complete two-control preflight, concurrent bounded captures, process-tree deadlines, source integrity and same-invocation positive/negative verification.
- Read-only protocol maps with URL/method/header/field metadata, source-location citations, source-provenance validation and separate static/captured/live categories.
- Extended runnable demo exercises reviewed HAR replay, actual implementation controls, changed-source rejection and mixed-source maps through source and installed CLI.
- Fixed quadratic text-secret matching on long unbroken non-secret response bodies while retaining adjacent credential redaction.
- Target verification appears separately from historical HTTP control gates in status/report guidance.

## 0.1.0 - 2026-10-05

First public release.

- Target-local SQLite evidence with immutable IDs, scoped claims and Markdown reports.
- Evidence/blob path containment, including external directory symlinks/junctions, and UTF-8 console JSON across source and installed entrypoints.
- Artifact import/download with SHA-256 provenance and bounded source-located text, archive and binary indexing.
- Explicit HTTP probes, cookie-session flows, body-driven classification, HAR import and exchange comparison.
- Command-local JSON/header extraction and `${flow.NAME}` request substitution, complete dependency preflight and secret-aware persistence.
- Append-only checkpoint/resume with expected revisions, task isolation, blockers, citations and project-file integrity.
- Paginated task history for reviewing experiments and session handoffs.
- Optional JADX, Android ADB, Frida and radare2 adapters with shared tool discovery and diagnostic reporting.
- A narrow live positive/negative protocol-control gate, distinct from target-checker execution.
- Installable Python CLI, optional curl extra, local executable demo, cross-platform CI and public contribution/security documentation.

### Boundaries

- No embedded model, model API key requirement, MCP registration or universal checker generator.
- No bundled SDK binaries, virtual environments, private notes, evidence or captures.
- No automatic emulator installation or iOS runtime adapter.
- Redaction is best-effort; raw artifacts and screenshots remain private-data boundaries.
- Response headers follow transport normalization. libcurl folding normalization is not raw wire evidence.
