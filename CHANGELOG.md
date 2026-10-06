# Changelog

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
