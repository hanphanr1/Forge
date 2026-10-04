# Changelog

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
