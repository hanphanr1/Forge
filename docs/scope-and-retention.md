# Scope, authorization and retention

## Task scope

`init` records the caller's authorization decision and network posture for a target. The values
are caller-declared metadata: FORGE does not verify them and they are not independent proof of
authorization.

```console
forge init --target https://client.example --authorization granted --basis own_system \
  --network-profile authorized_target_only --in-scope client.example --out-of-scope third-party hosts
```

| Field | CLI flag | Values |
|---|---|---|
| Authorization status | `--authorization` | `unspecified`, `granted`, `pending`, `denied` |
| Authorization basis | `--basis` | `unspecified`, `written_contract`, `bug_bounty_scope`, `ctf_public`, `own_system`, `lab_only` |
| Network posture | `--network-profile` | `unspecified`, `offline`, `lab_only`, `authorized_target_only`, `unrestricted_lab` |
| Declared assets | `--in-scope`, `--out-of-scope` | Repeatable strings |

`--authorization granted` requires an explicit `--basis`. The stored key names are
`scope_status` and `scope_basis` rather than `authorization`, because the core redactor treats a
key literally named `authorization` as a credential bearer and would mask the value.

### What the gate blocks

`status` and `resume` surface the scope. Active steps consult it:

| Situation | Effect |
|---|---|
| No task, or scope `unspecified` | No gating |
| `--authorization denied` | `probe`, `probe-run`, `adb *`, `adb-preflight`, `adb-install-splits`, `frida` refuse before doing anything |
| `--network-profile offline` | Network steps (`probe`, `probe-run`, `capture-ingest`) and device steps (`adb *`, `frida`) refuse |
| Denied scope, local-only work | Still allowed: analysing artifacts you already obtained is not active work |

`capture-ingest` counts as a network step even though it only listens on loopback: under an
`offline` profile it refuses, so an offline task stays strictly local instead of quietly opening
a socket. Decoding, signing and local analysis never consult the gate.

The gate is intentionally one-directional: a permissive scope never widens what FORGE is willing
to do, it only records what you declared. Local analysis of an already-obtained artifact stays
available under a denied or offline scope, which mirrors the intended reading of the contract.

## `storage-report`

Read-only inventory: counts and byte sizes per evidence kind, oldest/newest `created_at` per
kind, blob totals with the referenced/orphan split, orphan SHA-256 samples (capped at 100), and
database/WAL/SHM sizes. `--max-scan-rows` (default 200000) bounds the scan and reports
truncation.

## `evidence-prune`

Deletes nothing unless `--apply` is passed; the default is a plan.

```console
forge evidence-prune --unreferenced-blobs
forge evidence-prune --unreferenced-blobs --apply
forge evidence-prune --older-than 30 --kind http_probe --apply
```

Modes:

- `--unreferenced-blobs` removes only blobs that no evidence row references. Detection is
  SHA-256-token based, because the store has no explicit blob reference table; that is
  conservative, not exact.
- `--older-than DAYS` (`1..36500`) removes evidence rows older than the window, optionally
  narrowed by repeatable `--kind`.

Protections, all active unless `--force` is passed:

- Evidence cited by `claim`, `control_verification`, `target_verification`, `task` or
  `task_checkpoint` is never removed. `--force` lifts this.
- `maintenance` audit rows are never removed, even with `--force`.
- When an active task exists, the age filter refuses to remove records created after that task's
  latest checkpoint (falling back to the task's own creation time).
- `--apply` together with `--dry-run`, `--kind` without `--older-than`, and out-of-range values
  are rejected.

Every run appends a `maintenance` audit row describing the mode, filters, before/after counts
and bytes freed — including dry runs, which is why a dry run is not quite a no-op on the store.

### This breaks the append-only assumption

FORGE's normal contract is that evidence is append-only, so a citation always resolves. Pruning
is the deliberate exception: after `--apply`, citation ids that pointed at removed rows no
longer resolve, and previously exported bundles may reference evidence that no longer exists.
`bytes_freed` is logical payload plus blob bytes; the database file is not `VACUUM`ed, so the
file does not necessarily shrink. Use pruning to bound a long-running project, not to make a
case immutable.
