# Checkpoints and resume

A task is an immutable `task` evidence record created by `init`. Each `checkpoint` appends an immutable `task_checkpoint` referring to that task, with a monotonically increasing revision. Different tasks in one project keep separate histories.

## Create and select a task

```sh
forge --project target init --target https://example.invalid --goal "Investigate the observed client flow"
forge --project target status
forge --project target resume
```

`init` returns the task evidence ID. A new task starts at revision 0. Keep that ID if the project has multiple investigations; otherwise the newest task is selected.

## Save a checkpoint

```sh
forge --project target checkpoint --task "<task-id>" --phase analyze --state active --summary "Identified the request constructor" --next "Probe the captured payload with one control" --evidence "<evidence-id>" --file protocol.json --file client_auth.py --expect-revision 0
```

The ID placeholders above must come from real command output. Repeated `--evidence`, `--file` and `--blocker` flags are supported.

Phases are `discover`, `analyze`, `probe`, `implement`, `verify`. They describe work, not an enforced linear pipeline; returning to analysis is valid.

| State | Required | Meaning |
|---|---|---|
| `active` | Summary and next action | Work can continue |
| `blocked` | Summary, next action and at least one blocker | A named prerequisite is missing |
| `completed` | Summary; no pending next action or blockers | The author reports the task finished |

A checkpoint is agent-reported progress. Neither `--phase verify` nor `--state completed` runs a checker or grants a verification result.

## Optimistic revisions

`--expect-revision` is mandatory. It must match the selected task's current revision. Read/compare/append happens under a SQLite write lock. A stale session fails without adding a checkpoint, rather than replacing newer progress.

After a stale error:

1. Run `resume --task "<task-id>"`.
2. Read the newer findings and file integrity.
3. Reconcile your changes and use the current revision only if the new checkpoint still represents the task accurately.

Do not retry with an incremented number without reading the competing state.

## Resume and inspect files

```sh
forge --project target resume --task "<task-id>"
forge --project target resume --task "<task-id>" --checkpoint "<checkpoint-id>"
```

The result contains the original task, selected checkpoint, saved progress, `revision`, `current_revision`, `is_current` and `file_integrity`.

File entries store a project-relative path, SHA-256 and size, not bytes. Resume recomputes the supplied file hashes and reports:

- `unchanged`: hash and size still match.
- `changed`: the file exists but differs.
- `missing`: it no longer exists.
- `unsafe`: the saved path cannot be safely read or checked.

Only explicitly selected regular project files can be checkpointed. Traversal, symlinks/reparse points, external paths and known secret/data/dependency paths are rejected. Do not use checkpoint metadata as a backup or place secrets in filenames.

A historical checkpoint must belong to the selected task. It remains historical: resume does not update the current revision, clear blockers, reset files or execute `next_action`. `status` reads saved metadata without rehashing files; `resume` is the integrity check.

## Review task history

```sh
forge --project target history --task "<task-id>" --limit 20
forge --project target history --task "<task-id>" --after-revision 20 --limit 20
```

History returns checkpoints in ascending revision order. `has_more` and `next_revision` provide the exclusive cursor for the next page; use the returned cursor instead of guessing the number. The example cursor above is illustrative. Page size is 1 to 1000.

The original task is returned separately. History never rehashes files, clears blockers or mixes snapshots from other tasks. Use `resume --checkpoint` to inspect a selected snapshot and its file integrity.

## Existing stores

Older `task` evidence records remain readable. Without a checkpoint they resume at revision 0 with discovery defaults. The first new checkpoint adds state without rewriting old evidence.
