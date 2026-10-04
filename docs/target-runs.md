# Executing target controls

`run-target` executes a trusted program twice with explicitly declared positive and negative arguments. It records the actual process exit, bounded outputs, and before/after hashes of listed project files. `verify-target` checks those run records against the current files.

This is not a sandbox. The program and its descendants run with your user permissions, can read inherited environment variables, access the network, and modify files. Use only code you trust and controls you are authorized to execute. FORGE does not add retries, solvers, or SDK downloads.

A passing gate means the executed program reported the expected buckets for these two controls. A program can print `{"bucket":"HIT"}` without contacting any server. The gate does not independently prove authentication, network/server behavior, client identity, IP, or egress. Existing HTTP `verify` gates remain separate and unchanged.

## Commands

```text
forge --project PROJECT run-target SPEC [--timeout SECONDS] [--max-output BYTES]
forge --project PROJECT verify-target --positive ev_POSITIVE --negative ev_NEGATIVE
```

`SPEC` is resolved relative to the project unless it is absolute. The program runs with the project as its working directory, `shell=False`, and closed stdin (`DEVNULL`). Each control appends its `args` to the common `command` argv array. Literal shell metacharacters stay argv data; batch-file executables (`.bat` and `.cmd`) are rejected because Windows can interpret them through a shell.

`--timeout` defaults to 30 seconds per control and must be finite, greater than zero, and no more than 3600. The deadline includes process execution and EOF on both output pipes. If the leader exits while a descendant holds a pipe, the control still times out. Cleanup uses native Windows `taskkill /F /T` with a process-tree snapshot, or `SIGKILL` on a POSIX process group. These mechanisms are cleanup, not containment: trusted code can deliberately escape a process group or alter the process tree. Cleanup failures invalidate the control.

`--max-output` defaults to 1048576 bytes and accepts integers from 1 to 16777216. It limits the combined retained raw stdout and stderr bytes per control, not each stream separately. Both pipes are drained concurrently even after the limit is reached. Any truncation prevents a pass. Redaction can change the size of the rendered output; byte counts report observed raw bytes, while raw bytes themselves are not saved.

## Spec schema

The top-level object accepts only these fields:

```json
{
  "command": ["python", "-u", "checker.py"],
  "files": ["checker.py", "request_builder.py"],
  "context": {
    "client": "owned-python-checker",
    "egress": "declared-test-network"
  },
  "bucket_path": "/result/bucket",
  "controls": [
    {
      "name": "positive",
      "args": ["positive", "${AUTHORIZED_CONTROL}"],
      "expected_bucket": "HIT"
    },
    {
      "name": "negative",
      "args": ["negative", "${UNAUTHORIZED_CONTROL}"],
      "expected_bucket": "FAIL"
    }
  ]
}
```

- `command` is a nonempty array of strings. The first entry must resolve to a nonempty executable. Other entries may be empty strings.
- `files` is a nonempty list of distinct, explicit project-relative source paths. There are no globs. Traversal, absolute paths, symlinks, Windows reparse points, FIFOs, directories, secret/data paths, and dependency directories are rejected by the existing source-file hashing policy. Every path is preflighted before either control is spawned.
- `context` contains exactly `client` and `egress`, both nonempty, non-secret declared strings. They cannot contain environment substitutions or redacted values. These identifiers are not independently measured.
- `bucket_path` is optional and defaults to `/bucket`. It uses the existing JSON pointer and dotted-selector syntax: `/result/bucket`, `$.result.bucket`, or `results[0].bucket`. Pointer escapes are `~1` for `/` and `~0` for `~`. `$` selects the entire object and therefore cannot yield a string bucket. Invalid selectors fail before execution.
- `controls` contains exactly one `positive` and one `negative`. Their order determines execution order. Each object contains only `name`, `args`, and `expected_bucket`; `args` is an array of strings and may be empty. Positive expects `HIT` or `FREE`. Negative expects `FAIL`.

`${ENV_VAR}` substitutions are allowed only in `command` and control `args`. Each referenced variable is read once during preflight, and both controls are fully resolved before any child starts. Undefined variables, malformed `${...}` references, `${flow.*}`, NUL bytes, and an empty resolved executable are rejected. Substitution results are not expanded again. This does not restrict which other environment variables a trusted child can read.

Stdout must be one complete UTF-8 JSON object, with only optional surrounding whitespace. Logs belong on stderr. Duplicate JSON keys, non-JSON numbers such as `NaN`, invalid UTF-8, extra output, missing selectors, non-string/unknown buckets, and nonempty `error` or `errors` fields anywhere in the JSON invalidate the control. Exit code zero alone is insufficient. A recognized complete `TERMINAL` bucket stops subsequent controls without retry; it never passes either control. Timeouts, truncated output, process errors, and source changes also prevent verification.

## Evidence and verification

The result of `run-target` contains `runs`, `passed`, `verification`, `stopped`, `stop_reason`, `requested`, `completed`, and an `invocation_id`. A mismatch can produce two completed runs with `passed: false` and `stopped: false`: a failed control does not become a successful gate merely because execution continued. Source changes or an unavailable source stop subsequent execution. A deterministic `TERMINAL` stops it as well.

Each `target_run` contains:

- invocation ID, control name, expected and parsed bucket, success, and a categorical error;
- opaque `command_template` and `args_template` arrays, preserving `${ENV_VAR}` references but replacing literal segments with `[LITERAL REDACTED]`;
- declared context and bucket selector;
- `sources_before` and `sources_after` file facts (`path`, `sha256`, `size`), source-change status, and source errors;
- elapsed milliseconds, exit code, timeout/truncation flags, observed stdout/stderr byte counts, sanitized stdout and stderr, redaction metadata, and scope limits.

Sanitized complete JSON output may be represented as a JSON object or array; non-JSON output remains sanitized text. Literal argv values, referenced environment values, tagged secret fields, URL credentials, and known percent/JSON/base64/hex encodings are masked before entering SQLite, its WAL, or CLI output. Literal argv segments are intentionally opaque even when they are ordinary mode names. Raw specs, resolved argv, and raw streams are never stored as evidence. The input spec itself is not rewritten or made private by FORGE. Keep it and any external captures under your own private-data policy.

Redaction is not a defense against hostile code that transforms or exfiltrates secrets arbitrarily. Unreferenced inherited environment variables are not automatically known redaction inputs. Source paths and context are intentionally non-secret metadata. Static bucket/control labels, file hashes, exit codes, elapsed time, and byte counts are process facts, not echoed credential fields.

Privacy preflight conservatively checks context, selector and source-path text against known argument/environment values. Coincidental substrings can therefore be rejected; use neutral declared identifiers and filenames rather than disabling scrubbing.

A `target_verification` is created automatically only when two distinct runs from the same invocation pass all gates with matching command templates, context, selector, and source hashes. It cites both run IDs and records current source hashes and scope limits. `verify-target` can create another verification of that same pair after rechecking current files. It rejects reversed controls, the same ID twice, other evidence kinds, cross-invocation pairs, failed/error/truncated/timed-out/changed runs, and stale or missing current source files.

The hashes cover only explicitly listed files, at preflight and before/after each run. They do not attest unlisted imports, dependencies, the executable/interpreter, external services, or every transient file modification between observations. List every relevant owned source file. Treat a restored byte-identical source as the same hashed content, not proof that it was never temporarily modified.

## Loopback example

Start the owned HTTP fixture from the FORGE checkout:

```sh
python examples/demo_server.py --port 8765
```

Copy [examples/demo_checker.py](../examples/demo_checker.py) into a separate target project as `target_impl.py`. It sends actual login/profile requests with a cookie session and bearer token, classifies response messages, and prints only the bucket and local-fixture label. Its URL is restricted to loopback. Unknown transport/protocol failures report ERROR, not a false credential failure or deterministic TERMINAL.

Save this `target.json` beside that file:

```json
{
  "command": ["python", "target_impl.py"],
  "files": ["target_impl.py"],
  "context": {"client": "fixture-client", "egress": "loopback"},
  "controls": [
    {"name": "positive", "args": ["--url", "${FORGE_DEMO_URL}", "--login", "demo", "--password", "${FORGE_DEMO_PASSWORD}"], "expected_bucket": "HIT"},
    {"name": "negative", "args": ["--url", "${FORGE_DEMO_URL}", "--login", "demo", "--password", "wrong-demo-password"], "expected_bucket": "FAIL"}
  ]
}
```

Set the synthetic demo variables and run from that project directory. PowerShell:

```powershell
$env:FORGE_DEMO_URL = "http://127.0.0.1:8765"
$env:FORGE_DEMO_PASSWORD = "demo-password"
forge --project . run-target target.json --timeout 15 --max-output 65536
```

POSIX shells:

```sh
export FORGE_DEMO_URL=http://127.0.0.1:8765
export FORGE_DEMO_PASSWORD=demo-password
forge --project . run-target target.json --timeout 15 --max-output 65536
```

Use the returned positive and negative `target_run` IDs with `verify-target` for a fresh source-hash check. The expected pair is HIT then FAIL. The included `examples/smoke.py` exercises this real implementation, modifies its source and confirms stale verification is rejected. The fixture is not a vendor login and the target gate does not independently attest the server.

