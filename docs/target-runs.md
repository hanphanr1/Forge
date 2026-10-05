# Executing target controls

`run-target` executes a trusted program twice with explicitly declared positive and negative inputs. It records actual process exits, bounded outputs, and before/after hashes of listed project files and the resolved executable. `verify-target` checks those run records against current source files and the same executable identity and bytes.

This is not a sandbox. The program and its descendants run with your user permissions, can read inherited environment variables, access the network, and modify files. Use only code you trust and controls you are authorized to execute. FORGE does not add retries, solvers, or SDK downloads.

A passing gate means the executed program reported the expected buckets for these two controls. A program can print `{"bucket":"HIT"}` without contacting any server. The gate does not independently prove authentication, network/server behavior, client identity, IP, or egress. Existing HTTP `verify` gates remain separate and unchanged.

## Commands

```text
forge --project PROJECT run-target SPEC [--timeout SECONDS] [--max-output BYTES]
forge --project PROJECT verify-target --positive ev_POSITIVE --negative ev_NEGATIVE
```

`SPEC` is resolved relative to the project unless it is absolute. The program runs with the project as its working directory and `shell=False`. Each control appends its `args` to the common `command` argv array. Without `stdin_json`, stdin is closed (`DEVNULL`). With it, FORGE writes one bounded UTF-8 JSON value and closes the pipe. Literal shell metacharacters stay argv data; batch-file executables (`.bat` and `.cmd`), including those found through PATH, are rejected because Windows can interpret them through a shell.

`--timeout` defaults to 30 seconds per control and must be finite, greater than zero, and no more than 3600. The deadline includes process execution, delivery of stdin, and EOF on both output pipes. Input writing and output draining run concurrently. A program that never reads its input, or a descendant holding inherited pipes after the leader exits, still times out. Cleanup uses native Windows `taskkill /F /T` with a process-tree snapshot, or `SIGKILL` on a POSIX process group. These mechanisms are cleanup, not containment: trusted code can deliberately escape a process group or alter the process tree. Cleanup failures invalidate the control.

`--max-output` defaults to 1048576 bytes and accepts integers from 1 to 16777216. It limits the combined retained raw stdout and stderr bytes per control, not each stream separately. Both pipes are drained concurrently even after the limit is reached. Any truncation prevents a pass. Redaction can change the size of the rendered output; byte counts report observed raw bytes, while raw bytes themselves are not saved.

## Spec schema

The top-level object accepts only these fields:

```json
{
  "command": ["python", "-u", "checker.py"],
  "files": ["checker.py", "request_builder.py"],
  "version_argv": ["--version"],
  "context": {
    "client": "owned-python-checker",
    "egress": "declared-test-network"
  },
  "bucket_path": "/result/bucket",
  "controls": [
    {
      "name": "positive",
      "args": ["positive"],
      "stdin_json": {"credential": "${AUTHORIZED_CONTROL}", "options": {"fixture": true}},
      "expected_bucket": "HIT"
    },
    {
      "name": "negative",
      "args": ["negative"],
      "stdin_json": {"credential": "${UNAUTHORIZED_CONTROL}", "options": {"fixture": true}},
      "expected_bucket": "FAIL"
    }
  ]
}
```

- `command` is a nonempty array of strings. The first entry must resolve to a readable real executable. Other entries may be empty strings. The executable slot declares a public runtime identity, including paths supplied through nonsensitive environment variable names such as `${FORGE_DEMO_PYTHON}`. That path remains a stream-redaction input. Variables with credential-sensitive names, and real credential values supplied elsewhere in argv or stdin, retain all metadata privacy guards. FORGE resolves relative executable paths from the child project directory, searches the snapshotted inherited PATH with relative/empty entries based on that directory, and launches the resulting absolute path. On Windows it also checks the child directory first and honors PATHEXT. Resolution happens before either child starts, rather than relying on a second platform-dependent search in `Popen`.
- `files` is a nonempty list of distinct, explicit project-relative source paths. There are no globs. Traversal, absolute paths, symlinks, Windows reparse points, FIFOs, directories, secret/data paths, and dependency directories are rejected by the existing source-file hashing policy. Every path is preflighted before either control is spawned.
- `context` contains exactly `client` and `egress`, both nonempty, non-secret declared strings. They cannot contain environment substitutions or redacted values. These identifiers are not independently measured.
- `bucket_path` is optional and defaults to `/bucket`. It uses the existing JSON pointer and dotted-selector syntax: `/result/bucket`, `$.result.bucket`, or `results[0].bucket`. Pointer escapes are `~1` for `/` and `~0` for `~`. `$` selects the entire object and therefore cannot yield a string bucket. Invalid selectors fail before execution.
- `controls` contains exactly one `positive` and one `negative`. Their order determines execution order. Each object contains `name`, `args`, `expected_bucket`, and optionally `stdin_json`; `args` is an array of strings and may be empty. Positive expects `HIT` or `FREE`. Negative expects `FAIL`.
- `stdin_json` may be any structured JSON value and can be used alongside `args`. Object keys are public structure: they must be literal strings without NUL or environment references. Scalar values are private inputs. A missing field means `DEVNULL`; an explicit `null` sends JSON `null`. Each input permits at most 32 nesting levels, 10000 nodes (including object keys), and 1048576 encoded UTF-8 bytes after substitution. Duplicate keys, nonfinite numbers including exponent overflow, invalid Unicode, and NUL-containing strings are rejected before either process runs. The complete spec is limited to 4194304 bytes.
- `version_argv` is an optional, explicitly declared nonempty argument array for a single version probe of the same resolved executable. The sample above declares Python's `--version`; FORGE does not invent standard flags for other programs. The probe uses closed stdin, at most 5 seconds (or the smaller control timeout), and at most 4096 retained output bytes (or the smaller output cap). Failed, truncated, or timed-out declared probes prevent a pass. No probe means no version observation.

`${ENV_VAR}` substitutions are allowed in `command`, control `args`, `stdin_json` string leaves, and `version_argv`. The inherited environment is snapshotted for preflight and child execution; both controls are fully resolved and validated before any child or version probe starts. Undefined variables, malformed `${...}` references, `${flow.*}`, NUL bytes, and an empty resolved executable are rejected. Substitution results are not expanded again. This does not restrict which other inherited environment variables a trusted child can read.

Stdout must be one complete UTF-8 JSON object, with only optional surrounding whitespace. Logs belong on stderr. Recognized buckets are `HIT`, `FREE`, `FAIL`, `TERMINAL`, `RETRY`, `ERROR`, `BADFORMAT`, `CUSTOM`, and `RISK`. All observed recognized buckets are preserved. Only the declared positive `HIT`/`FREE` and negative `FAIL` can pass. `RETRY` does not trigger a retry, and the other nonpassing buckets are not rewritten to `FAIL`. Duplicate JSON keys, non-JSON numbers such as `NaN`, invalid UTF-8, extra output, missing selectors, non-string/unknown buckets, and nonempty `error` or `errors` fields anywhere in the JSON invalidate the control. Exit code zero alone is insufficient. A recognized complete `TERMINAL` bucket stops subsequent controls without retry; it never passes either control. Timeouts, truncated output, process errors, and source or executable changes also prevent verification.

## Evidence and verification

The result of `run-target` contains `runs`, `passed`, `verification`, `stopped`, `stop_reason`, `requested`, `completed`, `version`, and an `invocation_id`. A mismatch can produce two completed runs with `passed: false` and `stopped: false`: a failed control does not become a successful gate merely because execution continued. Source/executable changes or unavailable files stop subsequent execution. A deterministic `TERMINAL` stops it as well.

Each `target_run` uses schema `forge.target-run/v2` and contains:

- invocation ID, control name, expected and parsed bucket, success, and a categorical error;
- opaque `command_template` and `args_template` arrays, preserving `${ENV_VAR}` references but replacing literal segments with `[LITERAL REDACTED]`; `stdin_template` preserves safe object/list structure and masks every literal scalar, plus `stdin_provided`. Environment references survive only where the core privacy policy permits them: values beneath credential-sensitive keys are fully masked, including environment references;
- declared context and bucket selector;
- `sources_before` and `sources_after` file facts (`path`, `sha256`, `size`), source-change status, and source errors;
- `runtime_before` and `runtime_after` facts (`identity`, `resolved_identity`, `sha256`, `size`), executable-change status and errors; identity is the absolute launch path and resolved identity follows filesystem links;
- an optional version observation with declared argv template, sanitized stdout, exit/timeout/truncation/error facts, observed byte counts, and surrounding executable fingerprints; probe stderr content is not retained;
- elapsed milliseconds, exit code, timeout/truncation flags, observed stdout/stderr byte counts, sanitized stdout and stderr, redaction metadata, and scope limits.

Sanitized complete JSON output may be represented as a JSON object or array; non-JSON output remains sanitized text. Literal argv values, resolved stdin scalar values, referenced environment values, tagged secret fields, URL credentials, and known percent/JSON/base64/hex encodings are masked before entering SQLite, its WAL, or CLI output. Literal argv segments are intentionally opaque even when they are ordinary mode names. Raw specs, resolved argv, raw stdin, and raw streams are never stored as evidence. The input spec itself is not rewritten or made private by FORGE. Use stdin for credentials that should not appear in the child's process arguments; passing credentials in `args` still exposes them to ordinary process inspection. Keep the spec and any external captures under your own private-data policy.

Redaction is not a defense against hostile code that transforms or exfiltrates secrets arbitrarily. Unreferenced inherited environment variables are not automatically known redaction inputs. Source paths, executable identity, input object keys, and context are intentionally non-secret metadata. Static bucket/control labels, file hashes, exit codes, elapsed time, and byte counts are process facts, not echoed credential fields.

Privacy preflight conservatively checks context, selector, source paths, and executable identities against known private string argument/environment/input values, including normalized and canonical variants of actual private paths. Only a nonsensitive environment value in the executable slot is declared public runtime identity; this does not exempt matching credential values supplied anywhere else. Credential-bearing executable identities are rejected rather than stored in a form that cannot be rechecked. Coincidental substrings can therefore be rejected; use neutral declared identifiers and filenames rather than disabling scrubbing.

A `target_verification` uses schema `forge.target-verification/v2`. FORGE creates it automatically only when two distinct runs from the same invocation pass all gates with matching command templates, context, selector, source hashes, executable fingerprints, and version observation. It cites both run IDs and records current source/executable facts and scope limits. `verify-target` can create another verification of that same pair after rechecking current files and the recorded executable path and resolved identity. It does not launch another version probe. It rejects reversed controls, the same ID twice, other evidence kinds, cross-invocation pairs, failed/error/truncated/timed-out/changed runs, stale or missing source/executable files, changed link destinations, and legacy runs lacking v2 executable fingerprints. Historical v1 evidence remains readable; execute fresh controls to create a current gate.

Hashes cover explicitly listed sources and the resolved executable at preflight and before/after each run. The optional version probe also checks executable bytes before/after. Interpreter scripts remain explicitly listed source hashes; hashing Python itself does not hash every imported module. Unlisted imports, libraries, dependencies, their versions, external services, and transient modifications between observations are not attested. A probe's output is a program-reported version, not independently verified package inventory. List every relevant owned source file. Restored byte-identical content matches its recorded hash, but does not prove it was never temporarily modified.

## Loopback example

Start the owned HTTP fixture from the FORGE checkout:

```sh
python examples/demo_server.py --port 8765
```

Copy [examples/demo_checker.py](../examples/demo_checker.py) into a separate target project as `target_impl.py`. It sends actual login/profile requests with a cookie session and bearer token, classifies response messages, and prints only the bucket and local-fixture label. Its URL is restricted to loopback. Unknown transport/protocol failures report ERROR, not a false credential failure or deterministic TERMINAL.

Save this `target.json` beside that file:

```json
{
  "command": ["python", "target_impl.py", "--stdin-json"],
  "files": ["target_impl.py"],
  "context": {"client": "fixture-client", "egress": "loopback"},
  "controls": [
    {"name": "positive", "args": [], "stdin_json": {"url": "${FORGE_DEMO_URL}", "login": "demo", "password": "${FORGE_DEMO_PASSWORD}"}, "expected_bucket": "HIT"},
    {"name": "negative", "args": [], "stdin_json": {"url": "${FORGE_DEMO_URL}", "login": "demo", "password": "wrong-demo-password"}, "expected_bucket": "FAIL"}
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

Use the returned positive and negative `target_run` IDs with `verify-target` for fresh source and executable hash checks. The expected pair is HIT then FAIL. The demo checker also retains its `--url`, `--login`, and `--password` argument mode for manual use, but the stdin form avoids credentials in process arguments. The included `examples/smoke.py` exercises this real implementation, modifies its source and confirms stale verification is rejected. The fixture is not a vendor login and the target gate does not independently attest the server.

