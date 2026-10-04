# Explicit HTTP flows

`probe` executes one request JSON object. `probe-run` executes an array sequentially in one cookie session. Both save redacted evidence. They do not infer endpoints, retry, follow redirects, solve challenges or generate request signatures.

## Request fields

| Field | Purpose |
|---|---|
| `url` | Absolute HTTP(S) URL |
| `method` | HTTP method; defaults to GET |
| `headers` | Header names mapped to single-line strings |
| `json` / `body` | Structured JSON or a string body; mutually exclusive |
| `proxy` | Explicit HTTP(S) or supported SOCKS proxy URL |
| `context` | Non-secret client/egress labels for control comparison |
| `rules` | Per-step ordered body classification rules |
| `extract` | Named JSON/header response selectors |

Relative JSON file paths resolve against `--project`. All steps and rules are preflight-validated before the first HTTP request. A step is revalidated after its live flow values are substituted.

## Environment and flow values

`${ENV_VAR}` substitutes an environment value. Missing environment variables fail before traffic. Known values are treated as secrets for redaction; no `.env` loader is implied.

`${flow.AUTH}` substitutes a value extracted by an earlier step in this command. The namespaces are separate. Substitution operates on the original template, not recursively on substituted strings: a token that happens to contain placeholder syntax stays literal.

Flow values are allowed in request headers, JSON/body and URL path/query. They are not allowed in method, proxy, context, rules or extraction selectors, or the URL scheme/authority. Undefined, forward and malformed references fail before the first request. A step can rotate an earlier binding, but cannot consume its first-time output in its own request.

Substitution does not URL-encode values or calculate signatures. If the protocol needs encoding, signing, cryptographic nonces or derived fields, implement its observed request builder in a real helper.

## Response extraction

```json
{
  "url": "https://example.invalid/observed-login",
  "method": "POST",
  "json": {"login": "${CONTROL_LOGIN}", "password": "${CONTROL_PASSWORD}"},
  "extract": {
    "AUTH": {"json_path": "/result/access_token"},
    "REQUEST_ID": {"header": "x-request-id"}
  }
}
```

The URL and selectors above are illustrative, not a vendor protocol.

Each variable uses exactly one selector:

- `json_path`: a JSON pointer, `$`, or dotted path with numeric indexes, using the same grammar as classification rules.
- `header`: one HTTP header name, matched case-insensitively.

Extraction values must be nonempty strings from a complete response. Missing/null/object values, redacted strings, truncated responses and ambiguous or newline-containing header values produce `extraction_error`. The actual exchange is saved; dependent traffic is not sent. A selected stop bucket takes precedence over extraction, so a deterministic `TERMINAL` response is not relabeled as a missing token.

Values live only inside the command. Extraction happens before response sanitization, including values in innocuously named fields. Earlier records are sanitized with the final known-secret set before persistence, so an earlier echo of a token discovered later is scrubbed too. Rotated values remain in that set. The public extraction metadata names variables/selectors and success/errors, never their values.

This is best-effort redaction, not a guarantee that every unknown private value is identified. Raw artifacts and captures are a separate privacy boundary.

## Classification

```json
[
  {"bucket": "HIT", "json_path": "/message", "equals": "ACCEPTED"},
  {"bucket": "FAIL", "contains": "INVALID_PASSWORD"},
  {"bucket": "TERMINAL", "regex": "DOMAIN_NOT_ALLOWED"}
]
```

Use messages actually observed on the target. The first matching rule wins. A rule needs exactly one body predicate: `contains`, `regex` or `json_path` with optional `equals`. A `status` condition may constrain a predicate but cannot stand alone. Per-request `rules` override `--rules`; they do not merge. No match means `UNKNOWN`.

Default stop bucket is `TERMINAL`. Explicit repeated `--stop-bucket` flags replace that default; include `TERMINAL` again if adding another bucket:

```sh
forge --project target probe-run flow.json --stop-bucket TERMINAL --stop-bucket FAIL
```

Transport errors also stop. There are no implicit retries, proxy changes or direct-connection fallbacks.

## Result semantics

`probe-run` returns:

- `exchanges`: saved exchange records in request order.
- `completed` / `requested`: how many exchanges occurred and how many were specified.
- `stopped` / `stop_reason`: bucket, transport or extraction stop facts.
- `session_reused`: the same command-local session was used.

`ok: true` and exit 0 mean the command returned its structured result, not that every step or login succeeded. Check the stop reason, response and bucket. A single `probe` operational/extraction failure returns exit 2 and points to its saved evidence.

## Transports and limits

`urllib` is standard-library HTTP. It does not reproduce mobile TLS fingerprints. Gzip responses are decoded with the configured body cap; unsupported encodings fail explicitly.

Install the `http` extra and select `--transport curl_cffi` for curl support. Impersonation must be explicitly requested with a supported `--impersonate` profile; this is not a claim to reproduce OkHttp. Ambient proxy environment is not a substitute for an explicit request proxy.

Headers are the transport's parsed response fields, not a raw wire transcript. In particular, libcurl normalizes obsolete folded lines before Python receives them; FORGE cannot attest that the original wire header had no folding. Duplicate field values and remaining newline-containing extraction values are rejected, and materialized request headers are validated before dispatch.

`--timeout` must be finite and positive. `--max-body` bounds the decoded response bytes for each step. Flows retain sanitized exchanges in command memory until the final secret set is known; choose capture limits appropriate to the investigation.

## HAR and controls

`har-import` reads a bounded number of entries without replaying them. Imported HAR cannot qualify as a fresh positive/negative control. Redacted evidence cannot supply a token for a later process.

The `verify` gate checks cited live probe controls, not execution of a generated target checker. Run that implementation separately and save its observed results.
