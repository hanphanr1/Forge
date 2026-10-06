# Capture ingest and frame inspection

Three commands cover pushes and captures instead of manual file juggling:

- `capture-ingest` runs a bounded loopback HTTP receiver so a capture tool (Reqable, mitmproxy, Chrome, a script) can POST a HAR document directly and store it as imported exchanges.
- `websocket-analyze` summarizes WebSocket frame metadata already present in HAR files or explicit frames JSON.
- `api-shape` summarizes stored HTTP evidence per domain: identities, statuses, header names and body field names, never values.

`capture-ingest` is the only one that touches a socket, and only as a loopback listener. `websocket-analyze` and `api-shape` perform no network access; they read explicit files and existing evidence rows.

## capture-ingest

```console
forge --project ./owned-target capture-ingest --port 8765 --seconds 120 --route /report
forge --project ./owned-target capture-ingest --port 0 --seconds 60 --token "<shared-token>"
curl -X POST --data-binary @capture.har -H "X-Forge-Token: <shared-token>" http://127.0.0.1:8765/report
```

| Option | Range | Default | Meaning |
| --- | --- | --- | --- |
| `--port` | 0..65535 | 0 | `0` binds an ephemeral port; the bound port is announced and reported |
| `--seconds` | 1..3600 | 60 | Hard listener lifetime; the command returns when it ends |
| `--max-body` | 1..16777216 | 8388608 | Maximum accepted request body bytes |
| `--max-records` | 1..5000 | 200 | Maximum stored exchanges; the listener stops when reached |
| `--route` | absolute path | `/report` | Only this request path is accepted |
| `--token` | nonempty string | none | When set, a matching credential is required |

The receiver always binds `127.0.0.1` and refuses any other bind host. It is a single-threaded, bounded `http.server` loop: one request at a time, a per-request socket timeout of 5 seconds, at most 65536 bytes of a rejected body drained before responding, and `Content-Length` required (`Transfer-Encoding: chunked` is refused). Nothing about the request is logged or echoed; rejections return a fixed JSON reason plus counters.

The listener is a blocking command, so a fixed `--port` is the way to configure a capture tool in advance. With `--port 0` the effective port is printed once to stderr at startup (`forge capture-ingest: listening on 127.0.0.1:<port><route> for <seconds>s`) and also reported in the result when the command returns.

### Accepted documents

An accepted `POST` body must be one of:

1. a HAR document: `{"log": {"entries": [ ... ]}}`
2. a bare entries array: `[ {request, response}, ... ]`
3. a single entry object: `{request, response}`

Entries are normalized and stored through the same path as `har-import` (`forge_network._har_entry` plus the same secret scrubbing and `_sanitize` call), producing `har_exchange` evidence with `source: "har_import"`, `transport.replayed: false` and a recorded known-secret count. The store connection used for these writes is opened by the listener itself, because SQLite connections belong to the thread that created them.

One POST is one accept/reject decision and imports its entries atomically: an invalid entry rejects the whole document instead of storing a partial import.

### Rejections

| Reason | HTTP | Cause |
| --- | --- | --- |
| `wrong_method` | 405 | Anything other than `POST` |
| `wrong_route` | 404 | Path (query ignored) differs from `--route` |
| `unauthorized` | 401 | `--token` set and `X-Forge-Token` / `Authorization: Bearer` did not match |
| `unsupported_transfer_encoding` | 501 | Chunked request body |
| `missing_length` / `invalid_length` | 411 / 400 | Absent or unparseable `Content-Length` |
| `oversized_body` | 413 | Body above `--max-body` |
| `malformed_json` | 400 | Body is not UTF-8 JSON |
| `unsupported_document` / `empty_document` | 400 | Not one of the accepted shapes, or no entries |
| `invalid_entry` | 400 | Entry/header/status/body validation failed |
| `record_limit` | 429 | `--max-records` already stored |
| `storage_failure` | 500 | The evidence write itself failed |
| `incomplete_body` | 408 | Body not fully read inside the deadline |

### Result fields

`listener` reports bound `host`, `port`, `route` and `loopback_only`. `stopped_reason` is `deadline`, `max_records`, `interrupted` (Ctrl-C), or `stopped` (embedding stop hook). `accepted_requests`/`rejected_requests` count requests; `rejected_reasons` breaks the rejects down. `evidence` lists stored IDs, `exchanges_stored` their count, `entries_available` the entries seen in the accepted documents, and `records_omitted` the entries dropped because `--max-records` was reached. `truncated` is true when any stored response body hit `--max-body`; `bytes_read` counts request body bytes only; `handler_errors` counts internal handler failures that produced no response.

An accepted exchange is a redacted import of whatever a local client pushed to this receiver. The receiver identifies no capture tool, authenticates no user (a shared token is only a header check), and proves no live traffic or authentication. Such evidence is `captured_http`, never a live control.

## websocket-analyze

```console
forge --project ./owned-target websocket-analyze capture.har --max-frames 5000
forge --project ./owned-target websocket-analyze frames.json --max-frame-bytes 4096
```

Sources are explicit files that resolve against `--project`. Accepted shapes, detected in this order:

- a HAR document whose entries carry `_webSocketMessages` or `_webSocketFrames` lists (Chrome and compatible exports). Only entries with one of those keys become sessions.
- a bare HAR entries array with the same keys
- `{"url": ..., "frames": [...]}`
- an array of those frames objects

Anything else is an error, including a JSON file with no recognisable shape. A HAR without WebSocket entries is not an error: it reports zero sessions.

Per session the report contains the observed `url` (redacted with the existing URL redactor, `wss`/`ws` scheme preserved), `frames_observed`/`frames_parsed`/`frames_omitted`, `invalid_frames`, `directions`, `frame_types`, `payload_bytes`, `close_frames`/`close_codes`, and `json_shape`.

- Directions are `request` when the frame says `send`, `sent`, `request`, `client`, `outgoing` or `tx`, `response` for `receive`, `received`, `response`, `server`, `incoming` or `rx` (`direction`, `dir` or `type` may carry that word). Chrome's `send`/`receive` therefore yields real directions; anything else stays `unknown`.
- `frame_types` labels a frame by its `opcode` (0 continuation, 1 text, 2 binary, 8 close, 9 ping, 10 pong, other values as `opcode-N`), otherwise by a recognised `type`/`frameType` word, otherwise `unknown`.
- `payload_bytes` measures the observed `data` field: UTF-8 byte length for strings, the canonical JSON encoding length for objects/arrays. Base64 payloads are not decoded and the payload is never echoed. Frames without a measurable payload are counted in `frames_without_payload`.
- `close_codes` collects only explicit integer frame `code` values in 0..65535; many exports omit them even for close frames.
- `json_shape` reports `json_frames`, `unparsed_frames`, `empty_frames`, `root_kinds` (`object`/`array`/`scalar` from the first significant character) and `field_paths` — the JSON Pointer field names that `protocol-map` would also report. Values are never exported. Frames above `--max-frame-bytes`, or a field-name cap, set `field_paths_omitted` and/or `frames_over_byte_limit`. Concatenated or non-JSON payloads are counted as unparsed.

| Option | Range | Default | Caps |
| --- | --- | --- | --- |
| `--max-sources` | 1..5000 | 20 | Sources read; extras are `sources_omitted` |
| `--max-sessions` | 1..5000 | 50 | Sessions per source; extras are `sessions_omitted` |
| `--max-frames` | 1..200000 | 2000 | Frames parsed per session; extras are `frames_omitted` |
| `--max-frame-bytes` | 1..16777216 | 65536 | Payload bytes considered for shape parsing per frame |
| `--max-fields` | 1..2000 | 200 | JSON field-name paths kept per session |

The command writes no evidence and makes no requests. A parsed capture describes what some client observed earlier; it does not prove the endpoint behaves the same now.

## api-shape

```console
forge --project ./owned-target api-shape --limit 250
forge --project ./owned-target api-shape --domain api.example --domain api.example:8443
forge --project ./owned-target api-shape --evidence ev_CAPTURE_ID --evidence ev_LIVE_PROBE_ID
```

Selection is either repeatable `--evidence ID` (explicit, validated as `http_probe` or `har_exchange`, takes precedence over `--limit`) or the newest stored HTTP records (`--limit`, default 100, 1..1000). Repeatable `--domain` filters either selection by hostname or `hostname:port`; a `--domain` value may not contain a scheme, path, credentials or whitespace. Unknown IDs, non-HTTP kinds and inconsistent provenance (`data.source` other than `live_probe`/`har_import`) are errors. One extra record is fetched to detect a truncated newest-record window (`window_truncated`).

Each entry in `domains` reports `domain` (hostname), `ports` (explicit ports seen), `observations`, cited `evidence_ids`, `method_paths` (redacted path plus method and count), `statuses`, `response_status_unobserved`, `body_observations`, `unparsed_bodies`, and name lists: `request_header_names`, `response_header_names`, `request_json_field_paths`, `response_json_field_paths`, `request_form_field_names`, `response_form_field_names`, `query_field_names`.

Names only: paths come from the same redaction helper `protocol-map` uses, so query values never appear and sensitive query values are masked; identities carry no query string at all. Header, body, form and query values are never exported. Field paths and header names keep their escaped JSON Pointer form.

| Option | Range | Default | Caps |
| --- | --- | --- | --- |
| `--limit` | 1..1000 | 100 | Newest stored HTTP records without `--evidence` |
| `--max-domains` | 1..500 | 50 | Domains reported (sorted by observation count, then name) |
| `--max-paths` | 1..2000 | 100 | Method/path identities per domain |
| `--max-names` | 1..2000 | 200 | Names per header/field/query list |
| `--max-statuses` | 1..500 | 50 | Distinct statuses per domain |
| `--max-ids` | 1..1000 | 50 | Cited evidence IDs per domain |

Per-domain `paths_omitted`, `statuses_omitted`, `names_omitted` and `ids_omitted` describe caps that actually dropped data; top-level `domains_omitted` does the same for domains, and `input_fields_omitted` marks input whose own body parsing was already capped upstream. `values_withheld` is always true. The summary describes already-sanitized stored evidence, not raw traffic, and an imported `har_exchange` remains a captured observation rather than a live control.
