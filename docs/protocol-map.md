# Protocol map

`protocol-map` summarizes existing evidence without executing requests, scanning source files, opening stored artifact/index/HAR paths, or adding evidence rows. It returns JSON through the normal CLI result envelope.

```console
forge --project ./owned-target protocol-map
forge --project ./owned-target protocol-map --limit 250 --max-endpoints 500
forge --project ./owned-target protocol-map --evidence ev_CAPTURE_ID --evidence ev_PROBE_ID --evidence ev_INDEX_ID
```

Replace the illustrative IDs with IDs from `evidence` or `show`. Repeating an ID has no effect. Explicit IDs take precedence over the newest-record window: all unique selected records are considered, even with `--limit 1`. Unknown IDs, unrelated evidence kinds, non-static analysis records, and invalid protocol metadata are errors. Bounds are validated even for explicit selections.

To retain a view for later comparison, use `protocol-snapshot` with the same selection options; it creates cited immutable evidence rather than changing `protocol-map`'s read-only contract. `protocol-diff` compares two snapshot IDs with endpoint/method identity, name/status/provenance changes and completeness warnings. See [comparisons](comparisons.md); diff route identity deliberately differs from the exact redacted-URL grouping described below.

## Evidence selection

Without `--evidence`, the command selects the newest relevant records, ordered by creation time and then database insertion order. Relevant kinds are `http_probe`, `har_exchange`, `search`, and `analysis` whose `data.tool` is `static_index`. HTTP records must also have the matching `data.source` (`live_probe` or `har_import`); inconsistent provenance is rejected rather than promoted to live evidence. It filters relevance **before** applying `--limit`, so newer checkpoints, task events, and other analysis records do not hide captures. One additional relevant record is fetched to detect a truncated window.

`--limit` defaults to 100 and accepts 1 through 1000. `--max-endpoints` defaults to 200 and accepts 1 through 5000. Explicit selection preserves the order of first occurrence of each ID. Endpoint/output caps still apply to explicit selection.

## Provenance and identity

Each endpoint has `url`, optional `method`, `proven_live`, `proven_auth_path`, and an `observations` array. Identity is the exact URL after existing FORGE redaction, together with the exact observed method when one is present. Methods and remaining query strings are not collapsed into a route template. The redactor can normalize query encoding, remove fragments, and mask credential query values; identities indistinguishable after that redaction may group together.

Static strings have no invented method, host, headers, or response. A relative candidate such as `/api/login` remains unresolved and does not merge with `https://example.com/api/login`. A static URL without a method remains separate from an HTTP request observation of that URL.

Observation categories have different meanings:

| Category | Source | Meaning |
| --- | --- | --- |
| `static_candidate` | Stored index candidates or stored search-match candidates | A string occurred at a cited source location. It is not evidence of a reachable endpoint. |
| `captured_http` | Imported HAR exchange | A request/response was present in supplied capture data. FORGE did not replay or independently verify it. |
| `live_http` | Recorded live probe | FORGE attempted the request. `proven_live` is true only when a real recorded HTTP response status in 100 through 599 is present. |

A failed live transport still appears as an attempted `live_http` request with `response_observed: false`, a null `response_status`, and its redacted error. It does not prove a reachable endpoint. A live 401, 403, or 500 response does prove an HTTP response was observed, not successful authentication. Even a live 200 response is not authentication verification. `proven_auth_path` and top-level `authentication_verified` remain false. Use the separate control-verification workflow for authentication claims.

Every observation has citations containing `evidence_id`. Static citations preserve available location metadata: `source`, `member`, `line`, `column`, `offset`, `byte_offset`, `offset_space`, `compression`, `encoding`, `index_source`, and `kind`. The map never opens those locations. Binary offsets and text lines remain in their original coordinate space. HTTP observations cite their exchange/probe record directly.

Identical observations group together and collect unique citations. Repeated identical citations are omitted. Different response statuses, request/response field sets, selector metadata, categories, errors, and source locations remain distinct. Endpoint-level `proven_live` means at least one retained observation includes a live response, not that every citation is live evidence.

## Names, not credential values

HTTP observations include observed redacted URL/method, query field names, request/response header names, response status/truncation/error, and extraction selector metadata. Selector metadata retains only variable name, header or JSON path, success flag, and extraction error. Extracted values are never exported.

Bodies contribute JSON Pointer field paths and form field names, never scalar body values. Pointer escaping follows JSON Pointer (`~` becomes `~0`, `/` becomes `~1`); array positions remain numeric structure in paths such as `/items/0/name`. JSON strings are parsed when possible; structured stored bodies are traversed directly. Opaque/non-JSON bodies are marked `body_unparsed` and never echoed.

Form extraction requires a stored `Content-Type` attesting `application/x-www-form-urlencoded` or `multipart/form-data`. URL-encoded strings provide names through bounded parsing. Stored form dictionaries, including HAR parameter dictionaries, provide their keys. Multipart text is not decoded into fields; it is marked unparsed. An unattested `name=value` body is not called a form. Missing or truncated content, redacted nested subtrees, and invalid JSON can prevent field recovery. This command cannot recover discarded capture metadata or values from private/raw files.

Existing FORGE URL/text redaction is reused. Sensitive field and header **names** stay inspectable. Header/body/form values and raw search-match text are not exported. Non-sensitive query values may remain in the redacted URL because they affect endpoint identity. This map is a summary of already-sanitized evidence, not a way to retrieve raw traffic.

## Completeness and limits

The output uses `schema_version: 1`, reports selected `evidence_ids`, and distinguishes `selection: explicit` from `selection: newest_relevant`. `empty: true` and `endpoints: []` describe an empty map, including selected records with no stored candidates.

| Flag | Meaning |
| --- | --- |
| `window_truncated` | More relevant records exist beyond the automatic newest-record window. Never set solely because explicit IDs exceed `--limit`. |
| `input_truncated` | A selected record declares truncation/omitted input, a response body is truncated, or metadata exceeds the map's search/candidate caps. |
| `output_truncated` | Additional endpoint identities were encountered after `--max-endpoints`. |
| `observations_omitted` | An endpoint or total observation cap prevented retaining another distinct observation. |
| `citations_omitted` | A grouped observation reached its unique-citation cap. |
| `fields_omitted` | HTTP name, selector, body-depth, node, field, or parse-size limits prevented complete field extraction. |

Static indexes store at most **100 metadata candidates per index**, even when the private index file contains more. `static_candidate_sampling` reports each selected index's `metadata_candidate_limit: 100` and `sampling_possible: true` when the stored sample reaches that cap. Reaching 100 does not establish the exact number omitted. A sample below 100 can still be incomplete if indexing itself was truncated. The map deliberately does not open the index to fill missing candidates. Search records likewise store at most 20 candidates per match; the map uses those candidates, not the match text or original source.

Additional fixed limits, also returned in `limits`:

- 256 names per header/query/form list, 256 JSON field paths per body, and 256 extraction-selector entries.
- 1,048,576 characters per body string considered for parsing; 2,048 traversal nodes; depth 16. Encoded byte size may differ from the character limit.
- 100 distinct observations per endpoint, 20,000 retained observations in total, and 100 unique citations per observation.
- 1,000 matches per search record, 20 stored candidates per search match, and 100 stored candidates per static index.

Omission flags describe this view, not a completeness guarantee for the underlying application. Existing redaction, importer limits, upstream sampling, and unavailable bodies can remove information before the map is built. No host resolution, endpoint probing, authentication inference, or raw-file fallback takes place.
