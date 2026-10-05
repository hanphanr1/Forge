# Cited protocol and client comparisons

FORGE stores each snapshot and comparison as a new evidence record. These commands do not replay captures, contact endpoints, change source files, or update earlier evidence.

## Protocol snapshots

```console
forge protocol-snapshot --evidence HTTP_ID --evidence INDEX_ID
forge protocol-snapshot --limit 100 --max-endpoints 200
forge protocol-diff --before BEFORE_SNAPSHOT_ID --after AFTER_SNAPSHOT_ID
```

Replace the uppercase ID arguments with IDs returned by FORGE. `protocol-snapshot` uses the existing `protocol-map` selection rules: repeatable `--evidence` takes precedence over the newest-record `--limit` window. Limits and validation match `protocol-map`: 1 through 1,000 records in the automatic window and 1 through 5,000 endpoint identities. The default endpoint limit is 200.

A `protocol_snapshot` record has `schema_version: 1`, the selected `options`, and the complete metadata-only `map`. The map retains its underlying evidence IDs, observation citations, source categories, provenance, limits, sampling notices, and omission flags. Protocol comparisons need only these records; deleting the original capture, source, or index file does not affect an existing snapshot comparison.

A `protocol_diff` record has `schema_version: 1` and cites its `before_id` and `after_id`. Endpoint identity is URL scheme, authority, path, and observed method. FORGE excludes query values and fragments from identity so a query-name change becomes a field change rather than an unrelated endpoint addition/removal. A static candidate has no observed method and stays separate from an HTTP observation with a method. Relative static paths stay relative.

For each shared identity, `changed` contains sorted before/after sets for:

- Source category and observed HTTP status.
- Query, request-header, and response-header names.
- Request and response form-field names and JSON field paths.
- Extraction-selector metadata, including success/error metadata but excluding extracted values.
- Observation provenance, truncation, errors, and body-parsing/field omissions.

Each changed entry also includes the original metadata observations and their underlying evidence citations. `added` and `removed` include identity, dimensions, and cited observations. `before_scope`, `after_scope`, `scope_changes`, and `selection_options` expose differing selection windows, evidence inputs, caps, and sampling. Output order is deterministic for the same records.

`complete` is false when either map reports omissions, when static candidate sampling remains possible, or when redaction/query grouping makes an identity ambiguous. `ambiguities` identifies redacted identities and the number of distinct stored query variants grouped under an identity. FORGE cannot recover distinctions already lost to redaction. A missing observation is not proof that a server removed an endpoint, and a successful HTTP status is not authentication proof. `authentication_verified` remains false.

## Client artifacts with static indexes

Import each version, then index its stored blob, not its original filename:

```console
forge artifact-add old-client.zip --version 1.0
forge artifact-add new-client.zip --version 2.0
forge artifact-index .forge/blobs/OLD_SHA256
forge artifact-index .forge/blobs/NEW_SHA256
forge client-diff --before OLD_ARTIFACT_ID --after NEW_ARTIFACT_ID --before-index OLD_INDEX_ID --after-index NEW_INDEX_ID
```

Use the SHA256 and evidence IDs returned by the preceding commands. The inverse form accepts primary static-index records with explicit artifacts:

```console
forge client-diff --before OLD_INDEX_ID --after NEW_INDEX_ID --before-artifact OLD_ARTIFACT_ID --after-artifact NEW_ARTIFACT_ID
```

FORGE requires each paired index's recorded `input` to equal its corresponding artifact's stored blob `path`. It does not assume that an index of an original source path still represents the imported bytes. Both forms work after deletion of the original imported files, provided the stored blobs and indexes remain available and valid.

You may omit indexes to compare artifact SHA256, size, caller-supplied version/platform metadata, and file/member bytes. The result explicitly states that endpoint and source-string comparison is unavailable. Version labels are caller metadata, not versions inferred from an executable.

A `client_diff` record has `schema_version: 1` and includes:

- Primary and paired citation IDs in `before`, `after`, and their metadata.
- `metadata_changes` for artifact SHA256, size, version, platform, and filename.
- Bounded before/after file inventories and `files.added`, `files.removed`, and `files.changed`.
- SHA256, size, `hash_basis`, and citations for each file/member.
- Added/removed endpoint candidates with source-location citations and false live/authentication flags.
- Added/removed source-string observations represented by hashes of already-redacted index text and location citations. The result does not export source lines or credential values.
- `limits`, per-side `omissions`, `complete`, `file_inventory_complete`, and explicit `limitations`.

Single-file artifacts use the logical inventory name `artifact`, independent of original filename. ZIP-family archives use normalized member paths. Member hashes cover the member's actual uncompressed bytes; single-file hashes cover the artifact bytes. Inventory size is the corresponding byte count.

## Indexed source versions

```console
forge artifact-index old-source-directory
forge artifact-index new-source-directory
forge client-diff --before OLD_INDEX_ID --after NEW_INDEX_ID
```

The stored JSONL indexes suffice after deletion or modification of the original directories. FORGE groups indexed records by source path relative to each index's recorded input, or by archive member. For a single indexed input it uses the logical name `artifact`.

Index-only file inventories use `hash_basis: redacted_index_projection`. Their hash covers ordered, length-delimited, canonical records with source/index path prefixes excluded. Their `size` counts those serialized projection bytes, not original file bytes. Strings, coordinates, encodings, and retained index metadata participate in the projection. Files that produced no index records are unknown. Thus index-only `file_inventory_complete` and `complete` remain false, even when every stored index record was read. Endpoint and string differences still carry the source-index citations that support them.

FORGE rejects comparisons that mix raw-byte inventories with index-only projections. Supply paired artifacts on both sides or compare indexes on both sides.

## Integrity and bounds

Stored inputs must be regular, nonlinked files under this project's `.forge` directory. FORGE rejects outside paths, traversal, symlinks, and Windows junctions. It verifies artifact bytes against the evidence's SHA256 and size and rechecks them after inventory/index processing. Indexes created with `index_sha256` and `index_size` must match those creation-time facts; FORGE also checks record count and verifies the bytes did not change while it read them.

Older `static_index` records do not contain creation-time hash metadata. FORGE records and pins their read-time index SHA256/size, but reports `hash_verified: false`, `legacy_index_creation_hash_unavailable: true`, and `complete: false`. This does not establish original source-file integrity. Missing or corrupt stored files fail rather than falling back to an original source path.

ZIP inventory never extracts members. It checks the bounded ZIP footer before loading the central directory. ZIP64, multidisk, corrupt archives, or archives exceeding the entry cap fail without publishing a comparison. Traversal/absolute/drive/alternate-stream paths, duplicate or case/path-aliased member names, symlinks and other nonregular members, inconsistent directory metadata, encrypted members, and expansion ratios above 200:1 produce explicit omissions. Members beyond byte caps also produce omissions. CRC/decompression errors and declared-size mismatches fail. Endpoint/string observations from omitted or ambiguous archive members do not enter the comparison.

| Option | Default | Meaning |
| --- | ---: | --- |
| `--max-input-bytes` | 268435456 | Bytes hashed/read per stored artifact or index |
| `--max-file-bytes` | 16777216 | Maximum uncompressed ZIP member bytes |
| `--max-total-bytes` | 134217728 | Total inventoried uncompressed ZIP member bytes per side |
| `--max-entries` | 10000 | ZIP central-directory or projected-file cap; maximum 100000 |
| `--max-records` | 10000 | Index records processed for comparison; maximum 100000 |
| `--max-endpoints` | 5000 | Unique index endpoint candidates per side; maximum 5000 |

All options require positive integers. Index records have a 128 KiB line limit, source text uses at most 4,096 characters per existing index record, and each endpoint/string observation retains at most 20 location citations. Comparison caps and original indexing omissions remain visible. A complete file inventory can coexist with incomplete endpoint/string analysis; read `file_inventory_complete` separately from `complete`.

Client differences describe the supplied stored versions and their static observations. They cannot establish server behavior or authentication changes. `server_changes_verified` and `authentication_verified` remain false.
