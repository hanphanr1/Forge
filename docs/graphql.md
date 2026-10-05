# GraphQL document analysis

`graphql-analyze` parses executable GraphQL documents from an explicit project file or selected evidence. It performs no network calls, introspection, traffic capture, schema inference, or request replay.

```console
forge --project ./owned-project graphql-analyze client.graphql
forge --project ./owned-project graphql-analyze client.js --evidence ev_example
forge --project ./owned-project graphql-analyze --evidence ev_first --evidence ev_second
```

Supply a source file, one or more `--evidence` IDs, or both. The command does not search the project or automatically select recent records. Source and static-index paths must resolve to regular files inside the selected project, including when a symlink is used.

## Inputs

- `.graphql`, `.gql`, and `.txt`: executable documents, including anonymous selection sets.
- `.json`: a GraphQL request object or a flat array of request objects. Only `query`, `operationName`, and `extensions.persistedQuery` contribute output. Request `variables` and other values are not exported.
- `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, and `.jsx`: syntactically delimited quoted strings beginning with an operation/fragment keyword or `#graphql`, plus templates tagged with the identifiers `gql` or `graphql`. Tagged templates can contain anonymous selections. Supported JavaScript escapes are decoded before GraphQL parsing, and positions map back to the source string.
- `http_probe` and `har_exchange` evidence: the actual stored request body and URL query parameters. JSON, `application/graphql`, and URL-encoded request bodies are supported. Captured HAR observations remain distinct from live-probe observations. HTTP response content is not parsed.
- `analysis` evidence with `tool: static_index`: the cited index JSONL file, not the original artifact or member.
- `search` evidence: stored match text, not source paths reopened from the record.

Static text is already redacted and may be incomplete. Adjacent text records are combined only when source, member, and encoding match, lines are consecutive, and the next record starts at column 1. Missing lines, long-line chunks, binary strings, unsupported file formats, and record limits can prevent recovery of a complete document. The command reports this limitation; it does not fill gaps or invent content. An unavailable or out-of-project index is an input error.

JavaScript extraction is deliberately limited and always carries a warning. It does not evaluate JavaScript, substitutions, function calls, document composition, imported fragments, or generated queries. Untagged templates are omitted. An interpolated template stops extraction for the remainder of that source span because skipping an arbitrary expression safely would require a JavaScript parser. A slash outside strings/comments also stops extraction for the remaining span rather than guessing whether it begins a regular expression or division. Unsupported escapes and unterminated strings/comments are reported without reproducing source text.

## Stored result

The command appends one immutable `analysis` record with `tool: graphql_analyze` and `schema_version: 1`. Its `data` contains `documents`, `warnings`, `evidence_ids`, `omissions`, `empty`, and the applied `limits`.

A document has one of these statuses:

- `parsed`: complete lexical and executable-document structural parsing succeeded.
- `parse_failed`: a failure code and position are recorded; partial operations/fragments are discarded.
- `omitted`: the document or aggregate size limit was exceeded.
- `document_absent`: request metadata was observed, but no query text was present.

Parsed documents contain named or anonymous `query`, `mutation`, and `subscription` operations. Each operation records declared variable names/types, field names, aliases, actual selection `path`, alias-aware `response_path`, fragment spreads, and positions. Fragment definitions record their name, type condition, fields, and spreads. Inline fragments use a null spread name and an optional type condition. Fragment paths are local to their definitions; spreads are not expanded. Undefined fragment names are listed without assuming an external fragment is available.

Comments, quoted strings, escaped strings, block strings, nested selections, list/non-null types, directives, arguments, and nested input values are parsed structurally. Argument values, enum literals, default values, variable values, directive values, comments, and raw documents are never included in the result or its database row. Structural names remain metadata, not an assurance that those names contain no private information. Existing FORGE sanitization still applies when the result is stored.

`operation_name` records a valid request `operationName`, and `operation_name_matches` indicates whether it names an operation in the available parsed document. Persisted-query metadata contains a validated 64-digit hexadecimal SHA-256 hash and bounded integer version when present. `document_recovered` is always false: a hash does not recover its document. A hash-only request has empty operations/fragments and `document_absent`; no schema or fields are inferred.

Source citations include the project-relative file name and SHA-256 of the complete input bytes. Operation, variable, field, fragment, and spread positions use 1-based line/column and a 0-based character offset. For JavaScript these refer to decoded UTF-8 source positions, including mapped escape locations. For JSON/HTTP envelopes they refer to the decoded query string, not the enclosing JSON or percent-encoded URL. Static citations preserve the underlying evidence ID and available source/member/line/column metadata; offsets are relative to the contiguous reconstructed span. Index citations also hash the complete index file.

When static-index evidence contains `index_sha256` or `index_size`, the current index bytes must match each recorded value before any document is parsed. Invalid or mismatched identity metadata rejects the input. Citation flags `index_recorded_identity_verified` and `index_recorded_size_verified` distinguish those checks from hashes/sizes measured during this analysis. A legacy index without a recorded hash carries `legacy_static_index_identity_unverified`; its measured hash describes current bytes only and does not establish creation-time identity.

HTTP citations include the underlying evidence ID, creation time, captured/live category, and whether a response status was observed. Observing a live response does not prove GraphQL execution, authentication, authorization, or success. Existing stored request redaction may change a document and cause parsing to fail. The analyzer does not change the underlying evidence or remove literals already retained by a previous importer/probe.

## Fixed limits

| Bound | Maximum |
| --- | ---: |
| Source/index file or serialized HTTP body/URL size | 1,048,576 bytes for files; 1,048,576 characters for stored strings |
| Query document / contiguous static span | 262,144 characters |
| Total attempted query text per analysis | 4,194,304 characters |
| Lexical tokens per document | 20,000 |
| Selection, input-value, and type nesting | 32 per structure |
| Document attempts | 100 |
| Explicit evidence IDs | 100 |
| Static records per evidence / warning records | 2,000 |
| Static record text | 4,096 characters |
| Serialized index record | 131,072 characters |

Caps and parse failures remain visible through warning/failure codes and `omissions`. Oversized source/index files are rejected before analysis. A request batch is flat and bounded; nested batches are omitted. The parser checks syntax, not schema semantics, operation uniqueness, fragment cycles, argument validity against a schema, or server behavior.

The numeric lexical-token cap is stored as `limits.lexical_items_per_document`; this metadata key does not bypass FORGE's sensitive-key redaction.
