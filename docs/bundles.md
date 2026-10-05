# Evidence handoff bundles

`bundle` publishes a new ZIP from explicitly selected evidence IDs. It follows stored citation IDs within a bounded window and preserves process/control facts, hashes and provenance labels. It never reads or embeds artifact blobs, private index files, screenshots, raw captures or source files.

```sh
forge --project target bundle --evidence ev_FINDING --evidence ev_GATE --output handoff/review.zip
```

Use actual IDs from `claim`, `verify`, `verify-target`, snapshots or analyses. The output must be a new safe project path; collisions, traversal, secret/dependency paths and symlink/reparse paths fail without overwriting files.

## Contents

- `manifest.json`: schema/version, explicitly selected and included IDs, missing/omitted citations, reference-scan truncation, disclosure flags, scope limits and SHA-256/byte size for the other two members.
- `evidence.json`: lossy metadata projections, provenance labels, cited IDs, typed status/control facts and declared source/runtime hashes.
- `report.md`: a readable view of those same projections and scope limits.

The published `handoff_bundle` evidence records the ZIP hash/size and included IDs. Member hashes detect altered bytes; neither hashes nor this unsigned bundle authenticate its author or prove the underlying claims.

## Privacy defaults

Request/response bodies, headers and payload values, process stdout/stderr, argv/stdin, local filesystem paths, raw source snippets and arbitrary unknown fields are withheld. URL identities are represented by hashes rather than hostname/path/query text. Metadata labels and hashes are not raw traffic. Source/runtime path text is not exported.

Free-text findings are also withheld by default because a human-authored statement can contain an opaque credential. To include reviewed claim prose explicitly:

```sh
forge --project target bundle --evidence ev_FINDING --output handoff/reviewed.zip --include-findings
```

This option includes existing scrubbed claim text, not raw HTTP or process output. Review the original claim before enabling it: heuristic redaction cannot identify every unlabelled secret or confidential statement. Schema labels, timestamps, fingerprints, provenance and citations can still be confidential. A metadata projection is not automatic disclosure approval.

## Completeness and bounds

- `--limit`: 1..1000 visited records, default 100. Explicit IDs must fit this limit; citation closure may be partial.
- `--max-record-bytes`: 1..64 MiB, default 16 MiB. Oversized selected/cited records fail before publication.
- `--max-bytes`: 1..32 MiB, default 8 MiB. Both total uncompressed member bytes and the final ZIP must fit.
- Reference scanning and metadata projection: depth 32 and 20,000 nodes per record. Projection retains at most 1000 items per list and reports `metadata_node_cap_reached`.
- Citation queue/visited set: bounded by `--limit`; omitted ID samples contain at most 1000 IDs. `omitted_reference_occurrences` counts unvisited references across records, not distinct IDs; `omitted_references_sampled` reports an incomplete omitted-ID sample.

`closure_complete` concerns citation reachability only. It is false for missing references, records omitted at the limit or bounded reference scans. `projection_lossy` is always true; a complete citation closure is not complete application evidence. Missing fields must not be interpreted as absence from the client or capture.

The bundle does not import evidence into another database, carry credentials for replay, promote captures to live proof or mark a resumed investigation verified. The recipient uses cited records and supplied owned source/artifacts under a separate disclosure policy.
