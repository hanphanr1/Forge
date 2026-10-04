# HAR to editable flow

`har-to-flow` reads an explicitly supplied UTF-8 HAR and writes a new JSON request array compatible with `probe-run`. It sends no requests, exports no environment assignments or captured URL/header/string-body values, and never overwrites a file.

```console
forge --project ./owned-target har-to-flow capture.har --output flows/from-capture.json
forge --project ./owned-target show ev_FLOW_RECORD_ID
```

The result includes the output path, converted/available/omitted counts, warnings and `variables`. The `har_flow` evidence record retains the input/output SHA-256 and the variable descriptors, not raw requests or responses. The original HAR is unchanged and remains private.

## Filling the template

Each descriptor identifies its generated variable, zero-based HAR entry, source pointer and required format. Variable numbering follows the selected capture; use the returned descriptors instead of guessing names.

| Format | Environment value |
| --- | --- |
| `http_url` | The complete original HTTP(S) URL, with its original escaping. |
| `text` | A complete header value or the indicated string/body value. |
| `json_text` | The complete JSON body text, preserving numeric credential types and complex structures. |
| `form_urlencoded` | Ordered URL-encoded form pairs. Preserve repeated names and encode values. |
| `cookie_header` | The complete explicit Cookie header, assembled from the captured cookie entries. |

Pointers such as `/log/entries/0/request/headers/0/value` address the HAR document. A pointer containing `#`, such as `/log/entries/0/request/postData/text#/login`, first decodes the JSON in `postData.text`, then follows the JSON Pointer after `#`. An empty suffix addresses the decoded JSON root.

Set the referenced variables in the invoking process's environment using your own trusted capture or fresh authorized values. FORGE does not print a credential-bearing `.env` file. Environment substitution is single-pass: inserted `${...}` text is not evaluated again.

Inspect and edit the generated array before running it:

```console
forge --project ./owned-target probe-run flows/from-capture.json --rules verified-body-rules.json
```

Missing environment variables fail before traffic. Rules must come from observed response semantics. Conversion does not invent classification rules, token selectors, TLS fingerprints, proxy configuration, client/egress identities or success claims.

## Token and cookie handoff

A captured Authorization or Cookie header becomes an environment placeholder, not an automatically refreshed login credential. To reproduce a fresh session:

1. Add an `extract` selector to the observed login response, using its actual JSON field/header.
2. Replace the dependent header value with the appropriate `${flow.NAME}` expression.
3. Remove a captured Cookie header if the dependent request should use the cookie jar created by the preceding login.

See [HTTP flows](http-flows.md) for explicit extraction. No response-to-request token binding is inferred from a coincidental matching string.

## Preserved and omitted data

Captured request order and method are retained. Whole URLs are parameterized, including paths, queries and hostnames, so opaque URL credentials are not copied into templates and escaping is not changed. Header names and JSON field names remain editable. Nonempty JSON string values become separate placeholders; booleans, nulls and empty strings remain structural constants. Bodies containing numeric values, non-string sensitive fields or shapes exceeding field/depth limits use a whole-body variable to preserve types without exporting numeric credentials.

Host, Content-Length, Connection, Transfer-Encoding, Accept-Encoding, Proxy-Connection and recognized HTTP/2 pseudo-headers are omitted with warnings; the transport must construct them for the actual request. All other nonempty header values require environment input. Raw non-JSON text bodies use a whole-body variable. Params-only URL-encoded forms use a whole form-body variable, preserving the possibility of duplicate fields rather than collapsing them into a dictionary.

Structured JSON is reserialized by `probe-run`; whitespace/escaping can differ from captured bytes. Request signatures or content hashes must be reconstructed using the real client's protocol, not reused blindly. The current HTTP body API sends UTF-8 text. Review captured content encodings/charsets before replay; compressed or non-UTF-8 wire bodies are not guaranteed equivalent by this template conversion.

## Errors and bounds

- `--limit`: 1..1000 entries, default 50. Only the selected prefix is converted; omitted entries are counted.
- `--max-input-bytes`: 1..134217728, default 16777216. Oversized files are rejected before JSON parsing.
- Input must be a regular file, not a direct symlink or pipe. Output must be a new safe project path; traversal, secret/dependency paths and reparse/symlink output paths are rejected.
- Invalid selected entries, duplicate request headers, URL userinfo, malformed/incomplete JSON, multipart/file bodies and encoded/binary request bodies fail before a template or evidence record is published.

Raw captures can contain credentials. Templates retain field/header names and structural constants and still need review before publication. This is a request-template conversion, not evidence that a vendor accepts the requests or that the capture can be replayed byte-for-byte. Run the explicit positive/negative protocol controls and the actual target implementation separately.
