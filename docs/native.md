# Native disassembly and call references

FORGE uses the installed radare2 selected by `forge_toolchain.executable("r2")`. It does not download a tool, execute the input binary, or provide a decompiler.

```console
forge native disasm owned/program.exe --max-items 100 --max-output 1048576
forge native xrefs owned/program.exe --address 0x401000
forge native callgraph owned/program.exe --max-items 1000
```

Inputs must be explicit regular files inside the project. The existing source-file policy rejects traversal, symlinks, Windows reparse points, credential/data/dependency paths, secret-file suffixes and alternate data streams. An absolute path is allowed only inside the project. FORGE opens files for hashing read-only, and starts radare2 without write mode or user startup scripts. This is not a sandbox for a compromised backend. Use disposable copies of binaries you own or are authorized to inspect.

## Actions and addresses

- `disasm`: runs `aaa;pdj N @ ADDRESS` and retains observed instruction offsets, sizes, opcode text and supported backend bytes/type/mnemonic/jump/fail fields. `N` is `--max-items`. The output is a linear instruction window, not a reconstruction of source code or a function boundary.
- `xrefs`: runs `aaa;axtj @ ADDRESS` for incoming references and `aaa;axfj @ ADDRESS` for outgoing references. Each retained reference records its direction and backend type. If the backend omits the queried endpoint, it is supplied from the query address and labeled `endpoint_from_query`; the other endpoint must appear in backend output.
- `callgraph`: without an address, runs `aaa;axlj` and keeps only references whose observed type is `CALL`. With an address, uses `aaa;axfj @ ADDRESS` for outgoing call references at that address. It also queries `aaa;aflj` for observed function offsets/sizes/names, then collects `afbj @ FUNCTION_OFFSET` basic blocks in a single bounded `aaa;afbj ...;afbj ...` invocation. Function membership uses these observed basic-block intervals, not guessed function names or contiguous function-size ranges. Exact observed function-entry targets resolve directly; other targets use collected blocks. Missing or overlapping memberships remain explicitly unresolved or ambiguous.

Addresses accept decimal digits or `0x` hexadecimal digits, including zero, up to an unsigned 64-bit value. Symbol names, expressions and radare2 commands are rejected. If `disasm` or `xrefs` has no address, FORGE queries `iej` and selects the first observed `vaddr`. No entrypoint means a clear failure requesting an explicit address. `callgraph` without an address examines global backend call references instead.

radare2 6.2.2 uses `addr` for instruction/function addresses and for targets in the global `axlj` listing. FORGE normalizes these observed fields to evidence `offset`/`to`, retaining `backend_address_field`/`backend_target_field` provenance. Legacy `offset`/`to` fields remain accepted; conflicting or invalid address fields fail. `axj` is not the global JSON listing command in this version.

## Bounds and evidence

`--timeout` must be finite, positive and at most 3600 seconds. It is a shared process budget for the version query, optional entrypoint query and analysis commands. Hashing is streamed and is outside that process budget. `--max-output` is a shared retained stdout/stderr byte budget from 1 to 16777216 bytes (default 1048576). The version command additionally has a 16384-byte capture ceiling. `--max-items` ranges from 1 to 100000 (default 1000), shared across retained result arrays. The capture helper drains output with bounded retained memory and terminates timed-out process trees; it does not impose an OS-level backend memory limit.

Each `analysis` evidence record uses schema `forge.native.v1` and includes:

- SHA-256, byte size and project-relative path before and after analysis, plus `binary_unchanged`;
- selected executable and version observed from an actual bounded `r2 -v` invocation;
- requested/selected addresses, entrypoint selection provenance, analysis commands and caps;
- process exit/timeout/error/duration, observed stdout/stderr byte counts, sanitized stderr, a bounded 4096-byte stdout diagnostic preview and SHA-256 of retained raw stdout;
- structured `instructions`, `xrefs`, `call_edges`, `function_nodes`, `function_blocks` and `function_edges`, success, errors and stated limitations.

Only whitelisted backend fields are retained. JSON must be UTF-8, arrays of objects, and contain no duplicate keys or nonfinite numbers. The basic-block batch must return exactly one sequential JSON array per command with only whitespace between documents. Malformed schemas, failed processes, timeouts and truncated capture produce failed evidence with an evidence ID, not invented or partially parsed instructions. Earlier successful observations may remain in a failed record. If input hashing fails after analysis or its hash/size changes, the record also fails.

`items_omitted` counts results discarded from completely captured JSON, not references the backend failed to discover. `items_limit_reached` signals saturation even when the number beyond a bounded disassembly request is unknown. Output truncation prevents treating a cut JSON document as complete. Full backend stdout is not stored separately; the bounded preview remains diagnostic only, and retained structured fields and diagnostics pass through the existing evidence sanitization. The stdout hash identifies captured bytes, not necessarily all emitted bytes when capture was truncated.

Callgraph reserves up to one quarter of the shared item budget each for function nodes and basic blocks, then splits the remaining budget between call-site observations and aggregated function edges. Function nodes follow capped backend `aflj` order. The single basic-block command batch is at most 12000 ASCII characters and queries no more functions than its block-item allocation; it does not start one analysis process per function. `block_functions_unqueried` counts observed functions whose blocks were not queried. Uncollected blocks and capped nodes can leave call membership unresolved even when the backend could have resolved it with more scope.

`function_nodes` retain observed `offset`, `size` and optional `name`; `function_blocks` retain owning `function`, block `address` and `size`. `call_edges` preserve observed instruction-site `from`/`to`/`type` plus nullable `caller_function`/`target_function` and their membership bases. `function_edges` aggregate those retained calls by resolved function endpoints, preserving `unresolved_callsite`/`unresolved_target` when an endpoint cannot resolve and counting `observed_calls`. Function edges are therefore supported by retained call-site evidence, not reconstructed names or inferred missing calls.

## Interpretation and verification

Disassembly and `aaa` analysis are architecture-dependent heuristics. Packed code, data interpreted as instructions, indirect calls, tail calls and runtime-generated code can make results incomplete or inaccurate. The callgraph is a static call-reference approximation, not proof of runtime reachability, authentication, or a complete function-level graph. Matching before/after hashes do not prove the file was unchanged at every instant between them.

`tests/test_native.py` includes preflight and schema/cap behavior tests with labeled subprocess fixtures, plus an installed-radare2 test that analyzes a disposable copy of the running Python executable and skips when radare2 is absent. Fixture tests are not runtime proof. Release verification should run the full suite after integration and exercise all three actions using the actual installed radare2 on an owned disposable binary, retaining the generated evidence records.
