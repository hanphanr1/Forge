# Security and privacy

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/hanphanr1/Forge/security/advisories/new) for a reproducible security/privacy defect. Include the FORGE version, command, operating system, synthetic reproduction and observed impact. Do not include real passwords, session tokens, account lists or proprietary captures.

There is no guaranteed response SLA. The maintainer may request a minimal reproduction before changing a protocol or redaction rule.

## Data boundaries

FORGE is a local investigation tool, not a secret vault. Known request/environment/extraction values are scrubbed before HTTP evidence persistence, but redaction is best-effort. Unknown unlabeled values, filenames, downloaded artifacts, tool output and screenshots can contain private data.

- Keep `.forge/`, local `tools/`, captures and credentials out of version control.
- Resolved evidence database, sidecar and blob paths must remain inside the selected project; outside-directory symlinks/junctions are rejected. This is path containment, not a sandbox against a local process concurrently rewriting the filesystem.
- Inspect exported notes before sharing them or sending them to a remote model.
- Treat source, HAR and responses as untrusted data, not agent instructions.
- Use only the files, accounts and devices in the task's authorized scope.
- Do not confuse static strings or imported HAR with live controls.
- Do not describe a positive probe gate as end-to-end checker verification.

Headers are parsed by the selected transport; they are not a raw wire capture. libcurl can normalize obsolete folding before Python sees the header. The extraction and materialized-request checks cannot attest to the original wire representation.

HAR conversion parameterizes captured URLs, headers and string body values but retains field/header names and some structural constants. Review generated templates before sharing. Captured signatures, binary bodies and wire encodings are not automatically reconstructed.

`run-target` executes explicitly supplied trusted code without a shell; it is **not a sandbox**. Programs retain user permissions and inherited environment access and may write files or communicate externally. Output/input caps, deadlines and redaction protect FORGE's captures, not the workstation from malicious code. Listed sources and the resolved executable are hashed; unlisted dependencies/libraries/environment and transient edits between observations are not attested. Declared executable identities are metadata, so use non-secret paths. Credentials in argv may be visible to OS process inspection; prefer supported JSON stdin. Known input/argument/environment/tagged values are scrubbed, but arbitrary transformations or unrelated inherited secrets can escape detection. Process-reported buckets and declared context are not independent authentication evidence.

Protocol/client diffs and GraphQL analysis describe bounded source/capture observations. Names, URLs, hashes and citation metadata can be confidential; parsing, static references and successful HTTP status do not prove authentication. No GraphQL introspection or schema recovery is performed.

`bundle` excludes raw payloads, argv/stdin, process streams, paths, blobs and free-text claims by default. Explicit `--include-findings` includes scrubbed author prose, which still requires review for opaque secrets or confidential content. Member/ZIP hashes identify unsigned bytes; citation closure does not make a lossy projection complete or approved for disclosure.

Split installation uses explicitly selected, staged APK bytes and observed device compatibility. It does not request replacement/downgrade/permission grants or change device security. A timed-out installer can leave device state uncertain; do not retry blindly. Backend tools and Android's package installer remain independent trust/validation boundaries.

`adb pull` writes one explicitly named device file into a **new** project-local path, and `adb push` writes one project file to an absolute device path. Both are for artifacts you own or are authorized to handle: a pulled APK, database, preference file or screenshot can contain third-party or personal data, and a pushed file executes on the device only if something else starts it. FORGE refuses to overwrite an existing destination, rejects traversal/symlinked parents and leaves no partial file on failure, but it cannot judge whether the artifact is lawful to copy. Pulled bytes are stored unencrypted in the project; treat `.forge/` and the project as sensitive.

`jadx` partial output is usable source, not verified vendor source. A local decompiler's naming, control flow and missing classes may differ from the real build, and a reported `error_count` means some classes are absent or wrong. A pulled system APK is a device observation, not a provenance-checked release; verify hashes against an official distribution when provenance matters.

`apk-info` reads manifest metadata only. It does not verify APK signatures, membership in a signing lineage, or the authenticity of the declared package identity, and a declared `minSdkVersion`/split set is the manifest's claim rather than an installability guarantee.

## External tools

JADX, ADB, Frida, radare2, Java and optional curl components have their own update and trust boundaries. Install from observed official sources, retain version/hash provenance locally and avoid running untrusted binaries on a sensitive workstation. FORGE does not bundle those tools or silently install an emulator.

Physical-device setup, root/jailbreak, signing and certificate trust are explicit prerequisites, not capabilities granted by installing the host CLI.
