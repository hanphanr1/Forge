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

`run-target` executes explicitly supplied trusted code without a shell; it is **not a sandbox**. Programs retain user permissions and inherited environment access and may write files or communicate externally. The output cap/deadline and redaction protect FORGE's captures, not the workstation from malicious code. Only listed sources are hashed; unlisted dependencies, interpreters and transient edits between hashes are not attested. Environment/argument/tagged values are scrubbed where known, but arbitrary transformations or unrelated inherited secrets can escape detection. Process-reported buckets and declared client/egress context are not independent authentication evidence.

## External tools

JADX, ADB, Frida, radare2, Java and optional curl components have their own update and trust boundaries. Install from observed official sources, retain version/hash provenance locally and avoid running untrusted binaries on a sensitive workstation. FORGE does not bundle those tools or silently install an emulator.

Physical-device setup, root/jailbreak, signing and certificate trust are explicit prerequisites, not capabilities granted by installing the host CLI.
