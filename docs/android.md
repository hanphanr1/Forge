# Android preflight, installed APK pull, observation and split installation

FORGE uses the configured ADB executable: `FORGE_ADB`, the bundled platform-tools directory, or PATH, in that order. An invalid explicit override does not fall back. These commands do not download an SDK, alter device security, root a device, or configure Frida.

## Observe the host and device

```console
forge adb-preflight
forge adb-preflight --serial OWNED_DEVICE_SERIAL
```

Preflight runs actual `adb version`, `adb devices -l`, and selected-device `shell getprop` calls. Without `--serial`, exactly one authorized device is selected, even if other devices are offline or unauthorized. Multiple authorized devices require explicit selection. Explicit serials must appear in the observed listing as authorized.

The `runtime` evidence uses schema `forge.android.v1`. Its `status` distinguishes `authorized`, `absent`, `unauthorized`, `offline`, `multiple`, `missing-tool`, `adb-failed`, and `incomplete-device-facts`; other states reported by ADB remain visible rather than being relabeled. `success` means that an authorized device exposed an OS release, numeric API, and ABI list. Inspect the evidence fields, not just the CLI exit status: preflight returns an evidence record even when a prerequisite is absent.

Device facts come from `ro.build.version.release`, `ro.build.version.sdk`, and `ro.product.cpu.abilist`. If the ABI-list property is empty, FORGE uses the actual `ro.product.cpu.abi` and `ro.product.cpu.abi2` values. Property call exits, bodies, and errors are retained. Preflight is **not** installation, application-launch, root, certificate, or injection proof.

## Discover, pull and triage before installing anything

```console
forge apk-info ./owned/base.apk ./owned/config.arm64_v8a.apk
forge apk-info --archive ./owned/application.xapk --member base.apk --member config.arm64_v8a.apk
forge adb packages --third-party --filter "<observed-name-part>"
forge adb package --serial OWNED_DEVICE_SERIAL --package com.example.app
forge adb pull --serial OWNED_DEVICE_SERIAL --remote /data/local/tmp/sample.bin --path sample.bin
forge adb push --serial OWNED_DEVICE_SERIAL --path ./hook.js --remote /data/local/tmp/hook.js
```

`apk-info` is a read-only metadata command. It reads compiled manifests from explicit APK paths or exact archive members and reports package, split name, combined version code, literal `minSdkVersion`, declared split dependencies/types and observed native ABIs. It does not install, unpack, or verify signatures. Add `--validate-selection` only when you also want the set judged as one installable split selection.

`adb package` reports the observed `pm path` entries plus `versionName`, `versionCode`, `primaryCpuAbi` and `splitNames` parsed from `dumpsys package`. `dumpsys` output is a claimed system fact, not an independent verification, and retained detail is capped by `--max-output`.

`adb pull` copies exactly one absolute device file into the project. The destination must be a new project-local path: existing files, traversal, and symlinked parent directories are rejected, and directories on the device are not copied. Retained bytes are capped by `--max-bytes` (default 256 MiB); an over-cap or failed pull leaves no partial file. `adb push` copies one regular project file to an absolute device path. Both actions are for artifacts you own or are authorized to handle.

`adb ui-tree` wakes the screen and retries once. `uiautomator` still needs a quiescent foreground window, so an animated or locked screen can fail with an explicit `could not get idle state` error; unlock the device or stop animations and retry.


## Android Lab for an installed app

Start from the build on the device, not a guessed APK download. `adb pull-package` reads every path
returned by `pm path`, copies the base and splits to a new project directory, hashes each file, and
records package/version/split metadata. The pull is read-only. A hash identifies the bytes copied
from the device; it does not authenticate the publisher.

To find API strings without indexing archive resources first, run `artifact-index` on the pulled
base APK with `--dex`, then `search` the returned index. The index keeps each DEX member and byte
offset. When JADX output exists, `android-api-map` links those candidates to source literal
occurrences, class/line/hash citations and bounded same-file Java traces. It does not prove dispatch.

```console
mkdir installed
forge adb pull-package --serial OWNED_DEVICE_SERIAL --package com.example.app --path installed/example
forge artifact-index installed/example/base.apk --dex --max-records 500000 --max-index-bytes 268435456
forge search "/api/" "<returned-index-path>" --max-records 500000
forge android-api-map --index-evidence "<dex-index-id>" --jadx-evidence "<jadx-evidence-id>" --class-filter "<observed-class>"
forge adb launch --serial OWNED_DEVICE_SERIAL --package com.example.app --component com.example.app/.MainActivity
forge adb observe --serial OWNED_DEVICE_SERIAL --package com.example.app --seconds 90 --lines 3000 --ui-snapshots
```

Open the app before `adb observe`, or launch it first with the manifest component shown above.
While the command waits, perform one action in the app. FORGE does not clear logcat or restart the
app. It samples the app's process IDs before and after the window, reads the device log buffer at
the end, and keeps rows for those PIDs whose epoch timestamps fall inside the window. `--lines`
limits recent rows per session and is divided across the sampled PIDs; older rows may have rolled
out of the device buffer or fallen past that cap. A process that starts and exits between the two
PID samples can be missed. `--ui-snapshots` is opt-in; UI trees can contain private screen text and
stay in the local evidence store. Logcat redaction is best-effort.

`adb observe` records process logs, not HTTP traffic. To learn API requests, capture traffic with an
authorized tool, export a HAR to the project, and run `har-import`. A capture tool running on the
same host can instead POST the HAR to the loopback-only `capture-ingest` listener. Then use
`api-shape` and `protocol-map` to inspect captured names and citations. ADB observation does not
decrypt TLS, install a trust certificate, bypass certificate pinning, or prove that an endpoint
belongs to the app. Unmatched or unobserved fields remain unknown.

### Follow a Java literal without a device

The same `android-api-map` command now emits `source_traces`. For a literal passed as the entire
argument of an unqualified `new ClassName(...)`, it can link that argument to a unique same-arity
constructor parameter, a direct `this.field = parameter` assignment, and field reads in the same
class. Direct String field initializers and literals in methods are also traced.

Each trace root carries its source path/hash and literal line/column. Method and assignment lines
let the agent open the cited source instead of searching the entire tree again. `callers` means
one-hop reverse name matches in that class; overload counts remain explicit. Request markers
describe lexical co-occurrence in a method, not that the URL reaches a network client.

The parser excludes nested/local/anonymous class bodies from outer-class attribution and only
traces the first top-level Java type. It is not a Java compiler, type resolver or inter-file
callgraph. Kotlin/smali and malformed source remain literal citations with unsupported traces.
`--max-trace-items` caps all retained trace objects across files; inspect `trace_truncated` and
`trace_items_omitted` before interpreting an empty result. This step requires neither root nor
Frida and makes no device changes.

## Capture the app's own traffic without root

`adb observe` reads logcat, not HTTP. To get real host evidence from an unrooted device, use the installed
PCAPdroid app through its documented Intent API:

```console
forge pcapdroid-preflight --serial OWNED_DEVICE_SERIAL --package com.example.app
forge pcapdroid-capture --serial OWNED_DEVICE_SERIAL --package com.example.app --path captures/run.pcap --seconds 20
forge pcap-analyze captures/run.pcap --capture-evidence "<capture-id>" --map-evidence "<api-map-id>"
```

`pcapdroid-capture` prints a ready line once the scoped `CaptureService` is running and the generated dump
file exists (it may still be 0 bytes), then waits out the bounded window while the operator performs one named
action. The app may ask for consent on start and stop; a prompt left open is reported as a blocker, not retried.
If a device step is blocked, tell the operator the exact observed status and the one to three things to do
(data-capable cable, USB debugging, accept the RSA prompt, unlock the screen, launch the app, approve the
PCAPdroid prompt) and retry after they confirm; a locked screen or an empty device listing is a request for
help, not a reason to drop the runtime step or to substitute an emulator.
Root capture, TLS decryption, SOCKS5, PCAPNG, private-DNS blocking and remote exporters are all sent as off.
`success` requires an observed service, the generated dump name, an observed stop and a hash-verified retrieval.

`pcap-analyze` then reports DNS names, TLS ClientHello SNI, plaintext HTTP `Host`, per-direction flows and the
optional PCAPdroid trailer UID/app-name claims. It never retains or prints payload, request targets, headers or
bodies, and it never decrypts. With `--capture-evidence` it checks the cited capture hash/size/path and splits
observations and packets by the trailer UID claim, so packets without a claim stay `unknown` instead of being
credited to the target. With `--map-evidence` it re-hashes the cited static index and lists exact hostname
matches: that ties an APK URL candidate to an observed host, and still does not prove a path, method, body or
authenticated call. A zero-length or headerless dump is a start observation, never traffic or success.

The raw PCAP stays local and may contain private data. This path needs no root, no certificate install, no
pinning bypass, no app re-signing and no emulator.

### Opt-in decryption and scripted windows

`pcapdroid-capture --tls-decryption` asks PCAPdroid for its own decryption mode scoped to the target app
(`decryption_rules` APP rule, `block_quic to_decrypt`). FORGE installs no CA, adds no trust anchor and edits no
app preference: without the operator-installed PCAPdroid CA, without app trust, or with certificate pinning the
flows stay encrypted. The request is recorded (`decryption_requested`, `operator_approved_tls_decryption`,
`decryption_scope`) and never claimed as performed; `pcap-analyze` computes `decryption_performed` from the
cited request plus decoded request lines, so a still-encrypted capture stays honestly `false`.

`--repeat N --gap SECONDS [--launch PACKAGE/ACTIVITY] [--force-stop]` runs several bounded windows in one
session: per window a scoped service precheck, a unique dump, optional `am force-stop` + `am start -W -n`, the
bounded window, an observed stop and a hash-verified pull to `window-NN.pcap` in an existing project directory.
Each window gets its own evidence record, and one `capture-session` record lists every window, failure and the
post-session service observation. A window failure stops further windows while completed files and records stay
intact; `--continue-on-error` keeps later windows running instead, with the session still reporting
`success: false`. `pcapdroid-preflight` observes the PCAPdroid MITM addon (`com.pcapdroid.mitm`) as its own
scoped fact, and `--tls-decryption` refuses with `mitm-addon-absent` before any Intent is sent when that addon
is missing — on hardware the missing app otherwise looks like a consent timeout that never resolves.

### Cross-file caller candidates

`android-caller-map --jadx-evidence ID --method NAME [--class OWNER] [--path-filter SUBSTRING]` answers "who
calls this method name
anywhere in the tree": bare calls list possible owner classes from that file's imports and same-package classes,
receivers are classified (`this`, owner class, named, expression, constructor), declarations and annotations are
skipped, and `--class` keeps only candidates attributable to one owner. These are name candidates, not a
resolved call graph: overloads, inheritance, reflection and generated call sites are not resolved, and caps are
reported. On the 23,387-file Grok tree, `--method a --class e5.c --max-files 5000` scanned 5,000 files in 58
seconds and kept 39 bare + 11 owner-class candidates, with `truncated: true` because the file cap stopped the
walk — raise the caps before treating absence as evidence. `--path-filter` (repeatable) scopes the walk to a
path/class substring and is recorded in the evidence, so following one package no longer tokenizes the whole
tree.

## Install a selected APK set

Use only APKs you own or are authorized to install on the selected device. The package must not already be installed under this command's new-install policy.

```console
forge adb-install-splits --serial OWNED_DEVICE_SERIAL --apk ./owned/base.apk --apk ./owned/config.arm64_v8a.apk --apk ./owned/config.en.apk
forge adb-install-splits --serial OWNED_DEVICE_SERIAL --archive ./owned/application.apks --member selected/base.apk --member selected/config.arm64_v8a.apk
forge adb-install-splits --serial OWNED_DEVICE_SERIAL --archive ./owned/application.xapk --member base.apk --member config.en.apk
```

`--apk` and `--member` are repeatable and preserve the supplied order. Choose either explicit APK paths or one APKS/XAPK archive. Archives require exact APK member names; FORGE does not guess ABI, density, language, feature, or universal variants from filenames or bundle metadata. XAPK OBB files and APKS device specifications are not installed or interpreted. A single base APK is also accepted using one `--apk`.

All selected APKs are copied into an owned temporary directory before inspection and dispatch. Original files remain unchanged. An archive is first copied into that directory, then only explicitly selected APK members are extracted into generated filenames. The temporary directory is removed on success, rejection, timeout, or installer failure. Abrupt host termination can prevent normal cleanup.

Validation happens before any installation command:

- Inputs must be explicit regular files, without symlink/reparse components. Windows device, UNC, alternate-stream, and drive-relative paths are rejected. Relative paths are interpreted against the FORGE project directory.
- Every ZIP member name, including unselected members, must be a contained canonical POSIX name without traversal, absolute paths, backslashes, drive/stream colons, or control characters. Duplicate names are rejected case-insensitively. Encrypted, symlink, reparse, special-file, multi-disk, and unsupported-compression entries are rejected.
- A bounded parser reads actual compiled Android binary XML, including UTF-8/UTF-16 string pools and typed values; ordinary XML is also supported. The parser does not substitute raw spellings for unresolved resource references. A resource-dependent package, version, SDK, or dependency value is a missing metadata precondition, not a successful inspection.
- Every APK must have the same package and combined `versionCodeMajor`/`versionCode`, unique split names, and exactly one base. Absent or empty `split` denotes the base. Absent `versionCodeMajor` contributes zero to the combined version. Declared `uses-split`, `configForSplit`, `isSplitRequired`, and `requiredSplitTypes` requirements are checked against the selected set. Split types are read from the selected manifests, not invented from member names.
- The base must declare a literal numeric `minSdkVersion`. FORGE deliberately rejects a missing base SDK value rather than substituting Android's default. A split without its own SDK declaration is checked against the base's requirement. Preview codenames and resource references are not resolved; provide an APK with inspectable compiled literal metadata instead.
- The selected device is independently preflighted. Each selected APK's declared SDK must fit the observed API. Split installation also requires API 21 or later. Native ABIs are observed from `lib/ABI/*.so` entries; each APK containing native libraries must intersect the observed device ABI list. No ABI claim is made for an APK without those entries.

FORGE dispatches `adb -s SERIAL install-multiple PATH...` for multiple APKs and `adb -s SERIAL install PATH` for one base. Neither includes `-r`, `-d`, `-g`, replacement, downgrade, permission-grant, uninstall, root, unlock, certificate, or profile operations. There is no update-policy override in these commands. The older `adb install` command belongs to the existing runtime interface and is unchanged; its behavior is not this command's policy.

`--timeout` defaults to 120 seconds and must be greater than zero and at most 3600. A timeout is recorded as failure; it does not prove that Android rolled back an in-progress install. ADB may start its normal host server during discovery. Device-side installer validation remains authoritative for signatures, required shared libraries/features, resources, storage, and other constraints not established by these lightweight facts. FORGE does not claim to validate APK signatures or to prove application functionality.

## Bounds and evidence

Fixed limits apply before installation:

| Item | Limit |
| --- | --- |
| Explicit files or archive input, and total selected APK bytes | 512 MiB |
| APK selection | 128 APKs |
| Entries per ZIP | 4,096 |
| Central directory | 8 MiB |
| Total declared uncompressed bytes per ZIP | 1 GiB |
| One ZIP member | 512 MiB |
| Member compression ratio | 200:1 |
| Manifest | 4 MiB |
| Binary XML strings | 65,536 |
| Manifest element nesting | 128 |
| Retained stdout/stderr per process | 256 KiB per stream |

ZIP64 and compression methods other than stored/deflated are unsupported. Limits apply to all declared entries, not only selected members. Unselected data is not decompressed. APK central directories and selected manifest reads are bounded as well as the outer archive. These limits may reject legitimate very large or highly compressible packages; rejection does not label the source malicious.

Install evidence records source paths, exact archive member selections, selected APK SHA-256 hashes and sizes, archive SHA-256 where applicable, parsed manifest metadata, actual device facts, ADB version output, preflight evidence ID, installer action, and actual installer exit/stdout/stderr/error/timeout. Output beyond the retained stream cap has an explicit omitted-byte count. Evidence passes through the existing secret sanitization and remains append-only. Validation or prerequisite failures also create rejection evidence; they are not successful installation records.

An installer exit of zero is not accepted as success when its retained body reports `Failure`/`Error` or either output stream was truncated. Truncation leaves the actual installation outcome unproven rather than triggering another install.

No connected authorized compatible device means installation cannot be demonstrated. A real runtime check additionally needs an explicitly supplied owned APK set with inspectable metadata and an acceptable new-install package. Deterministic fixture tests exercise parser, selection, compatibility, cleanup, and dispatch decisions; patched backend results in those tests are **not device-installation proof**.

Manifest attribute handling follows Android's [ApkLiteParseUtils](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/content/pm/parsing/ApkLiteParseUtils.java). FORGE's parser is a bounded metadata reader, not Android's full package/resource parser.

To change an APK and run the result on the device instead of only reading it, continue with the [APK patching](apk-patching.md) loop: `apk-decode`, `apk-manifest`, `apk-rebuild`, `apk-sign`, then `adb install` or `adb-install-splits`. A rebuilt APK is not installable until signing verifies, and a base plus its config splits must share one signing certificate.

### Declaring the install source

`--installer PACKAGE` passes `adb install -i PACKAGE` and records `declared_installer` in evidence. Some apps refuse to run unless their recorded install source is the store, which is a check on the install source rather than on the byte signature. Declaring `com.android.vending` satisfies that check; it does not defeat a real signature or Play Integrity verification, and the record's policy text says the flag only declared the source. A locked device with no `su` and no `adb root` cannot run `frida-server`, so the only Frida transport there is a Gadget repackage installed this way; see [hooking a device without root](apk-patching.md#hooking-a-device-without-root).
