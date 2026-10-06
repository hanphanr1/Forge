# Android preflight and explicit split installation

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
