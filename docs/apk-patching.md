# APK decoding, rebuilding and signing

These commands cover the authorized patch loop around an APK you own: decode it, read the
declared surface, rebuild it, sign it, then install the result on a device you are allowed to
use. They do not download anything, do not invent a signing identity silently, and never
overwrite an existing output path.

```console
forge apk-decode client.apk --output decoded
forge apk-manifest decoded
forge apk-manifest client.apk
forge apk-rebuild decoded --output rebuilt.apk
forge apk-sign rebuilt.apk --output signed.apk --debug-keystore
forge adb install --serial OWNED_SERIAL --path signed.apk
```

## Tools

| Tool | Override | Portable path | Used for |
|---|---|---|---|
| apktool | `FORGE_APKTOOL` | `tools/apktool/apktool.bat` or `tools/apktool/apktool` | decode and rebuild |
| apksigner | `FORGE_APKSIGNER` | `tools/build-tools/apksigner.bat` or `tools/build-tools/apksigner` | sign and verify |
| zipalign | `FORGE_ZIPALIGN` | `tools/build-tools/zipalign.exe` or `tools/build-tools/zipalign` | alignment before signing |
| Java | `FORGE_JAVA` | `java` on `PATH` | runs apktool and keytool |

The two signature tools are also found inside a caller-configured Android SDK: when
`ANDROID_HOME` or `ANDROID_SDK_ROOT` points at an SDK, FORGE selects the newest numeric
`build-tools/*/` directory that contains the requested launcher. An explicit but broken
override still fails rather than falling back. `doctor` reports which source won.

## `apk-decode`

Runs `apktool d --force -o OUTPUT INPUT` into a new project-local directory. `--no-sources`
skips dex disassembly and `--no-resources` skips resource decoding. The command only reports
success when apktool exited zero **and** the decoded `AndroidManifest.xml` exists, so a
half-written output directory is never reported as usable.

Decoding does not rebuild, sign or install anything, and a decoded tree is not proof that the
original APK behaves as the decoded sources suggest.

## `apk-manifest`

Summarizes what the manifest *declares*: package, launcher activity, permissions,
`uses-feature` entries, components (activity, activity-alias, service, receiver, provider) with
their `android:exported` value, intent-filter actions/categories, data schemes and hosts, and a
deeplink list. Components whose intent filter has no explicit `android:exported` declaration are
flagged, because that combination is exactly what fails on modern Android.

`PATH` may be a decoded directory, a decoded `AndroidManifest.xml`, or a raw `.apk`. For a raw
APK only the literal values readable by the bounded compiled-manifest parser are shown; decode
the APK to see permissions, components and intent filters. Component retention is capped at 500
with `components_omitted` reported.

A declared component, permission or deeplink is a declaration, not a reachable or exploitable
path. Exported is not the same as unauthenticated: a component can require a `permission`, and
the platform can still refuse the call.

## `apk-rebuild`

Runs `apktool b DECODED_DIR -o OUTPUT` and only publishes when apktool exited zero and produced
a file. `--use-aapt2` and `--debug` are passed through when you ask for them. The rebuilt bytes
are unsigned: they are not installable until `apk-sign` succeeds for that exact file.

## `apk-sign`

Runs `zipalign -f -p 4`, then `apksigner sign`, then `apksigner verify --verbose --print-certs`.
A signature that does not verify aborts the command and no output file is published.

Two identity modes:

- `--keystore PATH --alias NAME` with `--store-pass-env` (default `FORGE_KEYSTORE_PASS`) and
  `--key-pass-env` (default `FORGE_KEY_PASS`). An empty or unset password variable is a hard
  error. Passwords are passed to the tool as `pass:` arguments and are never written to
  evidence.
- `--debug-keystore` creates a throwaway local key for this run only and deletes it afterwards.
  The evidence row records `debug_identity: true`.

A debug identity is not a release identity. Signing proves possession of that key for those
bytes only; it says nothing about who published the original APK, and two APKs can only be
installed together as one split set when they share a signing certificate. That is why signing
a base and its config splits in separate `--debug-keystore` runs produces a set Android rejects
with `signatures are inconsistent` — use one explicit keystore for the whole set.

## Verifying the loop on real hardware

A complete check on an authorized device is: decode, rebuild, sign, install with
`adb install` (single APK) or `adb-install-splits` (base plus splits), confirm the package with
`adb package --package PACKAGE`, then remove it. `apk-sign` output is only proven installable
when the device actually accepted it; `apksigner verify` proves the signature, not the install.
