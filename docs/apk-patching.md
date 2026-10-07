# APK decoding, rebuilding, signing and Gadget repackaging

These commands cover the authorized patch loop around an APK you own: decode it, read the
declared surface, rebuild it, sign it, repackage it with a Frida Gadget for a device without
root, then install the result on a device you are allowed to use. They do not download
anything, do not invent a signing identity silently, and never overwrite an existing output
path.

```console
forge apk-decode client.apk --output decoded
forge apk-manifest decoded
forge apk-manifest client.apk
forge apk-rebuild decoded --output rebuilt.apk
forge apk-sign rebuilt.apk --output signed.apk --debug-keystore
forge apk-gadget client.apk --gadget frida-gadget-17.22.1-android-arm64.so --output gadget.apk
forge apk-sign gadget.apk --output gadget-signed.apk --debug-keystore
forge adb install --serial OWNED_SERIAL --path gadget-signed.apk
```

## Tools

| Tool | Override | Portable path | Used for |
|---|---|---|---|
| apktool | `FORGE_APKTOOL` | `tools/apktool/apktool.bat` or `tools/apktool/apktool` | decode and rebuild |
| apksigner | `FORGE_APKSIGNER` | `tools/build-tools/apksigner.bat` or `tools/build-tools/apksigner` | sign and verify |
| zipalign | `FORGE_ZIPALIGN` | `tools/build-tools/zipalign.exe` or `tools/build-tools/zipalign` | alignment before signing |
| Java | `FORGE_JAVA` | `java` on `PATH` | runs apktool and keytool |
| frida-apk | `FORGE_FRIDA_APK` | `tools/frida/Scripts/frida-apk.exe` or `tools/frida/bin/frida-apk` | inject a Gadget into an APK |

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

## `apk-gadget`

Runs `frida-apk -g GADGET -o OUTPUT INPUT`. That upstream tool is what a Frida hook needs on a
device without root: `frida-server` requires root, and a Gadget is a shared library that the app
loads itself. FORGE adds validation around it:

- The Gadget must be one project-local ELF shared object. FORGE reads `e_machine` and `e_class`
  from its header, refuses an executable (`ET_EXEC`) or an unknown machine, and reports the
  Android ABI and bitness it found. Nothing is guessed from the file name.
- After the run, FORGE opens the produced archive and requires
  `lib/<abi>/libfridagadget.so`, `lib/<abi>/wrap.sh`, `lib/<abi>/libfridagadget.config.so` and
  `AndroidManifest.xml`. It hashes the embedded Gadget and requires it to equal the supplied
  file, and it compares the package name before and after. A mismatch fails the command and the
  failed run is recorded with its reason instead of a published APK.
- `--gadget-config KEY=VALUE` is repeatable. Keys are recorded in evidence; values are not,
  because a value can carry a host, port or token that belongs in the APK only.

What the repackaged build actually is, so nothing is mistaken for the original app:

- `frida-apk` inserts `android:debuggable="true"` on `<application>` and adds the three
  `lib/<abi>/` members above. `wrap.sh` is an `LD_PRELOAD` wrapper, and the platform only
  honours it for a debuggable app, which is why the flag is forced.
- The injected manifest invalidates the original signature. The output is unsigned: sign it with
  `apk-sign` before installing.
- The default Gadget interaction is `type: listen, on_load: wait`, so the app blocks at launch
  until a Frida client connects. Pass `--gadget-config on_load=resume` to keep it starting
  normally.
- Installing over an existing copy of the same package fails, because the signing certificate
  changed. Removing the installed app first deletes that app's data.
- `debuggable` and a non-original signature are both visible to the app. Integrity, tamper and
  anti-fraud checks may refuse, hang or answer differently, and any value the app derives from
  its own signature or install source can differ from the official build. Treat hook output from
  a repackaged build as evidence about a modified build. When an app carries such checks, the
  honest routes are a rooted test device, a desktop or web client of the same service, or static
  analysis of the original artifact.
- Split apps: injecting the base APK places the Gadget in the base's `lib/<abi>/`, while the
  ABI split holds the app's own native libraries. Whether the merged install loads it is a
  device fact, not something this command proves.

The Gadget itself is not downloaded. Use `artifact-fetch` with the official Frida release URL
and the published SHA-256, then decompress the `.so.xz`; the Gadget must match the Frida version
you will connect with and the device ABI.

```console
forge --project investigation artifact-fetch https://github.com/frida/frida/releases/download/17.22.1/frida-gadget-17.22.1-android-arm64.so.xz --sha256 <published-sha256> --version 17.22.1
forge --project investigation apk-gadget client.apk --gadget frida-gadget-17.22.1-android-arm64.so --output gadget.apk
forge --project investigation apk-sign gadget.apk --output gadget-signed.apk --debug-keystore
forge --project investigation adb install --serial OWNED_SERIAL --path gadget-signed.apk
```

The Gadget is only proven working when a device accepted the signed APK and a Frida client
actually attached to it. Nothing up to that point demonstrates the hook ran.

## Verifying the loop on real hardware

A complete check on an authorized device is: decode, rebuild, sign, install with
`adb install` (single APK) or `adb-install-splits` (base plus splits), confirm the package with
`adb package --package PACKAGE`, then remove it. `apk-sign` output is only proven installable
when the device actually accepted it; `apksigner verify` proves the signature, not the install.
