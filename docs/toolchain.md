# Toolchain setup

Core artifact indexing, evidence, tasks and urllib probes require Python 3.10+ only. Install a runtime dependency when its command is needed. FORGE does not install system images, drivers, device servers or Java for you.

## Discovery order

1. Explicit environment override.
2. A known portable path under `tools/` beside the source modules.
3. The executable on `PATH`.

An explicit but broken override fails. It does not silently select a different tool/version. `forge --project target doctor` reports paths, availability and source. Presence is not a device or target-login smoke test.

| Tool | Override | Portable source-checkout path |
|---|---|---|
| ADB | `FORGE_ADB` | `tools/platform-tools/adb.exe` or `adb` |
| JADX | `FORGE_JADX` | `tools/jadx/bin/jadx.bat` or `jadx` |
| Frida | `FORGE_FRIDA` | `tools/frida/Scripts/frida.exe` or `tools/frida/bin/frida` |
| radare2 | `FORGE_R2` | `tools/radare2/bin/radare2.exe`, `r2.exe` or `r2` |
| Java | `FORGE_JAVA` | Explicit executable or `PATH` |

For wheel installations, use `PATH` or explicit executable overrides. The wheel does not bundle the portable `tools/` directory.

## Official sources

- [Android Platform Tools](https://developer.android.com/tools/releases/platform-tools).
- [JADX releases](https://github.com/skylot/jadx/releases), with the Java version required by that release.
- [Frida installation](https://frida.re/docs/installation/) and [Android setup](https://frida.re/docs/android/).
- [radare2 releases](https://github.com/radareorg/radare2/releases).

Keep publication URL, version, hash and applicable license in your own local installation records. A third-party mirror is not official merely because it hosts the same filename.

`FORGE_JAVA` chooses the Java executable/JAVA_HOME for the JADX subprocess, not a machine-wide setting. FORGE adds a 2 GiB Java heap cap unless `JAVA_OPTS` or `JADX_OPTS` already contains `-Xmx`. JADX defaults to two jobs. Heap cap is not total process memory.

## Android device handoff

1. Use a device available for the specific investigation. Name the app/package and capture before requesting connection.
2. Enable Developer options and USB debugging, connect a data cable, unlock the device and approve the computer's RSA prompt.
3. Run `forge --project target adb-preflight`. Observe `authorized`, `unauthorized`, `offline`, `multiple`, incomplete properties or absence; resolve the actual state. `adb devices` remains available for direct enumeration.
4. Supply `--serial` when selection is ambiguous. Inspect observed OS/API/ABI before preparing device-side tools. For installation, `adb-install-splits` requires explicitly selected APKs or exact archive members with compatible manifests; it performs a new install, not replacement. See [Android](android.md).
5. Configure the correct Frida server/Gadget/debuggable-app path for the target if a hook is required. ADB authorization alone does not provide injection.

Do not root, unlock bootloaders, factory-reset or install certificates/profiles automatically. Do not assume that root/jailbreak, TLS capture or attestation bypass is available. No Android or iOS hardware result is implied by a host executable version check.

Deep radare2 actions (`native disasm`, `native xrefs`, `native callgraph`) record bounded backend/version results and source-byte fingerprints. Function-level graph membership comes from observed function/basic-block data rather than guessed names or address spans. Static analysis never executes the binary or recovers source automatically. See [native analysis](native.md).

## iOS boundary

There is no FORGE iOS runtime adapter. ADB cannot operate an iPhone. Use an actually available compatible external capture/debug environment and record its evidence and pairing/signing prerequisites. Certificate trust does not automatically remove application pinning.
