# iOS boundary

FORGE has **no iOS runtime adapter**. There is no capture, hooking, injection, jailbreak or
certificate capability here, and ADB is not an iOS transport. These two commands exist so that
the prerequisites you cannot check from the host — is a device attached, is this host paired —
are observable *before* anyone is asked to change device settings.

```console
forge ios-devices
forge ios-pair --udid OBSERVED_UDID
```

Both are read-only invocations of an explicitly configured external tool. Neither opens a
listener or socket, writes to the device, or modifies trust.

## Tools

| Tool | Override | Default | Used for |
|---|---|---|---|
| `idevice_id` | `FORGE_IDEVICE_ID` | `idevice_id` on `PATH` | listing attached UDIDs |
| `idevicepair` | `FORGE_IDEVICEPAIR` | `idevicepair` on `PATH` | validating host/device pairing |

Both come from libimobiledevice. Install it, or point the override at an explicit executable. An
unset or broken tool is a hard error that names what to install; FORGE does not download or
bundle it. `doctor` reports the resolved path and source for both.

## `ios-devices`

Runs `<idevice_id> -l` with a 15 second bound and records the observed UDIDs (capped at 128,
with `devices_omitted`), plus `malformed_lines`. Raw malformed lines are counted, not stored.
`status` is `missing-tool`, `tool-failed`, `absent` (the tool ran and listed nothing) or
`observed`.

An empty listing means no *usable* device was attached at that moment; it does not prove the
target app was never installed for someone else.

## `ios-pair`

Runs `<idevicepair> validate -u UDID` with a 30 second bound. The UDID is validated before any
spawn. `pairing_state` is `paired`, `not-paired` or `unknown`; `paired` additionally requires a
zero exit code, and a verdict that disagrees with the exit code is reported as `unknown` rather
than guessed. `status` is `missing-tool`, `tool-failed`, `paired`, `not-paired` or `unknown`.

Pairing is host/device trust metadata. It is not proof of capture, of a trusted application
session, or of any login succeeding — and it says nothing about application layer pinning.

## What an iPhone task actually needs

Decide these before asking for a device:

1. **Transport.** USB pairing plus a compatible external environment. FORGE cannot supply it.
2. **Instrumentation.** A jailed (non-jailbroken) device cannot be instrumented. Hooking needs a
   jailbroken device or a repackaged build; certificate trust does not remove application layer
   pinning.
3. **Scope.** Which app, which build, and what exactly is being observed.

Until those exist, keep the task at the static stage — the artifact, decoded sources and native
libraries are normally analysable without the phone — and record the missing prerequisite as a
blocker rather than claiming a runtime result.
