# Contributing

Discuss an observable protocol/evidence problem in an issue, or submit a focused pull request with a reproducible case. Do not attach production credentials, account lists, private captures or proprietary client binaries.

## Local development

Python 3.10+. Use an isolated environment and install the checkout:

```sh
python -m venv .venv
# Activate using the command for your operating system.
python -m pip install -e ".[http]"
python -m unittest discover -s tests -v
python examples/smoke.py --cli forge
python examples/smoke.py --transport curl_cffi --cli forge
```

The HTTP smoke uses a loopback fixture and temporary target directories. It performs real CLI subprocesses, live local login/profile requests, control comparison, checkpoint handoff, stale-write rejection, file integrity and history pagination. It is not proof of a vendor login.

Hardware/tool checks are separate. Do not mark a device path verified from a mocked ADB/Frida response or a host version command. Run the actual configured tool when modifying its adapter and describe any missing prerequisite.

## Changes

- Keep commands deterministic and target-scoped. Prefer an explicit input over a guessed endpoint or token.
- Preserve immutable evidence and existing stores. Task progress and protocol verification are different contracts.
- Validate the complete flow before traffic; revalidate live substitutions before dispatch.
- Keep extraction values out of stdout, persistent evidence and artifacts. Test body, header and opaque echo boundaries.
- Add regression tests for behavior, isolation, transitions, precedence and errors. Avoid source-text or mock-forwarding assertions.
- Update the relevant command documentation and CHANGELOG. Keep changes small enough to review.
- Preserve the author's attribution and the MIT notice. Optional tool licenses remain separate.

Use synthetic fixture data and an ephemeral loopback server for network tests. Tests must not need vendor accounts, fixed ports, solver credits or globally installed SDKs. Optional curl tests skip when the dependency is absent; CI installs it to exercise both transports.

## Build and release

```sh
python -m pip install build
python -m build
```

Before publishing:

1. Run the regression suite and installed-wheel smoke from outside the source checkout.
2. Inspect wheel/source archive members. Exclude tools, venvs, notes, evidence stores, secrets and captures.
3. Update `forge_version.py` and the dated changelog. The package derives its version from that module.
4. Publish only after the relevant CI run succeeds. Tag the same verified commit as `v<version>`.
5. Attach the wheel, source archive and checksums to the GitHub release. A checksum identifies bytes; do not describe an unsigned release as signed.

The project does not currently publish to PyPI automatically. No repository secret or model API key is required for the existing CI.

## Review and conduct

Be specific about evidence and limitations. Keep discussion technical and respectful. Report a privacy/security issue through the private route in SECURITY.md, not through a public capture dump.
