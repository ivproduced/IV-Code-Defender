# OpenShell migration log

The active pipeline still requires its existing gVisor boundary. OpenShell is
an experimental transport in this checkout, not a selectable pipeline backend.

## 2026-10-31 — runtime inventory and local transport qualification

**Objective.** Establish a supported, pinned OpenShell development environment
and exercise the independent, credential-free replay path before changing any
pipeline execution route.

**Environment.** The Mac is arm64, macOS 26.6.2, with Docker Desktop Engine
29.9.2. Proxmox `eucann` has running Ubuntu 24.04 LXC CT 120
(`security-runtime`), Docker 29.6.2, and runsc release-20260714.0. CT 120 is
configured with nesting, `lxc.apparmor.profile: unconfined`, and an empty
capability drop list. It shares the Proxmox host kernel. OpenShell is absent
there. CT 120 remains available for comparison, but was not used for these
OpenShell experiments.

**Release and gateway.** Pinned NVIDIA OpenShell v0.1.6. The official Homebrew
formula could not install because the Mac's Command Line Tools do not support
macOS 26. The CLI, gateway, and prover release archives were instead downloaded
to `/private/tmp/ivcd-openshell-v0.1.6` and verified against the v0.1.6 formula
SHA-256 values. A temporary gateway used the Docker driver, loopback-only
`https://localhost:17670`, and mTLS user authentication. `openshell status`
reported `connected` and `authenticated`, both at version 0.1.6. No provider
was attached to the probe sandboxes.

**Transport probe.** Run with the local binary and the digest-pinned Debian
arm64 image:

```bash
XDG_CONFIG_HOME=/private/tmp/ivcd-openshell-v0.1.6/config \
python3 -m harness.openshell \
  --binary /private/tmp/ivcd-openshell-v0.1.6/openshell \
  --image debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 \
  --policy policies/openshell/replay-probe.yaml \
  --output /private/tmp/ivcd-openshell-transport-report.json
```

The 256 KiB binary upload/download matched byte-for-byte. A second sandbox
started from the same image without the first sandbox's file. The process ran
as UID 1000. An outbound TCP attempt to `example.com:443` failed with
`Permission denied`. The tested model credential environment variables were
absent. The accepted policy hash was
`519187891fe94c5790f1a34d709e6db2a2706ad17a34adf50af10ee7c2be6a1e`.
The machine-readable result is in the temporary report path above. OpenShell's
download command only accepts paths in `/sandbox`; `/tmp` download failed as
expected. The probe reports `qualified_for_pipeline: false`.
`pytest -q tests/test_openshell.py` passed (2 tests), and Ruff reported no
issues in the new module and test file.

**Canary replay.** The existing arm64 `vuln-pipeline-canary` image could not
start directly because its root-owned `/work` is not usable as OpenShell's
non-root working directory. A disposable wrapper image created an owned
`/sandbox`, set `WORKDIR /sandbox`, and ran as UID:GID 1000:1000. Its image
digest was `sha256:0060c95648e2906dadba941378674647ad6cdf733100926b913d3aa8bed80ca1`.
The replay policy also needed read-only `/work` access for the binary and
source; without it the exec failed with `Permission denied`. These two failures
were fail-closed and resolved in the disposable image and the policy file.

The `run_000` fixture PoC was uploaded to `/sandbox/poc.bin` in a fresh,
credential-free sandbox. Three executions of `/work/entry /sandbox/poc.bin`
each produced an ASAN `heap-buffer-overflow` in `parse_alpha` at
`/work/entry.c:27`. The sandbox's policy was accepted as `Ready` with the hash
above. All manually created sandboxes and the probe's own sandboxes were
deleted; the gateway list was empty afterward.
The temporary gateway was stopped after the tests.

**Limits and next work.** These checks cover CLI transport and one replay
path on Docker Desktop. They do not qualify a Proxmox LXC deployment or prove
all filesystem and network denial cases. The active find, grade, report,
judge, compare, patch, and re-attack paths still use Docker/gVisor operations.
Before OpenShell becomes selectable, implement a complete execution interface,
provider mediation, effective-policy checks, bounded transfers and streaming,
timeouts and cancellation, reproducible patched image builds, and a full
canary run. Keep the gVisor gate until every path and failure mode passes.

Sources: [OpenShell v0.1.6 release](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.6),
[installation](https://docs.nvidia.com/openshell/v0.1.6/about/installation/),
[sandbox runtimes](https://docs.nvidia.com/openshell/v0.1.6/how-it-works/sandboxes/runtimes),
[policy schema](https://docs.nvidia.com/openshell/v0.1.6/how-it-works/policies/schema).
