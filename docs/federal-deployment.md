# Federal deployment

This repository provides technical capabilities and evidence artifacts. It is
not an authorization package, a FedRAMP authorization, a FISMA assessment, or
a determination of data rights, export controls, or records obligations.
Those decisions belong to the deploying organization's authorized officials.

## Keep the internal port distinct

Create the internal port from an approved, pinned revision. Give it a separate
repository identity, `NOTICE`, provenance record, release process, artifact
store, and authorization boundary. Do not cite this public repository or its
NOTICE as an approval for the internal port.

Before adding internal changes, obtain a determination of the ownership and
rights in those changes. Work made by federal personnel as part of official
duties may be a United States Government work; contractor work may be governed
by its contract. Do not add personal copyright notices unless the responsible
organization has determined they are appropriate.

Record, at minimum:

| Record | Owner |
| --- | --- |
| Approved source revision, local changes, and third-party notices | Configuration manager |
| Copyright, government-work, license, data-rights, and export determinations | Legal and acquisition officials |
| System boundary, data flows, model-provider approval, and risk acceptance | Authorizing official and system owner |
| Retention, disclosure, and incident-response handling for findings and PoCs | Records and security officials |

## Deploy inside the authorization boundary

Run agent-spawning commands only from a hardened Linux environment using
`bin/vp-sandboxed`; macOS and Windows must use a Linux VM rather than the
unsandboxed override. Keep the orchestrator, gVisor runtime, allowlist proxy,
target source, result store, and approved model-provider endpoint within the
documented boundary.

Use a dedicated project or account with least-privilege, short-lived
model-invocation credentials. Do not mount credential stores, production
access, home directories, or external-write tools into agent containers.
Document the egress allowlist and independently verify it after every runtime
or network-policy change. Apply resource limits and retain operational logs
according to the system's approved records schedule.

## Treat OSCAL as evidence, not an assessment

`vuln-pipeline oscal` exports crash-type-based NIST mappings. Each finding
includes the relative source report path and its SHA-256 digest so reviewers
can trace the mapping to the underlying evidence. The mappings identify
controls that the evidence may support; they do not establish implementation,
effectiveness, inheritance, residual risk, or authorization.

Validate generated OSCAL using the organization's approved OSCAL tooling and
review process before importing it into governance systems. Associate each
finding with system-specific assets, control implementations, assessor
observations, remediation ownership, and POA&M handling as applicable.

## Supply-chain and operational evidence

Before operational use, establish approved processes for signed releases,
SBOM generation and review, dependency and container-image vulnerability
management, build provenance, change control, backup and recovery, incident
response, and continuous monitoring. Retain the resulting evidence with the
internal port; the pipeline does not create or attest to these artifacts.
