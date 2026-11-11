# From Vulnerability Leads to Reproducible Fixes: Inside IVCD

Security teams do not usually lack alerts. They lack enough time to determine
which alerts are real, which matter, and whether a proposed fix actually
removes the bug.

IVProduced Code Defender (IVCD) builds on Anthropic's [Defending Code
Reference Harness](https://github.com/anthropics/defending-code-reference-harness),
an open-source example of combining agent-assisted code review with sandboxed
vulnerability discovery. IVCD carries that approach into a broader workflow:
understand a codebase, look for vulnerabilities, verify evidence, prioritize
the results, and prepare fixes for review.

The central idea carries through from the reference harness: a plausible
explanation is a lead. A reproducible failure, together with its evidence and
code path, is a stronger basis for engineering work. IVCD takes the workflow
further by widening the target profiles, supporting more deployment contexts,
and connecting verified findings to reports, compliance evidence, and patch
validation.

## Two ways into the workflow

IVCD has an interactive path and an execution path.

The interactive skills help a reviewer bootstrap a threat model, inspect source
code for possible vulnerabilities, and triage findings. This path is useful
when the first question is where to look or when target code should not be run.
It produces reviewable artifacts such as a threat model, static findings, and a
ranked triage report.

The `vuln-pipeline` is for targets that can be built and exercised. Its current
reference profiles cover C/C++ targets instrumented with AddressSanitizer
(ASAN), plus Docker-replayable Python, Node, and React web targets. A target
definition records how to build the image, where the source and executable
live, and, for web targets, how to replay a request or browser interaction.

These paths complement each other. Threat modeling gives the review useful
context; static analysis can point toward suspicious code; and execution can
turn a candidate into an input that demonstrates a failure.

## From source tree to evidence

A pipeline run begins by building the target image. An optional recon stage
asks an agent to divide the attack surface into focus areas, so parallel find
runs explore different parts of the program. Operators can also provide those
areas directly.

Each find agent reads the source, constructs inputs, and runs the target in its
own container. For a C/C++ target, the goal is an ASAN crash that reproduces
reliably. For a web target, the agent records a self-contained replay manifest
with the request or browser steps and observations. The agent submits the
artifact and explains why it is distinct from findings already recorded for
the batch.

Verification is a separate stage. The pipeline-owned replay executes the
submitted command several times in a fresh container without model credentials
or network access. A separate model-driven grader evaluates the captured
evidence without tools and cannot override a failed machine criterion. The
semantic grader uses model credentials and restricted API egress, but it does
not execute the target; only the credential-free replay container does. The
T0–T2 patch grader likewise executes target code without model credentials or
network access. Keeping these roles distinct makes the replay artifact central
evidence without implying that every model-assisted stage is credential-free.

When a finding passes, the pipeline can deduplicate it against earlier crashes
and produce a structured report. The report describes the failure, its likely
impact, and how an attacker could reach it. An optional novelty check looks at
upstream Git history to help determine whether a fix has landed.

The output is meant to be useful to an engineer: a replayable artifact,
transcripts, a result record, and a report that can be inspected and discussed.
The system does not ask teams to accept scanner prose as the final result.

## Turning a finding into a candidate fix

IVCD can generate a candidate patch for each selected finding. The patch
verification ladder applies the diff in a fresh environment, rebuilds the
target, checks whether the original proof of concept still fails, runs the
configured test suite, and attempts a limited re-attack against the patched
program.

This gives reviewers more evidence than “the patch compiles” or “the original
input no longer crashes.” It can still miss a bypass or a regression, so the
generated diff remains a proposal for human review, not an automatically
approved fix.

## The sandbox is part of the design

The execution pipeline runs agents and target programs inside containers, with
gVisor used to add a stronger boundary between container processes and the
host. Network access is routed through a proxy that allows the selected model
provider’s endpoints. Docker is the default container engine; rootful Podman is
also supported with a corresponding sandbox setup.

This boundary matters because vulnerability research deliberately feeds
untrusted inputs to target code, and autonomous agents can run commands while
they investigate. The sandbox limits where those actions can go. It does not
make arbitrary targets harmless: operators should use an isolated Linux
environment, narrowly scoped credentials, and the documented launch wrapper.
The target code executes during discovery and replay, and candidate patches
need a person to inspect them before adoption.

## One workflow, multiple agent runtimes

IVCD now separates pipeline orchestration from the agent CLI. A backend adapter
translates IVCD's prompts, model choice, tool permissions, and turn limits into
the selected runtime's command, then maps its streamed events, errors, and
resume state back into IVCD's common result format. The current adapters cover
Claude, Codex, Gemini, and Ollama for self-hosted models. Operators can choose
among them while using the same discovery and artifact workflow.

Provider neutrality does not mean every runtime has identical capabilities.
For example, the current Codex CLI path cannot enforce a tool-free phase, so
IVCD rejects workflows that require it instead of quietly weakening the grade
or report stage. Adding another provider means implementing an adapter and
checking that its tool controls, structured output, and resume behavior fit the
pipeline's requirements. A text-generation API by itself is not an agent
runtime; it needs an agent CLI or an IVCD-managed tool loop.

The runtime can change, but the evidence standard stays the same: agent output
is a lead, replayable artifacts are checked independently, and proposed fixes
go through a verification ladder and human review.

The repository also supports rootful Podman and maps findings to CWE
categories and selected NIST SP 800-53 controls. The `oscal` command
aggregates those mappings into an OSCAL assessment-results document. OSCAL
output is technical evidence for review, not a compliance assessment,
authorization decision, or claim that a control is effective. Organizations
must validate the mapping and add their system-specific assessment context.

## Where IVCD fits

IVCD is useful when a team needs to move from a broad search to a prioritized
set of findings it can reproduce, inspect, and try to fix. It connects several
steps that are often handled by separate tools: threat modeling, candidate
discovery, independent replay, deduplication, reporting, and patch validation.

It is not a proof that a codebase is secure. The included pipeline targets
specific build and replay profiles; results depend on the target’s configuration
and the inputs the agents find. A clean run does not rule out untested bugs, and
a passing patch ladder does not replace a maintainer’s review.

That is the role IVCD aims to play: make security findings easier to verify and
act on, while leaving the final risk decision and code change with the people
responsible for the system.

## Project references

- [README](../README.md) — project overview and quick start.
- [Pipeline guide](pipeline.md) — stages, commands, results, and architecture.
- [Agent sandbox guide](agent-sandbox.md) — providers, Podman, credentials,
  and isolation setup.
- [Patching guide](patching.md) — verification ladder and human review guidance.
- [Federal deployment guide](federal-deployment.md) — OSCAL evidence limits.
