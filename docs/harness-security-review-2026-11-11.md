# Harness security and reliability review — 2026-11-11

## Scope

This review covers the autonomous `vuln-pipeline` harness, including agent
execution, proof-of-concept extraction, deterministic replay, grading,
sandboxing, artifact persistence, and the model-provider adapters. It was
performed against the uncommitted working tree that followed the
provider-agnostic runtime, verified-replay, immutable-image, and durable-run
work. That working tree was subsequently captured at commit `20c9cb7`; findings
and strengths below describe that snapshot unless explicitly marked resolved.

The review is a point-in-time engineering assessment, not a claim that the
harness or its targets are free of vulnerabilities.

## Strengths

- **Machine-owned grading.** `harness/grade.py` replays submitted artifacts in
  a credential-free container with networking disabled. The semantic grader
  receives no tools, cannot execute the target, and can veto but cannot upgrade
  a failed machine criterion.
- **Trusted replay construction.** `harness/profiles.py` constructs the C/C++
  replay command from the configured binary and a validated PoC path instead
  of executing find-agent shell text. Web replay commands must match the
  configured replay entrypoint and validated manifest.
- **Container hardening.** Containers drop all capabilities, set
  `no-new-privileges`, enforce a PID limit, and verify the requested image and
  OCI runtime after startup.
- **Durable private artifacts.** `harness/io_utils.py` provides atomic,
  fsynced, mode-`0600` writes and an exclusive lock for mutable results
  directories.
- **Backend no-tools controls.** An explicit empty tool list is distinct from
  the default tool set. Claude and Gemini are configured to disable tools,
  while Codex/Ollama tool-free invocations are rejected before launch. At the
  reviewed snapshot, the orchestrator did not reject an unexpected tool event
  emitted during an otherwise successful no-tools run.

## Findings

### P1 — Bound and validate agent-selected artifact reads

`harness/find.py` reads the path emitted in `<poc_path>` or
`<replay_manifest_path>` through `docker_ops.read_file()`. That helper runs
`docker exec ... cat <path>` synchronously, captures all output in host memory,
and has no timeout or size limit. A compromised or prompt-injected find agent
can select a non-terminating device such as `/dev/zero`, a FIFO, or an
arbitrarily large regular file. This can exhaust host memory and blocks the
event loop that coordinates every other agent.

Remediation:

1. Restrict submitted artifacts to an expected workspace directory and reject
   traversal, devices, sockets, FIFOs, and symlinks outside that directory.
2. Inspect the file type and size inside the container before transfer.
3. Enforce a small profile-specific maximum size and a short wall-clock
   timeout while streaming no more than that limit.
4. Perform the blocking container operation outside the event-loop thread.
5. Add regression tests for `/dev/zero`, FIFOs, oversized files, traversal,
   and read timeouts.

### P1 — Bound replay output and terminate timed-out executions

`docker_ops.exec_sh()` captures unlimited stdout and stderr. A replay can
therefore consume host memory for up to the 600-second grading timeout. When
the host-side Docker client times out, the harness does not explicitly
terminate the process created by `docker exec`. A surviving target can compete
with later replay attempts for the same container memory limit and produce
misleading timeout or OOM evidence.

Remediation:

- Stream output through a fixed-size tail or capped temporary file.
- Run each replay under an in-container process-group timeout and kill the
  process group on expiry.
- Prefer a fresh replay container per attempt, or verify that no submitted
  process remains before starting the next attempt.
- Record truncation and forced termination in the machine evidence.

### P1 — Add an outer wall-clock deadline for every agent invocation

Claude and Gemini expose backend turn controls. Codex and Ollama currently
receive the requested turn budget as prompt text, and no backend has an
orchestrator-owned wall-clock deadline around the complete invocation and
resume loop. A stalled CLI, blocked stream, or tool process can therefore hold
a workflow indefinitely. Resume attempts can add up to approximately one hour
of backoff before accounting for execution time.

Remediation:

- Apply an orchestrator-owned deadline to the entire logical agent run.
- Apply a shorter deadline to each individual CLI attempt.
- On expiry, terminate the CLI process tree and remove the agent container.
- Persist a distinct timeout status and the consumed retry budget.

### P1 — Drain agent stderr concurrently

`run_agent()` consumes stdout while deferring stderr until stdout closes. The
async subprocess transport buffers stderr up to its configured reader limit,
but a sufficiently noisy CLI can fill that buffer, block, and prevent stdout
from completing. This is a bounded-buffer deadlock risk, especially for
backends that emit diagnostics or progress on stderr.

Remediation: consume stderr concurrently into a capped tail, include that tail
in terminal errors, and add a regression test with sustained stderr output.

### P2 — Move container lifecycle operations off the event loop

`sandbox.agent_container()` synchronously builds or inspects images, starts
containers, verifies them, and removes them. It is entered directly from async
find, grade, recon, report, judge, and patch workflows. A slow build or
container-engine call stalls unrelated workflows even when bounded parallelism
is enabled.

Remediation: introduce an async lifecycle wrapper that delegates blocking OCI
operations to worker threads, while keeping teardown cancellation-safe.

### P2 — Make the CONNECT proxy backpressure-safe

The egress proxy sets both tunnel sockets nonblocking and then calls
`sendall()`. Under backpressure, `sendall()` can raise `BlockingIOError`; the
broad `OSError` handler silently closes the tunnel. The tunnel also closes
after 60 seconds without readable bytes. Both conditions can surface as
intermittent model API failures and trigger expensive agent resume behavior.

Remediation: maintain per-direction output buffers, select for writability,
handle partial writes, use half-close semantics, and make idle timeout behavior
explicit and configurable. Add a slow-reader and long-idle integration test.

### P2 — Reconcile the C/C++ replay threshold

The find prompt and several operator documents require a crash to reproduce
three times out of three. The C/C++ machine grader and grade prompt accept two
matching crashes out of three so that flaky-but-real crashes can pass with a
lower score. The web profile remains strict at three out of three.

This is a policy inconsistency rather than a hidden implementation behavior:
parts of `docs/pipeline.md` already describe the two-of-three allowance. Choose
one contract, encode it in a named policy constant, and update the find,
grade, report, and operator documentation together.

### P3 — Reject tool events during no-tools runs

Backend flags disable tools where supported, and backends that cannot express
a tool-free phase are rejected before launch. The orchestrator still accepts a
successful normalized result even if that result unexpectedly contains a
`tool_use` event. Treat backend controls as defense in depth: inspect normalized
assistant messages and fail the logical run immediately if `tools=[]` and any
tool event appears. Add a regression test using a backend stream that emits a
tool call followed by a nominally successful result.

## Resolved in the reviewed snapshot

- Transcript JSONL files use `open_private_text()`, which creates mode-`0600`
  files and keeps their parent directory private.
- Codex and Ollama receive system guidance through `developer_instructions`;
  Gemini receives it through `GEMINI_SYSTEM_MD`. Only the turn-budget reminder
  is prepended to the user prompt.

## Maintainability and release hygiene

- `CLAUDE.md` still describes the previous tool-enabled grade agent and should
  match the machine-replay plus no-tools semantic-grader architecture.
- `harness/cli.py` has reached roughly 2,000 lines. Streaming judge/report
  dispatch, recovery, and manifest management form a natural extraction
  boundary.
- Backend agent images use digest-specific runtime tags, but setup probes share
  a mutable `:latest` alias across backends. The alias does not select the
  normal runtime image, but it can confuse concurrent setup or verification.
- Provider-runtime, replay, image-pinning, durability, OpenShell experiment,
  and publication changes should remain separate commits or stacked pull
  requests.

## Recommended order

1. Bound artifact reads.
2. Bound replay output and guarantee process termination.
3. Add agent deadlines and concurrent stderr draining.
4. Repair proxy backpressure handling.
5. Move container lifecycle work off the event loop.
6. Resolve the replay-threshold policy and documentation drift.
7. Split orchestration modules and add an event-level no-tools guard.

## Validation snapshot

At review time, the local unit suite reported `359 passed, 9 skipped`. The
skipped tests were five real-infrastructure gVisor boundary tests and four
Docker patch-grading tests. Python compilation and `git diff --check` passed.
Those results provide strong unit-level evidence but do not replace a complete
Linux/gVisor canary run with each supported backend.
