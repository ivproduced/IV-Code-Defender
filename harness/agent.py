# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Claude Code headless CLI wrapper.

Invokes `claude -p --output-format stream-json` via `docker exec` into the
agent's gVisor container and streams the JSONL. The Agent SDK is itself a
subprocess wrapper around the same CLI; going direct keeps the argv shape
under our control (resume, tools, system-prompt).

Key responsibilities:
  1. run_agent(): async subprocess wrapper around the CLI
  2. AgentResult.find_tagged_message(): agents often emit structured tags, then
     a short "Done!" message. Naive last-message parsing returns the prose.
     We scan backwards for the tags instead.
  3. Transcript streaming: per-message JSONL with fsync, so a mid-run kill
     leaves a readable transcript on disk.

Messages are stored as raw stream-json dicts (not SDK dataclasses). Transcript
files are stream-json shape, which includes per-turn `usage` blocks — richer
than the old SDK-serialized format.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from . import agent_backends, budget, docker_ops, events, sandbox
from .io_utils import open_private_text


# ──────────────────────────────────────────────────────────────────────────────
# ANSI color — shared by cli.py. No dependency; gated on isatty().
# ──────────────────────────────────────────────────────────────────────────────

_ANSI = {
    # signal level
    "dim": "2;90",   # low-signal progress (tool calls) — dim + bright-black = faintest grey
    "red": "91",     # crash landed
    "bold": "1",     # verified / important finding
    # phase (start-of-phase lines so interleaved agents are scannable)
    "recon": "96",   # cyan
    "find": "94",    # blue
    "grade": "93",   # yellow
    "judge": "95",   # magenta
    "report": "92",  # green
    "patch": "92",   # green (never interleaves with report)
}


def color(text: str, name: str, stream=sys.stdout) -> str:
    """Wrap ``text`` in ANSI color ``name`` if ``stream`` is a TTY.

    dim  — low-signal progress lines (tool calls)
    red  — a crash landed
    bold — verified / important findings

    No-op when piped or redirected so grep/tee/log files stay clean.
    """
    if not getattr(stream, "isatty", lambda: False)():
        return text
    return f"\033[{_ANSI[name]}m{text}\033[0m"


# ──────────────────────────────────────────────────────────────────────────────
# Message → text extraction (stream-json dicts)
# ──────────────────────────────────────────────────────────────────────────────

def _blocks_to_text(content: Any) -> str:
    """Extract plain text from a content-block list.

    stream-json content is list[{"type":"text","text":...} | {"type":"tool_use",...} | ...].
    We only want text blocks — tool calls and thinking are not output tags.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b.get("text", "") for b in content
            if isinstance(b, dict) and b.get("type") == "text"
        )
    return ""


def _truncate_tool_results(msg: dict) -> dict:
    """Clip large tool_result content (ASAN traces) for transcript persistence.

    Mutates a copy. Only touches user messages with tool_result blocks.
    """
    if msg.get("type") != "user":
        return msg
    inner = msg.get("message", {})
    content = inner.get("content")
    if not isinstance(content, list):
        return msg
    clipped = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "tool_result":
            c = b.get("content")
            if isinstance(c, str):
                b = {**b, "content": c[:5000]}
            elif isinstance(c, list):
                b = {**b, "content": [
                    ({**x, "text": x.get("text", "")[:5000]} if isinstance(x, dict) else x)
                    for x in c[:10]
                ]}
        clipped.append(b)
    return {**msg, "message": {**inner, "content": clipped}}


def _contains_tool_use(msg: dict) -> bool:
    """Return whether a normalized assistant message attempts any tool call."""
    return any(
        isinstance(block, dict) and block.get("type") == "tool_use"
        for block in msg.get("message", {}).get("content", [])
    )


def _progress_line(msg: dict, prefix: str) -> None:
    """Print a one-line summary of an assistant message to stderr.
    Tool calls show name + key arg; text shows a truncated preview."""
    if msg.get("type") != "assistant":
        return
    for b in msg.get("message", {}).get("content", []):
        if not isinstance(b, dict):
            continue
        if b.get("type") == "tool_use":
            inp = b.get("input") or {}
            arg = (inp.get("command") or inp.get("file_path") or inp.get("path")
                   or inp.get("pattern") or "")
            arg = str(arg).replace("\n", " ")[:120]
            line = color(f"{prefix}   → {b.get('name')}: {arg}", "dim", sys.stderr)
            print(line, file=sys.stderr, flush=True)
        elif b.get("type") == "text":
            t = (b.get("text") or "").strip().replace("\n", " ")
            if t:
                line = color(f"{prefix}   · {t[:140]}", "dim", sys.stderr)
                print(line, file=sys.stderr, flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# XML tag parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_xml_tag(text: str, tag: str) -> str | None:
    """Extract content of <tag>...</tag>. DOTALL so multiline ASAN traces work.
    Not a real XML parser — tags are markers in prose, not well-formed XML.
    """
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return m.group(1).strip() if m else None


# ──────────────────────────────────────────────────────────────────────────────
# AgentResult — the find_tagged_message bugfix lives here
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    """Collected output of one agent run."""
    messages: list[dict] = field(default_factory=list)  # raw stream-json dicts
    result_message: dict | None = None                  # terminal {"type":"result",...}
    session_id: str | None = None                       # for resume on transient failure
    error: str | None = None                            # if the agent loop died
    resume_count: int = 0                               # how many times we auto-resumed
    stop_reason: str | None = None                      # terminal non-error stop (e.g. error_max_turns)

    def find_tagged_message(self, tag: str) -> str:
        """Return the most-recent assistant message text containing <tag>.

        Agents emit structured tags, then often a short final "Done!" message.
        If you take the last message you get prose, not tags. Scan backwards
        instead. Falls back to the last assistant message.
        """
        needle = f"<{tag}>"
        last_assistant = ""
        for msg in reversed(self.messages):
            if msg.get("type") != "assistant":
                continue
            text = _blocks_to_text(msg.get("message", {}).get("content"))
            if not last_assistant:
                last_assistant = text
            if needle in text:
                return text
        return last_assistant

    @property
    def last_assistant_message(self) -> str:
        for msg in reversed(self.messages):
            if msg.get("type") == "assistant":
                return _blocks_to_text(msg.get("message", {}).get("content"))
        return ""

    def transcript(self) -> list[dict]:
        """JSON-serializable transcript for persistence."""
        return [_truncate_tool_results(m) for m in self.messages]


# ──────────────────────────────────────────────────────────────────────────────
# The core wrapper
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_TOOLS = ["Read", "Write", "Bash"]


def build_claude_argv(
    cli_argv: list[str],
    *,
    model: str,
    max_turns: int,
    tools: list[str] | None,
    permission_mode: str,
    system_prompt: str | None = None,
    max_budget_usd: float | None = None,
) -> list[str]:
    """Build the argv passed to the in-container Claude CLI."""
    # ``None`` means the normal agent tool set; an explicit empty list means
    # no tools. Treating [] as falsy accidentally gave judge/grader agents Bash.
    effective_tools = DEFAULT_TOOLS if tools is None else tools
    argv = [
        *cli_argv, "-p", "--verbose",
        "--output-format", "stream-json",
        "--permission-mode", permission_mode,
        "--model", model,
        "--max-turns", str(max_turns),
        "--tools", ",".join(effective_tools),
        "--strict-mcp-config",
        "--setting-sources", "",
    ]
    if system_prompt:
        argv += ["--system-prompt", system_prompt]
    if max_budget_usd:
        argv += ["--max-budget-usd", f"{max_budget_usd:g}"]
    return argv


DEFAULT_DEADLINE_S = 8 * 3600
STDERR_TAIL_BYTES = 64 * 1024

# CLI result subtypes that mean "the agent ran out of budget", not "the call
# failed". Resuming cannot help: the same limit trips again, so a retry loop
# would burn up to max_resume_attempts sessions for nothing.
_TERMINAL_SUBTYPES = ("error_max_turns", "error_max_budget_usd",
                      "error_max_structured_output_retries")
# Non-transient API failures: retrying a bad key or exhausted credit is waste.
_FATAL_MARKERS = ("invalid x-api-key", "invalid api key", "authentication_error",
                  "credit balance", "permission_error", "oauth token has expired")


def _deadline_default() -> float:
    raw = os.environ.get("VULN_PIPELINE_AGENT_DEADLINE_S", "").strip()
    try:
        return float(raw) if raw else float(DEFAULT_DEADLINE_S)
    except ValueError:
        return float(DEFAULT_DEADLINE_S)


async def _drain_stderr(stream, sink: bytearray) -> None:
    """Read stderr concurrently with stdout, keeping only the tail.

    Reading it after stdout closes lets a chatty CLI fill the stderr pipe and
    block forever while we wait on stdout."""
    try:
        while chunk := await stream.read(65536):
            sink.extend(chunk)
            if len(sink) > STDERR_TAIL_BYTES:
                del sink[:len(sink) - STDERR_TAIL_BYTES]
    except Exception:
        pass


async def _stop(proc, container: str | None = None) -> None:
    """Terminate the host-side exec client, escalating to kill.

    ``docker exec`` does not forward the signal to the in-container CLI, so
    for a deadline/budget stop we also SIGKILL the container's processes."""
    if proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), 10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
    if container:
        await asyncio.to_thread(docker_ops.kill_all, container)


async def run_agent(
    prompt: str,
    *,
    container: str,
    max_turns: int,
    model: str,
    max_resume_attempts: int = 20,
    transcript_path: str | None = None,
    heartbeat_every: int = 25,
    progress_prefix: str | None = None,
    tools: list[str] | None = None,
    system_prompt: str | None = None,
    deadline_s: float | None = None,
) -> AgentResult:
    """Run the selected agent CLI inside ``container``.

    Invokes ``docker exec <container> claude -p --output-format stream-json``
    and streams the JSONL output. Permission mode comes from
    :func:`sandbox.permission_mode` — ``bypassPermissions`` under gVisor (the
    sandbox is the boundary), ``auto`` otherwise so the classifier is the
    last line of defense for ``--dangerously-no-sandbox`` runs.

    Resilience: if the CLI process dies mid-stream (API 500, network blip,
    OOM on host), we resume the session up to `max_resume_attempts` times.
    `--resume <session_id>` reloads full context on the CLI side; the stream
    only yields NEW messages, so appending to the same result is correct.
    Partial transcripts are always preserved — AgentResult is never lost to
    an exception.

    If `transcript_path` is given, each message is written to that JSONL file
    as it arrives (fsync'd). A process kill mid-run still leaves a readable
    transcript on disk. Every `heartbeat_every` assistant turns, a progress
    line is printed so long runs don't look hung.

    Bounds: ``deadline_s`` (default 8h, env ``VULN_PIPELINE_AGENT_DEADLINE_S``)
    is a wall-clock cap over the whole run including resumes; the shared
    :mod:`budget` ledger stops agents once the batch spend/token ceiling is hit.
    """
    backend = agent_backends.selected()
    if backend in ("codex", "ollama") and tools == []:
        # Codex CLI has no enforceable per-invocation tool deny. Grade and
        # judge phases must see only supplied evidence and have no tools.
        return AgentResult(error=f"{backend} cannot run a tool-free phase through Codex CLI")
    if backend == "gemini":
        # System settings override target-controlled project settings. tools.core
        # is an actual tool allowlist; --allowed-tools would only skip prompts.
        gemini_tools = [] if tools == [] else [
            "read_file", "write_file", "replace", "run_shell_command", "glob", "grep"
        ]
        config = {"model": {"maxSessionTurns": max_turns},
                  "tools": {"core": gemini_tools},
                  "mcp": {"allowed": []},
                  "context": {"fileName": [], "includeDirectoryTree": False},
                  "privacy": {"usageStatisticsEnabled": False}}
        docker_ops.write_file(container, "/tmp/ivcd-gemini-settings.json",
                              json.dumps(config).encode())
        if system_prompt:
            docker_ops.write_file(container, "/tmp/ivcd-gemini-system.md",
                                  system_prompt.encode("utf-8"))
    if backend != "claude":
        constraints = [f"Complete within {max_turns} agent turns."]
        prompt = "\n\n".join([*constraints, prompt])
    result = AgentResult()
    agent_label = progress_prefix or "[agent]"
    started = time.monotonic()
    deadline_at = started + (deadline_s if deadline_s is not None else _deadline_default())
    ledger = budget.ledger()
    events.emit("agent.start", agent_label, model=model, backend=backend,
                max_turns=max_turns, tools=(DEFAULT_TOOLS if tools is None else tools))
    attempt = 0
    assistant_count = 0
    tool_call_count = 0
    gemini_text = ""
    held_cap: float | None = None   # dollar reservation of the in-flight launch
    holding = False
    launch_cost = 0.0

    transcript_file = open_private_text(transcript_path, "w") if transcript_path else None
    try:
        while True:
            if (reason := ledger.exceeded()):
                result.error = f"budget exceeded: {reason}"
                events.emit("budget.exceeded", agent_label, reason=reason)
                return result
            if time.monotonic() >= deadline_at:
                result.error = "deadline exceeded before launch"
                return result
            if holding:  # book the previous launch before reserving the next
                ledger.end_launch(held_cap, launch_cost)
                holding = False
            try:
                held_cap = ledger.begin_launch()
            except budget.BudgetExhausted as exc:
                result.error = f"budget exceeded: {exc}"
                events.emit("budget.exceeded", agent_label, reason=str(exc))
                return result
            holding, launch_cost = True, 0.0
            resume_id = result.session_id if attempt > 0 else None
            cmd = agent_backends.command(
                container, backend, model=model, max_turns=max_turns,
                tools=tools, system_prompt=system_prompt,
                resume_id=resume_id, sandboxed=bool(sandbox.runtime()),
                max_budget_usd=held_cap,
            )
            if backend == "gemini":
                # A system override prevents untrusted .gemini/settings.json
                # from restoring tools or enabling MCP servers.
                pos = cmd.index("-w")
                cmd[pos:pos] = ["-e", "GEMINI_CLI_SYSTEM_SETTINGS_PATH=/tmp/ivcd-gemini-settings.json",
                                "-e", "GEMINI_CLI_TRUST_WORKSPACE=true"]
                if system_prompt:
                    cmd[pos:pos] = ["-e", "GEMINI_SYSTEM_MD=/tmp/ivcd-gemini-system.md"]
            if resume_id:
                if backend == "claude":
                    prompt_stdin: bytes | None = None
                else:
                    prompt_stdin = b"continue"
            else:
                # Keep target-derived prompts out of host process listings.
                # Bounded parallelism prevents the high-fanout stdin startup
                # starvation that originally motivated putting prompts in argv.
                prompt_stdin = prompt.encode("utf-8")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=(
                    asyncio.subprocess.PIPE
                    if prompt_stdin is not None
                    else asyncio.subprocess.DEVNULL
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Default 64KB limit trips on large tool results (e.g. recon
                # `find` on a 60k-LOC tree). stream-json emits one JSON line
                # per message; a single Bash/Read result can be hundreds of KB.
                limit=16 * 1024 * 1024,
            )
            assert proc.stdout
            stderr_tail = bytearray()
            stderr_task = (asyncio.create_task(_drain_stderr(proc.stderr, stderr_tail))
                           if proc.stderr else None)
            async def _consume() -> AgentResult | None:
                """Read stdout until a result lands. Returns the final result
                (terminal) or None if the stream ended without one."""
                nonlocal assistant_count, tool_call_count, gemini_text, launch_cost
                if prompt_stdin is not None:
                    # Prompt delivery is under the deadline too: a CLI that
                    # never reads stdin must not hang us past it.
                    assert proc.stdin
                    proc.stdin.write(prompt_stdin)
                    await proc.stdin.drain()
                    proc.stdin.close()
                    await proc.stdin.wait_closed()
                async for raw in proc.stdout:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if backend == "gemini" and event.get("type") == "message" \
                            and event.get("role") == "assistant" and event.get("delta"):
                        gemini_text += str(event.get("content") or event.get("text") or "")
                    if backend == "gemini" and event.get("type") == "result" \
                            and gemini_text and not event.get("response"):
                        event = {**event, "response": gemini_text}
                    for msg in agent_backends.normalize(backend, event):
                        result.messages.append(msg)
                        ledger.record_message(msg)
                        if progress_prefix:
                            _progress_line(msg, progress_prefix)
                        if transcript_file:
                            transcript_file.write(
                                json.dumps(_truncate_tool_results(msg)) + "\n"
                            )
                            transcript_file.flush()
                            os.fsync(transcript_file.fileno())

                        mtype = msg.get("type")
                        if mtype == "assistant":
                            if tools == [] and _contains_tool_use(msg):
                                result.error = "no-tools agent attempted a tool call"
                                return result
                            assistant_count += 1
                            for b in msg.get("message", {}).get("content", []):
                                if isinstance(b, dict) and b.get("type") == "tool_use":
                                    tool_call_count += 1
                                    inp = b.get("input") or {}
                                    events.emit(
                                        "agent.tool_call", agent_label, tool=b.get("name"),
                                        arg=str(inp.get("command") or inp.get("file_path")
                                                or inp.get("path") or "")[:200],
                                    )
                            if assistant_count % heartbeat_every == 0:
                                print(f"  [agent] {tool_call_count} tool calls "
                                      f"({assistant_count} msgs)")
                            if (reason := ledger.exceeded()):
                                result.error = f"budget exceeded: {reason}"
                                events.emit("budget.exceeded", agent_label, reason=reason)
                                return result
                        elif mtype == "system" and msg.get("subtype") == "init":
                            sid = msg.get("session_id")
                            if sid and result.session_id is None:
                                result.session_id = sid
                        elif mtype == "result":
                            result.result_message = msg
                            launch_cost = float(msg.get("total_cost_usd") or 0.0)
                            subtype = str(msg.get("subtype") or "")
                            # Agents with run_in_background bash tasks keep the
                            # CLI stream alive past the result message; break on
                            # the FIRST result instead of waiting for stream
                            # exhaustion.
                            if subtype in _TERMINAL_SUBTYPES:
                                # Budget/turn exhaustion arrives with is_error
                                # set on some CLI versions. Resuming re-trips the
                                # same limit, so record it and stop — partial
                                # output (tags emitted before the limit) is kept.
                                result.stop_reason = subtype
                                if subtype != "error_max_turns":
                                    # Out of money is not a clean finish: a
                                    # re-attack or grader must not read it as
                                    # "attacked and found nothing".
                                    result.error = f"budget exhausted: {subtype}"
                                return result
                            if msg.get("is_error"):
                                detail = str(msg.get("result"))
                                if any(m in detail.lower() for m in _FATAL_MARKERS):
                                    result.error = f"non-retryable CLI error: {detail[:500]}"
                                    return result
                                raise RuntimeError(f"CLI result is_error: {detail}")
                            return result
                return None

            async def _attempt() -> AgentResult:
                """One CLI launch, start to process exit, under one deadline."""
                final = await _consume()
                if final is not None:
                    return final
                # Stream ended without a result message — wait for exit too:
                # a CLI that closes stdout but never exits must not hang us.
                rc = await proc.wait()
                if stderr_task:
                    try:
                        await asyncio.wait_for(stderr_task, 5)
                    except asyncio.TimeoutError:
                        pass
                raise RuntimeError(
                    f"CLI exited rc={rc} without result: "
                    f"{bytes(stderr_tail).decode(errors='replace')[-2000:]}"
                )

            try:
                remaining = deadline_at - time.monotonic()
                try:
                    final = await asyncio.wait_for(_attempt(), timeout=max(remaining, 0.001))
                except asyncio.TimeoutError:
                    await _stop(proc, container)
                    result.error = (f"deadline exceeded after "
                                    f"{time.monotonic() - started:.0f}s")
                    events.emit("agent.deadline", agent_label,
                                elapsed_s=time.monotonic() - started)
                    return result
                # An error stop (budget, no-tools violation, fatal CLI error)
                # must also kill the in-container CLI: terminating the host-side
                # exec client alone leaves it running and spending.
                await _stop(proc, container if final.error else None)
                return final

            except Exception as e:
                await _stop(proc)
                # 429 rate-limit, upstream 5xx, or CLI crash all surface here.
                # The attempt cap bounds wasted retries on a genuine bug.
                attempt += 1
                if result.session_id is None or attempt > max_resume_attempts:
                    # Can't resume without a session_id, or retries exhausted.
                    # Preserve partial transcript — don't re-raise.
                    result.error = f"{type(e).__name__} after {attempt} attempt(s): {e}"
                    return result
                # Backoff then resume. Cap at 300s — a sustained 5xx burst can
                # outlast shorter caps; 20 attempts × 300s ≈ 1h retry budget,
                # proportionate to overnight runs.
                backoff = min(2 ** attempt, 300)
                if time.monotonic() + backoff >= deadline_at:
                    result.error = f"deadline exceeded while retrying: {e}"
                    return result
                print(
                    f"[agent] {type(e).__name__} on attempt {attempt}, "
                    f"resuming session {result.session_id} in {backoff}s: {e}",
                    file=sys.stderr,
                )
                result.resume_count = attempt
                events.emit("agent.resume", agent_label, attempt=attempt,
                            error=str(e)[:300])
                await asyncio.sleep(backoff)
    finally:
        if holding:
            ledger.end_launch(held_cap, launch_cost)
        events.emit("agent.end", agent_label,
                    elapsed_s=time.monotonic() - started,
                    error=result.error, stop_reason=result.stop_reason,
                    resumes=result.resume_count, tool_calls=tool_call_count,
                    cost_usd=(result.result_message or {}).get("total_cost_usd"))
        if transcript_file:
            transcript_file.close()
