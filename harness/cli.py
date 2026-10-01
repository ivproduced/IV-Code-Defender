# Copyright 2026 IVProduced contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""CLI entrypoint.

  vuln-pipeline run <target> --model <model>                   # one find + grade cycle
  vuln-pipeline run <target> --model <m> --runs 8 --parallel   # 8 concurrent, round-robin focus areas
  vuln-pipeline run <target> --model <m> --auto-focus          # recon discovers focus areas first
  vuln-pipeline recon <target> --model <model>                 # standalone: print discovered areas
  vuln-pipeline dedup <results_dir>                            # group crashes by signature
  vuln-pipeline report <results_dir> --model <m> [--novelty]   # exploitability analysis per unique crash

Output: ./results/<target>/<timestamp>/{result.json,find_transcript.jsonl,
grade_transcript.jsonl,poc.bin}; reports → .../reports/bug_NN/

Auth: resolved by ``harness.auth`` (Bedrock / Vertex / ANTHROPIC_API_KEY /
CLAUDE_CODE_OAUTH_TOKEN — one required; see docs/agent-sandbox.md).
Model: --model flag, or VULN_PIPELINE_MODEL env var (required, one or the other).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path

from . import docker_ops, providers, sandbox, compliance
from .agent import color
from .artifacts import CrashArtifact, RunResult
from .asan import asan_excerpt, crash_reason, top_frame
from .config import TargetConfig
from .dedup import dedup
from .find import run_find, DEFAULT_FIND_MAX_TURNS
from .grade import run_grade
from .io_utils import (
    append_jsonl,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    exclusive_lock,
    ResultsLockError,
)
from .judge import run_judge, run_compare
from .profiles import is_web
from .novelty import upstream_log, crash_file_from_frame, NOVELTY_NOT_CHECKED
from .patch import run_patch, PATCH_MAX_TURNS, DEFAULT_MAX_ITERATIONS
from .recon import run_recon, RECON_MAX_TURNS
from .report import run_report, REPORT_MAX_TURNS
from .prompts.system_prompt import build_system_prompt
from .auth import (
    resolve_auth_env as _resolve_environment_auth,
    warn_bedrock_model as _warn_bedrock_model,
)


NO_AUTH_MSG = (
    "error: no auth found for the selected provider.\n"
    "  anthropic: ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN\n"
    "  bedrock:   AWS_* creds + --provider bedrock (CLAUDE_CODE_USE_BEDROCK)\n"
    "  vertex:    project, region, and GOOGLE_APPLICATION_CREDENTIALS + --provider vertex"
)
DEFAULT_MAX_PARALLEL = 4


async def _gather_bounded(coroutines, limit: int):
    """Gather coroutines while bounding live agent/container workflows."""
    semaphore = asyncio.Semaphore(limit)

    async def _one(coroutine):
        async with semaphore:
            return await coroutine

    return await asyncio.gather(
        *[_one(coroutine) for coroutine in coroutines],
        return_exceptions=True,
    )


def _resolve_auth_env(provider: str | None = None) -> dict[str, str] | None:
    """Resolve provider + auth for the in-container `claude -p` process. Returns
    the env dict set on the agent container at ``docker run`` time, or None if
    auth is missing.

    Anthropic precedence:
      1. ANTHROPIC_API_KEY            — long-lived key
      2. CLAUDE_CODE_OAUTH_TOKEN      — subscription-plan token

    Bedrock/Vertex authenticate through scoped cloud credentials. The same
    resolver is used by sandbox setup to derive the provider egress allowlist.
    """
    return _resolve_environment_auth(provider)


def _provider_name(provider: str | None) -> str:
    """Report the selected provider for both CLI and environment-based modes."""
    if provider is not None:
        return providers.resolve_provider(provider)
    if os.environ.get("CLAUDE_CODE_USE_BEDROCK") == "1":
        return "bedrock"
    if os.environ.get("CLAUDE_CODE_USE_VERTEX") == "1":
        return "vertex"
    return "anthropic"


def _resolve_target_dir(target: str) -> Path:
    """Accept either a name (looked up under ./targets/) or a direct path."""
    p = Path(target)
    if p.exists() and (p / "config.yaml").exists():
        return p.resolve()
    local = Path.cwd() / "targets" / target
    if local.exists() and (local / "config.yaml").exists():
        return local.resolve()
    raise FileNotFoundError(
        f"Target '{target}' not found. Looked at: {p}, {local}"
    )


def _terminate_subprocesses() -> None:
    """SIGKILL all direct children. The SDK's claude subprocess (Node) does not
    die when we do — it gets orphaned to init and keeps executing Bash tool
    calls against whatever container is named find_target. Observed running
    11+ hours after its parent died. Walk /proc, find PPID==us, kill.
    No-op on platforms without /proc (macOS); container cleanup in _on_signal
    still removes the targets the orphan would be exec'ing into."""
    if not os.path.isdir("/proc"):
        return
    me = os.getpid()
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            with open(f"/proc/{entry.name}/stat", "rb") as f:
                # stat format: pid (comm) state ppid ...  — comm can contain spaces/parens,
                # so split on the last ')' to safely get the fields after it.
                after_comm = f.read().rsplit(b")", 1)[1].split()
            ppid = int(after_comm[1])  # state=[0], ppid=[1]
            if ppid == me:
                os.kill(int(entry.name), signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
            pass


_current_container_token: str | None = None


def _container_scope(path: Path) -> str:
    """Stable, short namespace for every container belonging to one batch."""
    return hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:10]


def _container_name(
    phase: str, target_name: str, scope: str, index: int | None = None,
) -> str:
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "-", target_name)[:48] or "target"
    suffix = f"_{index}" if index is not None else ""
    return f"{phase}_{safe_target}_{scope}{suffix}"[:120]


def _set_container_cleanup_scope(target_name: str, scope: str) -> None:
    global _current_container_token
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "-", target_name)[:48] or "target"
    _current_container_token = f"_{safe_target}_{scope}"


def _on_signal(signum, frame) -> None:
    """Best-effort container cleanup on SIGTERM/SIGINT.

    find.py/grade.py/recon.py have finally: blocks that rm their containers, but
    finally only runs on Python exceptions — not on signals. Without this, a
    SIGTERM leaves containers orphaned (4GB memory reservation each) AND the
    SDK's Node subprocess orphaned to init, still executing tool calls against
    whatever container holds the name. Kill children first, then containers.
    Container names include a stable results-batch namespace, so cleanup
    matches only containers launched for this command and cannot remove a
    concurrent batch scanning the same target.
    """
    print(f"\n[cleanup] signal {signum} received, terminating subprocesses + removing containers", file=sys.stderr)
    _terminate_subprocesses()
    if _current_container_token:
        r = subprocess.run(
            docker_ops.command(
                "ps", "-q", "--filter", f"name={_current_container_token}"
            ),
            capture_output=True,
            text=True,
        )
        ids = r.stdout.split()
        if ids:
            subprocess.run(docker_ops.command("rm", "-f", *ids), capture_output=True)
    # Re-raise with default handling so exit code reflects the signal.
    signal.signal(signum, signal.SIG_DFL)
    signal.raise_signal(signum)


_RUN_TERMINAL = {"crash_found", "crash_rejected", "no_crash_found"}


def _load_run_checkpoint(out_dir: Path) -> RunResult | None:
    """Return a prior run's result if it reached a terminal status.

    agent_failed / build_failed / error are NOT terminal — resume retries them.
    Transcripts in result.json are slimmed to strings; reload as empty lists.
    """
    result = _load_run_result(out_dir)
    if result is None or result.status not in _RUN_TERMINAL:
        return None
    return result


def _load_run_result(out_dir: Path) -> RunResult | None:
    """Load any complete run result, including ``crash_ungraded``."""
    p = out_dir / "result.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    d["find_transcript"] = []
    d["grade_transcript"] = []
    try:
        return RunResult.from_dict(d)
    except (KeyError, TypeError, ValueError):
        return None


def _resume_layout_error(results_root: Path, runs: int) -> str | None:
    """Return an error string if --runs is incompatible with the on-disk layout
    of a --resume dir. out_dirs is [root] when runs==1 vs [root/run_NNN] when
    runs>1; mixing the two corrupts dedup/report."""
    n_existing = len(list(results_root.glob("run_[0-9][0-9][0-9]")))
    if n_existing and runs < (need := max(n_existing, 2)):
        return (f"--resume dir has {n_existing} run_* subdir(s) but --runs={runs}; "
                f"pass --runs {need} (or more to extend)")
    if not n_existing and runs > 1 and (results_root / "result.json").exists():
        return (f"--resume dir is a single-run layout (top-level result.json) "
                f"but --runs={runs}; pass --runs 1")
    return None


def _write_result(out_dir: Path, result: RunResult) -> None:
    # out_dir already exists (created before run_find); transcripts already
    # streamed to disk by run_agent. Only poc.bin and result.json left.

    # PoC bytes if we have them
    if result.crash:
        artifact_name = "replay.json" if is_web(result.crash.profile) else "poc.bin"
        atomic_write_bytes(out_dir / artifact_name, result.crash.poc_bytes)

    # result.json — strip transcripts to keep it readable (they're in the JSONLs)
    slim = result.to_dict()
    slim["find_transcript"] = f"see find_transcript.jsonl ({len(result.find_transcript)} messages)"
    slim["grade_transcript"] = f"see grade_transcript.jsonl ({len(result.grade_transcript)} messages)"
    # Pipeline-parsed classification: deterministic crash_type / severity /
    # operation. Sits alongside the agent-emitted crash_type so downstream
    # consumers can cross-check (the agent tag is free-text and fragments).
    if result.crash:
        if is_web(result.crash.profile):
            slim["crash"]["evidence_excerpt"] = _evidence_excerpt(result.crash)
        else:
            slim["crash"]["reason"] = crash_reason(result.crash.crash_output)
    atomic_write_json(out_dir / "result.json", slim)


async def _run_once(
    run_idx: int,
    target: TargetConfig,
    model: str,
    find_only: bool,
    max_turns: int,
    agent_env: dict[str, str],
    out_dir: Path,
    focus_area: str | None,
    found_bugs_path: Path | None,
    stream_ctx: dict | None = None,
    accept_dos: bool = False,
    system_prompt: str | None = None,
    container_scope: str = "default",
) -> RunResult:
    """One find(+grade) attempt. Assumes image is already built.

    Writes result.json to out_dir before returning — stragglers no longer
    block disk writes. If stream_ctx is set, also runs judge→report dispatch
    for graded crashes (passed or rejected) and appends any spawned report
    task to stream_ctx["report_tasks"].
    """
    timings: dict[str, float] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    find_container = _container_name("find", target.name, container_scope, run_idx)
    grade_container = _container_name("grader", target.name, container_scope, run_idx)

    def _done(result: RunResult) -> RunResult:
        _write_result(out_dir, result)
        return result

    # Merge static known_bugs with whatever siblings have already landed. The
    # read is best-effort — a missing or half-written file just yields fewer
    # entries, which is fine (the list is advisory).
    known_bugs = list(target.known_bugs)
    if found_bugs_path:
        known_bugs += _read_found_summaries(found_bugs_path)

    # ── Find ─────────────────────────────────────────────────────────────────────────────
    focus_note = f" (focus: {focus_area})" if focus_area else ""
    print(color(f"[find:{run_idx}] Starting find agent (model={model}, max_turns={max_turns}){focus_note} ...", "find"))
    try:
        crash, find_result, find_timings = await run_find(
            target, model=model, max_turns=max_turns, agent_env=agent_env,
            container_name=find_container, focus_area=focus_area,
            known_bugs=known_bugs,
            found_bugs_path=str(found_bugs_path) if found_bugs_path else None,
            transcript_path=str(out_dir / "find_transcript.jsonl"),
            progress_prefix=f"[find:{run_idx}]",
            accept_dos=accept_dos,
            system_prompt=system_prompt,
        )
    except Exception as e:
        traceback.print_exc()
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=None, verdict=None, timings=timings,
            error=f"find agent: {type(e).__name__}: {e}",
        ))
    timings.update(find_timings)
    find_transcript = find_result.transcript()
    resumes = f" ({find_result.resume_count} resume(s))" if find_result.resume_count else ""
    print(f"[find:{run_idx}] done in {timings.get('find', 0):.1f}s, {len(find_transcript)} messages{resumes}")

    # Agent died mid-run (ProcessError, retries exhausted). Transcript preserved.
    if find_result.error:
        print(f"[find:{run_idx}] Agent failed: {find_result.error}")
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=None, verdict=None,
            find_transcript=find_transcript, timings=timings,
            error=f"find agent: {find_result.error}",
        ))

    if crash is None:
        print(f"[find:{run_idx}] No crash artifact emitted.")
        return _done(RunResult(
            target=target.name, status="no_crash_found",
            crash=None, verdict=None,
            find_transcript=find_transcript, timings=timings,
        ))

    print(color(f"[find:{run_idx}] Crash claimed: {crash.crash_type} at {crash.poc_path} ({len(crash.poc_bytes)} bytes)", "red"))

    # <dup_check> is mandatory alongside <poc_path>. The agent makes the
    # judgment (it knows root cause, a regex can't), the pipeline enforces
    # that the judgment happened. Reject before jsonl write so an unchecked
    # crash doesn't pollute siblings' dedup context.
    if crash.dup_check is None:
        print(f"[find:{run_idx}] Rejected: missing <dup_check> tag.")
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=crash, verdict=None,
            find_transcript=find_transcript, timings=timings,
            error="find agent: <dup_check> tag missing — submission rejected",
        ))

    # Record it for siblings before grading — grading can take ~20min and a
    # concurrent agent shouldn't spend that window re-discovering the same bug.
    # Entries are framed as "claims" in the prompt, not confirmed crashes.
    if found_bugs_path:
        _append_found(found_bugs_path, crash, run_idx)

    if find_only:
        return _done(RunResult(
            target=target.name, status="crash_ungraded",
            crash=crash, verdict=None,
            find_transcript=find_transcript, timings=timings,
        ))

    # ── Grade ────────────────────────────────────────────────────────────────────
    print(color(f"[grade:{run_idx}] Starting grader agent in fresh container ...", "grade"))
    workspace = out_dir / "grade_workspace"
    try:
        verdict, grade_result, grade_elapsed = await run_grade(
            crash, target, model=model, workspace_dir=str(workspace), agent_env=agent_env,
            container_name=grade_container,
            transcript_path=str(out_dir / "grade_transcript.jsonl"),
            progress_prefix=f"[grade:{run_idx}]",
            system_prompt=system_prompt,
            accept_dos=accept_dos,
        )
    except Exception as e:
        traceback.print_exc()
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=crash, verdict=None,
            find_transcript=find_transcript, timings=timings,
            error=f"grade agent: {type(e).__name__}: {e}",
        ))
    timings["grade"] = grade_elapsed
    grade_transcript = grade_result.transcript()

    if grade_result.error:
        print(f"[grade:{run_idx}] Agent failed: {grade_result.error}")
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=crash, verdict=None,
            find_transcript=find_transcript, grade_transcript=grade_transcript,
            timings=timings, error=f"grade agent: {grade_result.error}",
        ))

    _gline = f"[grade:{run_idx}] done in {grade_elapsed:.1f}s: passed={verdict.passed}, score={verdict.score}"
    print(color(_gline, "bold") if verdict.passed else _gline)

    status = "crash_found" if verdict.passed else "crash_rejected"
    result = RunResult(
        target=target.name, status=status,
        crash=crash, verdict=verdict,
        find_transcript=find_transcript, grade_transcript=grade_transcript,
        timings=timings,
    )
    _write_result(out_dir, result)

    # ── Streaming: judge → report dispatch ───────────────────────────────────────
    # result.json is already on disk — errors here shouldn't clobber it. The
    # find+grade result is the ground truth; judge→report is downstream polish.
    if stream_ctx is not None:
        try:
            await _stream_dispatch(run_idx, target, model, agent_env, crash,
                                   status, verdict.score, stream_ctx)
        except Exception:
            traceback.print_exc()
            print(f"[judge:{run_idx}] stream dispatch failed — result.json preserved")

    return result


async def _grade_existing(
    run_idx: int,
    target: TargetConfig,
    model: str,
    agent_env: dict[str, str],
    out_dir: Path,
    previous: RunResult,
    stream_ctx: dict | None,
    system_prompt: str | None,
    container_scope: str,
    accept_dos: bool = False,
) -> RunResult:
    """Resume a find-only checkpoint at grade without rerunning discovery."""
    assert previous.crash is not None
    crash = previous.crash
    timings = dict(previous.timings)
    print(f"[resume] run_{run_idx:03d}: grading saved ungraded crash")
    try:
        verdict, grade_result, elapsed = await run_grade(
            crash,
            target,
            model=model,
            workspace_dir=str(out_dir / "grade_workspace"),
            agent_env=agent_env,
            container_name=_container_name(
                "grader", target.name, container_scope, run_idx
            ),
            transcript_path=str(out_dir / "grade_transcript.jsonl"),
            progress_prefix=f"[grade:{run_idx}]",
            system_prompt=system_prompt,
            accept_dos=accept_dos,
        )
    except Exception as exc:
        traceback.print_exc()
        result = RunResult(
            target=target.name, status="agent_failed", crash=crash, verdict=None,
            timings=timings, error=f"grade agent: {type(exc).__name__}: {exc}",
        )
        _write_result(out_dir, result)
        return result
    timings["grade"] = elapsed
    if grade_result.error:
        result = RunResult(
            target=target.name, status="agent_failed", crash=crash, verdict=None,
            grade_transcript=grade_result.transcript(), timings=timings,
            error=f"grade agent: {grade_result.error}",
        )
    else:
        status = "crash_found" if verdict.passed else "crash_rejected"
        result = RunResult(
            target=target.name, status=status, crash=crash, verdict=verdict,
            grade_transcript=grade_result.transcript(), timings=timings,
        )
    _write_result(out_dir, result)
    if stream_ctx is not None and result.verdict is not None:
        try:
            await _stream_dispatch(
                run_idx, target, model, agent_env, crash,
                result.status, result.verdict.score, stream_ctx,
            )
        except Exception:
            traceback.print_exc()
            print(f"[judge:{run_idx}] stream dispatch failed — result.json preserved")
    return result


async def _stream_dispatch(
    run_idx: int,
    target: TargetConfig,
    model: str,
    agent_env: dict[str, str],
    crash: CrashArtifact,
    grade_status: str,
    grade_score: float,
    ctx: dict,
) -> None:
    """Judge → maybe-report. Serialized on ctx["lock"] so two simultaneous
    arrivals don't both claim NEW for the same root cause. Report dispatch
    happens outside the lock (the slow part)."""
    reports_root: Path = ctx["reports_root"]
    reports_root.mkdir(parents=True, exist_ok=True)
    excerpt = _evidence_excerpt(crash)

    async with ctx["lock"]:
        manifest = _read_manifest(reports_root)
        print(color(f"[judge:{run_idx}] {len(manifest)} bug(s) in manifest ...", "judge"))
        jv, _jr, elapsed = await run_judge(
            asan_excerpt=excerpt, dup_check=crash.dup_check,
            grade_status=grade_status, grade_score=grade_score,
            poc_size=len(crash.poc_bytes),
            manifest_entries=manifest,
            model=model, image_tag=target.image_tag, agent_env=agent_env,
            container_name=_container_name(
                "judge", target.name, ctx["container_scope"], run_idx
            ),
            transcript_path=str(reports_root / f"judge_run{run_idx:03d}.jsonl"),
            progress_prefix=f"[judge:{run_idx}]",
            system_prompt=ctx["system_prompt"],
            profile=target.profile,
        )
        _jline = (f"[judge:{run_idx}] {jv.judgment} in {elapsed:.1f}s"
                  + (f" → bug_{jv.bug_id:02d}" if jv.bug_id is not None else ""))
        print(color(_jline, "red") if jv.judgment == "NEW" else _jline)

        if jv.judgment == "DUP_SKIP":
            _log_judge(reports_root, run_idx, jv, bug_id=jv.bug_id)
            return

        if jv.judgment == "NEW":
            bug_id = _next_bug_id(manifest)
            _append_manifest(reports_root, bug_id, run_idx, excerpt, target.profile)
        else:  # DUP_BETTER
            bug_id = jv.bug_id
            assert bug_id is not None  # _parse_judge enforces
        _log_judge(reports_root, run_idx, jv, bug_id=bug_id)

    # Lock released. Reports for different bugs can run in parallel; reports
    # for one bug must finish in judge order before replacing its canonical
    # report or comparing a DUP_BETTER candidate.
    _queue_stream_report(
        run_idx, bug_id, crash, target, model, agent_env, ctx,
        re_report=(jv.judgment == "DUP_BETTER"),
    )


def _queue_stream_report(
    run_idx: int, bug_id: int, crash: CrashArtifact,
    target: TargetConfig, model: str, agent_env: dict[str, str], ctx: dict,
    *, re_report: bool,
) -> None:
    previous = ctx["report_tails"].get(bug_id)

    async def _queued():
        if previous is not None:
            await asyncio.gather(previous, return_exceptions=True)
        async with ctx["agent_semaphore"]:
            return await _stream_report(
                run_idx, bug_id, crash, target, model, agent_env,
                ctx["reports_root"], re_report=re_report,
                novelty=ctx["novelty"], max_turns=ctx["report_max_turns"],
                system_prompt=ctx["system_prompt"],
                container_scope=ctx["container_scope"],
            )

    task = asyncio.create_task(_queued())
    ctx["report_tails"][bug_id] = task
    ctx["report_tasks"].append(task)


def _log_judge(reports_root: Path, run_idx: int, jv, bug_id: int | None) -> None:
    reports_root.mkdir(parents=True, exist_ok=True)
    append_jsonl(reports_root / "judge_log.jsonl", {
        "run_idx": run_idx, "judgment": jv.judgment, "bug_id": bug_id,
        "reasoning": jv.reasoning,
    })


def _judged_runs(reports_root: Path) -> set[int]:
    """run_idx values that already passed through _stream_dispatch — the
    idempotence key for --resume --stream replay (one judge_log line per run,
    including DUP_SKIPs)."""
    p = reports_root / "judge_log.jsonl"
    seen: set[int] = set()
    if not p.exists():
        return seen
    for line in p.read_text().splitlines():
        try:
            seen.add(json.loads(line)["run_idx"])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return seen


def _repair_judge_log_from_manifest(reports_root: Path) -> None:
    """Recover NEW decisions persisted just before their judge-log write."""
    manifest = reports_root / "manifest.jsonl"
    if not manifest.exists():
        return
    judged = _judged_runs(reports_root)
    for line in manifest.read_text().splitlines():
        try:
            entry = json.loads(line)
            run_idx, bug_id = entry["run_idx"], entry["bug_id"]
            if (not isinstance(run_idx, int) or not isinstance(bug_id, int)
                    or run_idx in judged):
                continue
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        append_jsonl(reports_root / "judge_log.jsonl", {
            "run_idx": run_idx, "judgment": "NEW", "bug_id": bug_id,
            "reasoning": "recovered NEW decision from manifest",
        })
        judged.add(run_idx)


def _pending_stream_reports(reports_root: Path) -> list[dict]:
    """Recover judged report jobs that did not finish before interruption."""
    log = reports_root / "judge_log.jsonl"
    if not log.exists():
        return []
    jobs: list[tuple[dict, bool]] = []
    seen: set[int] = set()
    for line in log.read_text().splitlines():
        try:
            entry = json.loads(line)
            run_idx, bug_id = entry["run_idx"], entry["bug_id"]
            if (entry["judgment"] not in {"NEW", "DUP_BETTER"}
                    or not isinstance(run_idx, int)
                    or not isinstance(bug_id, int)
                    or run_idx in seen):
                continue
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        seen.add(run_idx)
        jobs.append((entry, _stream_report_complete(reports_root, run_idx, bug_id)))
    # A later completed DUP_BETTER report supersedes an earlier failed job for
    # the same bug. Replaying the old job would replace newer canonical work.
    completed_later: set[int] = set()
    pending: list[dict] = []
    for entry, complete in reversed(jobs):
        bug_id = entry["bug_id"]
        if complete:
            completed_later.add(bug_id)
        elif bug_id not in completed_later:
            pending.append(entry)
    return list(reversed(pending))


def _stream_report_complete(reports_root: Path, run_idx: int, bug_id: int) -> bool:
    bug_dir = reports_root / f"bug_{bug_id:02d}"
    attempt = bug_dir / f"report_run{run_idx:03d}.json"
    if attempt.exists():
        try:
            report = json.loads(attempt.read_text())
            return (report.get("status") == "report_submitted"
                    and report.get("stream_complete") is True)
        except (OSError, json.JSONDecodeError):
            return False
    # Results created before per-run completion records existed are complete
    # when their submitted report is present in the canonical or versioned set.
    for path in [bug_dir / "report.json", *bug_dir.glob("report_v*.json")]:
        try:
            report = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if (report.get("from_run") == run_idx
                and report.get("status") == "report_submitted"):
            return True
    return False


async def _stream_report(
    run_idx: int,
    bug_id: int,
    crash: CrashArtifact,
    target: TargetConfig,
    model: str,
    agent_env: dict[str, str],
    reports_root: Path,
    re_report: bool,
    novelty: bool,
    max_turns: int,
    system_prompt: str | None,
    container_scope: str,
) -> dict:
    """Generate one report candidate, then publish a canonical report."""
    out_dir = reports_root / f"bug_{bug_id:02d}"
    out_dir.mkdir(parents=True, exist_ok=True)
    attempt_path = out_dir / f"report_run{run_idx:03d}.json"
    candidate: dict | None = None
    if attempt_path.exists():
        try:
            saved = json.loads(attempt_path.read_text())
            if saved.get("status") == "report_submitted" and saved.get("report"):
                candidate = saved
        except (OSError, json.JSONDecodeError):
            pass
    if candidate is not None and candidate.get("stream_complete") is True:
        return candidate

    if candidate is None:
        frame = top_frame(crash.crash_output) or ""
        crash_file = crash_file_from_frame(frame)
        log = None
        # Web replay evidence has no trustworthy source-file attribution yet.
        if novelty and not is_web(target.profile):
            print(f"[report:{run_idx}→bug_{bug_id:02d}] novelty: fetching upstream log for {crash_file or '?'} ...")
            log = upstream_log(target.github_url, target.commit,
                               crash_file or "", max_bytes=2000)

        print(color(f"[report:{run_idx}→bug_{bug_id:02d}] starting ({len(crash.poc_bytes)}B PoC) ...", "report"))
        try:
            verdict, report_text, result, elapsed = await run_report(
                crash, target, model=model,
                workspace_dir=str(out_dir / "workspace"),
                upstream_log=log, crash_file=crash_file,
                agent_env=agent_env,
                container_name=_container_name(
                    "report", target.name, container_scope, run_idx
                ),
                max_turns=max_turns,
                transcript_path=str(out_dir / f"report_transcript_run{run_idx:03d}.jsonl"),
                progress_prefix=f"[report:{run_idx}→bug_{bug_id:02d}]",
                system_prompt=system_prompt,
            )
        except Exception as e:
            traceback.print_exc()
            failure = {"bug_id": bug_id, "from_run": run_idx,
                       "status": "agent_failed",
                       "error": f"{type(e).__name__}: {e}"}
            atomic_write_json(attempt_path, failure)
            return failure

        status = "report_submitted" if verdict and report_text else "no_report"
        if result.error:
            status = "agent_failed"
        _rline = (f"[report:{run_idx}→bug_{bug_id:02d}] done in {elapsed:.1f}s: {status}"
                  + (f" rubric={verdict.rubric_score}/10 sev={verdict.severity_rating}"
                     if verdict else ""))
        print(color(_rline, "bold") if status == "report_submitted" else _rline)

        candidate = {
            "signature": {"crash_type": crash.crash_type, "top_frame": frame},
            "bug_id": bug_id, "from_run": run_idx, "status": status,
            "error": result.error, "elapsed": elapsed,
            "upstream_log": log if log else NOVELTY_NOT_CHECKED,
            "verdict": verdict.to_dict() if verdict else None,
            "report": report_text,
        }
        atomic_write_json(attempt_path, candidate)

    if candidate["status"] != "report_submitted":
        return candidate

    # Keep the existing canonical report intact until the candidate and any
    # comparison succeed. A failed replacement remains retryable on --resume.
    prior = _read_submitted_report(out_dir / "report.json")
    if prior and prior.get("from_run") == run_idx:
        prior = _latest_prior_report(out_dir, run_idx)
    winner = "B"
    reasoning = "first report for this bug"
    if re_report and prior and prior.get("report"):
        winner, reasoning, compare_result, elapsed = await run_compare(
            report_a=prior["report"], report_b=candidate["report"],
            model=model, image_tag=target.image_tag, agent_env=agent_env,
            container_name=_container_name(
                "compare", target.name, container_scope, run_idx
            ),
            transcript_path=str(out_dir / f"compare_run{run_idx:03d}.jsonl"),
            progress_prefix=f"[compare:{run_idx}→bug_{bug_id:02d}]",
            system_prompt=system_prompt,
        )
        if compare_result.error:
            raise RuntimeError(f"compare agent failed: {compare_result.error}")
        print(f"[compare:{run_idx}→bug_{bug_id:02d}] canonical={winner} in {elapsed:.1f}s")

    if winner == "B":
        current = _read_submitted_report(out_dir / "report.json")
        if current and current.get("from_run") != run_idx:
            _archive_report(out_dir, current)
        _write_report_json(out_dir, candidate)
    if re_report and prior:
        atomic_write_json(out_dir / "canonical.json", {
            "winner": winner, "reasoning": reasoning,
            "a": f"run_{prior.get('from_run', 'unknown')}",
            "b": f"run_{run_idx:03d}",
        })
    candidate["stream_complete"] = True
    atomic_write_json(attempt_path, candidate)
    return candidate


def _read_submitted_report(path: Path) -> dict | None:
    try:
        report = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return report if report.get("status") == "report_submitted" else None


def _latest_prior_report(out_dir: Path, run_idx: int) -> dict | None:
    versions = sorted(
        out_dir.glob("report_v*.json"),
        key=lambda path: int(path.stem.removeprefix("report_v"))
        if path.stem.removeprefix("report_v").isdigit() else -1,
        reverse=True,
    )
    for path in versions:
        report = _read_submitted_report(path)
        if report and report.get("from_run") != run_idx:
            return report
    return None


def _archive_report(out_dir: Path, report: dict) -> None:
    for path in out_dir.glob("report_v*.json"):
        if _read_submitted_report(path) == report:
            return
    n = 1
    while (out_dir / f"report_v{n}.json").exists():
        n += 1
    atomic_write_json(out_dir / f"report_v{n}.json", report)


def _assigned_focus(i: int, focus_areas: list[str]) -> str | None:
    if not focus_areas:
        return None
    return focus_areas[i % len(focus_areas)]


# ── found_bugs.jsonl: runtime bug-sharing ───────────────────────────────────────


def _evidence_excerpt(crash: CrashArtifact) -> str:
    if not is_web(crash.profile):
        return asan_excerpt(crash.crash_output)
    evidence = crash.evidence_bundle or {}
    if not evidence and crash.replay_manifest:
        evidence = crash.replay_manifest.get("evidence") or {}
    signal = crash.detection_signal or ""
    return json.dumps(
        {"finding_type": crash.crash_type, "evidence": evidence, "detection_signal": signal},
        sort_keys=True,
    )[:4000]


def _seed_found_bugs(path: Path, known_bugs: list[str]) -> None:
    """Seed the jsonl with config known_bugs so a mid-run `cat` is a
    complete view, not just peer discoveries. System-prompt attention fades
    at high turn counts; the cat check doesn't."""
    atomic_write_text(
        path,
        "".join(
            json.dumps({"source": "config", "summary": kb}) + "\n"
            for kb in known_bugs
        ),
    )


def _append_found(path: Path, crash: CrashArtifact, run_idx: int) -> None:
    # Raw ASAN excerpt — SUMMARY line + first stack frames. Agents parse the
    # signature themselves; the pipeline doesn't pre-canonicalize crash_type or
    # top_frame anymore (that was a fragility point — adjacent lines, format
    # variance, free-text agent tags all fragmented the dedup).
    entry = {"run_idx": run_idx}
    entry["evidence_excerpt" if is_web(crash.profile) else "asan_excerpt"] = _evidence_excerpt(crash)
    append_jsonl(path, entry)


def _read_found_summaries(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Config-seeded entries are prose; runtime entries carry ASAN excerpts.
        out.append(d.get("asan_excerpt") or d.get("evidence_excerpt") or d.get("summary") or "")
    return [s for s in out if s]


# ── reports/manifest.jsonl: streaming-mode judge context ─────────────────────────

def _read_manifest(reports_root: Path) -> list[dict]:
    """Manifest entries with existing report text attached if it's landed."""
    mf = reports_root / "manifest.jsonl"
    if not mf.exists():
        return []
    entries: list[dict] = []
    for line in mf.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        rp = reports_root / f"bug_{e['bug_id']:02d}" / "report.json"
        if rp.exists():
            try:
                e["report_text"] = json.loads(rp.read_text()).get("report", "")
            except (OSError, json.JSONDecodeError):
                e["report_text"] = None
        else:
            e["report_text"] = None
        entries.append(e)
    return entries


def _next_bug_id(entries: list[dict]) -> int:
    if not entries:
        return 0
    return max(e["bug_id"] for e in entries) + 1


def _append_manifest(reports_root: Path, bug_id: int, run_idx: int,
                     excerpt: str, profile: str = "cpp_asan") -> None:
    reports_root.mkdir(parents=True, exist_ok=True)
    append_jsonl(reports_root / "manifest.jsonl", {
        "bug_id": bug_id, "run_idx": run_idx, "profile": profile,
        ("evidence_excerpt" if is_web(profile) else "asan_excerpt"): excerpt,
    })


async def _run_all(
    target: TargetConfig,
    args,
    agent_env: dict[str, str],
    results_root: Path,
) -> list[tuple[Path, RunResult]]:
    """Build once, optionally recon, then dispatch N find+grade cycles."""
    system_prompt = build_system_prompt(args.engagement_context)
    container_scope = _container_scope(results_root)

    # ── Build (once, shared by all runs) ──────────────────────────────────────────
    print(color(f"[build] Building {target.image_tag} from {target.dockerfile_dir} ...", "dim"))
    t0 = time.time()
    try:
        docker_ops.build(target.dockerfile_dir, target.image_tag)
    except Exception as e:
        results_root.mkdir(parents=True, exist_ok=True)
        err = RunResult(
            target=target.name, status="build_failed",
            crash=None, verdict=None,
            error=f"{type(e).__name__}: {e}",
        )
        return [(results_root, err)]
    target_image_id = docker_ops.image_id(target.image_tag)
    print(f"[build] done in {time.time() - t0:.1f}s ({target_image_id[:23]})")

    metadata_error = _record_or_verify_batch_image(
        results_root, target, target_image_id, is_resume=bool(args.resume)
    )
    if metadata_error:
        err = RunResult(
            target=target.name, status="build_failed", crash=None, verdict=None,
            error=metadata_error,
        )
        return [(results_root, err)]
    # Never dereference the mutable configured tag again during this batch.
    # Concurrent batches may rebuild that tag; the image ID remains immutable.
    frozen_tag = _freeze_target_image(target, target_image_id)
    target = replace(target, image_tag=frozen_tag)

    # ── Focus areas (optional auto-discover via recon) ───────────────────────────
    # focus_areas.json is the checkpoint of record: written on every fresh run,
    # read on every resume regardless of --auto-focus, so a resumed run_NNN gets
    # the same i % len() assignment as the original.
    results_root.mkdir(parents=True, exist_ok=True)
    focus_areas = list(target.focus_areas)
    focus_ckpt = results_root / "focus_areas.json"
    if args.resume and focus_ckpt.exists():
        try:
            focus_areas = json.loads(focus_ckpt.read_text())
            print(f"[resume] {len(focus_areas)} focus area(s) from {focus_ckpt}\n")
        except (OSError, json.JSONDecodeError):
            print(f"[resume] {focus_ckpt} unreadable; falling back to config.yaml list\n")
            focus_ckpt.unlink(missing_ok=True)
    elif args.auto_focus:
        print(color("[recon] Auto-discovering focus areas ...", "recon"))
        discovered, _ = await run_recon(
            target, model=args.model, agent_env=agent_env,
            max_turns=args.recon_max_turns,
            transcript_path=str(results_root / "recon_transcript.jsonl"),
            system_prompt=system_prompt,
            container_name=_container_name(
                "recon", target.name, container_scope
            ),
        )
        if discovered:
            focus_areas = discovered
            print(color(f"[recon] Discovered {len(discovered)} focus area(s):", "bold"))
            for a in discovered:
                print(color(f"  - {a}", "bold"))
        else:
            print("[recon] No focus areas discovered; using config.yaml list")
        print()
    if not focus_ckpt.exists():
        atomic_write_json(focus_ckpt, focus_areas)

    # ── Dispatch ─────────────────────────────────────────────────────────────────────────────
    out_dirs = [results_root if args.runs == 1 else results_root / f"run_{i:03d}"
                for i in range(args.runs)]
    # Checkpoint: skip runs whose result.json already landed with a terminal
    # status. agent_failed/error are retried.
    checkpoints: dict[int, RunResult] = {}
    ungraded: dict[int, RunResult] = {}
    if args.resume:
        for i, d in enumerate(out_dirs):
            r = _load_run_result(d)
            if r is None:
                continue
            if r.status in _RUN_TERMINAL or (
                args.find_only and r.status == "crash_ungraded"
            ):
                checkpoints[i] = r
            elif r.status == "crash_ungraded" and r.crash is not None:
                ungraded[i] = r
        if checkpoints:
            print(f"[resume] {len(checkpoints)}/{args.runs} run(s) already terminal "
                  f"({', '.join(f'run_{i:03d}' for i in sorted(checkpoints))}); skipping")
        if ungraded:
            print(f"[resume] {len(ungraded)} saved crash(es) will continue at grade")
    # Shared file for runtime bug-sharing. Only wire it up for multi-run — a
    # solo agent has no siblings and the concurrent-agents prompt section would
    # just be noise. Absolute path: the agent's cwd is /tmp (find.py), not here.
    found_bugs_path = (results_root / "found_bugs.jsonl").absolute() if args.runs > 1 else None
    if found_bugs_path and not (args.resume and found_bugs_path.exists()):
        _seed_found_bugs(found_bugs_path, target.known_bugs)

    # Streaming: shared judge lock + reports root + task sink. Serialized
    # judge calls mean two simultaneous grade-passes don't both claim NEW for
    # the same bug; report dispatch happens outside the lock.
    stream_ctx: dict | None = None
    judged: set[int] = set()
    if args.stream:
        stream_ctx = {
            "lock": asyncio.Lock(),
            "agent_semaphore": asyncio.Semaphore(args.max_parallel),
            "reports_root": results_root / "reports",
            "report_tasks": [],
            "report_tails": {},
            "novelty": args.novelty,
            "report_max_turns": args.report_max_turns,
            "system_prompt": system_prompt,
            "container_scope": container_scope,
        }
        if args.resume:
            _repair_judge_log_from_manifest(stream_ctx["reports_root"])
            judged = _judged_runs(stream_ctx["reports_root"])
            for entry in _pending_stream_reports(stream_ctx["reports_root"]):
                run_idx = entry["run_idx"]
                if run_idx >= len(out_dirs):
                    print(f"[resume] report run_{run_idx:03d} is outside --runs={args.runs}")
                    continue
                saved = _load_run_result(out_dirs[run_idx])
                if saved is None or saved.crash is None:
                    print(f"[resume] report run_{run_idx:03d} has no saved crash")
                    continue
                print(f"[resume] retrying report for run_{run_idx:03d}")
                _queue_stream_report(
                    run_idx, entry["bug_id"], saved.crash, target,
                    args.model, agent_env, stream_ctx,
                    re_report=(entry["judgment"] == "DUP_BETTER"),
                )

    async def _checkpointed(i: int) -> RunResult:
        r = checkpoints[i]
        # Replay graded crashes through judge→report so a kill between
        # _write_result and _stream_dispatch doesn't strand them. judge_log
        # is the per-run idempotence key.
        if (stream_ctx is not None and r.crash is not None
                and r.verdict is not None and i not in judged):
            try:
                await _stream_dispatch(i, target, args.model, agent_env, r.crash,
                                       r.status, r.verdict.score, stream_ctx)
            except Exception:
                traceback.print_exc()
                print(f"[judge:{i}] stream dispatch failed — result.json preserved")
        return r

    def _task(i: int):
        if i in checkpoints:
            return _checkpointed(i)
        if i in ungraded:
            return _grade_existing(
                i, target, args.model, agent_env, out_dirs[i], ungraded[i],
                stream_ctx, system_prompt, container_scope, args.accept_dos,
            )
        return _run_once(i, target, args.model, args.find_only, args.max_turns, agent_env,
                         out_dirs[i], _assigned_focus(i, focus_areas), found_bugs_path,
                         stream_ctx, accept_dos=args.accept_dos, system_prompt=system_prompt,
                         container_scope=container_scope)

    if args.parallel:
        n_live = args.runs - len(checkpoints)
        print(f"[dispatch] Launching {n_live} run(s), at most {args.max_parallel} concurrently"
              f"{' (streaming judge→report)' if args.stream else ''} ...\n")
        semaphore = (
            stream_ctx["agent_semaphore"] if stream_ctx is not None
            else asyncio.Semaphore(args.max_parallel)
        )

        async def _bounded_task(i: int):
            async with semaphore:
                return await _task(i)

        raw = await asyncio.gather(*[_bounded_task(i) for i in range(args.runs)],
                                   return_exceptions=True)
        results: list[RunResult] = []
        for r in raw:
            if isinstance(r, BaseException):
                results.append(RunResult(
                    target=target.name, status="error",
                    crash=None, verdict=None,
                    error=f"{type(r).__name__}: {r}",
                ))
            else:
                results.append(r)
    else:
        results = []
        for i in range(args.runs):
            if i in checkpoints:
                results.append(await _checkpointed(i))
                continue
            print(f"── Run {i + 1}/{args.runs} ──────────────────────────────────────────")
            try:
                r = await _task(i)
            except Exception as e:
                traceback.print_exc()
                r = RunResult(
                    target=target.name, status="error",
                    crash=None, verdict=None,
                    error=f"{type(e).__name__}: {e}",
                )
            results.append(r)

    # Await any report agents spawned during streaming so `run` doesn't exit
    # with orphaned report containers. Errors are captured, not raised.
    if stream_ctx and stream_ctx["report_tasks"]:
        print(f"\n[dispatch] Waiting on {len(stream_ctx['report_tasks'])} report agent(s) ...")
        await asyncio.gather(*stream_ctx["report_tasks"], return_exceptions=True)

    return list(zip(out_dirs, results))


def _record_or_verify_batch_image(
    results_root: Path,
    target: TargetConfig,
    target_image_id: str,
    *,
    is_resume: bool,
) -> str | None:
    """Pin a batch to the exact target image used for discovery and grading."""
    metadata_path = results_root / "batch_metadata.json"
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return f"batch metadata is unreadable: {exc}"
        return _batch_metadata_mismatch(metadata, target, target_image_id, "resume")

    atomic_write_json(metadata_path, {
        "schema_version": 1,
        "target": target.name,
        "target_image_tag": target.image_tag,
        "target_image_id": target_image_id,
        "source_commit": target.commit,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "legacy_resume_without_prior_metadata": is_resume,
    })
    if is_resume:
        print(
            "[resume] warning: legacy batch had no image metadata; "
            "pinning it to the current build"
        )
    return None


def _batch_metadata_mismatch(
    metadata: object, target: TargetConfig, image_id: str, context: str
) -> str | None:
    """Reject a batch created for another target, source commit, or image."""
    if not isinstance(metadata, dict):
        return "batch metadata must be a JSON object"
    for field, current in (
        ("target", target.name),
        ("source_commit", target.commit),
        ("target_image_id", image_id),
    ):
        expected = metadata.get(field)
        if expected != current:
            label = "image" if field == "target_image_id" else field.replace("_", " ")
            return (
                f"{context} {label} mismatch: batch used {expected!r}, "
                f"current target uses {current!r}"
            )
    return None


def _pin_target_for_existing_batch(
    results_root: Path, target: TargetConfig
) -> tuple[TargetConfig | None, str | None]:
    """Resolve a standalone report/patch command to the batch's exact image."""
    if not docker_ops.image_exists(target.image_tag):
        print(f"[build] Building {target.image_tag} ...")
        docker_ops.build(target.dockerfile_dir, target.image_tag)
    current_id = docker_ops.image_id(target.image_tag)
    metadata_path = results_root / "batch_metadata.json"
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"batch metadata is unreadable: {exc}"
        if error := _batch_metadata_mismatch(metadata, target, current_id, "batch"):
            return None, error
    frozen_tag = _freeze_target_image(target, current_id)
    return replace(target, image_tag=frozen_tag), None


def _freeze_target_image(target: TargetConfig, image_id: str) -> str:
    """Give a content-addressed local image a batch-stable Docker reference."""
    digest = image_id.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError(f"invalid target image ID: {image_id!r}")
    safe_name = (
        re.sub(r"[^a-z0-9._-]+", "-", target.name.lower()).strip("-")
        or "target"
    )
    frozen_tag = f"vuln-pipeline-frozen-{safe_name}:{digest}"
    return docker_ops.tag(image_id, frozen_tag)


def main() -> int:
    # Line-buffer stdout so progress prints appear immediately when piped/
    # redirected (Python block-buffers by default when not a TTY).
    sys.stdout.reconfigure(line_buffering=True)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    parser = argparse.ArgumentParser(prog="vuln-pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run find+grade against a target")
    p_run.add_argument("target", help="Target name (under ./targets/) or path to target dir")
    p_run.add_argument("--find-only", action="store_true", help="Skip grade stage")
    p_run.add_argument("--runs", type=int, default=1, help="Number of independent runs")
    p_run.add_argument("--parallel", action="store_true",
                       help="Run multiple --runs concurrently")
    p_run.add_argument(
        "--max-parallel",
        type=int,
        default=int(os.environ.get(
            "VULN_PIPELINE_MAX_PARALLEL", str(DEFAULT_MAX_PARALLEL)
        )),
        help="Maximum concurrent agent containers with --parallel (default 4)",
    )
    p_run.add_argument("--auto-focus", dest="auto_focus", action="store_true",
                       help="Run recon agent to auto-discover focus areas (overrides config.yaml)")
    p_run.add_argument("--max-turns", type=int, default=DEFAULT_FIND_MAX_TURNS,
                       help=f"Find-agent turn budget (default {DEFAULT_FIND_MAX_TURNS})")
    p_run.add_argument("--recon-max-turns", type=int, default=RECON_MAX_TURNS,
                       help=f"Recon-agent turn budget for --auto-focus (default {RECON_MAX_TURNS})")
    p_run.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                       help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_run.add_argument("--provider", default=os.environ.get("VULN_PIPELINE_PROVIDER"),
                       choices=providers.FLEET_PROVIDERS,
                       help="Model provider: anthropic (default), bedrock, vertex")
    p_run.add_argument("--results-dir", default="./results", help="Output root")
    p_run.add_argument("--resume", type=Path, default=None, metavar="DIR",
                       help="Resume a partially-completed batch dir (results/<target>/<ts>/). "
                            "Runs whose result.json reached a terminal status are skipped; "
                            "crash_ungraded runs continue at grade; agent_failed/error runs "
                            "are retried. found_bugs.jsonl and "
                            "focus_areas.json are reused, not re-seeded.")
    p_run.add_argument("--stream", action="store_true",
                       help="Stream judge→report as each grade lands. First report shows up "
                            "in minutes, not hours; stragglers don't block disk writes. "
                            "Recommended. Off by default for batch-mode compatibility.")
    p_run.add_argument("--accept-dos", dest="accept_dos", action="store_true",
                       help="Benchmark mode — DoS-class crashes (allocation-size-too-big, "
                            "stack exhaustion, alloc-driven null-derefs) count as valid "
                            "finds; agents won't skip them hunting for memory corruption")
    p_run.add_argument("--novelty", action="store_true",
                       help="(--stream only) Enable host-side upstream novelty check for reports. "
                            "Clones github_url; off by default for air-gapped environments.")
    p_run.add_argument("--report-max-turns", type=int, default=REPORT_MAX_TURNS,
                       help=f"(--stream only) Report-agent turn budget (default {REPORT_MAX_TURNS})")
    p_run.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                       action="store_true",
                       help="Spawn agents under plain runc with no syscall isolation. The "
                            "shipped path is `bin/vp-sandboxed` (gVisor); see "
                            "docs/agent-sandbox.md. Development on a throwaway VM only.")
    p_run.add_argument("--engagement-context", type=Path, default=None,
                       help="Path to an authorization/engagement-scope file injected into the "
                            "agent system prompt. Defaults to a built-in authorized-security-"
                            "research block. Use to supply org-specific scope/disclosure context.")

    p_recon = sub.add_parser("recon", help="Auto-discover focus areas by exploring target source")
    p_recon.add_argument("target", help="Target name (under ./targets/) or path to target dir")
    p_recon.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                         help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_recon.add_argument("--provider", default=os.environ.get("VULN_PIPELINE_PROVIDER"),
                       choices=providers.FLEET_PROVIDERS,
                       help="Model provider: anthropic (default), bedrock, vertex")
    p_recon.add_argument("--max-turns", type=int, default=RECON_MAX_TURNS,
                         help=f"Recon-agent turn budget (default {RECON_MAX_TURNS})")
    p_recon.add_argument("--engagement-context", type=Path, default=None,
                         help="Path to an authorization/engagement-scope file (see `run --help`)")
    p_recon.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                         action="store_true", help="See `run --help`.")

    p_dedup = sub.add_parser("dedup", help="Group crashes under a results dir by signature")
    p_dedup.add_argument("results_dir", type=Path,
                         help="Directory to walk for result.json files (e.g. results/<target>/)")

    p_report = sub.add_parser("report",
                              help="Generate exploitability reports for unique crashes under a results dir")
    p_report.add_argument("results_dir", type=Path,
                          help="Batch directory (results/<target>/<timestamp>/)")
    p_report.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                          help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_report.add_argument("--provider", default=os.environ.get("VULN_PIPELINE_PROVIDER"),
                       choices=providers.FLEET_PROVIDERS,
                       help="Model provider: anthropic (default), bedrock, vertex")
    p_report.add_argument("--parallel", action="store_true",
                          help="Run report agents concurrently")
    p_report.add_argument(
        "--max-parallel", type=int, default=DEFAULT_MAX_PARALLEL,
        help=f"Maximum concurrent report workflows (default {DEFAULT_MAX_PARALLEL})",
    )
    p_report.add_argument("--max-turns", type=int, default=REPORT_MAX_TURNS,
                          help=f"Report-agent turn budget (default {REPORT_MAX_TURNS})")
    p_report.add_argument("--only-passed", action="store_true",
                          help="Skip groups where no run passed grading (default: include crash_rejected)")
    p_report.add_argument("--novelty", action="store_true",
                          help="Enable host-side upstream novelty check (clones github_url; "
                               "default off — air-gapped and restricted environments won't need this)")
    p_report.add_argument("--targets-dir", type=Path, default=Path("targets"),
                          help="Where to find target config dirs (default: ./targets)")
    p_report.add_argument("--fresh", action="store_true",
                          help="Ignore existing bug_NN/report.json checkpoints and re-report "
                               "every group. Default: skip groups already at report_submitted.")
    p_report.add_argument("--engagement-context", type=Path, default=None,
                          help="Path to an authorization/engagement-scope file (see `run --help`)")
    p_report.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                          action="store_true", help="See `run --help`.")

    p_patch = sub.add_parser("patch",
                             help="Generate and verify a fix for each unique crash under a results dir")
    p_patch.add_argument("results_dir", type=Path,
                         help="Batch directory (results/<target>/<timestamp>/)")
    p_patch.add_argument("--bug", type=int, default=None,
                         help="Only patch bug_NN (default: all)")
    p_patch.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                         help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_patch.add_argument("--provider", default=os.environ.get("VULN_PIPELINE_PROVIDER"),
                       choices=providers.FLEET_PROVIDERS,
                       help="Model provider: anthropic (default), bedrock, vertex")
    p_patch.add_argument("--parallel", action="store_true",
                         help="Run patch agents concurrently")
    p_patch.add_argument(
        "--max-parallel", type=int, default=DEFAULT_MAX_PARALLEL,
        help=f"Maximum concurrent patch workflows (default {DEFAULT_MAX_PARALLEL})",
    )
    p_patch.add_argument("--max-turns", type=int, default=PATCH_MAX_TURNS,
                         help=f"Patch-agent turn budget per iteration (default {PATCH_MAX_TURNS})")
    p_patch.add_argument("--max-iterations", type=int, default=DEFAULT_MAX_ITERATIONS,
                         help=f"Fix↔grade iteration cap (default {DEFAULT_MAX_ITERATIONS})")
    p_patch.add_argument("--no-reattack", action="store_true",
                         help="Skip the re-attack tier (T0-T2 only)")
    p_patch.add_argument("--style", action="store_true",
                         help="Run the advisory T3 style judge")
    p_patch.add_argument("--targets-dir", type=Path, default=Path("targets"),
                         help="Where to find target config dirs (default: ./targets)")
    p_patch.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                         action="store_true", help="See `run --help`.")
    p_patch.add_argument("--engagement-context", type=Path, default=None,
                         help="Path to an authorization/engagement-scope file (see `run --help`)")

    p_oscal = sub.add_parser("oscal",
                             help="Export NIST 800-53 / OSCAL assessment-results JSON from reports")
    p_oscal.add_argument("results_dir", type=Path,
                         help="Batch directory containing reports/bug_*/report.json")
    p_oscal.add_argument("-o", "--out", type=Path, default=None,
                         help="Output path (default: <results_dir>/oscal.json)")

    args = parser.parse_args()

    if args.command in ("run", "recon", "report", "patch"):
        if err := sandbox.require(args.dangerously_no_sandbox):
            print(err, file=sys.stderr)
            return 1

    if args.command == "run":
        return _cmd_run(args)
    if args.command == "recon":
        return _cmd_recon(args)
    if args.command == "dedup":
        return _cmd_dedup(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "patch":
        return _cmd_patch(args)
    if args.command == "oscal":
        out = args.out or (args.results_dir / "oscal.json")
        doc = compliance.build_oscal(args.results_dir)
        n = len(doc["assessment-results"]["results"][0]["findings"])
        atomic_write_json(out, doc)
        print(f"  {n} finding(s) → {out}")
        return 0
    return 1


def _cmd_run(args) -> int:
    if args.runs < 1:
        print("error: --runs must be at least 1", file=sys.stderr)
        return 1
    if args.max_parallel < 1:
        print("error: --max-parallel must be at least 1", file=sys.stderr)
        return 1
    # Resolve target
    try:
        target_dir = _resolve_target_dir(args.target)
        target = TargetConfig.load(target_dir)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    agent_env = _resolve_auth_env(getattr(args, "provider", None))
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1

    # Model: required, via --model or env
    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model, getattr(args, "provider", None))

    print(f"Target: {target.name}")
    print(f"  image_tag:   {target.image_tag}")
    print(f"  model:       {args.model}")
    print(f"  provider:    {_provider_name(getattr(args, 'provider', None))}")
    print(f"  binary:      {target.binary_path}")
    print(f"  source_root: {target.source_root}")
    print(f"  max_turns:   {args.max_turns}")
    print(f"  runs:        {args.runs}{' (parallel)' if args.parallel else ''}")
    if args.parallel:
        print(f"  max_parallel:{args.max_parallel}")
    print(f"  find_only:   {args.find_only}")
    if target.focus_areas and not args.auto_focus:
        print(f"  focus_areas: {len(target.focus_areas)} configured")
    if args.auto_focus:
        print("  auto_focus:  True (recon will discover focus areas)")
    print()

    if args.resume:
        results_root = args.resume
        if not results_root.is_dir():
            print(f"error: --resume dir {results_root} does not exist", file=sys.stderr)
            return 1
        if (err := _resume_layout_error(results_root, args.runs)):
            print(f"error: {err}", file=sys.stderr)
            return 1
        print(f"  resume:      {results_root}")
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        results_root = Path(args.results_dir) / target.name / timestamp
        try:
            results_root.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            print(f"error: results directory collision: {results_root}", file=sys.stderr)
            return 1

    _set_container_cleanup_scope(target.name, _container_scope(results_root))

    try:
        with exclusive_lock(results_root / ".orchestrator.lock"):
            pairs = asyncio.run(_run_all(target, args, agent_env, results_root))
    except ResultsLockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("\n── Summary ────────────────────────────────────────────────────────────────────")
    exit_code = 0
    for i, (out_dir, result) in enumerate(pairs):
        # result.json was already written inside _run_once as each run
        # finished. Rewrite here only for the error-path entries gather
        # synthesized (those never hit _run_once's _done()).
        if result.status == "error":
            _write_result(out_dir, result)
        _sline = f"  run {i}: {result.status:16s} → {out_dir}/result.json"
        print(color(_sline, "red") if result.status == "crash_found" else _sline)
        if result.status != "crash_found":
            exit_code = 2
    if args.stream:
        reports = results_root / "reports"
        n = sum(1 for _ in reports.glob("bug_*/report.json")) if reports.exists() else 0
        print(f"  {n} report(s) → {reports}/")
    return exit_code


def _cmd_recon(args) -> int:
    try:
        target_dir = _resolve_target_dir(args.target)
        target = TargetConfig.load(target_dir)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    recon_scope = f"p{os.getpid()}"
    _set_container_cleanup_scope(target.name, recon_scope)

    agent_env = _resolve_auth_env(getattr(args, "provider", None))
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1

    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model, getattr(args, "provider", None))

    print(color(f"[build] Building {target.image_tag} ...", "dim", sys.stderr), file=sys.stderr)
    try:
        docker_ops.build(target.dockerfile_dir, target.image_tag)
    except Exception as e:
        print(f"error: build failed: {e}", file=sys.stderr)
        return 1

    print(color(f"[recon] Exploring {target.source_root} (model={args.model}) ...", "recon", sys.stderr), file=sys.stderr)
    areas, result = asyncio.run(run_recon(
        target, model=args.model, agent_env=agent_env, max_turns=args.max_turns,
        system_prompt=build_system_prompt(args.engagement_context),
        container_name=_container_name("recon", target.name, recon_scope),
    ))

    if result.error:
        print(f"error: recon agent failed: {result.error}", file=sys.stderr)
        return 1
    if not areas:
        print("error: recon agent produced no focus areas", file=sys.stderr)
        return 1

    # YAML fragment to stdout — paste directly into config.yaml
    print("focus_areas:")
    for a in areas:
        escaped = a.replace('"', '\\"')
        print(f'  - "{escaped}"')
    return 0


def _cmd_dedup(args) -> int:
    from .dedup import format_report
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    groups = dedup(root)
    print(format_report(groups, root), end="")
    return 0 if groups else 2


# ── report ───────────────────────────────────────────────────────────────────

_STATUS_ORDER = {"crash_found": 0, "crash_rejected": 1}


def _pick_representative(entries: list[tuple[Path, str, dict]]) -> tuple[Path, dict, dict]:
    """Pick the best result.json from a dedup group for the report agent.

    Prefer passed-grade > rejected, then highest grade score, then smallest PoC
    (cleaner to analyze). Returns (result_path, result_dict, crash_dict).
    Unreadable entries are skipped; ValueError if nothing is readable.
    """
    candidates: list[tuple[tuple[int, float, int, str], Path, dict, dict]] = []
    for path, status, _reason in entries:
        try:
            r = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        crash = r.get("crash")
        if not crash:
            continue
        score = (r.get("verdict") or {}).get("score") or 0.0
        poc_len = len(crash.get("poc_bytes") or "")
        key = (_STATUS_ORDER.get(status, 2), -score, poc_len, str(path))
        candidates.append((key, path, r, crash))

    if not candidates:
        raise ValueError("no readable result.json in group")
    _k, path, result, crash = min(candidates, key=lambda c: c[0])
    return path, result, crash


async def _report_one(
    idx: int,
    sig: tuple[str, str],
    entries: list[tuple[Path, str, dict]],
    target: TargetConfig,
    args,
    agent_env: dict[str, str],
    reports_root: Path,
    container_scope: str,
) -> dict:
    crash_type, frame = sig
    out_dir = reports_root / f"bug_{idx:02d}"
    out_dir.mkdir(parents=True, exist_ok=True)

    rep_path, _result, crash_dict = _pick_representative(entries)
    crash = CrashArtifact.from_dict(crash_dict)

    crash_file = crash_file_from_frame(frame)
    log = None
    if args.novelty and not is_web(target.profile):
        print(f"[report:{idx}] novelty: fetching upstream log for {crash_file or '?'} ...")
        log = upstream_log(target.github_url, target.commit,
                           crash_file or "", max_bytes=2000)

    print(color(f"[report:{idx}] {crash_type} in {frame} "
                f"(from {rep_path.parent.name}, {len(crash.poc_bytes)}B PoC) ...", "report"))

    try:
        verdict, report_text, result, elapsed = await run_report(
            crash, target, model=args.model,
            workspace_dir=str(out_dir / "workspace"),
            upstream_log=log, crash_file=crash_file,
            agent_env=agent_env,
            container_name=_container_name(
                "report", target.name, container_scope, idx
            ),
            max_turns=args.max_turns,
            transcript_path=str(out_dir / "report_transcript.jsonl"),
            progress_prefix=f"[report:{idx}]",
            system_prompt=build_system_prompt(args.engagement_context),
        )
    except Exception as e:
        traceback.print_exc()
        out = {"signature": {"crash_type": crash_type, "top_frame": frame},
               "from_run": str(rep_path), "status": "agent_failed",
               "error": f"{type(e).__name__}: {e}"}
        _write_report_json(out_dir, out)
        return out

    status = "no_report" if verdict is None else "report_submitted"
    if result.error:
        status = "agent_failed"
    _rline = (f"[report:{idx}] done in {elapsed:.1f}s: {status}"
              + (f" rubric={verdict.rubric_score}/10 sev={verdict.severity_rating}"
                 if verdict else ""))
    print(color(_rline, "bold") if status == "report_submitted" else _rline)

    out = {
        "signature": {"crash_type": crash_type, "top_frame": frame},
        "from_run": str(rep_path),
        "runs_in_group": [str(p) for p, _s, _r in entries],
        "status": status,
        "error": result.error,
        "elapsed": elapsed,
        "upstream_log": log if log else NOVELTY_NOT_CHECKED,
        "verdict": verdict.to_dict() if verdict else None,
        "report": report_text,
    }
    _write_report_json(out_dir, out)
    return out


def _write_report_json(out_dir: Path, d: dict) -> None:
    if d.get("signature"):
        compliance.enrich(d)
    atomic_write_json(out_dir / "report.json", d)


def _load_report_checkpoint(out_dir: Path, sig: tuple[str, str]) -> dict | None:
    """Return prior report.json if it landed with status report_submitted AND
    its signature matches. agent_failed / no_report are retried. A signature
    mismatch means bug_NN index drifted (e.g. --resume added new crashes
    between report invocations) and the checkpoint is for a different bug."""
    p = out_dir / "report.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if d.get("status") != "report_submitted":
        return None
    s = d.get("signature", {})
    if (s.get("crash_type"), s.get("top_frame")) != sig:
        return None
    return d


def _cmd_report(args) -> int:
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    if args.max_parallel < 1:
        print("error: --max-parallel must be at least 1", file=sys.stderr)
        return 1

    agent_env = _resolve_auth_env(getattr(args, "provider", None))
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1

    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model, getattr(args, "provider", None))

    groups = dedup(root)
    if not groups:
        print("No crashes under results dir.", file=sys.stderr)
        return 2

    # Filter + order: passed groups first, then rejected (or drop if --only-passed).
    def _has_passed(entries): return any(s == "crash_found" for _p, s, _r in entries)
    items = [(sig, ents) for sig, ents in groups.items()
             if not args.only_passed or _has_passed(ents)]
    items.sort(key=lambda kv: (0 if _has_passed(kv[1]) else 1, kv[0]))

    if not items:
        print("No passed-grade crashes (use without --only-passed to include rejected).",
              file=sys.stderr)
        return 2

    # Infer target from the first result.json — all runs in a batch share one target.
    first_path = next(p for _sig, ents in items for p, _s, _r in ents)
    try:
        target_name = json.loads(first_path.read_text())["target"]
        target = TargetConfig.load(args.targets_dir / target_name)
    except Exception as e:
        print(f"error: could not load target config for batch: {e}", file=sys.stderr)
        return 1
    container_scope = _container_scope(root)
    _set_container_cleanup_scope(target.name, container_scope)

    target, pin_error = _pin_target_for_existing_batch(root, target)
    if pin_error:
        print(f"error: {pin_error}", file=sys.stderr)
        return 1
    assert target is not None

    reports_root = root / "reports"
    checkpoints: dict[int, dict] = {}
    if not args.fresh:
        for i, (sig, _ents) in enumerate(items):
            if (r := _load_report_checkpoint(reports_root / f"bug_{i:02d}", sig)) is not None:
                checkpoints[i] = r
    print(f"[report] {len(items)} unique signature(s) → {reports_root}/"
          + (f" ({len(checkpoints)} already reported, skipping)" if checkpoints else ""))
    print(f"  model:   {args.model}")
    print(f"  novelty: {'on (fetches ' + target.github_url + ')' if args.novelty else 'off'}")
    print()

    async def _ckpt(i: int) -> dict:
        print(f"[report:{i}] checkpoint: report_submitted (skipping)")
        return checkpoints[i]

    async def _dispatch():
        tasks = [_ckpt(i) if i in checkpoints
                 else _report_one(
                     i, sig, ents, target, args, agent_env, reports_root,
                     container_scope,
                 )
                 for i, (sig, ents) in enumerate(items)]
        if args.parallel:
            return await _gather_bounded(tasks, args.max_parallel)
        out = []
        for t in tasks:
            out.append(await t)
        return out

    try:
        with exclusive_lock(root / ".orchestrator.lock"):
            results = asyncio.run(_dispatch())
    except ResultsLockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("\n── Summary ────────────────────────────────────────────────────────────────────")
    exit_code = 0
    for i, r in enumerate(results):
        if isinstance(r, BaseException):
            print(f"  bug_{i:02d}: error — {type(r).__name__}: {r}")
            exit_code = 2
            continue
        status = r.get("status")
        v = r.get("verdict") or {}
        sev = v.get("severity_rating", "-")
        score = v.get("total_score")
        score_s = f" score={score:.2f}" if score is not None else ""
        print(f"  bug_{i:02d}: {status:18s} sev={sev:<10}{score_s}  "
              f"→ {reports_root / f'bug_{i:02d}'}/report.json")
        if status != "report_submitted":
            exit_code = 2
    return exit_code


def _cmd_patch(args) -> int:
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    if args.max_parallel < 1:
        print("error: --max-parallel must be at least 1", file=sys.stderr)
        return 1
    agent_env = _resolve_auth_env(getattr(args, "provider", None))
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1
    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model, getattr(args, "provider", None))

    groups = dedup(root)
    if not groups:
        print("No crashes under results dir.", file=sys.stderr)
        return 2

    # Same ordering as _cmd_report so bug_NN here matches reports/bug_NN/
    def _has_passed(ents): return any(s == "crash_found" for _p, s, _r in ents)
    ordered = sorted(groups.items(),
                     key=lambda kv: (0 if _has_passed(kv[1]) else 1, kv[0]))
    items = [(i, sig, ents) for i, (sig, ents) in enumerate(ordered)
             if args.bug is None or i == args.bug]
    if not items:
        print(f"No bug matching --bug {args.bug}.", file=sys.stderr)
        return 2

    first_path = next(p for _i, _s, ents in items for p, _st, _r in ents)
    target_name = json.loads(first_path.read_text())["target"]
    target = TargetConfig.load(args.targets_dir / target_name)
    if not target.build_command:
        print(f"error: target {target.name!r} has no build_command in config.yaml — "
              f"the patch grader needs an in-container rebuild step", file=sys.stderr)
        return 1
    container_scope = _container_scope(root)
    _set_container_cleanup_scope(target.name, container_scope)

    target, pin_error = _pin_target_for_existing_batch(root, target)
    if pin_error:
        print(f"error: {pin_error}", file=sys.stderr)
        return 1
    assert target is not None

    reports_root = root / "reports"
    system_prompt = build_system_prompt(args.engagement_context)

    print(color(f"[patch] {len(items)} bug(s) → {reports_root}/bug_NN/{{patch.diff,patch_result.json}}", "patch"))
    print(f"  model: {args.model}  reattack: {'off' if args.no_reattack else 'on'}  "
          f"iterations≤{args.max_iterations}\n")

    async def _one(idx: int, entries) -> dict:
        out_dir = reports_root / f"bug_{idx:02d}"
        out_dir.mkdir(parents=True, exist_ok=True)
        rep_path, _result, crash_dict = _pick_representative(entries)
        crash = CrashArtifact.from_dict(crash_dict)
        report_json = out_dir / "report.json"
        report_text = (json.loads(report_json.read_text()).get("report")
                       if report_json.exists() else None)
        try:
            diff, verdict, _ = await run_patch(
                crash, target, model=args.model, out_dir=out_dir,
                report_text=report_text,
                max_iterations=args.max_iterations, max_turns=args.max_turns,
                container_name=_container_name(
                    "patch", target.name, container_scope, idx
                ),
                run_reattack=not args.no_reattack, run_style=args.style,
                agent_env=agent_env, system_prompt=system_prompt,
                progress_prefix=f"[patch:bug_{idx:02d}]",
            )
        except Exception as e:
            traceback.print_exc()
            return {"bug_id": idx, "status": "error", "error": f"{type(e).__name__}: {e}"}
        status = ("no_diff" if diff is None
                  else "patch_verified" if verdict and verdict.passed
                  else "patch_rejected")
        _pline = (f"[patch:bug_{idx:02d}] {status}"
                  + (f"  t0={verdict.t0_builds} t1={verdict.t1_poc_stops} "
                     f"t2={verdict.t2_tests_pass} reattack={verdict.re_attack_clean}"
                     if verdict else ""))
        print(color(_pline, "bold") if status == "patch_verified" else _pline)
        return {"bug_id": idx, "status": status, "from": str(rep_path),
                "verdict": verdict.to_dict() if verdict else None}

    async def _dispatch():
        coros = [_one(i, ents) for i, _sig, ents in items]
        if args.parallel:
            return await _gather_bounded(coros, args.max_parallel)
        return [await c for c in coros]

    try:
        with exclusive_lock(root / ".orchestrator.lock"):
            results = asyncio.run(_dispatch())
    except ResultsLockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("\n── Summary ────────────────────────────────────────────────────────────────────")
    exit_code = 0
    for r in results:
        if isinstance(r, BaseException):
            print(f"  error — {type(r).__name__}: {r}")
            exit_code = 2
            continue
        bug_id = r["bug_id"]
        print(f"  bug_{bug_id:02d}: {r['status']:16s} → "
              f"{reports_root}/bug_{bug_id:02d}/patch_result.json")
        if r["status"] != "patch_verified":
            exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
