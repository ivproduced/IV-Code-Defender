# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Streaming report completion, recovery, and per-bug ordering."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from harness.agent import AgentResult
from harness.artifacts import CrashArtifact, GraderVerdict, ReportVerdict, RunResult
from harness.cli import (
    _append_manifest,
    _pending_stream_reports,
    _queue_stream_report,
    _repair_judge_log_from_manifest,
    _record_or_verify_batch_image,
    _run_all,
    _stream_report,
    _write_result,
)
from harness.config import TargetConfig


TARGET = TargetConfig(
    name="t", dockerfile_dir="/tmp/t", image_tag="t:latest",
    github_url="https://github.com/example/t", commit="a" * 40,
    binary_path="/work/entry", source_root="/work",
)
CRASH = CrashArtifact(
    poc_path="/tmp/poc.bin", poc_bytes=b"x",
    reproduction_command="/work/entry /tmp/poc.bin",
    crash_type="heap-buffer-overflow",
    crash_output=(
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /work/entry.c:25\n"
        "    #0 0x123 in parse /work/entry.c:25\n"
    ),
    exit_code=134,
)
VERDICT = ReportVerdict(
    section_scores={}, rubric_score=8, escalation_bonus=0,
    total_score=8 / 14, severity_rating="HIGH",
    novelty_status="NOT_CHECKED", reachability_verdict="REACHABLE",
)


def _call_report(run_idx, reports_root, *, re_report=False):
    return _stream_report(
        run_idx, 0, CRASH, TARGET, "m", {}, reports_root,
        re_report=re_report, novelty=False, max_turns=10,
        system_prompt=None, container_scope="test",
    )


def _log(reports_root, *entries):
    reports_root.mkdir(parents=True, exist_ok=True)
    (reports_root / "judge_log.jsonl").write_text(
        "".join(json.dumps(entry) + "\n" for entry in entries)
    )


def test_resume_retries_judged_report_without_completion(tmp_path):
    reports_root = tmp_path / "reports"
    _log(reports_root, {
        "run_idx": 0, "bug_id": 0, "judgment": "NEW",
    })
    assert [entry["run_idx"] for entry in _pending_stream_reports(reports_root)] == [0]

    bug_dir = reports_root / "bug_00"
    bug_dir.mkdir()
    (bug_dir / "report_run000.json").write_text(json.dumps({
        "from_run": 0, "status": "agent_failed",
    }))
    assert [entry["run_idx"] for entry in _pending_stream_reports(reports_root)] == [0]

    (bug_dir / "report_run000.json").write_text(json.dumps({
        "from_run": 0, "status": "report_submitted", "stream_complete": True,
    }))
    assert _pending_stream_reports(reports_root) == []


def test_resume_recovers_manifest_written_before_judge_log(tmp_path):
    reports_root = tmp_path / "reports"
    _append_manifest(reports_root, 0, 3, "ASAN crash")
    _repair_judge_log_from_manifest(reports_root)
    _repair_judge_log_from_manifest(reports_root)
    pending = _pending_stream_reports(reports_root)
    assert [(entry["run_idx"], entry["bug_id"]) for entry in pending] == [(3, 0)]
    assert len((reports_root / "judge_log.jsonl").read_text().splitlines()) == 1


def test_later_completed_replacement_supersedes_failed_report(tmp_path):
    reports_root = tmp_path / "reports"
    _log(reports_root,
         {"run_idx": 0, "bug_id": 0, "judgment": "NEW"},
         {"run_idx": 1, "bug_id": 0, "judgment": "DUP_BETTER"})
    bug_dir = reports_root / "bug_00"
    bug_dir.mkdir()
    (bug_dir / "report_run001.json").write_text(json.dumps({
        "from_run": 1, "status": "report_submitted", "stream_complete": True,
    }))
    assert _pending_stream_reports(reports_root) == []


def test_run_resume_requeues_judged_report(tmp_path):
    image_id = "sha256:" + "a" * 64
    _record_or_verify_batch_image(tmp_path, TARGET, image_id, is_resume=False)
    _write_result(tmp_path, RunResult(
        target="t", status="crash_found", crash=CRASH,
        verdict=GraderVerdict(True, 1.0, {}, "reproduced"),
    ))
    _log(tmp_path / "reports", {
        "run_idx": 0, "bug_id": 0, "judgment": "NEW",
    })
    args = SimpleNamespace(
        engagement_context=None, resume=tmp_path, auto_focus=False,
        runs=1, find_only=False, stream=True, max_parallel=2,
        novelty=False, report_max_turns=10, parallel=False,
        model="m", accept_dos=False, max_turns=10,
    )
    with (
        patch("harness.cli.docker_ops.build"),
        patch("harness.cli.docker_ops.image_id", return_value=image_id),
        patch("harness.cli.docker_ops.tag", side_effect=lambda _src, dest: dest),
        patch("harness.cli._queue_stream_report") as queue,
    ):
        pairs = asyncio.run(_run_all(TARGET, args, {}, tmp_path))
    assert pairs[0][1].status == "crash_found"
    assert queue.call_count == 1
    assert queue.call_args.args[0:2] == (0, 0)


def test_failed_replacement_preserves_canonical_report(tmp_path):
    reports_root = tmp_path / "reports"

    async def scenario():
        with patch("harness.cli.run_report", new=AsyncMock(return_value=(
            VERDICT, "original report", AgentResult(), 0.01,
        ))):
            await _call_report(0, reports_root)
        with patch("harness.cli.run_report", new=AsyncMock(side_effect=RuntimeError("API down"))):
            result = await _call_report(1, reports_root, re_report=True)
        return result

    result = asyncio.run(scenario())
    bug_dir = reports_root / "bug_00"
    assert result["status"] == "agent_failed"
    assert json.loads((bug_dir / "report.json").read_text())["from_run"] == 0
    _log(reports_root,
         {"run_idx": 0, "bug_id": 0, "judgment": "NEW"},
         {"run_idx": 1, "bug_id": 0, "judgment": "DUP_BETTER"})
    assert [entry["run_idx"] for entry in _pending_stream_reports(reports_root)] == [1]


def test_failed_comparison_preserves_canonical_and_reuses_candidate(tmp_path):
    reports_root = tmp_path / "reports"

    async def scenario():
        with patch("harness.cli.run_report", new=AsyncMock(return_value=(
            VERDICT, "original report", AgentResult(), 0.01,
        ))):
            await _call_report(0, reports_root)
        with (
            patch("harness.cli.run_report", new=AsyncMock(return_value=(
                VERDICT, "candidate report", AgentResult(), 0.01,
            ))) as generate,
            patch("harness.cli.run_compare", new=AsyncMock(return_value=(
                "B", "", AgentResult(error="API down"), 0.01,
            ))),
        ):
            try:
                await _call_report(1, reports_root, re_report=True)
            except RuntimeError as exc:
                assert "compare agent failed" in str(exc)
            else:
                assert False, "comparison failure should remain retryable"
            assert generate.await_count == 1
        assert json.loads(
            (reports_root / "bug_00" / "report.json").read_text()
        )["from_run"] == 0
        with (
            patch("harness.cli.run_report", new=AsyncMock()) as generate,
            patch("harness.cli.run_compare", new=AsyncMock(return_value=(
                "A", "original is better", AgentResult(), 0.01,
            ))),
        ):
            await _call_report(1, reports_root, re_report=True)
            generate.assert_not_awaited()

    asyncio.run(scenario())
    bug_dir = reports_root / "bug_00"
    assert json.loads((bug_dir / "report.json").read_text())["from_run"] == 0
    assert json.loads((bug_dir / "canonical.json").read_text())["winner"] == "A"
    assert json.loads((bug_dir / "report_run001.json").read_text())["stream_complete"]


def test_reports_for_same_bug_run_in_judge_order(tmp_path):
    reports_root = tmp_path / "reports"

    async def scenario():
        first_started = asyncio.Event()
        release_first = asyncio.Event()
        calls = []

        async def fake_report(*_args, **_kwargs):
            index = len(calls)
            calls.append(index)
            if index == 0:
                first_started.set()
                await release_first.wait()
            return VERDICT, f"report {index}", AgentResult(), 0.01

        ctx = {
            "report_tails": {}, "report_tasks": [],
            "agent_semaphore": asyncio.Semaphore(2),
            "reports_root": reports_root, "novelty": False,
            "report_max_turns": 10, "system_prompt": None,
            "container_scope": "test",
        }
        with (
            patch("harness.cli.run_report", new=AsyncMock(side_effect=fake_report)),
            patch("harness.cli.run_compare", new=AsyncMock(return_value=(
                "B", "better", AgentResult(), 0.01,
            ))),
        ):
            _queue_stream_report(0, 0, CRASH, TARGET, "m", {}, ctx, re_report=False)
            _queue_stream_report(1, 0, CRASH, TARGET, "m", {}, ctx, re_report=True)
            await first_started.wait()
            await asyncio.sleep(0)
            assert calls == [0]
            release_first.set()
            await asyncio.gather(*ctx["report_tasks"])
        return calls

    assert asyncio.run(scenario()) == [0, 1]
    bug_dir = reports_root / "bug_00"
    assert json.loads((bug_dir / "report.json").read_text())["from_run"] == 1
    assert json.loads((bug_dir / "report_v1.json").read_text())["from_run"] == 0
    assert json.loads((bug_dir / "canonical.json").read_text())["winner"] == "B"
    for run_idx in (0, 1):
        attempt = json.loads((bug_dir / f"report_run{run_idx:03d}.json").read_text())
        assert attempt["stream_complete"] is True
