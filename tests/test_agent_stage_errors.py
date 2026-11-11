# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Agent-backed review stages must not parse failures as valid output."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

import pytest

from harness.agent import AgentResult
from harness.judge import run_compare, run_judge
from harness.patch_grade import _style_score
from harness.report import grade_report


@contextmanager
def _container(*_args, **_kwargs):
    yield "agent"


def _failed_agent():
    return AsyncMock(return_value=AgentResult(error="backend failed"))


def test_judge_agent_error_is_not_parsed_as_new():
    with (
        patch("harness.judge.sandbox.agent_container", new=_container),
        patch("harness.judge.run_agent", new=_failed_agent()),
        pytest.raises(RuntimeError, match="judge agent failed"),
    ):
        asyncio.run(run_judge(
            asan_excerpt="ASAN", dup_check="distinct", grade_status="crash_found",
            grade_score=1.0, poc_size=1, manifest_entries=[], model="m",
            image_tag="image", agent_env={},
        ))


def test_compare_agent_error_is_not_parsed_as_candidate_winner():
    with (
        patch("harness.judge.sandbox.agent_container", new=_container),
        patch("harness.judge.run_agent", new=_failed_agent()),
        pytest.raises(RuntimeError, match="compare agent failed"),
    ):
        asyncio.run(run_compare("old", "new", "m", "image", {}))


def test_report_grader_error_is_not_scored_as_zero():
    with (
        patch("harness.report.sandbox.agent_container", new=_container),
        patch("harness.report.run_agent", new=_failed_agent()),
        pytest.raises(RuntimeError, match="report grader failed"),
    ):
        asyncio.run(grade_report("report", "m", "image", {}))


def test_style_agent_error_returns_no_advisory_score():
    with (
        patch("harness.patch_grade.sandbox.agent_container", new=_container),
        patch("harness.patch_grade.run_agent", new=_failed_agent()),
    ):
        assert asyncio.run(_style_score(b"diff", "m", "image", "style", {})) is None
