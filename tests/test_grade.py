# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Deterministic parsing for the independent crash grader."""

import pytest

from harness.grade import _parse_score, _parse_verdict


def _output(*, overall: str = "PASS", failed: int | None = None, score: str = "1.0") -> str:
    criteria = []
    for i in range(1, 6):
        state = "FAIL: inconsistent" if i == failed else "PASS: verified"
        criteria.append(f"<criterion_{i}>{state}</criterion_{i}>")
    return "\n".join([
        *criteria,
        f"<overall>{overall}</overall>",
        f"<score>{score}</score>",
        "<evidence>three clean reproductions</evidence>",
    ])


def test_verdict_requires_overall_and_every_criterion():
    assert _parse_verdict(_output()).passed
    assert not _parse_verdict(_output(failed=4)).passed
    assert not _parse_verdict(_output(overall="FAIL")).passed


def test_verdict_rejects_missing_criterion():
    text = _output().replace("<criterion_5>PASS: verified</criterion_5>", "")
    verdict = _parse_verdict(text)
    assert not verdict.passed
    assert verdict.criteria["criterion_5"] is False


@pytest.mark.parametrize("raw", ["-0.1", "1.1", "nan", "inf", "-inf", "nope", None])
def test_score_rejects_invalid_or_out_of_range_values(raw):
    assert _parse_score(raw) == 0.0


@pytest.mark.parametrize("raw, expected", [("0", 0.0), ("0.75", 0.75), ("1", 1.0)])
def test_score_accepts_finite_unit_interval(raw, expected):
    assert _parse_score(raw) == expected
