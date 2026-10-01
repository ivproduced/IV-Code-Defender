# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Deterministic parsing for the independent crash grader."""

import pytest

from harness.artifacts import CrashArtifact
from harness.config import TargetConfig
from harness.grade import (
    ReplayObservation,
    _machine_verdict,
    _parse_score,
    _parse_verdict,
)


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


def _target(profile="cpp_asan"):
    return TargetConfig(
        name="t", dockerfile_dir="/tmp/t", image_tag="t:latest",
        github_url="https://github.com/example/t", commit="a" * 40,
        binary_path="/work/entry", source_root="/work", profile=profile,
        replay_command="/opt/replay" if profile != "cpp_asan" else None,
        detection_signal="VULNERABLE" if profile != "cpp_asan" else None,
    )


def _crash(raw=b"x", profile="cpp_asan", crash_output=""):
    return CrashArtifact(
        poc_path="/tmp/poc.bin", poc_bytes=raw,
        reproduction_command="/work/entry /tmp/poc.bin",
        crash_type="heap-buffer-overflow", crash_output=crash_output, exit_code=134,
        profile=profile,
    )


def _asan(kind="heap-buffer-overflow", site="parse", line=25):
    return (
        f"ERROR: AddressSanitizer: {kind}\n"
        f"SUMMARY: AddressSanitizer: {kind} /work/entry.c:{line}\n"
        f"    #0 0x123 in {site} /work/entry.c:{line}\n"
    )


def test_machine_verdict_requires_two_consistent_project_crashes():
    observations = [
        ReplayObservation(134, "", _asan()),
        ReplayObservation(134, "", _asan()),
        ReplayObservation(0, "", ""),
    ]
    criteria, evidence = _machine_verdict(_crash(), _target(), observations)
    assert all(criteria.values())
    assert "[run 3] rc=0" in evidence


def test_machine_verdict_rejects_inconsistent_crash_classes():
    observations = [
        ReplayObservation(134, "", _asan()),
        ReplayObservation(134, "", _asan("heap-use-after-free")),
        ReplayObservation(134, "", _asan()),
    ]
    criteria, _ = _machine_verdict(_crash(), _target(), observations)
    assert criteria["criterion_5"] is False


def test_machine_verdict_rejects_different_sites_with_same_asan_class():
    observations = [
        ReplayObservation(134, "", _asan(site="parse_alpha")),
        ReplayObservation(134, "", _asan(site="parse_bravo")),
        ReplayObservation(134, "", _asan(site="parse_alpha")),
    ]
    criteria, _ = _machine_verdict(_crash(), _target(), observations)
    assert criteria["criterion_5"] is False


def test_machine_verdict_requires_replay_to_match_claimed_site():
    observations = [ReplayObservation(134, "", _asan(site="parse_bravo"))] * 3
    criteria, _ = _machine_verdict(
        _crash(crash_output=_asan(site="parse_alpha")), _target(), observations
    )
    assert criteria["criterion_5"] is False


def test_machine_verdict_ignores_line_only_differences():
    observations = [
        ReplayObservation(134, "", _asan(line=25)),
        ReplayObservation(134, "", _asan(line=26)),
        ReplayObservation(0, "", ""),
    ]
    criteria, _ = _machine_verdict(
        _crash(crash_output=_asan(line=27)), _target(), observations
    )
    assert all(criteria.values())


def test_machine_verdict_rejects_oom_and_timeout():
    observations = [
        ReplayObservation(137, "", "out of memory"),
        ReplayObservation(None, "", "", timed_out=True),
        ReplayObservation(134, "", _asan()),
    ]
    criteria, _ = _machine_verdict(_crash(), _target(), observations)
    assert criteria["criterion_2"] is False
    assert criteria["criterion_3"] is False


def test_machine_verdict_accepts_allocation_dos_only_in_benchmark_mode():
    output = _asan("allocation-size-too-big")
    observations = [
        ReplayObservation(134, "", output),
        ReplayObservation(134, "", output),
        ReplayObservation(134, "", output),
    ]
    normal, _ = _machine_verdict(_crash(), _target(), observations)
    benchmark, _ = _machine_verdict(
        _crash(), _target(), observations, accept_dos=True
    )
    assert normal["criterion_3"] is False
    assert benchmark["criterion_3"] is True
