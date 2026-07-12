# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Profile selection and replay-manifest contract tests."""
from harness.artifacts import CrashArtifact
from harness.config import TargetConfig
from harness.profiles import build_find_prompt, build_grade_prompt, load_web_manifest
from harness.prompts.find_prompt import build_find_prompt as build_cpp_find_prompt


def _target(profile="python_web"):
    return TargetConfig(
        name="web", dockerfile_dir="targets/web", image_tag="web:latest",
        github_url="https://example.invalid/web", commit="abc",
        binary_path="/work/server", source_root="/work",
        profile=profile, replay_command="/opt/vp/replay", detection_signal="FOUND",
    )


def _manifest():
    return {
        "replay_command": "/opt/vp/replay /tmp/replay.json",
        "evidence": {
            "kind": "http",
            "requests": [{"method": "GET", "path": "/api/users/2"}],
            "responses": [{"status": 200, "body": "FOUND"}],
        },
        "detection_signal": {"type": "response_marker", "value": "FOUND"},
        "security_impact": "A user reads another user's records.",
    }


def test_cpp_profile_delegates_to_unchanged_prompt(monkeypatch):
    monkeypatch.setattr("harness.prompts.find_prompt.make_nonce", lambda: "fixed")
    target = _target("cpp_asan")
    actual = build_find_prompt(target, "parser", ["known"], "/tmp/found", False)
    expected = build_cpp_find_prompt(
        target.github_url, target.commit, target.source_root, target.binary_path,
        focus_area="parser", known_bugs=["known"], found_bugs_path="/tmp/found",
        accept_dos=False, reattack_harness=None,
    )
    assert actual == expected


def test_web_find_and_grade_prompts_require_replay_evidence():
    target = _target()
    manifest = _manifest()
    crash = CrashArtifact(
        poc_path="/tmp/replay.json", poc_bytes=b"{}", reproduction_command=manifest["replay_command"],
        crash_type="idor", crash_output="{}", exit_code=0, profile="python_web",
        replay_manifest=manifest, evidence_bundle=manifest["evidence"],
    )
    find_prompt = build_find_prompt(target, None, None, None, False)
    grade_prompt = build_grade_prompt(target, crash, "/opt/vp/replay /tmp/replay.json", "/tmp/replay.json")

    assert "Static scanner output is lead generation only" in find_prompt
    assert "replay manifest" in find_prompt
    assert "three times" in grade_prompt
    assert "test-only route" in grade_prompt


def test_web_manifest_requires_structured_evidence():
    manifest = _manifest()
    assert load_web_manifest(__import__("json").dumps(manifest).encode()) == manifest
    manifest["evidence"] = {"kind": "http", "requests": []}
    try:
        load_web_manifest(__import__("json").dumps(manifest).encode())
    except ValueError as exc:
        assert "evidence" in str(exc)
    else:
        raise AssertionError("manifest without responses accepted")


def test_web_manifest_must_match_configured_replay_contract():
    target = _target()
    manifest = _manifest()

    assert load_web_manifest(__import__("json").dumps(manifest).encode(), target) == manifest

    manifest["replay_command"] = "/opt/vp/other /tmp/replay.json"
    try:
        load_web_manifest(__import__("json").dumps(manifest).encode(), target)
    except ValueError as exc:
        assert "replay_command" in str(exc)
    else:
        raise AssertionError("manifest with an unconfigured replay command accepted")

    manifest = _manifest()
    manifest["detection_signal"]["value"] = "UNRELATED"
    try:
        load_web_manifest(__import__("json").dumps(manifest).encode(), target)
    except ValueError as exc:
        assert "detection_signal" in str(exc)
    else:
        raise AssertionError("manifest with an unconfigured detection signal accepted")
