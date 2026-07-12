# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Target config validation."""
from __future__ import annotations

import pytest

from harness.config import TargetConfig


def _write_config(tmp_path, **overrides):
    values = {
        "image_tag": "target:latest",
        "github_url": "https://example.com/repo",
        "commit": "abc123",
        "binary_path": "/work/entry",
        "source_root": "/work/src",
    }
    values.update(overrides)
    (tmp_path / "config.yaml").write_text(
        "".join(f"{key}: {value!r}\n" for key, value in values.items())
    )
    return tmp_path


def test_load_accepts_safe_absolute_container_paths(tmp_path):
    cfg = TargetConfig.load(_write_config(tmp_path))

    assert cfg.binary_path == "/work/entry"
    assert cfg.source_root == "/work/src"


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_root", "/work/src; touch /tmp/pwned"),
        ("source_root", "/work/$(id)"),
        ("binary_path", "relative/entry"),
        ("binary_path", "/work/../etc/passwd"),
    ],
)
def test_load_rejects_unsafe_path_like_fields(tmp_path, field, value):
    with pytest.raises(ValueError, match=field):
        TargetConfig.load(_write_config(tmp_path, **{field: value}))


def test_web_profile_requires_safe_replay_contract(tmp_path):
    cfg = TargetConfig.load(_write_config(
        tmp_path,
        profile="python_web",
        replay_command="/opt/vp/replay --manifest",
        detection_signal="VULNERABILITY_DETECTED",
    ))

    assert cfg.profile == "python_web"
    assert cfg.replay_command == "/opt/vp/replay --manifest"


@pytest.mark.parametrize(
    "overrides",
    [
        {"profile": "unknown"},
        {"profile": "python_web", "replay_command": "/work/src/replay", "detection_signal": "FOUND"},
        {"profile": "node_web", "replay_command": "/work/replay; id", "detection_signal": "FOUND"},
        {"profile": "react_web", "replay_command": "/work/replay"},
        {"profile": "python_web", "replay_command": "/work/replay", "detection_signal": "x" * 257},
    ],
)
def test_web_profile_rejects_invalid_contract(tmp_path, overrides):
    with pytest.raises(ValueError):
        TargetConfig.load(_write_config(tmp_path, **overrides))
