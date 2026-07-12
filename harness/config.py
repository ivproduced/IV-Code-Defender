# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Target configuration loader.

A target is a directory under targets/ containing:
  - Dockerfile   (builds the isolated target image)
  - config.yaml  (metadata the pipeline needs)
  - any other build-context files the Dockerfile COPYs

Adding a new target = new dir, zero pipeline code changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import re

import yaml

_SAFE_CONTAINER_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
_SAFE_REPLAY_COMMAND = re.compile(r"^/[A-Za-z0-9._/-]+(?: [A-Za-z0-9._/:=-]+)*$")
PROFILES = frozenset({"cpp_asan", "python_web", "node_web", "react_web"})


def _safe_container_path(field: str, value: str) -> str:
    """Allow only absolute POSIX paths in shell-interpolated config fields."""
    if not isinstance(value, str) or not _SAFE_CONTAINER_PATH.fullmatch(value):
        raise ValueError(f"Unsafe {field}: {value!r}")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Unsafe {field}: {value!r}")
    return value


def _safe_replay_command(value: str) -> str:
    """Accept a simple, absolute in-container replay command, never shell syntax."""
    if not isinstance(value, str) or not _SAFE_REPLAY_COMMAND.fullmatch(value):
        raise ValueError(f"Unsafe replay_command: {value!r}")
    executable = value.split(" ", 1)[0]
    _safe_container_path("replay_command", executable)
    return value


@dataclass(frozen=True)
class TargetConfig:
    name: str
    dockerfile_dir: str   # build context dir (the target dir itself)
    image_tag: str
    github_url: str
    commit: str
    binary_path: str      # path inside the built container
    source_root: str      # path inside the built container
    profile: str = "cpp_asan"
    replay_command: str | None = None  # self-contained web replay entrypoint
    detection_signal: str | None = None  # marker absent once a web fix is effective
    focus_areas: list[str] = field(default_factory=list)
    known_bugs: list[str] = field(default_factory=list)
    attack_surface: str | None = None
    build_command: str | None = None  # rebuild in-container after applying a patch (T0)
    test_command: str | None = None   # regression suite for T2; None → T2 skipped
    build_timeout_s: int = 1800
    shm_size: str | None = None       # docker --shm-size
    memory_limit: str = "4g"          # docker --memory
    reattack_harness: str | None = None  # in-image script that runs every /poc/* and exits 1 on crash

    @classmethod
    def load(cls, target_dir: str | Path) -> TargetConfig:
        target_dir = Path(target_dir).resolve()
        config_path = target_dir / "config.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"No config.yaml in {target_dir}")

        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        profile = cfg.get("profile", "cpp_asan")
        if profile not in PROFILES:
            raise ValueError(
                f"Unsupported profile {profile!r}; expected one of {sorted(PROFILES)}"
            )
        replay_command = cfg.get("replay_command")
        detection_signal = cfg.get("detection_signal")
        if profile != "cpp_asan":
            if not replay_command:
                raise ValueError(f"profile {profile!r} requires replay_command")
            if not isinstance(detection_signal, str) or not detection_signal.strip():
                raise ValueError(f"profile {profile!r} requires detection_signal")
            if len(detection_signal) > 256 or any(c in detection_signal for c in "\r\n\0"):
                raise ValueError(f"Unsafe detection_signal: {detection_signal!r}")
            replay_executable = PurePosixPath(
                _safe_replay_command(replay_command).split(" ", 1)[0]
            )
            if replay_executable.is_relative_to(PurePosixPath(cfg["source_root"])):
                raise ValueError(
                    "web replay_command executable must be outside source_root "
                    "so patch diffs cannot alter the verifier"
                )

        return cls(
            name=target_dir.name,
            dockerfile_dir=str(target_dir),
            image_tag=cfg["image_tag"],
            github_url=cfg["github_url"],
            commit=cfg["commit"],
            binary_path=_safe_container_path("binary_path", cfg["binary_path"]),
            source_root=_safe_container_path("source_root", cfg["source_root"]),
            profile=profile,
            replay_command=_safe_replay_command(replay_command) if replay_command else None,
            detection_signal=detection_signal,
            focus_areas=cfg.get("focus_areas") or [],
            known_bugs=cfg.get("known_bugs") or [],
            attack_surface=cfg.get("attack_surface"),
            build_command=cfg.get("build_command"),
            test_command=cfg.get("test_command"),
            build_timeout_s=cfg.get("build_timeout_s", 1800),
            shm_size=cfg.get("shm_size"),
            memory_limit=cfg.get("memory_limit", "4g"),
            reattack_harness=cfg.get("reattack_harness"),
        )
