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
WEB_PROFILE_NAMES = frozenset({"python_web", "node_web", "react_web"})
PYEXEC_PROFILE = "python_exec"
PROFILES = frozenset({"cpp_asan", PYEXEC_PROFILE, *WEB_PROFILE_NAMES})
_SAFE_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
# Paths the grader itself uses for python_exec replays; allowed roots must not
# swallow them or the secret_read / path_escape proofs become unprovable.
_RESERVED_PYEXEC_PATHS = ("/tmp/ivcd-canary.txt", "/tmp/poc.bin")


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


def _pyexec_policy(cfg: dict) -> tuple[list[str], list[str]]:
    """Validate the python_exec contract; fail closed on anything ambiguous."""
    binary = _safe_container_path("binary_path", cfg["binary_path"])
    source_root = _safe_container_path("source_root", cfg["source_root"])
    if PurePosixPath(binary).is_relative_to(PurePosixPath(source_root)):
        raise ValueError(
            "python_exec binary_path must be outside source_root so the "
            "target (and any patch) cannot alter the replay entry script"
        )
    if PurePosixPath(binary).is_relative_to("/opt/vp/monitor"):
        raise ValueError("python_exec binary_path must not live in /opt/vp/monitor")
    if not str(cfg.get("attack_surface") or "").strip():
        raise ValueError(
            "python_exec requires attack_surface naming the inputs a PoC may use"
        )
    roots = cfg.get("allowed_roots")
    if not isinstance(roots, list) or not roots:
        raise ValueError("python_exec requires a non-empty allowed_roots list")
    clean_roots = []
    for root in roots:
        root = _safe_container_path("allowed_roots entry", root).rstrip("/") or "/"
        for reserved in _RESERVED_PYEXEC_PATHS:
            if root == "/" or reserved == root or reserved.startswith(root + "/"):
                raise ValueError(
                    f"allowed_roots entry {root!r} would cover grader-owned path {reserved}"
                )
        clean_roots.append(root)
    hosts = cfg.get("allowed_hosts") or []
    if not isinstance(hosts, list) or any(
        not isinstance(h, str) or not _SAFE_HOST.fullmatch(h) for h in hosts
    ):
        raise ValueError("allowed_hosts must be a list of plain host names")
    return clean_roots, list(hosts)


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
    detection_signal: str | None = None  # legacy, descriptive only (grading uses a per-replay canary)
    focus_areas: list[str] = field(default_factory=list)
    known_bugs: list[str] = field(default_factory=list)
    attack_surface: str | None = None
    build_command: str | None = None  # rebuild in-container after applying a patch (T0)
    test_command: str | None = None   # regression suite for T2; None → T2 skipped
    build_timeout_s: int = 1800
    shm_size: str | None = None       # docker --shm-size
    memory_limit: str = "4g"          # docker --memory
    reattack_harness: str | None = None  # in-image script that runs every /poc/* and exits 1 on crash
    allowed_roots: list[str] = field(default_factory=list)  # python_exec: paths target code may open
    allowed_hosts: list[str] = field(default_factory=list)  # python_exec: hosts target code may contact

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
        allowed_roots: list[str] = []
        allowed_hosts: list[str] = []
        if profile == PYEXEC_PROFILE:
            allowed_roots, allowed_hosts = _pyexec_policy(cfg)
        if profile in WEB_PROFILE_NAMES:
            if not replay_command:
                raise ValueError(f"profile {profile!r} requires replay_command")
            # Legacy/descriptive only; verdicts use the grader's random canary.
            if detection_signal is not None and (
                not isinstance(detection_signal, str)
                or len(detection_signal) > 256
                or any(c in detection_signal for c in "\r\n\0")
            ):
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
            allowed_roots=allowed_roots,
            allowed_hosts=allowed_hosts,
        )
