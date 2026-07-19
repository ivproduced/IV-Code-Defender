# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""OCI container-engine selection tests."""
from __future__ import annotations

import subprocess

import pytest

from harness import docker_ops
from harness.cli import _container_name, _container_scope


def test_docker_is_default(monkeypatch):
    monkeypatch.delenv("VULN_PIPELINE_CONTAINER_ENGINE", raising=False)
    monkeypatch.setattr(docker_ops.shutil, "which", lambda _: "/usr/bin/docker")
    assert docker_ops.command("ps") == ["docker", "ps"]


def test_podman_selects_rootful_engine(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_CONTAINER_ENGINE", "podman")
    monkeypatch.setattr(docker_ops.shutil, "which", lambda _: "/usr/bin/podman")
    monkeypatch.setattr(docker_ops.os, "geteuid", lambda: 0)
    assert docker_ops.command("inspect", "target") == ["podman", "inspect", "target"]


def test_rootless_podman_is_rejected(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_CONTAINER_ENGINE", "podman")
    monkeypatch.setattr(docker_ops.shutil, "which", lambda _: "/usr/bin/podman")
    monkeypatch.setattr(docker_ops.os, "geteuid", lambda: 1000)
    with pytest.raises(RuntimeError, match="rootful"):
        docker_ops.engine()


def test_remote_podman_is_rejected(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_CONTAINER_ENGINE", "podman")
    monkeypatch.setenv("CONTAINER_HOST", "unix:///run/user/1000/podman/podman.sock")
    monkeypatch.setattr(docker_ops.shutil, "which", lambda _: "/usr/bin/podman")
    monkeypatch.setattr(docker_ops.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="CONTAINER_HOST"):
        docker_ops.engine()


def test_named_remote_podman_connection_is_rejected(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_CONTAINER_ENGINE", "podman")
    monkeypatch.setenv("CONTAINER_CONNECTION", "remote-podman")
    monkeypatch.setattr(docker_ops.shutil, "which", lambda _: "/usr/bin/podman")
    monkeypatch.setattr(docker_ops.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="CONTAINER_CONNECTION"):
        docker_ops.engine()


def test_invalid_engine_is_rejected(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_CONTAINER_ENGINE", "nerdctl")
    with pytest.raises(ValueError, match="docker.*podman"):
        docker_ops.engine()


def test_run_failure_identifies_selected_engine(monkeypatch):
    monkeypatch.setattr(docker_ops, "engine", lambda: "podman")

    def failed_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stderr="container error")

    monkeypatch.setattr(docker_ops.subprocess, "run", failed_run)

    with pytest.raises(RuntimeError, match="podman run failed"):
        docker_ops.run("image:tag", "test-container")


def test_run_applies_least_privilege_defaults(monkeypatch):
    monkeypatch.setattr(docker_ops, "engine", lambda: "docker")
    commands = []

    def run(args, **kwargs):
        commands.append(args)
        if "inspect" in args:
            return subprocess.CompletedProcess(
                args, 0, stdout="image:tag\trunsc\n", stderr=""
            )
        return subprocess.CompletedProcess(args, 0, stdout="container\n", stderr="")

    monkeypatch.setattr(docker_ops.subprocess, "run", run)
    docker_ops.run("image:tag", "test-container", runtime="runsc")
    command = next(command for command in commands if "run" in command)
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop"):command.index("--cap-drop") + 2]
    assert ["--security-opt", "no-new-privileges:true"] == command[
        command.index("--security-opt"):command.index("--security-opt") + 2
    ]
    assert ["--pids-limit", "512"] == command[
        command.index("--pids-limit"):command.index("--pids-limit") + 2
    ]


def test_container_names_are_namespaced_by_results_batch(tmp_path):
    first = _container_scope(tmp_path / "results" / "target" / "batch-a")
    second = _container_scope(tmp_path / "results" / "target" / "batch-b")
    assert first != second
    assert _container_name("find", "target", first, 0) != \
        _container_name("find", "target", second, 0)


def test_container_name_sanitizes_target_and_stays_bounded():
    name = _container_name("report", "target with/slashes" * 20, "abc123", 7)
    assert len(name) <= 120
    assert " " not in name and "/" not in name
