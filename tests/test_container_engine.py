# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""OCI container-engine selection tests."""
from __future__ import annotations

import pytest

from harness import docker_ops


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
