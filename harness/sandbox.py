# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Agent-sandbox configuration.

The pipeline spawns each find/grade/report/recon agent inside a gVisor
container on an `--internal` docker network whose only egress is the
allowlist proxy (default ``api.anthropic.com:443``; provider-derived for
Bedrock/Vertex — see ``harness.auth``). bin/vp-sandboxed sets the env vars
below after verifying the runtime and proxy are up; the per-phase modules
read them via this module rather than threading them through cli.py.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

from . import agent_image, docker_ops

RUNTIME_ENV = "VULN_PIPELINE_AGENT_RUNTIME"
PROXY_ENV = "VULN_PIPELINE_EGRESS_PROXY"
NETWORK_ENV = "VULN_PIPELINE_AGENT_NETWORK"
GATEWAY_ENV = "VULN_PIPELINE_CREDENTIAL_GATEWAY"
NETWORK_DEFAULT = "vp-internal"
# Placeholder the in-container CLI sends; the gateway replaces it with the
# real credential, which never enters a container that runs target code.
GATEWAY_PLACEHOLDER = "sk-ant-ivcd-gateway-placeholder"
NONROOT_USER = "65534:65534"
VERTEX_CREDENTIAL_PATH = "/run/secrets/google-application-credentials.json"


def runtime() -> str | None:
    return os.environ.get(RUNTIME_ENV) or None


def proxy() -> str | None:
    return os.environ.get(PROXY_ENV) or None


def gateway() -> str | None:
    """URL of the credential-injecting gateway sidecar, when one is active."""
    return os.environ.get(GATEWAY_ENV) or None


def network() -> str:
    if not runtime():
        return "bridge"
    return os.environ.get(NETWORK_ENV) or NETWORK_DEFAULT


# Alias so ``agent_container``'s ``network`` parameter can shadow the function
# name without losing access to the default-resolution logic.
_default_network = network


def permission_mode() -> str:
    """Permission mode for in-container ``claude -p`` sessions.

    With gVisor + the egress allowlist, the container is the boundary and the
    auto-mode classifier only blocks the agent's own /work writes — so run
    ``bypassPermissions``. Without the sandbox (``--dangerously-no-sandbox``),
    fall back to ``auto`` so the classifier still gates risky Bash and other
    side-effecting actions even though the container boundary is weaker.
    """
    return "bypassPermissions" if runtime() else "auto"


@contextlib.contextmanager
def agent_container(
    target_tag: str,
    name: str,
    auth: dict[str, str] | None,
    memory: str = "4g",
    shm_size: str | None = None,
    mounts: list[tuple[str, str]] | None = None,
    network: str | None = None,
    hardened: bool = False,
) -> Iterator[str]:
    """Spawn the per-phase agent container and tear it down on exit.

    All find/grade/report/recon/judge agents go through this so the
    "every agent runs in the sandbox" invariant lives in one place.

    ``network`` overrides the sandbox default. Pass ``"none"`` for containers
    that never run ``claude -p`` (e.g. the T0–T2 patch grader): they only run
    target code via ``exec_sh`` and don't need any egress, so don't give them
    any — under ``--dangerously-no-sandbox`` the default falls back to
    ``bridge``, and a binary fed an attacker-crafted PoC shouldn't get that.

    ``hardened`` adds a read-only root filesystem (writable tmpfs ``/tmp`` and
    ``/run``) and a non-root user. Use it for execution-only replay containers;
    agent and patch containers must write ``/work``."""
    img = agent_image.ensure(target_tag)
    env, prepared_mounts = _prepare_container_auth(auth, mounts)
    container = docker_ops.run(
        img,
        name=name,
        runtime=runtime(),
        network=network if network is not None else _default_network(),
        memory=memory,
        shm_size=shm_size,
        env=env,
        mounts=prepared_mounts,
        read_only=hardened,
        user=NONROOT_USER if hardened else None,
    )
    try:
        yield container
    finally:
        docker_ops.rm(container)


def container_env(auth: dict[str, str] | None) -> dict[str, str]:
    """Env to set on the agent container at ``docker run`` time.

    With the credential gateway active, Anthropic secrets are replaced by a
    placeholder (see ``GATEWAY_PLACEHOLDER``); other providers' credentials
    still pass through (documented residual risk in docs/security.md).

    Auth env from ``harness.auth.resolve_auth_env`` passes straight through;
    the egress proxy is injected (both upper- and lower-case forms — AWS SDKs
    read the lower-case one) when the sandbox is active so the in-container
    CLI can reach the model API."""
    e = dict(auth or {})
    if (gw := gateway()) and runtime():
        # Anthropic API-key / OAuth auth: swap the real secret for a
        # placeholder and route through the gateway, which injects it.
        swapped = False
        for key in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
            if key in e:
                e[key] = GATEWAY_PLACEHOLDER
                swapped = True
        if swapped:
            e["ANTHROPIC_BASE_URL"] = gw
            # The gateway speaks plain HTTP on the internal network; send it
            # direct, not through the CONNECT-only egress proxy.
            host = urlparse(gw).hostname or ""
            e["NO_PROXY"] = e["no_proxy"] = host
    if p := proxy():
        e["HTTPS_PROXY"] = p
        e["https_proxy"] = p
    return e


def _prepare_container_auth(
    auth: dict[str, str] | None,
    mounts: list[tuple[str, str]] | None,
) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Translate host credential-file paths into one exact read-only mount.

    Vertex uses Application Default Credentials from a JSON file. Mount only
    that file—not its parent or the user's gcloud directory—and point the
    in-container process at a fixed path. Other providers remain env-only.
    """
    env = container_env(auth)
    prepared = list(mounts or [])
    credential = env.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not credential:
        return env, prepared

    source = Path(credential).expanduser().resolve()
    if not source.is_file():
        raise ValueError(f"GOOGLE_APPLICATION_CREDENTIALS is not a file: {source}")
    if any(dst == VERTEX_CREDENTIAL_PATH for _src, dst in prepared):
        raise ValueError(f"mount destination {VERTEX_CREDENTIAL_PATH} is reserved")
    prepared.append((str(source), VERTEX_CREDENTIAL_PATH))
    env["GOOGLE_APPLICATION_CREDENTIALS"] = VERTEX_CREDENTIAL_PATH
    return env, prepared


def require(override: bool) -> str | None:
    """Return an error message if the sandbox isn't configured; else None."""
    if override:
        return None
    rt = runtime()
    if not rt:
        return (
            "error: refusing to spawn agents outside the sandbox.\n"
            "  Run via `bin/vp-sandboxed ...` (see docs/agent-sandbox.md), or pass\n"
            "  --dangerously-no-sandbox to run without gVisor isolation\n"
            "  (auto-mode permission classifier only; development use — see docs/security.md)."
        )
    try:
        docker_ops.engine()
    except (RuntimeError, ValueError) as e:
        return f"error: {e}"
    probe = subprocess.run(
        docker_ops.command("run", "--rm", "--runtime", rt, agent_image.ALPINE_IMAGE, "true"),
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        return (
            f"error: {RUNTIME_ENV}={rt!r} cannot start a sandbox container via "
            f"{docker_ops.engine()}: {probe.stderr.strip()}"
        )
    return None
