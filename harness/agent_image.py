# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Build a per-target agent image by layering the pinned Claude CLI and
debugging tools onto the complete target image.

Keeping the target image as the base preserves runtime libraries installed
outside ``/work`` while leaving target Dockerfiles as the single source of
truth for the instrumented build.
"""

from __future__ import annotations

import functools
import hashlib
import re
import subprocess
import tempfile
import textwrap

from . import docker_ops

CLAUDE_CODE_VERSION = "2.1.144"  # bump alongside the dev-env CLI pin
CODEX_VERSION = "0.153.1"
GEMINI_VERSION = "0.61.0"
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")


def agent_tag(target_tag: str) -> str:
    """Legacy-compatible base tag for a target.

    ``ensure`` adds the immutable target image ID to the version component.
    Keeping this helper stable preserves the repository name used by setup
    tooling and older callers; it is not itself a freshness key.
    """
    return f"{target_tag.replace(':', '-')}-agent:{CLAUDE_CODE_VERSION}"


def _agent_dockerfile(target_tag: str) -> str:
    return textwrap.dedent(f"""\
        FROM {target_tag}
        USER root
        RUN apt-get update && \\
            apt-get install -y --no-install-recommends nodejs npm ca-certificates xxd gdb && \\
            rm -rf /var/lib/apt/lists/* && \\
            npm install -g @anthropic-ai/claude-code@{CLAUDE_CODE_VERSION}
        WORKDIR /work
    """)


def _backend_dockerfile(target_tag: str, backend: str) -> str:
    if backend == "claude":
        return _agent_dockerfile(target_tag)
    package = (f"@openai/codex@{CODEX_VERSION}" if backend in ("codex", "ollama")
               else f"@google/gemini-cli@{GEMINI_VERSION}")
    return textwrap.dedent(f"""\
        FROM node:22-bookworm-slim AS node
        FROM {target_tag}
        USER root
        RUN apt-get update && \\
            apt-get install -y --no-install-recommends ca-certificates xxd gdb && \\
            rm -rf /var/lib/apt/lists/*
        COPY --from=node /usr/local/bin/node /usr/local/bin/node
        COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
        RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \\
            npm install -g {package}
        WORKDIR /work
    """)


def _digest_tag(target_tag: str, target_image_id: str) -> str:
    digest = target_image_id.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-fA-F]{12,}", digest):
        raise ValueError(f"invalid target image ID: {target_image_id!r}")
    recipe = hashlib.sha256(
        _agent_dockerfile(target_tag).encode("utf-8")
    ).hexdigest()[:12]
    base = agent_tag(target_tag).rsplit(":", 1)[0]
    return f"{base}:{CLAUDE_CODE_VERSION}-{digest[:16].lower()}-{recipe}"


def latest_tag(target_tag: str) -> str:
    """Stable alias for infrastructure probes; never used as a cache key."""
    return f"{agent_tag(target_tag).rsplit(':', 1)[0]}:latest"


def _build(dockerfile: str, tag: str) -> None:
    with tempfile.TemporaryDirectory() as ctx:
        with open(f"{ctx}/Dockerfile", "w") as f:
            f.write(dockerfile)
        subprocess.run(
            docker_ops.command("build", "-q", "-t", tag, ctx),
            check=True,
            capture_output=True,
            text=True,
        )


@functools.lru_cache(maxsize=None)
def _ensure_for_image(target_tag: str, target_image_id: str) -> str:
    if not _TAG_RE.match(target_tag):
        raise ValueError(f"invalid image tag: {target_tag!r}")
    tag = _digest_tag(target_tag, target_image_id)
    if not docker_ops.image_exists(tag):
        _build(_agent_dockerfile(target_tag), tag)
    subprocess.run(
        docker_ops.command("tag", tag, latest_tag(target_tag)),
        check=True,
    )
    return tag


def ensure(target_tag: str) -> str:
    """Build and return an agent image for the target's current immutable ID."""
    from .agent_backends import selected
    backend = selected()
    if backend == "claude":
        return _ensure_for_image(target_tag, docker_ops.image_id(target_tag))
    return _ensure_backend_image(target_tag, docker_ops.image_id(target_tag), backend)


@functools.lru_cache(maxsize=None)
def _ensure_backend_image(target_tag: str, target_image_id: str, backend: str) -> str:
    if not _TAG_RE.match(target_tag):
        raise ValueError(f"invalid image tag: {target_tag!r}")
    digest = target_image_id.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-fA-F]{12,}", digest):
        raise ValueError(f"invalid target image ID: {target_image_id!r}")
    recipe = _backend_dockerfile(target_tag, backend)
    recipe_digest = hashlib.sha256(recipe.encode()).hexdigest()[:12]
    base = agent_tag(target_tag).rsplit(":", 1)[0]
    tag = f"{base}-{backend}:{digest[:16].lower()}-{recipe_digest}"
    if not docker_ops.image_exists(tag):
        _build(recipe, tag)
    subprocess.run(docker_ops.command("tag", tag, latest_tag(target_tag)), check=True)
    return tag
