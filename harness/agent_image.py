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
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

from . import docker_ops

CLAUDE_CODE_VERSION = "2.1.144"  # bump alongside the dev-env CLI pin
CODEX_VERSION = "0.153.1"
GEMINI_VERSION = "0.61.0"
# Base images are pinned by manifest-list digest (the tag is kept for humans).
# Agent CLIs install from a committed package-lock.json (harness/locks/<cli>/)
# via `npm ci`, so every transitive tarball is integrity-checked (sha512).
NODE_IMAGE = ("node:22-bookworm-slim@sha256:"
              "e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee")
ALPINE_IMAGE = ("alpine:3.21@sha256:"
                "bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab")
_LOCK_DIR = Path(__file__).parent / "locks"
_CLI_BIN = {"claude": "claude", "codex": "codex", "gemini": "gemini"}
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")


def agent_tag(target_tag: str) -> str:
    """Legacy-compatible base tag for a target.

    ``ensure`` adds the immutable target image ID to the version component.
    Keeping this helper stable preserves the repository name used by setup
    tooling and older callers; it is not itself a freshness key.
    """
    return f"{target_tag.replace(':', '-')}-agent:{CLAUDE_CODE_VERSION}"


def _lock_name(backend: str) -> str:
    return "codex" if backend == "ollama" else backend


def _lock_digest(backend: str) -> str:
    """Hash of the lock inputs, embedded in the Dockerfile so changing a lock
    changes the recipe digest and therefore the image tag."""
    d = _LOCK_DIR / _lock_name(backend)
    h = hashlib.sha256()
    for name in ("package.json", "package-lock.json"):
        h.update((d / name).read_bytes())
    return h.hexdigest()


def _cli_install(backend: str) -> list[str]:
    name = _lock_name(backend)
    binary = _CLI_BIN[name]
    return [
        f"COPY locks/{name}/package.json locks/{name}/package-lock.json /opt/ivcd-cli/",
        "RUN cd /opt/ivcd-cli && npm ci --no-audit --no-fund && \\",
        f"    ln -sf /opt/ivcd-cli/node_modules/.bin/{binary} /usr/local/bin/{binary}",
        f"# lock sha256: {_lock_digest(backend)}",
    ]


def _agent_dockerfile(base_image: str) -> str:
    return "\n".join([
        f"FROM {base_image}",
        "USER root",
        "RUN apt-get update && \\",
        "    apt-get install -y --no-install-recommends nodejs npm ca-certificates xxd gdb && \\",
        "    rm -rf /var/lib/apt/lists/*",
        *_cli_install("claude"),
        "WORKDIR /work",
        "",
    ])


def _backend_dockerfile(base_image: str, backend: str) -> str:
    if backend == "claude":
        return _agent_dockerfile(base_image)
    return "\n".join([
        f"FROM {NODE_IMAGE} AS node",
        f"FROM {base_image}",
        "USER root",
        "RUN apt-get update && \\",
        "    apt-get install -y --no-install-recommends ca-certificates xxd gdb && \\",
        "    rm -rf /var/lib/apt/lists/*",
        "COPY --from=node /usr/local/bin/node /usr/local/bin/node",
        "COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm",
        "RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm",
        *_cli_install(backend),
        "WORKDIR /work",
        "",
    ])


def _base_image_tag(target_image_id: str) -> str:
    """Name an exact local image without depending on its mutable target tag."""
    digest = target_image_id.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError(f"invalid target image ID: {target_image_id!r}")
    return f"vuln-pipeline-agent-base:{digest.lower()}"
def _digest_tag(target_tag: str, target_image_id: str) -> str:
    digest = target_image_id.removeprefix("sha256:")
    base_tag = _base_image_tag(target_image_id)
    recipe = hashlib.sha256(
        _agent_dockerfile(base_tag).encode("utf-8")
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
        shutil.copytree(_LOCK_DIR, f"{ctx}/locks")
        subprocess.run(
            docker_ops.command("build", "-q", "-t", tag, ctx),
            check=True,
            capture_output=True,
            text=True,
        )


def _tag_aliases(tag: str, target_tag: str) -> None:
    # Older infrastructure callers still use agent_tag(), while setup probes
    # use latest_tag(). Refresh both after every content-addressed build.
    for alias in (agent_tag(target_tag), latest_tag(target_tag)):
        subprocess.run(docker_ops.command("tag", tag, alias), check=True)


@functools.lru_cache(maxsize=None)
def _ensure_for_image(target_tag: str, target_image_id: str) -> str:
    if not _TAG_RE.match(target_tag):
        raise ValueError(f"invalid image tag: {target_tag!r}")
    tag = _digest_tag(target_tag, target_image_id)
    if not docker_ops.image_exists(tag):
        base_tag = _base_image_tag(target_image_id)
        docker_ops.tag(target_image_id, base_tag)
        _build(_agent_dockerfile(base_tag), tag)
    _tag_aliases(tag, target_tag)
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
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError(f"invalid target image ID: {target_image_id!r}")
    base_tag = _base_image_tag(target_image_id)
    recipe = _backend_dockerfile(base_tag, backend)
    recipe_digest = hashlib.sha256(recipe.encode()).hexdigest()[:12]
    base = agent_tag(target_tag).rsplit(":", 1)[0]
    tag = f"{base}-{backend}:{digest[:16].lower()}-{recipe_digest}"
    if not docker_ops.image_exists(tag):
        docker_ops.tag(target_image_id, base_tag)
        _build(recipe, tag)
    _tag_aliases(tag, target_tag)
    return tag
