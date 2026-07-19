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
import re
import subprocess
import tempfile
import textwrap

from . import docker_ops

CLAUDE_CODE_VERSION = "2.1.144"  # bump alongside the dev-env CLI pin
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")


def agent_tag(target_tag: str) -> str:
    """Distinct agent-image tag per *full* target tag, so a committed
    ``<name>:patched-<uuid>`` snapshot doesn't collide with ``<name>:v1``."""
    return f"{target_tag.replace(':', '-')}-agent:{CLAUDE_CODE_VERSION}"


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
def ensure(target_tag: str) -> str:
    """Build (if missing) and return the agent-image tag for ``target_tag``."""
    if not _TAG_RE.match(target_tag):
        raise ValueError(f"invalid image tag: {target_tag!r}")
    tag = agent_tag(target_tag)
    if docker_ops.image_exists(tag):
        return tag
    _build(
        textwrap.dedent(f"""\
            FROM {target_tag}
            USER root
            RUN apt-get update && \\
                apt-get install -y --no-install-recommends nodejs npm ca-certificates xxd gdb && \\
                rm -rf /var/lib/apt/lists/* && \\
                npm install -g @anthropic-ai/claude-code@{CLAUDE_CODE_VERSION}
            WORKDIR /work
        """),
        tag,
    )
    subprocess.run(
        docker_ops.command("tag", tag, f"{tag.rsplit(':', 1)[0]}:latest"),
        check=True,
    )
    return tag
