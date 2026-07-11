# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Thin docker CLI wrapper. Shelling out keeps it dependency-free.

Agent containers run under gVisor on the `vp-internal` `--internal` network;
egress is restricted to the API allowlist proxy. The agent gets Bash inside
that sandbox: read source, run the binary, write PoC files, nothing else.
"""
from __future__ import annotations

import os
import shutil
import subprocess


def engine() -> str:
    """Return the selected OCI engine (Docker by default, Podman when opted in)."""
    value = os.environ.get("VULN_PIPELINE_CONTAINER_ENGINE", "docker").strip()
    if value not in {"docker", "podman"}:
        raise ValueError(
            "VULN_PIPELINE_CONTAINER_ENGINE must be 'docker' or 'podman', "
            f"not {value!r}"
        )
    if not shutil.which(value):
        raise RuntimeError(
            f"container engine {value!r} is not installed or not on PATH"
        )
    if value == "podman" and os.geteuid() != 0:
        raise RuntimeError(
            "Podman execution verification requires rootful Podman. Run the "
            "pipeline with 'sudo -E bin/vp-sandboxed ...' or use Docker."
        )
    if value == "podman" and (
        os.environ.get("CONTAINER_HOST") or os.environ.get("CONTAINER_CONNECTION")
    ):
        raise RuntimeError(
            "Podman execution verification requires the local rootful Podman "
            "service; unset CONTAINER_HOST and CONTAINER_CONNECTION."
        )
    return value


def command(*args: str) -> list[str]:
    """Build an OCI-engine command using the configured engine."""
    return [engine(), *args]


def build(dockerfile_dir: str, tag: str) -> str:
    """Build a docker image from a directory containing a Dockerfile."""
    subprocess.run(
        command("build", "-t", tag, dockerfile_dir),
        check=True,
    )
    return tag


def run(
    image_tag: str,
    name: str,
    network: str = "none",
    memory: str = "4g",
    shm_size: str | None = None,
    shell: str = "/bin/bash",
    runtime: str | None = None,
    env: dict[str, str] | None = None,
    mounts: list[tuple[str, str]] | None = None,
) -> str:
    """Start a container, detached, interactive. Cleans up any existing
    container with the same name first (clean slate).

    ``runtime`` selects an OCI runtime (e.g. ``runsc`` for gVisor). The
    active runtime is verified via ``docker inspect`` so a typo or missing
    registration fails loudly instead of silently falling back to runc."""
    subprocess.run(command("rm", "-f", name), capture_output=True)
    runtime = runtime or os.environ.get("VULN_PIPELINE_DOCKER_RUNTIME")
    extra: list[str] = []
    if runtime:
        extra += ["--runtime", runtime]
    if shm_size:
        extra += ["--shm-size", shm_size]
    for k, v in (env or {}).items():
        extra += ["-e", f"{k}={v}"]
    selected_engine = engine()
    for src, dst in (mounts or []):
        # Podman on SELinux-enforcing hosts needs a shared relabel for the
        # container to read the mounted, host-owned artifact.
        suffix = ":ro,z" if selected_engine == "podman" else ":ro"
        extra += ["-v", f"{src}:{dst}{suffix}"]
    r = subprocess.run(
        [
            *command("run", "-dit"),
            *extra,
            "--name", name,
            "--network", network,
            "--memory", memory,
            image_tag, shell,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"{selected_engine} run failed (exit {r.returncode}): {r.stderr.strip()}"
        )
    runtime_field = "{{.OCIRuntime}}" if selected_engine == "podman" else "{{.HostConfig.Runtime}}"
    actual_image, actual_runtime = subprocess.run(
        command("inspect", name, "--format",
         f"{{{{.Config.Image}}}}\t{runtime_field}"),
        capture_output=True, text=True, check=True,
    ).stdout.rstrip("\n").split("\t")
    if actual_image != image_tag:
        rm(name)
        raise RuntimeError(
            f"container {name} has wrong image: requested {image_tag!r}, got {actual_image!r}"
        )
    if runtime and actual_runtime != runtime:
        rm(name)
        raise RuntimeError(
            f"container {name} runtime mismatch: requested {runtime!r}, "
            f"{selected_engine} reports {actual_runtime!r}"
        )
    return name


def read_file(container: str, path: str) -> bytes:
    """Read a file from inside a container. Returns b'' if the file doesn't
    exist — that's the detection for "agent narrated a PoC path it never wrote".
    """
    r = subprocess.run(
        command("exec", container, "cat", path),
        capture_output=True,
    )
    return r.stdout if r.returncode == 0 else b""


def write_file(container: str, path: str, content: bytes) -> None:
    """Write bytes to a path inside a container.

    Uses ``docker exec`` (not ``docker cp``) so the write happens from the
    container's own view of the filesystem — under gVisor, ``/tmp`` is an
    in-sandbox tmpfs that host-side ``docker cp`` can't reach."""
    subprocess.run(
        command("exec", "-i", container, "sh", "-c", 'cat > "$1"', "_", path),
        input=content,
        check=True,
        capture_output=True,
    )


def rm(container: str) -> None:
    """Remove a container, force-killing if running. Idempotent."""
    subprocess.run(command("rm", "-f", container), capture_output=True)


def image_exists(tag: str) -> bool:
    """Check whether an image tag exists locally."""
    r = subprocess.run(
        command("image", "inspect", tag),
        capture_output=True,
    )
    return r.returncode == 0


def exec_sh(
    container: str, shell_command: str, timeout: int | None = None
) -> tuple[int, str, str]:
    """Run a shell command inside a container and return (rc, stdout, stderr).

    Unlike read_file/write_file this passes the command through sh -c so shell
    syntax (pipes, &&, redirects) works. Raises subprocess.TimeoutExpired on
    timeout — caller decides whether that's a tier failure or a hard error.
    """
    r = subprocess.run(
        command("exec", container, "sh", "-c", shell_command),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def commit(container: str, tag: str) -> str:
    """Snapshot a container's filesystem as a new image. Used by re-attack to
    run a find-agent against the patched binary without rebuilding."""
    subprocess.run(command("commit", container, tag), check=True, capture_output=True)
    return tag


def rmi(tag: str) -> None:
    """Remove an image tag. Idempotent."""
    subprocess.run(command("rmi", "-f", tag), capture_output=True)
