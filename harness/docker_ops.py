# Copyright 2026 IVProduced contributors
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
import tempfile
import threading
from pathlib import Path

# Bounds on data that crosses from an untrusted container to the host.
DEFAULT_CPUS = "2"
READ_FILE_MAX_BYTES = 8 * 1024 * 1024
READ_FILE_TIMEOUT_S = 30
EXEC_MAX_OUTPUT_BYTES = 4 * 1024 * 1024


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
    """Build an image and return the immutable ID produced by that build.

    ``--iidfile`` binds the returned ID to this invocation even if another
    process concurrently replaces the mutable output tag.
    """
    with tempfile.TemporaryDirectory(prefix="ivcd-build-") as directory:
        iidfile = Path(directory) / "image-id"
        subprocess.run(
            command("build", "--iidfile", str(iidfile), "-t", tag, dockerfile_dir),
            check=True,
        )
        image_id = iidfile.read_text().strip()
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise RuntimeError(f"container build returned invalid image ID: {image_id!r}")
    return image_id


def run(
    image_tag: str,
    name: str,
    network: str = "none",
    memory: str = "4g",
    pids_limit: int = 512,
    shm_size: str | None = None,
    shell: str = "/bin/bash",
    runtime: str | None = None,
    env: dict[str, str] | None = None,
    mounts: list[tuple[str, str]] | None = None,
    cpus: str | None = None,
    read_only: bool = False,
    user: str | None = None,
) -> str:
    """Start a container, detached, interactive. Cleans up any existing
    container with the same name first (clean slate).

    ``runtime`` selects an OCI runtime (e.g. ``runsc`` for gVisor). The
    active runtime is verified via ``docker inspect`` so a typo or missing
    registration fails loudly instead of silently falling back to runc.
    The image's ENTRYPOINT is cleared because this function always starts
    ``shell`` explicitly."""
    subprocess.run(command("rm", "-f", name), capture_output=True)
    runtime = runtime or os.environ.get("VULN_PIPELINE_DOCKER_RUNTIME")
    extra: list[str] = []
    if runtime:
        extra += ["--runtime", runtime]
    # Agent containers execute attacker-influenced targets and receive model
    # instructions. Keep the OCI boundary least-privileged even under gVisor.
    extra += [
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", str(pids_limit),
        "--cpus", cpus or os.environ.get("VULN_PIPELINE_CPUS") or DEFAULT_CPUS,
        # Every caller starts its own shell. Do not run a target image's
        # inherited ENTRYPOINT with model credentials before that shell.
        "--entrypoint", "",
    ]
    if read_only:
        # Immutable root; only scratch space is writable.
        extra += ["--read-only",
                  "--tmpfs", "/tmp:rw,exec,mode=1777,size=512m",
                  "--tmpfs", "/run:rw,mode=755,size=16m"]
    if user:
        extra += ["--user", user]
    if shm_size:
        extra += ["--shm-size", shm_size]
    for k, v in (env or {}).items():
        # Prefer ``-e KEY`` (value read from this process's env) so secrets don't
        # appear in argv / host ps output. Fall back to ``-e KEY=VAL`` for
        # computed values (e.g. HTTPS_PROXY) that aren't in our env.
        extra += ["-e", k] if os.environ.get(k) == v else ["-e", f"{k}={v}"]
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


def read_file(
    container: str,
    path: str,
    max_bytes: int = READ_FILE_MAX_BYTES,
    timeout: float = READ_FILE_TIMEOUT_S,
) -> bytes:
    """Read a regular file from inside a container. Returns b'' if the file
    doesn't exist — that's the detection for "agent narrated a PoC path it never wrote".

    ``path`` is chosen by an untrusted agent, so the read is bounded three ways:
    only regular files (``test -f`` rejects /dev/zero, FIFOs and symlinks to
    them), at most ``max_bytes`` (larger files are rejected, not truncated, so
    a clipped PoC never gets graded), and a wall-clock ``timeout`` that kills
    the host-side exec."""
    script = 'test -f "$1" && head -c "$2" -- "$1"'
    try:
        rc, out, _err, over = _bounded_exec(
            command("exec", container, "sh", "-c", script, "_", path,
                    str(max_bytes + 1)),
            max_output=max_bytes + 1, timeout=timeout, text=False,
        )
    except subprocess.TimeoutExpired:
        return b""
    if rc != 0 or over or len(out) > max_bytes:
        return b""
    return out


def _bounded_exec(argv, *, max_output, timeout, text, stdin=None):
    """Run ``argv`` capturing at most ``max_output`` bytes per stream.

    Excess output is drained and discarded (so the child never blocks on a
    full pipe) and reported via the ``truncated`` flag. On timeout the child is
    killed and ``TimeoutExpired`` raised."""
    proc = subprocess.Popen(
        argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    bufs: list[list[bytes]] = [[], []]
    truncated = [False, False]

    def drain(stream, idx):
        kept = 0
        while chunk := stream.read(65536):
            room = max_output - kept
            if room > 0:
                bufs[idx].append(chunk[:room])
                kept += min(room, len(chunk))
            if len(chunk) > room:
                truncated[idx] = True

    threads = [threading.Thread(target=drain, args=(proc.stdout, 0), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, 1), daemon=True)]
    for t in threads:
        t.start()
    if stdin is not None:
        def feed():
            try:
                proc.stdin.write(stdin)
                proc.stdin.close()
            except OSError:
                pass
        threading.Thread(target=feed, daemon=True).start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        for t in threads:
            t.join(timeout=2)
        raise subprocess.TimeoutExpired(argv, timeout)
    for t in threads:
        t.join(timeout=5)
    out, err = b"".join(bufs[0]), b"".join(bufs[1])
    if text:
        out = out.decode("utf-8", errors="replace")
        err = err.decode("utf-8", errors="replace")
    return proc.returncode, out, err, any(truncated)


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


def image_id(tag: str) -> str:
    """Return the immutable OCI image ID behind ``tag``.

    Derived images must be keyed to this value rather than the mutable tag or
    they can silently retain an older target filesystem after a rebuild.
    """
    r = subprocess.run(
        command("image", "inspect", "--format", "{{.Id}}", tag),
        capture_output=True,
        text=True,
    )
    value = r.stdout.strip()
    if r.returncode != 0 or not value:
        detail = r.stderr.strip() or f"image {tag!r} has no ID"
        raise RuntimeError(f"unable to inspect image {tag!r}: {detail}")
    return value


def tag(source: str, destination: str) -> str:
    """Create or update a local image tag."""
    subprocess.run(
        command("tag", source, destination),
        check=True,
        capture_output=True,
        text=True,
    )
    return destination


class OutputTruncated(RuntimeError):
    """Captured output hit the cap and the caller needs the whole stream."""


def kill_all(container: str) -> None:
    """SIGKILL every process in a container (PID 1 is immune by design).

    Killing the host-side ``docker exec`` client does not signal the process it
    started inside the container, so a timed-out command keeps running (and
    consuming CPU/memory) unless we do this. Only call it on containers owned
    by a single sequential caller."""
    try:
        subprocess.run(
            command("exec", container, "sh", "-c", "kill -9 -1"),
            capture_output=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass


def exec_sh(
    container: str,
    shell_command: str,
    timeout: int | None = None,
    max_output: int = EXEC_MAX_OUTPUT_BYTES,
    env: dict[str, str] | None = None,
    fail_on_truncate: bool = False,
) -> tuple[int, str, str]:
    """Run a shell command inside a container and return (rc, stdout, stderr).

    Unlike read_file/write_file this passes the command through sh -c so shell
    syntax (pipes, &&, redirects) works. Output is capped at ``max_output``
    bytes per stream (a marker line is appended when clipped). On timeout the
    in-container processes are killed and subprocess.TimeoutExpired is raised —
    caller decides whether that's a tier failure or a hard error.

    ``fail_on_truncate`` raises ``OutputTruncated`` instead of returning clipped
    output. Use it for *absence* checks ("the canary/ASAN marker is not in the
    output"): a leak past the cap would otherwise read as a clean run.

    ``env`` sets per-exec variables (used for the web grader's one-shot
    canary; never pass secrets here — they appear in host argv).
    """
    env_args = [a for k, v in (env or {}).items() for a in ("-e", f"{k}={v}")]
    try:
        rc, out, err, clipped = _bounded_exec(
            command("exec", *env_args, container, "sh", "-c", shell_command),
            max_output=max_output, timeout=timeout, text=True,
        )
    except subprocess.TimeoutExpired:
        kill_all(container)
        raise
    if clipped:
        if fail_on_truncate:
            raise OutputTruncated(f"output exceeded {max_output} bytes")
        out += f"\n[output truncated at {max_output} bytes per stream]\n"
    return rc, out, err


def commit(container: str, tag: str) -> str:
    """Snapshot a container's filesystem as a new image. Used by re-attack to
    run a find-agent against the patched binary without rebuilding."""
    subprocess.run(command("commit", container, tag), check=True, capture_output=True)
    return tag


def rmi(tag: str) -> None:
    """Remove an image tag. Idempotent."""
    subprocess.run(command("rmi", "-f", tag), capture_output=True)
