# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Host-side upstream novelty check.

Opt-in (`--novelty`). When enabled, the orchestrator shallow-clones the
upstream repo and runs `git log <commit>..HEAD -- <file>` for the crashing
file. The output is injected into the report prompt — the report container
stays `--network none`, only the orchestrator touches the network.

When disabled (default), the prompt receives NOVELTY_NOT_CHECKED.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

CACHE_ROOT = Path.home() / ".cache" / "vuln-pipeline" / "novelty"
NOVELTY_NOT_CHECKED = "(host-side upstream check not performed — run with --novelty to enable)"


def upstream_log(github_url: str, commit: str, crash_file: str, max_bytes: int = 2000) -> str:
    """Return `git log <commit>..HEAD -- <crash_file>` from a cached shallow clone.

    Returns a status-prefixed string: either the truncated git log output or a
    one-line failure reason. Never raises — a network/git failure becomes
    prompt text, not a crashed pipeline.
    """
    try:
        github_url = _validated_upstream_url(github_url)
    except ValueError as exc:
        return f"[upstream URL rejected: {exc}]"
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        return "[upstream commit rejected: expected a 7-64 character hex object ID]"

    # Human-readable prefix plus a collision-resistant URL digest. Distinct
    # repositories must never share a writable git cache directory.
    parsed = urlparse(github_url)
    name = parsed.path.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    slug = re.sub(r"\W+", "_", name).strip("_")
    slug += "-" + hashlib.sha256(github_url.encode()).hexdigest()[:16]
    repo_dir = CACHE_ROOT / slug

    ok, msg = _ensure_clone(github_url, repo_dir)
    if not ok:
        return f"[upstream fetch failed: {msg}]"

    # The ASAN frame gives a container path (e.g. /work/dr_wav.h). The repo
    # clone won't have /work/ — match on basename. For multi-file repos this
    # might be ambiguous; take the first match.
    basename = crash_file.rsplit("/", 1)[-1]
    r = subprocess.run(
        ["git", "-C", str(repo_dir), "ls-files", "--", f"*{basename}"],
        capture_output=True, text=True,
    )
    candidates = r.stdout.split()
    if not candidates:
        return f"[no file matching {basename} in upstream repo]"
    repo_path = candidates[0]

    r = subprocess.run(
        ["git", "-C", str(repo_dir), "log", "--oneline",
         f"{commit}..HEAD", "--", repo_path],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return f"[git log failed: {r.stderr.strip()[:200]}]"

    log = r.stdout
    if not log.strip():
        return f"[no commits touched {repo_path} since {commit[:12]}]"
    if len(log) > max_bytes:
        kept = log[:max_bytes].rsplit("\n", 1)[0]
        return kept + f"\n[... truncated, {log.count(chr(10))} total commits]"
    return log


def _validated_upstream_url(value: str) -> str:
    """Allow only credential-free HTTPS repositories on approved hosts."""
    parsed = urlparse(value)
    allowed = {
        host.strip().lower()
        for host in os.environ.get(
            "VULN_PIPELINE_NOVELTY_HOSTS", "github.com"
        ).split(",")
        if host.strip()
    }
    if parsed.scheme != "https":
        raise ValueError("only https URLs are allowed")
    if parsed.username or parsed.password:
        raise ValueError("embedded credentials are not allowed")
    if parsed.port is not None:
        raise ValueError("explicit ports are not allowed")
    if (parsed.hostname or "").lower() not in allowed:
        raise ValueError(
            f"host {(parsed.hostname or '(missing)')!r} is not approved"
        )
    if parsed.query or parsed.fragment:
        raise ValueError("query strings and fragments are not allowed")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or any(part in (".", "..") for part in parts):
        raise ValueError("expected /owner/repository path")
    return value


def _ensure_clone(github_url: str, repo_dir: Path) -> tuple[bool, str]:
    """Clone if missing, fetch if present, without following HTTP redirects."""
    if (repo_dir / ".git").is_dir():
        r = subprocess.run(
            ["git", "-c", "http.followRedirects=false", "-C", str(repo_dir),
             "fetch", "--quiet", "origin", "HEAD"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return False, f"fetch: {r.stderr.strip()[:200]}"
        return True, ""

    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "-c", "http.followRedirects=false", "clone", "--quiet",
         "--filter=blob:none", github_url, str(repo_dir)],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        return False, f"clone: {r.stderr.strip()[:200]}"
    return True, ""


_FRAME_FILE = re.compile(r"(\S+):(\d+)$")


def crash_file_from_frame(frame: str) -> str | None:
    """Extract the file path from a top_frame string like `func /path/file.h:1234`."""
    m = _FRAME_FILE.search(frame)
    return m.group(1) if m else None
