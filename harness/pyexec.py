# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Machine-owned proof rules for the ``python_exec`` profile.

The in-container monitor (harness/monitor/sitecustomize.py) writes
``<token> IVCD-EVENT <json>`` lines to stderr. Everything here runs on the
host, against the observations the *grader* collected with a fresh random
token per replay. Nothing in this module trusts agent-authored text: lines
without the current token are ignored, and a token-prefixed line that does
not parse makes the replay fail (fail closed).

Proof kinds (the finding's claimed ``crash_type`` must be one of them):

* ``exec``         a command/exec event whose executable or command is
                   ``ivcd-proof``
* ``path_escape``  an ``open`` event resolving outside the allowed roots
* ``secret_read``  the per-replay canary, planted by the grader in a file
                   outside the allowed roots, appears in replay output
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field

EVENT_MARK = "IVCD-EVENT"
PROOF_COMMAND = "ivcd-proof"
KINDS = ("exec", "path_escape", "secret_read")
MONITOR_DIR = "/opt/vp/monitor"
CANARY_PATH = "/tmp/ivcd-canary.txt"
_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
# Command-position splitters for shell strings (os.system / shell=True).
_SPLIT = re.compile(r"[;&|\n`()]|\$\(")


@dataclass
class ParsedEvents:
    ready: bool = False
    events: list[dict] = field(default_factory=list)
    malformed: int = 0


@dataclass(frozen=True)
class ReplayProof:
    passed: bool
    reason: str
    signature: tuple[str, str, str] | None = None


def valid_token(token: str) -> bool:
    return bool(_TOKEN_RE.fullmatch(token or ""))


def parse_events(stderr: str, token: str) -> ParsedEvents:
    """Extract events carrying exactly ``token``; ignore every other line."""
    out = ParsedEvents()
    if not valid_token(token):
        out.malformed += 1  # no usable token => nothing can be trusted
        return out
    prefix = f"{token} {EVENT_MARK} "
    for line in stderr.splitlines():
        if not line.startswith(prefix):
            continue
        try:
            event = json.loads(line[len(prefix):])
        except json.JSONDecodeError:
            out.malformed += 1
            continue
        if (not isinstance(event, dict) or not isinstance(event.get("kind"), str)
                or not isinstance(event.get("sink"), str)):
            out.malformed += 1
            continue
        if event["kind"] == "monitor":
            out.ready = out.ready or event["sink"] == "ready"
        else:
            out.events.append(event)
    return out


def command_words(command: str) -> list[str]:
    """First word of every command position in a shell string."""
    words = []
    for segment in _SPLIT.split(command):
        parts = segment.split()
        if parts:
            words.append(parts[0])
    return words


def _is_proof_word(value: object) -> bool:
    return isinstance(value, str) and posixpath.basename(value) == PROOF_COMMAND


def is_proof_exec(event: dict) -> bool:
    if event.get("kind") not in ("command", "exec"):
        return False
    args = event.get("args")
    if not isinstance(args, list) or not args:
        return False
    if event.get("sink") == "os.system":
        return isinstance(args[0], str) and any(
            _is_proof_word(w) for w in command_words(args[0]))
    # subprocess.Popen / os.exec / os.posix_spawn: [executable, argv, ...]
    if _is_proof_word(args[0]):
        return True
    argv = args[1] if len(args) > 1 else None
    if isinstance(argv, list):
        return bool(argv) and _is_proof_word(argv[0])
    if isinstance(argv, str):  # Popen(shell=True)
        return any(_is_proof_word(w) for w in command_words(argv))
    return False


def _in_roots(path: str, roots: list[str]) -> bool:
    return any(path == r.rstrip("/") or path.startswith(r.rstrip("/") + "/") for r in roots)


def _frame_in_root(event: dict, source_root: str) -> str | None:
    frame = event.get("frame")
    if not isinstance(frame, dict):
        return None
    file, func = frame.get("file"), frame.get("function")
    if (isinstance(file, str) and isinstance(func, str)
            and file.startswith(source_root.rstrip("/") + "/")):
        return func
    return None


def is_path_escape(event: dict, allowed_roots: list[str], exclude: set[str]) -> bool:
    if event.get("kind") != "open" or event.get("sink") != "open":
        return False
    resolved = event.get("resolved")
    if not isinstance(resolved, str) or not resolved.startswith("/"):
        return False
    return resolved not in exclude and not _in_roots(resolved, allowed_roots)


def evaluate_replay(
    claimed_kind: str,
    parsed: ParsedEvents,
    *,
    output: str,
    canary: str,
    allowed_roots: list[str],
    source_root: str,
    artifact_path: str,
) -> ReplayProof:
    """Decide one replay. ``output`` is stdout+stderr as captured."""
    if claimed_kind not in KINDS:
        return ReplayProof(False, f"unknown proof kind {claimed_kind!r}")
    if parsed.malformed:
        return ReplayProof(False, "unparseable monitor event(s)")
    if not parsed.ready:
        return ReplayProof(False, "monitor handshake missing (monitor not loaded or token not honoured)")
    # The PoC file and the canary file are planted by the pipeline; reading
    # them is not an escape by itself (the entry script feeds the PoC in).
    exclude = {artifact_path}

    if claimed_kind == "exec":
        for ev in parsed.events:
            func = _frame_in_root(ev, source_root)
            if func and is_proof_exec(ev):
                return ReplayProof(True, "ivcd-proof executed", ("exec", ev["sink"], func))
        return ReplayProof(False, "no ivcd-proof command/exec event from target code")

    if claimed_kind == "path_escape":
        for ev in parsed.events:
            func = _frame_in_root(ev, source_root)
            if func and is_path_escape(ev, allowed_roots, exclude):
                return ReplayProof(True, f"opened {ev['resolved']}", ("path_escape", ev["sink"], func))
        return ReplayProof(False, "no open event outside allowed roots from target code")

    # secret_read
    if not canary or canary not in output:
        return ReplayProof(False, "canary not present in replay output")
    for ev in parsed.events:
        func = _frame_in_root(ev, source_root)
        if func and ev.get("kind") == "open" and ev.get("resolved") == CANARY_PATH:
            return ReplayProof(True, "canary file read and echoed", ("secret_read", ev["sink"], func))
    return ReplayProof(True, "canary echoed (no corroborating open event)",
                       ("secret_read", "output", "-"))


def lenient_signature(crash_output: str) -> tuple[str, str, str] | None:
    """(kind, sink, in-target function) from agent-claimed event text.

    DISPLAY ONLY (found_bugs/judge context). Agent text is untrusted, so this
    never feeds a verdict; the grader's own ``ReplayProof.signature`` does."""
    for line in crash_output.splitlines():
        _, _, rest = line.partition(EVENT_MARK + " ")
        if not rest:
            continue
        try:
            ev = json.loads(rest)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict) and ev.get("kind") not in (None, "monitor"):
            frame = ev.get("frame") if isinstance(ev.get("frame"), dict) else {}
            return (str(ev.get("kind")), str(ev.get("sink")), str(frame.get("function", "?")))
    return None


def excerpt(crash_output: str, max_lines: int = 8) -> str:
    """Compact, token-free excerpt of claimed events for dedup context."""
    lines = []
    for line in crash_output.splitlines():
        _, _, rest = line.partition(EVENT_MARK + " ")
        if rest:
            lines.append(f"{EVENT_MARK} {rest.strip()}"[:400])
        if len(lines) >= max_lines:
            break
    if not lines:
        lines = [l.strip() for l in crash_output.splitlines() if l.strip()][:3]
    sig = lenient_signature(crash_output)
    head = f"signature: {sig[0]} {sig[1]} in {sig[2]}\n" if sig else ""
    return head + "\n".join(lines)
