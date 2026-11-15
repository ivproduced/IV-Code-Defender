# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Structured event stream: one ``events.jsonl`` per batch.

Each line is a JSON object shaped for OpenTelemetry / OCSF-style ingestion:
``{"ts", "trace_id", "event", "agent", ...attrs}``. ``trace_id`` is constant
for a batch; ``agent`` is the progress prefix of the emitting agent
(``[find:3]``) so spans can be reconstructed from ``agent.start``/``agent.end``.

Events carry structural metadata only (tool names, counts, verdicts, costs).
Tool arguments are clipped and never include credentials, which the
orchestrator does not hold in agent-visible form. Emission is best-effort: a
full disk must never kill a run.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time

_lock = threading.Lock()
_path: str | None = None
_trace_id: str = ""


def configure(path: str | os.PathLike | None, trace_id: str | None = None) -> str:
    """Point the stream at ``path`` (None disables). Returns the trace id."""
    global _path, _trace_id
    _path = os.fspath(path) if path else None
    _trace_id = trace_id or secrets.token_hex(16)
    if _path:
        os.makedirs(os.path.dirname(_path) or ".", exist_ok=True)
    return _trace_id


def trace_id() -> str:
    return _trace_id


def emit(event: str, agent: str | None = None, **attrs) -> None:
    if not _path:
        return
    record = {"ts": time.time(), "trace_id": _trace_id, "event": event}
    if agent:
        record["agent"] = agent
    record.update(attrs)
    try:
        line = json.dumps(record, default=str) + "\n"
        with _lock:
            fd = os.open(_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
    except OSError:
        pass
