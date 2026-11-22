# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""IVCD runtime monitor for the ``python_exec`` profile.

Shipped into target images at /opt/vp/monitor (outside source_root) and loaded
by Python's ``sitecustomize`` mechanism via PYTHONPATH=/opt/vp/monitor. It
installs an audit hook that reports dangerous operations performed by *target*
code, one line per event on stderr (fd 2):

    <token> IVCD-EVENT <json>

The grader — never a model — decides from these lines. A line only counts when
it starts with the per-replay random token, which the grader passes in the
environment and this module removes from ``os.environ`` at startup.

Environment (read once at startup):
    IVCD_EVENT_TOKEN    per-replay secret prefix (removed from os.environ)
    IVCD_SOURCE_ROOT    only frames under this directory count as "target"
    IVCD_ALLOWED_ROOTS  os.pathsep-separated roots (informational; the grader
                        re-derives its verdict from its own configuration)
    IVCD_ALLOWED_HOSTS  comma-separated hosts (informational)

Fail closed: with no token or no source root the module installs nothing, no
handshake line is printed, and the grader fails the replay.

Standard library only. Never raises into the target.

Known limits (see docs/pipeline.md): the hook cannot see operations that do
not raise audit events (ctypes/FFI calls, native extension I/O, os.stat-style
reads, ``os.write`` to an already-open fd, writes by child processes), and code
that reaches arbitrary execution can read the token from /proc/self/environ
or gc-visible closures. Treat the monitor as an integrity check on honest
proof, not a sandbox.
"""
from __future__ import annotations

import os
import sys
import threading

_PREFIX = "IVCD-EVENT"
_MAX_ARG = 200
_MAX_ITEMS = 16
_MAX_LINE = 3800  # keep each os.write atomic on pipes (PIPE_BUF >= 4096)

# audit event -> (kind, indices of args to report). Env blocks are never
# reported: they can hold secrets.
_SINKS = {
    "os.system": ("command", (0,)),
    "subprocess.Popen": ("command", (0, 1, 2)),
    "os.exec": ("exec", (0, 1)),
    "os.posix_spawn": ("exec", (0, 1)),
    "open": ("open", (0, 1)),
    "socket.connect": ("connect", (1,)),
    "pickle.find_class": ("deserialize", (0, 1)),
    "exec": ("code", ()),
    "compile": ("code", (1,)),
}


def _render(value, depth=0):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value[:_MAX_ARG]
    if isinstance(value, (list, tuple)) and depth < 2:
        return [_render(v, depth + 1) for v in list(value)[:_MAX_ITEMS]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return repr(value)[:_MAX_ARG]


def _install() -> None:
    import json

    token = os.environ.get("IVCD_EVENT_TOKEN", "")
    source_root = os.environ.get("IVCD_SOURCE_ROOT", "")
    if not token or not source_root or any(c.isspace() for c in token):
        return  # fail closed: no handshake => grader fails the replay
    # Read everything we need, then take the token out of the environment so
    # target code and its children cannot read it from os.environ.
    allowed_roots = [r for r in os.environ.get("IVCD_ALLOWED_ROOTS", "").split(os.pathsep) if r]
    allowed_hosts = [h for h in os.environ.get("IVCD_ALLOWED_HOSTS", "").split(",") if h]
    del os.environ["IVCD_EVENT_TOKEN"]

    root = os.path.realpath(source_root).rstrip(os.sep) + os.sep
    write = os.write
    realpath = os.path.realpath
    getcwd = os.getcwd
    local = threading.local()
    in_root_cache: dict[str, bool] = {}
    head = (token + " " + _PREFIX + " ").encode()

    def emit(payload: dict) -> None:
        line = json.dumps(payload, separators=(",", ":"), default=repr)
        data = head + line.encode("utf-8", "replace")
        if len(data) > _MAX_LINE:
            payload = dict(payload, args=[_render(str(payload.get("args")))[:500]])
            data = head + json.dumps(payload, separators=(",", ":"), default=repr).encode()[: _MAX_LINE - len(head)]
        write(2, data + b"\n")

    def is_in_root(filename: str) -> bool:
        hit = in_root_cache.get(filename)
        if hit is None:
            hit = filename.startswith(root) or realpath(filename).startswith(root)
            in_root_cache[filename] = hit
        return hit

    def target_frame():
        """Innermost frame under source_root, or None.

        Import machinery between the hook and the first target frame means the
        event is the interpreter loading a module (e.g. reading its .py file),
        not an operation the target chose to perform: drop it."""
        f = sys._getframe(2)
        while f is not None:
            name = f.f_code.co_filename
            if name.startswith("<frozen importlib"):
                return None
            if is_in_root(name):
                return f
            f = f.f_back
        return None

    def hook(event, args):
        spec = _SINKS.get(event)
        if spec is None or getattr(local, "busy", False):
            return
        local.busy = True
        try:
            frame = target_frame()
            if frame is None:
                return
            kind, picks = spec
            if event == "exec":
                rendered = [getattr(args[0], "co_name", "<code>")] if args else []
            else:
                rendered = [_render(args[i]) for i in picks if i < len(args)]
            payload = {
                "kind": kind,
                "sink": event,
                "args": rendered,
                "frame": {
                    "file": realpath(frame.f_code.co_filename),
                    "function": frame.f_code.co_name,
                    "line": frame.f_lineno,
                },
            }
            if event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
                p = os.fsdecode(args[0])
                payload["resolved"] = realpath(p if os.path.isabs(p) else os.path.join(getcwd(), p))
            emit(payload)
        except BaseException:  # noqa: BLE001 — never break the target
            pass
        finally:
            local.busy = False

    # Handshake: lets the grader tell "monitor ran, saw nothing" from
    # "monitor missing". Not frame-gated by design.
    emit({"kind": "monitor", "sink": "ready", "args": [],
          "roots": allowed_roots, "hosts": allowed_hosts})
    sys.addaudithook(hook)


try:
    _install()
except BaseException:  # noqa: BLE001
    pass
