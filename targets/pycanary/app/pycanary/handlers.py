# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""pycanary — deliberately vulnerable. Three planted bugs, one per command.

The input is a text file whose first line is `<command> <argument>`. All
three commands are reachable from any untrusted input file.
"""
import base64
import os
import pickle

DATA_DIR = "/work/app/data"


def diag(host: str) -> str:
    """BUG 1 (command injection): `host` is spliced into a shell command."""
    os.system("echo diag " + host)  # noqa: S605 — planted
    return "diag ok"


def read(name: str) -> str:
    """BUG 2 (path traversal): `name` is joined to DATA_DIR without checks."""
    with open(os.path.join(DATA_DIR, name)) as handle:  # planted
        return handle.read()


def load(blob: str) -> str:
    """BUG 3 (unsafe deserialization): attacker pickle goes to pickle.loads."""
    value = pickle.loads(base64.b64decode(blob))  # noqa: S301 — planted
    return f"loaded {type(value).__name__}"


COMMANDS = {"diag": diag, "read": read, "load": load}


def handle(text: str) -> str:
    line = text.strip().splitlines()[0] if text.strip() else ""
    command, _, argument = line.partition(" ")
    fn = COMMANDS.get(command)
    if fn is None:
        return "unknown command"
    return fn(argument)
