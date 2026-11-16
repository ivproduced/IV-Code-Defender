#!/usr/bin/env python3
# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Replay entry: feeds the PoC file to pycanary, as an attacker's file would arrive.

Lives outside source_root (/opt/vp/entry.py) so neither the target nor a patch
can change what the grader runs. It never performs a dangerous operation itself.
"""
import sys

sys.path.insert(0, "/work/app")

from pycanary import handle  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: entry.py <input_file>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as poc:
        text = poc.read().decode("utf-8", "replace")
    print(handle(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
