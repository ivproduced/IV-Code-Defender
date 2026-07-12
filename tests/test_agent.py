# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Claude CLI argument builder."""
from harness.agent import DEFAULT_TOOLS, build_claude_argv


CLI_ARGV = ["docker", "exec", "-i", "--", "vp-canary", "claude"]


def test_empty_tool_list_uses_defaults():
    argv = build_claude_argv(
        CLI_ARGV,
        model="model",
        max_turns=10,
        tools=[],
        permission_mode="bypassPermissions",
    )

    assert argv[argv.index("--tools") + 1] == ",".join(DEFAULT_TOOLS)


def test_custom_tools_and_system_prompt_are_preserved():
    argv = build_claude_argv(
        CLI_ARGV,
        model="model",
        max_turns=10,
        tools=["Read", "Bash"],
        permission_mode="auto",
        system_prompt="Review code.",
    )

    assert argv[argv.index("--tools") + 1] == "Read,Bash"
    assert argv[argv.index("--system-prompt") + 1] == "Review code."
