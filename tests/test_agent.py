# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Claude CLI argument builder."""
from harness.agent import (
    DEFAULT_TOOLS,
    _contains_tool_use,
    _truncate_tool_results,
    build_claude_argv,
)


CLI_ARGV = ["docker", "exec", "-i", "--", "vp-canary", "claude"]


def test_none_tool_list_uses_defaults():
    argv = build_claude_argv(
        CLI_ARGV,
        model="model",
        max_turns=10,
        tools=None,
        permission_mode="bypassPermissions",
    )

    assert argv[argv.index("--tools") + 1] == ",".join(DEFAULT_TOOLS)


def test_empty_tool_list_disables_tools():
    argv = build_claude_argv(
        CLI_ARGV,
        model="model",
        max_turns=10,
        tools=[],
        permission_mode="bypassPermissions",
    )

    assert argv[argv.index("--tools") + 1] == ""


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


def test_normalized_tool_event_is_detected_for_no_tools_guard():
    assert _contains_tool_use({
        "type": "assistant",
        "message": {"content": [{"type": "tool_use", "name": "Bash"}]},
    })
    assert not _contains_tool_use({
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": "done"}]},
    })


def test_tool_result_truncation_preserves_user_message_shape():
    message = {
        "type": "user",
        "message": {"content": [{"type": "tool_result", "content": "x" * 6000}]},
    }

    truncated = _truncate_tool_results(message)

    assert truncated["type"] == "user"
    assert truncated["message"]["content"][0]["type"] == "tool_result"
    assert truncated["message"]["content"][0]["content"] == "x" * 5000
