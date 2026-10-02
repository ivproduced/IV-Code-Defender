# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Backend protocol and authentication boundaries."""
import pytest

from harness import agent_backends
from harness.agent import AgentResult
from harness.auth import required_egress_hosts, resolve_auth_env


def test_codex_events_preserve_final_tags_and_session():
    events = [
        {"type": "thread.started", "thread_id": "s1"},
        {"type": "item.completed", "item": {"type": "command_execution", "command": "ls"}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "<poc_path>/work/poc</poc_path>"}},
        {"type": "turn.completed", "usage": {"input_tokens": 12}},
    ]
    messages = [message for event in events for message in agent_backends.normalize("codex", event)]
    result = AgentResult(messages=messages)
    assert messages[0]["session_id"] == "s1"
    assert result.find_tagged_message("poc_path") == "<poc_path>/work/poc</poc_path>"
    assert messages[-1]["type"] == "result"


def test_gemini_events_preserve_tags_and_failure():
    messages = agent_backends.normalize("gemini", {"type": "message", "role": "assistant",
                                                    "content": "<grade>PASS</grade>"})
    assert AgentResult(messages=messages).find_tagged_message("grade") == "<grade>PASS</grade>"
    assert agent_backends.normalize("gemini", {"type": "result", "status": "error"})[-1]["is_error"]


def test_backend_auth_and_egress(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_AGENT_BACKEND", "codex")
    monkeypatch.setenv("OPENAI_API_KEY", "key")
    assert resolve_auth_env() == {"OPENAI_API_KEY": "key"}
    assert required_egress_hosts() == ["api.openai.com:443"]
    monkeypatch.setenv("VULN_PIPELINE_AGENT_BACKEND", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "key2")
    assert resolve_auth_env() == {"GEMINI_API_KEY": "key2"}
    assert required_egress_hosts() == ["generativelanguage.googleapis.com:443"]


def test_ollama_rejects_loopback_and_has_no_external_egress(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_AGENT_BACKEND", "ollama")
    monkeypatch.setenv("VULN_PIPELINE_OLLAMA_URL", "http://localhost:11434/v1")
    with pytest.raises(ValueError, match="reachable from agent containers"):
        resolve_auth_env()
    monkeypatch.setenv("VULN_PIPELINE_OLLAMA_URL", "http://ollama:11434/v1")
    assert resolve_auth_env() == {"CODEX_OSS_BASE_URL": "http://ollama:11434/v1"}
    assert required_egress_hosts() == []


@pytest.mark.parametrize("backend,executable,expected", [
    ("codex", "codex", "--json"),
    ("gemini", "gemini", "stream-json"),
    ("ollama", "codex", "ivcd_ollama"),
])
def test_backend_commands_use_structured_streams_and_stdin(monkeypatch, backend,
                                                            executable, expected):
    from harness import docker_ops
    monkeypatch.setattr(docker_ops, "command", lambda *parts: ["docker", *parts])
    monkeypatch.setenv("VULN_PIPELINE_OLLAMA_URL", "http://ollama:11434/v1")
    argv = agent_backends.command("agent", backend, model="test-model",
                                  max_turns=8, tools=None, system_prompt=None,
                                  resume_id=None, sandboxed=True)
    assert executable in argv
    assert expected in " ".join(argv)
    assert "test-model" in argv
    if backend != "gemini":
        assert argv[-1] == "-"
