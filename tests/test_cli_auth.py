# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Back-compat shim: cli._resolve_auth_env / NO_AUTH_MSG re-export harness.auth."""
import pytest

import harness.auth as auth
from harness.cli import _resolve_auth_env, NO_AUTH_MSG


AUTH_VARS = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)


@pytest.fixture(autouse=True)
def _clear_auth(monkeypatch):
    for v in AUTH_VARS:
        monkeypatch.delenv(v, raising=False)


def test_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    env = _resolve_auth_env()
    assert env and env["ANTHROPIC_API_KEY"] == "sk-ant-x"
    assert "ANTHROPIC_CUSTOM_HEADERS" in env


def test_oauth_token(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
    env = _resolve_auth_env()
    assert env and env["CLAUDE_CODE_OAUTH_TOKEN"] == "tok"
    assert "ANTHROPIC_CUSTOM_HEADERS" in env


def test_precedence_api_key_over_oauth(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
    env = _resolve_auth_env()
    assert env and env["ANTHROPIC_API_KEY"] == "sk-ant-x"
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env


def test_none():
    assert _resolve_auth_env() is None


def test_error_message_names_all_modes():
    assert "ANTHROPIC_API_KEY" in NO_AUTH_MSG
    assert "CLAUDE_CODE_OAUTH_TOKEN" in NO_AUTH_MSG


def test_provider_egress_guidance_names_matching_setup_scripts(capsys):
    _resolve_auth_env("bedrock")
    err = capsys.readouterr().err
    assert "scripts/setup_sandbox.sh (Docker)" in err
    assert "scripts/setup_podman_sandbox.sh (Podman)" in err
