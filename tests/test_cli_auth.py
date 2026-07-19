# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Back-compat shim: cli._resolve_auth_env / NO_AUTH_MSG re-export harness.auth."""
import pytest

import harness.auth as auth
from harness.cli import _resolve_auth_env, NO_AUTH_MSG


AUTH_VARS = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "AWS_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_BEARER_TOKEN_BEDROCK",
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


def test_explicit_provider_uses_strict_auth_validation(monkeypatch, capsys):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    assert _resolve_auth_env("bedrock") is None
    err = capsys.readouterr().err
    assert "no credentials" in err
