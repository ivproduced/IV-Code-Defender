# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Model-provider resolution for the agent fleet.

The fleet runs `claude -p` inside each gVisor container, so the backend must be
one Claude Code speaks natively: the Anthropic API, Amazon Bedrock, or Google
Vertex. Bedrock/Vertex are selected purely through environment variables on the
container — no code path change. A custom gateway (e.g. an Anthropic-compatible
Azure deployment) is supported via ANTHROPIC_BASE_URL passthrough.

OpenAI, Azure-OpenAI and Ollama cannot host Claude Code's tool-calling loop;
selecting them for the fleet raises a clear error. They are reserved for a
future non-agent static pass.

resolve_provider_env() returns the dict merged onto the container at
`docker run` time, plus the egress hosts the allowlist proxy must permit.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# Backends Claude Code can drive as the agent fleet.
FLEET_PROVIDERS = ("anthropic", "bedrock", "vertex")
# Reserved for a future static-analysis pass; not agent-fleet capable.
STATIC_ONLY_PROVIDERS = ("openai", "azure", "ollama")
ALL_PROVIDERS = FLEET_PROVIDERS + STATIC_ONLY_PROVIDERS

DEFAULT_PROVIDER = "anthropic"


@dataclass(frozen=True)
class ProviderEnv:
    """Resolved provider: env to set on the container + extra egress hosts."""
    provider: str
    env: dict[str, str] = field(default_factory=dict)
    egress_hosts: list[str] = field(default_factory=list)


def resolve_provider(explicit: str | None) -> str:
    """Pick the provider: explicit flag > env > default."""
    p = (explicit or os.environ.get("VULN_PIPELINE_PROVIDER") or DEFAULT_PROVIDER)
    p = p.strip().lower()
    if p not in ALL_PROVIDERS:
        raise ValueError(
            f"unknown provider {p!r}; choose one of {', '.join(ALL_PROVIDERS)}"
        )
    return p


def resolve_provider_env(provider: str) -> ProviderEnv:
    """Build the agent container env for a provider, or raise if it can't host
    the fleet. Egress hosts are added to the allowlist proxy alongside the
    always-present api.anthropic.com:443."""
    if provider in STATIC_ONLY_PROVIDERS:
        raise ValueError(
            f"provider {provider!r} cannot host the autonomous agent fleet "
            f"(claude -p runs only on {', '.join(FLEET_PROVIDERS)}). "
            f"Reserved for a future static pass."
        )

    if provider == "anthropic":
        env = _passthrough(("ANTHROPIC_BASE_URL",))
        if key := os.environ.get("ANTHROPIC_API_KEY"):
            env["ANTHROPIC_API_KEY"] = key
        elif token := os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
            env["CLAUDE_CODE_OAUTH_TOKEN"] = token
        else:
            return ProviderEnv(provider, env, [])  # auth checked by caller
        hosts = []
        if base := env.get("ANTHROPIC_BASE_URL"):
            hosts = [_host(base)]
        return ProviderEnv(provider, env, hosts)

    if provider == "bedrock":
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        env = {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": region}
        env.update(_passthrough((
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AWS_PROFILE", "AWS_BEARER_TOKEN_BEDROCK", "ANTHROPIC_MODEL",
        )))
        return ProviderEnv(provider, env,
                           [f"bedrock-runtime.{region}.amazonaws.com:443",
                            f"bedrock.{region}.amazonaws.com:443"])

    if provider == "vertex":
        region = os.environ.get("CLOUD_ML_REGION", "us-east5")
        env = {"CLAUDE_CODE_USE_VERTEX": "1", "CLOUD_ML_REGION": region}
        env.update(_passthrough((
            "ANTHROPIC_VERTEX_PROJECT_ID", "GOOGLE_APPLICATION_CREDENTIALS",
        )))
        return ProviderEnv(provider, env,
                           [f"{region}-aiplatform.googleapis.com:443"])

    raise ValueError(f"unhandled fleet provider {provider!r}")


def _passthrough(keys: tuple[str, ...]) -> dict[str, str]:
    return {k: os.environ[k] for k in keys if os.environ.get(k)}


def _host(url: str) -> str:
    from urllib.parse import urlparse
    u = urlparse(url if "//" in url else f"https://{url}")
    return f"{u.hostname}:{u.port or 443}"
