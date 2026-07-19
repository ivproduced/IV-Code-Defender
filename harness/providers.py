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
    the fleet. The returned hosts are the complete provider-specific proxy
    allowlist for that selection."""
    provider = resolve_provider(provider)
    if provider in STATIC_ONLY_PROVIDERS:
        raise ValueError(
            f"provider {provider!r} cannot host the autonomous agent fleet "
            f"(claude -p runs only on {', '.join(FLEET_PROVIDERS)}). "
            f"Reserved for a future static pass."
        )

    from .auth import required_egress_hosts, resolve_auth_env

    env = resolve_auth_env(provider)
    if env is None:
        raise ValueError(f"provider {provider!r} is selected but its credentials are incomplete")
    return ProviderEnv(provider, env, required_egress_hosts(provider))
