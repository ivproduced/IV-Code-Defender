# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Agent Bill of Materials (AgBOM): a per-batch inventory of everything that
shaped what the agents could do — models, CLIs, tools, images, prompts,
network policy and limits. Written once per batch as ``agbom.json`` beside
``events.jsonl`` so a run can be audited or reproduced without reading code.

Contains no secrets: credential *kinds* are listed, never values."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import agent_backends, agent_image, budget, events, sandbox
from .agent import DEFAULT_TOOLS
from .io_utils import atomic_write_json

SCHEMA = "ivcd-agbom/0.1"
_PROMPT_DIR = Path(__file__).parent / "prompts"


def _prompt_hashes() -> dict[str, str]:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(_PROMPT_DIR.glob("*.py"))
    }


def build(target, *, model: str, auth_env: dict | None, args=None,
          target_image_id: str | None = None) -> dict:
    backend = agent_backends.selected()
    led = budget.ledger()
    cli = {"claude": ("@anthropic-ai/claude-code", agent_image.CLAUDE_CODE_VERSION),
           "codex": ("@openai/codex", agent_image.CODEX_VERSION),
           "ollama": ("@openai/codex", agent_image.CODEX_VERSION),
           "gemini": ("@google/gemini-cli", agent_image.GEMINI_VERSION)}[backend]
    return {
        "schema": SCHEMA,
        "trace_id": events.trace_id(),
        "target": {
            "name": target.name, "profile": target.profile,
            "github_url": target.github_url, "commit": target.commit,
            "image_tag": target.image_tag, "image_id": target_image_id,
        },
        "agents": {
            "model": model,
            "backend": backend,
            "cli": {"package": cli[0], "version": cli[1]},
            "tools": {"find/grade-semantic/report/patch/recon": DEFAULT_TOOLS,
                      "judge/compare/report-grader/semantic-grader": []},
            "mcp": "disabled", "setting_sources": "none",
        },
        "credentials": {
            "kinds": sorted((auth_env or {}).keys()),
            "gateway": bool(sandbox.gateway()),
            "in_agent_container": ("placeholder-only" if sandbox.gateway() else "real"),
        },
        "sandbox": {
            "runtime": sandbox.runtime(), "network": sandbox.network(),
            "egress_proxy": sandbox.proxy(),
        },
        "limits": {
            "find_max_turns": getattr(args, "max_turns", None),
            "max_batch_usd": led.max_usd, "max_batch_tokens": led.max_tokens,
            "max_agent_usd": led.max_agent_usd,
        },
        "prompts_sha256": _prompt_hashes(),
    }


def write(path: Path, bom: dict) -> None:
    atomic_write_json(path, bom)
    events.emit("batch.agbom", path=str(path),
                sha256=hashlib.sha256(json.dumps(bom, sort_keys=True).encode()).hexdigest())
