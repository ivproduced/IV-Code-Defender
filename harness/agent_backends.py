# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Agent CLI selection and normalization into IVCD's stream-json shape.

The pipeline consumes assistant text, tool-use progress, a session ID and a
terminal result. Keep backend-specific event formats at this boundary.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from urllib.parse import urlparse

BACKENDS = ("claude", "codex", "gemini", "ollama")
ENV = "VULN_PIPELINE_AGENT_BACKEND"


def _ollama_endpoint() -> tuple[str, str, int | None]:
    url = os.environ.get("VULN_PIPELINE_OLLAMA_URL", "")
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid VULN_PIPELINE_OLLAMA_URL port: {exc}") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("ollama requires VULN_PIPELINE_OLLAMA_URL, e.g. http://ollama:11434/v1")
    host = parsed.hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    mapped = getattr(address, "ipv4_mapped", None)
    # Some resolvers accept short, integer, or hexadecimal IPv4 spellings.
    # Reject numeric host aliases we cannot safely classify as remote.
    numeric_alias = address is None and bool(re.fullmatch(
        r"[0-9.]+|0x[0-9a-f]+|(?:0x[0-9a-f]+\.)+[0-9a-fx.]+", host
    ))
    if (host == "localhost" or numeric_alias
            or (address is not None and (address.is_loopback or address.is_unspecified))
            or (mapped is not None and (mapped.is_loopback or mapped.is_unspecified))):
        raise ValueError("ollama URL must name a server reachable from agent containers")
    return url, parsed.hostname, port


def selected(explicit: str | None = None) -> str:
    value = (explicit or os.environ.get(ENV) or "claude").strip().lower()
    if value not in BACKENDS:
        raise ValueError(f"unknown agent backend {value!r}; choose one of {', '.join(BACKENDS)}")
    return value


def auth_env(backend: str) -> dict[str, str] | None:
    if backend == "codex":
        return {"OPENAI_API_KEY": os.environ["OPENAI_API_KEY"]} if os.environ.get("OPENAI_API_KEY") else None
    if backend == "gemini":
        return {"GEMINI_API_KEY": os.environ["GEMINI_API_KEY"]} if os.environ.get("GEMINI_API_KEY") else None
    if backend == "ollama":
        url, _, _ = _ollama_endpoint()
        return {"CODEX_OSS_BASE_URL": url}
    raise ValueError(f"unsupported backend {backend!r}")


def egress_hosts(backend: str) -> list[str]:
    if backend == "codex":
        return ["api.openai.com:443"]
    if backend == "gemini":
        return ["generativelanguage.googleapis.com:443"]
    if backend == "ollama":
        url, host, port = _ollama_endpoint()
        # HTTP model servers can be attached to vp-internal directly. HTTPS
        # endpoints go through the allowlist proxy.
        proxy_host = f"[{host}]" if ":" in host else host
        return [f"{proxy_host}:{port or 443}"] if urlparse(url).scheme == "https" else []
    raise ValueError(f"unsupported backend {backend!r}")


def command(container: str, backend: str, *, model: str, max_turns: int,
            tools: list[str] | None, system_prompt: str | None,
            resume_id: str | None, sandboxed: bool) -> list[str]:
    """Build the in-container command. The caller supplies the prompt on stdin."""
    from . import docker_ops, sandbox
    from .agent import DEFAULT_TOOLS, build_claude_argv

    prefix = [*docker_ops.command("exec", "-i"), "-w", "/work", "--", container]
    effective = DEFAULT_TOOLS if tools is None else tools
    if backend == "claude":
        prefix = [*docker_ops.command("exec", "-i"), "-e", "CLAUDECODE=",
                  "-e", "IS_SANDBOX=1", "-w", "/work", "--", container, "claude"]
        argv = build_claude_argv(prefix, model=model, max_turns=max_turns,
                                 tools=tools, permission_mode=sandbox.permission_mode(),
                                 system_prompt=system_prompt)
        return argv + (["--resume", resume_id, "continue"] if resume_id else [])

    if backend in ("codex", "ollama"):
        if tools == []:
            raise ValueError("Codex CLI cannot enforce a tool-free phase")
        # The OCI container is the security boundary. Codex's own sandbox may
        # be unavailable under gVisor, so use full access only there.
        argv = [*prefix, "codex", "exec"]
        if resume_id:
            argv += ["resume", "--json", "--ignore-user-config",
                     "--skip-git-repo-check", "--model", model]
        else:
            argv += ["--json", "--ignore-user-config", "--skip-git-repo-check",
                     "--model", model]
        argv += ["--config", 'web_search="disabled"',
                 "--config", "mcp_servers={}",
                 "--config", "project_doc_max_bytes=0",
                 "--config", "project_doc_fallback_filenames=[]"]
        if system_prompt:
            argv += ["--config", "developer_instructions=" + json.dumps(system_prompt)]
        if sandboxed:
            argv += ["--dangerously-bypass-approvals-and-sandbox"]
        else:
            argv += ["--sandbox", "workspace-write" if effective else "read-only"]
        if backend == "ollama":
            # A named provider avoids --oss's localhost-only discovery probe.
            argv += ["--config", 'model_provider="ivcd_ollama"',
                     "--config", 'model_providers.ivcd_ollama.name="Ollama"',
                     "--config", 'model_providers.ivcd_ollama.wire_api="responses"',
                     "--config", "model_providers.ivcd_ollama.base_url="
                     + json.dumps(os.environ["VULN_PIPELINE_OLLAMA_URL"])]
        if resume_id:
            argv += [resume_id, "-"]
        else:
            argv += ["-"]
        return argv

    # Gemini accepts system instructions through the input prompt. Its CLI
    # system settings file is generated in the agent container by the caller.
    argv = [*prefix, "gemini", "--model", model, "--output-format", "stream-json",
            "--extensions", "none", "--approval-mode", "yolo" if sandboxed else "default"]
    if resume_id:
        argv += ["--resume", resume_id]
    return argv + ["--prompt", "Follow the complete instructions on standard input."]


def normalize(backend: str, event: dict) -> list[dict]:
    """Return zero or more Claude-shaped messages for a backend event."""
    if backend == "claude":
        return [event]
    kind = event.get("type")
    if backend in ("codex", "ollama"):
        if kind == "thread.started":
            return [{"type": "system", "subtype": "init", "session_id": event.get("thread_id")}]
        if kind == "item.completed":
            item = event.get("item") or {}
            if item.get("type") == "agent_message":
                return [_assistant(item.get("text", ""))]
            if item.get("type") == "command_execution":
                return [_tool(item.get("command", ""), "Bash")]
            if item.get("type") == "file_change":
                return [_tool("file change", "Write")]
        if kind == "turn.completed":
            return [{"type": "result", "is_error": False, "usage": event.get("usage", {})}]
        if kind in ("turn.failed", "error"):
            detail = event.get("error") or event
            return [{"type": "result", "is_error": True, "result": str(detail)}]
        return []

    if kind == "init":
        return [{"type": "system", "subtype": "init", "session_id": event.get("session_id")}]
    if kind == "message":
        if event.get("role") != "assistant":
            return []
        if event.get("delta"):
            return []
        return [_assistant(event.get("content") or event.get("text") or "")]
    if kind == "tool_use":
        return [_tool(str(event.get("parameters") or event.get("args") or ""),
                      event.get("tool_name") or event.get("name") or "tool")]
    if kind == "result":
        out = []
        if event.get("response"):
            out.append(_assistant(event["response"]))
        out.append({"type": "result", "is_error": bool(event.get("error")) or event.get("status") not in (None, "success"),
                    "result": event.get("error"), "usage": event.get("stats", {})})
        return out
    if kind == "error":
        # Gemini also emits non-fatal warnings as error events. Its terminal
        # result or process exit decides whether the run failed.
        return []
    return []


def _assistant(value: str) -> dict:
    return {"type": "assistant", "message": {"content": [{"type": "text", "text": value}]}}


def _tool(value: str, name: str) -> dict:
    return {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": name, "input": {"command": value}}
    ]}}
