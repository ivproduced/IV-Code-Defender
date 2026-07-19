# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Provider/auth resolution — single source of truth for cli.py and the
sandbox shell scripts (setup_sandbox.sh, vp-sandboxed)."""
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$")
_VERTEX_REGION_RE = re.compile(r"^[a-z]+-[a-z]+[0-9]+$")

NO_AUTH_MSG = (
    "error: no model-API auth found. Set one of:\n"
    "  CLAUDE_CODE_USE_BEDROCK=1 + AWS_REGION + (AWS_BEARER_TOKEN_BEDROCK or AWS_ACCESS_KEY_ID/SECRET)\n"
    "  CLAUDE_CODE_USE_VERTEX=1  + ANTHROPIC_VERTEX_PROJECT_ID + CLOUD_ML_REGION "
    "+ GOOGLE_APPLICATION_CREDENTIALS\n"
    "  ANTHROPIC_API_KEY                     (long-lived key)\n"
    "  CLAUDE_CODE_OAUTH_TOKEN               (from `claude setup-token`)"
)

_BEDROCK_OPTIONAL = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                     "AWS_SESSION_TOKEN", "AWS_BEARER_TOKEN_BEDROCK")
_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def _selected_provider(explicit: str | None = None) -> str:
    if explicit is not None:
        from .providers import resolve_provider
        provider = resolve_provider(explicit)
        if provider not in ("anthropic", "bedrock", "vertex"):
            raise ValueError(f"provider {provider!r} cannot host the autonomous agent fleet")
        return provider
    if configured := os.environ.get("VULN_PIPELINE_PROVIDER"):
        return _selected_provider(configured)
    if os.environ.get("CLAUDE_CODE_USE_BEDROCK") == "1":
        return "bedrock"
    if os.environ.get("CLAUDE_CODE_USE_VERTEX") == "1":
        return "vertex"
    return "anthropic"


def _with_small_fast_model(env: dict[str, str]) -> dict[str, str]:
    """Forward ANTHROPIC_SMALL_FAST_MODEL (a model ID, not a secret) so
    background side-queries can be pinned to e.g. a regional Bedrock Haiku ID
    instead of the CLI's default."""
    if v := os.environ.get("ANTHROPIC_SMALL_FAST_MODEL"):
        env["ANTHROPIC_SMALL_FAST_MODEL"] = v
    return env


def _usage_marker() -> str:
    """ANTHROPIC_CUSTOM_HEADERS value identifying runbook traffic in API
    request telemetry (structural metadata only — never content). The leading
    UA token is the marker; the pinned claude-cli version stays in the
    parenthetical. Imports are function-local so the vp-sandboxed /
    setup_sandbox.sh egress preflights don't pay for them."""
    import importlib.metadata

    from .agent_image import CLAUDE_CODE_VERSION
    try:
        version = importlib.metadata.version("vuln-pipeline")
    except importlib.metadata.PackageNotFoundError:
        version = "0"
    return ("anthropic-cyber-runbook: pipeline\n"
            f"User-Agent: cyber-runbook/{version} "
            f"(claude-cli/{CLAUDE_CODE_VERSION})")


def _with_usage_marker(env: dict[str, str]) -> dict[str, str]:
    """Stamp the usage marker (docs/pipeline.md#usage-marker) onto the agent
    env. 1P callers only — Bedrock/Vertex rewrite the User-Agent and don't
    forward custom headers to Anthropic, so the marker has no value there.
    Ambient ANTHROPIC_CUSTOM_HEADERS is deliberately not forwarded: a Claude
    Code session in this repo injects the interactive-surface value from
    .claude/settings.json, which would mislabel pipeline traffic. Opt-out:
    VULN_PIPELINE_NO_TELEMETRY=1."""
    if os.environ.get("VULN_PIPELINE_NO_TELEMETRY") != "1":
        env["ANTHROPIC_CUSTOM_HEADERS"] = _usage_marker()
    return env


def resolve_auth_env(provider: str | None = None) -> dict[str, str] | None:
    """Resolve auth for the in-container ``claude -p`` process.

    Precedence: Bedrock → Vertex → ANTHROPIC_API_KEY → CLAUDE_CODE_OAUTH_TOKEN.
    Returns the env dict to set on the agent container, or None if no auth is
    configured. Misconfigured-but-selected providers print a specific diagnostic
    to stderr and return None (callers then print NO_AUTH_MSG)."""
    selected = _selected_provider(provider)
    if selected == "bedrock":
        region = os.environ.get("AWS_REGION")
        if not region or not _REGION_RE.match(region):
            print(f"error: CLAUDE_CODE_USE_BEDROCK=1 but AWS_REGION is "
                  f"{'unset' if not region else f'invalid ({region!r})'}", file=sys.stderr)
            return None
        env = {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": region}
        for k in _BEDROCK_OPTIONAL:
            if v := os.environ.get(k):
                env[k] = v
        has_bearer = "AWS_BEARER_TOKEN_BEDROCK" in env
        has_access_pair = (
            "AWS_ACCESS_KEY_ID" in env and "AWS_SECRET_ACCESS_KEY" in env
        )
        if not has_bearer and not has_access_pair:
            print("error: CLAUDE_CODE_USE_BEDROCK=1 but no credentials in env "
                  "(need AWS_BEARER_TOKEN_BEDROCK or AWS_ACCESS_KEY_ID; "
                  "AWS_PROFILE / ~/.aws are not forwarded into the sandbox). "
                  "Instance-profile/IMDS credentials are deliberately not "
                  "supported: the agent container has no route to "
                  "169.254.169.254 and no STS egress, so hostile target code "
                  "cannot steal the instance role or pivot via AssumeRole. "
                  "Materialize credentials into the environment instead, e.g. "
                  "`eval $(aws configure export-credentials --format env)`, "
                  "using a principal scoped to bedrock:InvokeModel*.",
                  file=sys.stderr)
            return None
        return _with_small_fast_model(env)

    if selected == "vertex":
        project = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "")
        region = os.environ.get("CLOUD_ML_REGION", "")
        credentials = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
        if not _PROJECT_RE.fullmatch(project):
            print("error: Vertex requires a valid ANTHROPIC_VERTEX_PROJECT_ID", file=sys.stderr)
            return None
        if not _VERTEX_REGION_RE.fullmatch(region):
            print("error: Vertex requires a valid CLOUD_ML_REGION", file=sys.stderr)
            return None
        if not credentials:
            print("error: Vertex requires GOOGLE_APPLICATION_CREDENTIALS pointing to "
                  "a scoped service-account JSON file", file=sys.stderr)
            return None
        credential_path = Path(credentials).expanduser().resolve()
        if not credential_path.is_file():
            print(f"error: GOOGLE_APPLICATION_CREDENTIALS is not a file: "
                  f"{credential_path}", file=sys.stderr)
            return None
        env = {
            "CLAUDE_CODE_USE_VERTEX": "1",
            "ANTHROPIC_VERTEX_PROJECT_ID": project,
            "CLOUD_ML_REGION": region,
            "GOOGLE_APPLICATION_CREDENTIALS": str(credential_path),
        }
        return _with_small_fast_model(env)

    if v := os.environ.get("ANTHROPIC_API_KEY"):
        env = {"ANTHROPIC_API_KEY": v}
        if base_url := os.environ.get("ANTHROPIC_BASE_URL"):
            env["ANTHROPIC_BASE_URL"] = base_url
        return _with_usage_marker(
            _with_small_fast_model(env))
    if v := os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        env = {"CLAUDE_CODE_OAUTH_TOKEN": v}
        if base_url := os.environ.get("ANTHROPIC_BASE_URL"):
            env["ANTHROPIC_BASE_URL"] = base_url
        return _with_usage_marker(
            _with_small_fast_model(env))
    return None


def warn_bedrock_model(model: str | None, provider: str | None = None) -> None:
    """Non-fatal preflight: on Bedrock, a bare foundation-model ID
    (``anthropic.…``) usually fails with a ValidationException because
    on-demand invocation goes through a cross-region inference profile,
    whose ID carries a region-group prefix. ARNs and other formats are
    deliberately not flagged (too many valid shapes to false-positive on)."""
    if _selected_provider(provider) != "bedrock":
        return
    if not model or not model.startswith("anthropic."):
        return
    region = os.environ.get("AWS_REGION", "")
    group = region.split("-", 1)[0]
    example = {"us": "us.", "ca": "us.", "sa": "us.", "mx": "us.",
               "eu": "eu.", "ap": "apac."}.get(group, "us.")
    print(f"WARNING: {model!r} looks like a bare Bedrock foundation-model ID; "
          "on-demand invocation usually needs a cross-region inference-profile "
          "prefix matching your region group — us., eu., apac., or global. "
          f"(e.g. {example}{model})", file=sys.stderr)


def required_egress_hosts(provider: str | None = None) -> list[str]:
    """host:port entries the current provider needs on the proxy allowlist.
    Called from setup_sandbox.sh / vp-sandboxed via ``python3 -c``; exits
    non-zero on misconfig so the shell ``|| die`` fires."""
    selected = _selected_provider(provider)
    if selected == "bedrock":
        region = os.environ.get("AWS_REGION", "")
        if not _REGION_RE.fullmatch(region):
            sys.exit("error: CLAUDE_CODE_USE_BEDROCK=1 requires a valid AWS_REGION")
        # No STS: forwarded creds are already-resolved; STS would enable
        # AssumeRole lateral movement from hostile target code.
        return [f"bedrock-runtime.{region}.amazonaws.com:443"]
    if selected == "vertex":
        region = os.environ.get("CLOUD_ML_REGION", "")
        if not _VERTEX_REGION_RE.fullmatch(region):
            sys.exit("error: CLAUDE_CODE_USE_VERTEX=1 requires a valid CLOUD_ML_REGION")
        return [
            f"{region}-aiplatform.googleapis.com:443",
            "oauth2.googleapis.com:443",
        ]
    if base_url := os.environ.get("ANTHROPIC_BASE_URL"):
        parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
        if not parsed.hostname:
            sys.exit(f"error: ANTHROPIC_BASE_URL is invalid: {base_url!r}")
        return [f"{parsed.hostname}:{parsed.port or 443}"]
    return ["api.anthropic.com:443"]


def _host_allowed(target: str, allow: set[str]) -> bool:
    """Mirror of scripts/egress_proxy.py:_allowed — keep in sync."""
    t = target.lower()
    return any(t == e or (e.startswith("*.") and t.endswith(e[1:])) for e in allow)


def check_egress_satisfied(proxy_allow_csv: str) -> None:
    """Preflight for vp-sandboxed: exit non-zero if any required host is not
    covered by the running proxy's allowlist."""
    allow = {h.strip().lower() for h in proxy_allow_csv.split(",") if h.strip()}
    needed = required_egress_hosts()
    missing = [h for h in needed if not _host_allowed(h, allow)]
    if missing:
        sys.exit(
            f"error: egress proxy allowlist ({proxy_allow_csv}) does not cover "
            f"required host(s): {', '.join(missing)}"
        )
