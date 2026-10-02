# Agent backends

IVCD separates the **agent CLI** (`--agent-backend`) from the model API provider
used by Claude Code (`--provider`). `run`, `recon`, `report`, and `patch` accept
the same backend option. The CLI runs inside each agent container; IVCD still
owns crash replay, grading, deduplication, and artifacts.

| Backend | Authentication | Model endpoint |
| --- | --- | --- |
| `claude` (default) | `ANTHROPIC_API_KEY`, Claude OAuth token, Bedrock, or Vertex | Provider selected by `--provider` |
| `codex` | `OPENAI_API_KEY` | `api.openai.com:443` |
| `gemini` | `GEMINI_API_KEY` | `generativelanguage.googleapis.com:443` |
| `ollama` | none | `VULN_PIPELINE_OLLAMA_URL` |

Use a separate setup for each backend so the agent image and proxy allowlist
match it. For example:

```bash
export VULN_PIPELINE_AGENT_BACKEND=codex OPENAI_API_KEY=...
scripts/setup_sandbox.sh
bin/vp-sandboxed run canary --agent-backend codex --model <codex-model> \
  --runs 3 --parallel --find-only --max-turns 100
```

For Gemini, set `VULN_PIPELINE_AGENT_BACKEND=gemini` and `GEMINI_API_KEY`,
then use `--agent-backend gemini --model <gemini-model>`. IVCD installs pinned
CLI versions in derived agent images and normalizes their JSON streams into
the existing transcript format. Gemini gets a system settings file in its
container that restricts built-in tools and disables MCP servers. Codex
disables web search and user configuration. Under gVisor, the container and
egress allowlist remain the main trust boundary.

For a local open model, attach an Ollama server to the `vp-internal` network
under a resolvable name (for example `ollama`). Configure an endpoint that is
reachable **from the agent containers**:

```bash
export VULN_PIPELINE_AGENT_BACKEND=ollama
export VULN_PIPELINE_OLLAMA_URL=http://ollama:11434/v1
scripts/setup_sandbox.sh
bin/vp-sandboxed run canary --agent-backend ollama --model <ollama-model> \
  --runs 3 --parallel --find-only --max-turns 100
```

`localhost` refers to the agent container and is rejected. For an HTTPS model
endpoint, the setup script adds its host and port to the proxy allowlist. For
an HTTP Ollama endpoint, connect the server to the internal container network;
the proxy allows no external hosts. The server must provide an
OpenAI-compatible Responses API for Codex's tool loop. Model capability
matters: use a model with reliable tool calls and enough context for the target.

Claude's `--max-turns` and `--tools` flags are enforced by its CLI. Gemini's
turn budget and tool allowlist are set in system settings. Codex does not
expose equivalent per-invocation turn and tool allowlists. IVCD passes the
turn budget in the prompt and keeps the fixed pipeline instructions in Codex's
developer-instruction channel. Gemini receives those instructions through
`GEMINI_SYSTEM_MD`, which replaces its default system prompt. The container
limits files, processes, and network access. Target-provided `AGENTS.md` and
`GEMINI.md` files are not loaded as runtime instructions. Check transcripts
when calibrating a new model.

Codex and Ollama can run `recon` or `run --find-only`. Full `run`, `report`, and
`patch` include tool-free grade/judge phases, which IVCD refuses for these
backends until the runtime can enforce an empty tool set. Use Claude or Gemini
for those phases.

These adapters have unit tests for argument construction, auth/egress, and
stream normalization. The full gVisor smoke test still needs a configured
model account or reachable Ollama server on a Linux host.
