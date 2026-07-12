# IVProduced Code Defender

IVProduced Code Defender is an open-source security workflow for finding,
verifying, prioritizing, and remediating vulnerabilities in source code. It
combines interactive Claude Code skills for code review with an autonomous,
sandboxed pipeline for execution-verified C/C++ memory-safety and
Docker-replayable web findings.

The project is designed to help security and engineering teams move from an
understood attack surface to reproducible evidence and candidate fixes without
treating unverified scanner output as a security result.

## What it includes

| Component | Purpose |
| --- | --- |
| Claude Code skills | Build threat models, statically scan code, triage findings, and produce candidate patches. |
| `vuln-pipeline` | Run isolated agents against ASAN C/C++ targets or Docker-replayable Python, Node, and React web targets. |
| Report and patch stages | Deduplicate verified crashes, assess exploitability, and validate proposed fixes against the original proof of concept. |
| Sample targets | Start with the canary target, then adapt the pipeline for a supported target or your own codebase. |

## Choose a workflow

**Start with source review** when you need to understand a codebase or assess
findings without executing target code:

```text
/quickstart
/threat-model bootstrap <repository>
/vuln-scan <repository>
/triage <repository>/VULN-FINDINGS.json
/patch ./TRIAGE.json --repo <repository>
```

**Use the execution pipeline** when you need reproducible C/C++ memory-safety
or web findings. C/C++ targets use ASAN crashes. Web targets use a
self-contained Docker replay command and preserve HTTP request/response or
browser evidence; the grader repeats that exact replay in a separate container.
Scanner output is lead generation only, never verified evidence.

## Quick start

Clone the IVProduced repository and open it with Claude Code:

```bash
git clone https://github.com/ivproduced/IV-Code-Defender.git
cd IV-Code-Defender
claude

# In the Claude Code prompt, run:
/quickstart
```

The interactive skills read and write artifacts in the selected repository.
They do not build or execute the target. Review and approve tool use in Claude
Code, particularly when working with sensitive source code.

## Run the pipeline

The autonomous pipeline executes target code. Set up the sandbox before using
agent-spawning commands:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
./scripts/setup_sandbox.sh

# Configure Claude authentication for the agent runtime.
export ANTHROPIC_API_KEY=...

# Run a small parallel wave against the built-in canary target.
bin/vp-sandboxed run canary --model <model-id> --runs 3 --parallel --stream
```

Results are written to `results/<target>/<timestamp>/`. In streaming mode,
reports appear as crashes are graded under `reports/bug_NN/`.

For a real target, begin with a small run to confirm the build, inputs, and
focus areas before increasing concurrency:

```bash
# Run the recon → find → verify → report loop
bin/vp-sandboxed run <target> --model <model-id> --runs 3 --parallel --stream --auto-focus
# Generate a candidate patch for each finding
bin/vp-sandboxed patch results/<target>/<timestamp>/ --model <model-id>
# Export traceable NIST 800-53 mappings as OSCAL technical evidence
bin/vp-sandboxed oscal results/<target>/<timestamp>/
```

Or ask Claude Code to launch the pipeline and watch the run for you:

```text
run the pipeline on <target> and explain findings as they come
```

Candidate patches are validated by rebuilding the target, replaying the
original proof of concept, running the target test suite when configured, and
attempting a limited re-attack. They still require human security and code
review before adoption.

## Security model

- Interactive skills perform source-level analysis and artifact generation.
- Autonomous pipeline agents run inside the configured gVisor sandbox with network egress restricted to the model API, and refuse to start outside it unless you explicitly pass `--dangerously-no-sandbox`.
- Find and grade agents use separate containers; only a PoC input or replay
  manifest/evidence bundle crosses the trust boundary.
- Do not mount secrets, production credentials, or sensitive host paths into
  the sandbox.

Read [Security](docs/security.md) and [Agent sandbox](docs/agent-sandbox.md)
before running targets outside the supplied examples.

For deployment in a federal environment, see [Federal deployment](docs/federal-deployment.md).

## Customize for your codebase

The included pipeline supports `cpp_asan` plus Docker-replayable `python_web`,
`node_web`, and `react_web` target profiles. The workflow can also be adapted
to other languages, vulnerability classes, and detection signals:

```text
/customize use <repository>/THREAT_MODEL.md and <repository>/TRIAGE.md
```

See [Customizing](docs/customizing.md) for the target contract and adaptation
guide.

## Documentation

- [Pipeline](docs/pipeline.md): architecture, stages, commands, and outputs
- [Threat model and triage](docs/triage.md): reviewing and prioritizing findings
- [Patching](docs/patching.md): patch-generation verification ladder
- [Security](docs/security.md): safe operating requirements
- [Agent sandbox](docs/agent-sandbox.md): gVisor isolation and egress policy
- [Troubleshooting](docs/troubleshooting.md): common setup and runtime issues
- [Targets](targets/README.md): built-in targets and target configuration

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
