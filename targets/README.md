# Adding a new target

A target is a directory under `targets/` containing everything the pipeline
needs to build an ASAN-instrumented binary or a Docker-replayable web target.

## Required files

### `config.yaml`

```yaml
image_tag: vuln-pipeline-<name>:latest   # docker tag to build/run
github_url: https://github.com/...      # for the prompt (agent reads source, needs context)
commit: <full-sha>                      # pin exactly what you tested
binary_path: /work/entry                # path INSIDE the container
source_root: /work                      # path INSIDE the container
```

### Profiles

`profile` defaults to `cpp_asan`, preserving the original ASAN contract.
Supported web profiles are `python_web`, `node_web`, and `react_web`. They
retain `binary_path` for compatibility (use the replay executable) and require:

```yaml
profile: python_web
replay_command: /work/replay             # absolute, simple command; no shell syntax
detection_signal: VULNERABILITY_DETECTED # marker printed only while the issue remains
```

The `replay_command` script owns its complete lifecycle: it starts the local
service/browser, replays `/tmp/replay.json`, captures evidence, and stops its
children. Docker is primary; Podman remains supported by the existing sandbox
setup. A web find must save a UTF-8 JSON replay manifest with its exact
self-contained command, structured HTTP `requests`/`responses` or browser
`steps`/`observations`, a deterministic target-owned detection signal, and
concrete security impact. That manifest—not scanner output—crosses into the
pristine grader, which replays it three times and rejects test-only paths.

Optional fields:

```yaml
focus_areas:                            # starting points for parallel runs (or use --auto-focus)
  - "PNG chunk parsing (decode_chunk) — IDAT decompression, filter reconstruction"

known_bugs:                             # rendered into the prompt as do-not-resubmit
  - "Crashes in decode_chunk (decoder.h ~4500-4530) — may show as heap-overflow OR assertion. Upstream #123."

attack_surface: |                       # anchors the report-agent's reachability section
  Header-only image decoder library. Real surface: any caller of the public
  load-from-bytes API on untrusted image data. Pure file parser — no wire
  protocol, no auth.

build_command: gcc -O1 -g -fsanitize=address -o /work/entry /work/entry.c
                                        # in-container rebuild for the patch grader (T0).
                                        # Required for `vuln-pipeline patch`; the grader
                                        # applies the diff then runs this to recompile.

test_command: cd /work/src && make check
                                        # regression suite for the patch grader (T2).
                                        # Optional; T2 is skipped if absent.
```

**`known_bugs` format matters.** These go into the find-agent's prompt. Key on
**function name**, not line number — the same bug crashes at different lines
or with different ASAN types (SEGV vs assertion vs stack-overflow) depending on
input. `"null-deref at file.h:1234"` won't match when the agent's crash lands
at `:1240`. Include: crash function, approximate line range, alternate crash
types you've observed.

### `Dockerfile`

Must produce an image where:
- `{binary_path}` is an ASAN-instrumented executable taking one argument (input file)
- `{source_root}` contains the source the agent will read
- `python3`, `xxd`, `file`, `gdb` are available (agent uses these to craft inputs)
- `/bin/bash` works (container entrypoint)

For web profiles, also include the application runtime and an immutable
`/opt/vp/replay` verifier outside `source_root`, executable without host
networking or credentials. Do not rely on a service left by the find agent:
find, grade, report, and patch-grade containers are intentionally separate.

Template:

```dockerfile
FROM gcc:14
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends python3 xxd file gdb && rm -rf /var/lib/apt/lists/*

# COPY source files into /work. Prefer local COPY over git-clone — faster,
# no network in build, pins commit for free.
COPY <your_source_files> /work/

COPY entry.c /work/entry.c
RUN gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer -o /work/entry /work/entry.c -lm

CMD ["/bin/bash"]
```

**Flags:** `-O1` per ASAN docs (O0 too slow, O2+ can optimize bugs away).
`-fno-omit-frame-pointer` for readable stack traces.

### `entry.c`

A thin wrapper: `./entry <input_file>` → run the parser on the file, exit.
Keep it minimal — it defines the attack surface. ASAN abort happens before
`return 0` if there's memory corruption.

## Examples

`targets/examples/` has lightweight Python, Node, and React configuration
shapes. They are non-runnable templates; copy one beside a Dockerfile and a
replay script that match your application.

## Zero pipeline changes

The pipeline reads `config.yaml` and runs `docker build` on this directory.
No Python edits needed to add a target.
