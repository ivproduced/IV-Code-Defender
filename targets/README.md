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
```

**Canary contract.** The grader runs every replay with a fresh random secret in
`IVCD_CANARY` (a different value for each of the three replays, and for the
patch-verification replay). The replay entrypoint must plant that value in
data an attacker should not be able to read (another user's record, an
admin-only field, a server-side secret) before replaying the manifest. A
finding passes criterion 3 only if the exact canary appears in the replay
output 3/3; a patch passes T1 only if it no longer does. The old static
`detection_signal` key is accepted but ignored for grading — a fixed string is
forgeable by any replay that echoes manifest text.

The `replay_command` script owns its complete lifecycle: it starts the local
service/browser, replays `/tmp/replay.json`, captures evidence, and stops its
children. Docker is primary; Podman remains supported by the existing sandbox
setup. A web find must save a UTF-8 JSON replay manifest with its exact
self-contained command, structured HTTP `requests`/`responses` or browser
`steps`/`observations`, and concrete security impact. That manifest—not scanner output—crosses into the
pristine grader, which replays it three times and rejects test-only paths.

#### `python_exec` (Python, runtime-monitor verified)

For Python code where a finding is a dangerous *operation* rather than a
sanitizer abort. Same contract as `cpp_asan`: only PoC bytes cross from find to
grade, and the grader builds the replay command from config
(`<binary_path> <poc_path>`). The grader is code, not a model.

```yaml
profile: python_exec
binary_path: /opt/vp/entry.py      # replay entry script; MUST be outside source_root
source_root: /work/app             # only frames under here count as "target code"
allowed_roots: [/work/app/data]    # paths target code may open (required)
allowed_hosts: []                  # hosts target code may contact
attack_surface: |                  # required: the only inputs a PoC may use
  ...
```

The image must ship the monitor at `/opt/vp/monitor/sitecustomize.py` (copy
`harness/monitor/sitecustomize.py`; a test enforces the `pycanary` copy is
identical) and the entry script outside `source_root`. The grader replays three
times with `PYTHONPATH=/opt/vp/monitor` and per-replay random
`IVCD_EVENT_TOKEN`, `IVCD_SOURCE_ROOT`, `IVCD_ALLOWED_ROOTS`,
`IVCD_ALLOWED_HOSTS`; the monitor prints `<token> IVCD-EVENT <json>` to stderr
for dangerous operations (os.system, subprocess, exec, spawn, open, socket
connect, pickle.find_class, exec/compile) performed from `source_root`. A
finding passes only if one proof holds 3/3 with a fresh token each time:

| `crash_type` | Proof |
|---|---|
| `exec` | command/exec event whose executable or command is `ivcd-proof` |
| `path_escape` | `open` event resolving outside `allowed_roots` |
| `secret_read` | the per-replay canary, planted by the grader at `/tmp/ivcd-canary.txt` (outside the allowed roots), appears in the replay output |

Lines without the current token are ignored (a target cannot forge events
without the token), a missing monitor handshake or unparseable event fails the
replay, and the token/canary must not appear in the PoC bytes. `allowed_roots`
may not cover `/` or the grader-owned `/tmp/ivcd-canary.txt` and `/tmp/poc.bin`.
Patching and standalone `dedup`/`report` are not supported for this profile in
this release (`run --stream` works). See `targets/pycanary` for a complete example.

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
