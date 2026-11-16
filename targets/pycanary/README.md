# pycanary — python_exec smoke-test target

A deliberately vulnerable Python package with three planted bugs, one per
proof kind, for validating the `python_exec` profile (runtime monitor,
machine proof rules, prompts) without a real codebase. **Not a real target.**

| Command | Function | Bug | Proof kind | Example PoC (first line of the file) |
|---|---|---|---|---|
| `diag` | `handlers.diag` | command injection | `exec` | `diag x; ivcd-proof` |
| `read` | `handlers.read` | path traversal | `path_escape` / `secret_read` | `read ../../../tmp/ivcd-canary.txt` |
| `load` | `handlers.load` | unsafe `pickle.loads` | `exec` | `load <base64 of a pickle whose __reduce__ runs os.system("ivcd-proof")>` |

`/opt/vp/entry.py <file>` is the replay entry (outside `source_root`); the
monitor lives in `/opt/vp/monitor`. `monitor/sitecustomize.py` here is a copy of
`harness/monitor/sitecustomize.py`; a unit test fails if they drift.

```bash
docker build -t vuln-pipeline-pycanary:latest targets/pycanary
bin/vp-sandboxed run pycanary --runs 3 --parallel --stream --model <model-id>
```

Patching and standalone `dedup`/`report` are not supported for `python_exec`
in this release.
