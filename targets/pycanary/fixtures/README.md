# pycanary fixtures

`results_sample/` holds three pre-baked `python_exec` results, one per planted
bug (command injection, path traversal, unsafe deserialization). The PoCs are
real: `tests/test_pyexec_e2e.py` replays them through the machine grader in a
container. Patching and standalone dedup/report do not support `python_exec`.
