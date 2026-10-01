# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
import json
import stat

import pytest

from harness.io_utils import (
    append_jsonl,
    atomic_write_json,
    atomic_write_text,
    exclusive_lock,
    ResultsLockError,
)


def test_atomic_write_replaces_complete_document_and_is_private(tmp_path):
    path = tmp_path / "result.json"
    atomic_write_json(path, {"generation": 1})
    atomic_write_json(path, {"generation": 2, "complete": True})
    assert json.loads(path.read_text()) == {"generation": 2, "complete": True}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700


def test_append_jsonl_is_private_and_complete(tmp_path):
    path = tmp_path / "events.jsonl"
    append_jsonl(path, {"event": 1})
    append_jsonl(path, {"event": 2})
    assert [json.loads(line) for line in path.read_text().splitlines()] == [
        {"event": 1},
        {"event": 2},
    ]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_atomic_write_leaves_no_temporary_files(tmp_path):
    path = tmp_path / "artifact.txt"
    atomic_write_text(path, "complete")
    assert path.read_text() == "complete"
    assert [p.name for p in tmp_path.iterdir()] == ["artifact.txt"]


def test_results_lock_rejects_second_orchestrator(tmp_path):
    lock = tmp_path / ".orchestrator.lock"
    with exclusive_lock(lock):
        with pytest.raises(ResultsLockError, match="already in use"):
            with exclusive_lock(lock):
                pass
