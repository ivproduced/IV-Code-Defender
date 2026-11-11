"""Fail-closed checks for the experimental OpenShell transport."""

from pathlib import Path

import pytest

from harness.openshell import OpenShellError, _check_replay_inputs, probe


IMAGE = "example.com/probe@sha256:" + "a" * 64


def _policy(path: Path, *, landlock: str = "hard_requirement") -> Path:
    path.write_text(
        "version: 1\n"
        f"landlock:\n  compatibility: {landlock}\n"
        "network_policies: {}\n"
    )
    return path


def test_replay_rejects_mutable_image_and_best_effort_landlock(tmp_path):
    policy = _policy(tmp_path / "policy.yaml")
    with pytest.raises(OpenShellError, match="immutable"):
        _check_replay_inputs("example.com/probe:latest", policy)
    _policy(policy, landlock="best_effort")
    with pytest.raises(OpenShellError, match="Landlock"):
        _check_replay_inputs(IMAGE, policy)


def test_probe_cleans_up_after_transfer_failure(tmp_path):
    policy = _policy(tmp_path / "policy.yaml")

    class FailedTransfer:
        deleted = []

        def status(self):
            return {"version": "0.1.6"}

        def version(self):
            return "openshell 0.1.6"

        def create_replay(self, name, image, policy_path):
            return {"configuration_admission": {"policy_hash": "hash"}}

        def upload(self, name, source, destination):
            raise OpenShellError("transfer failed")

        def delete(self, name):
            self.deleted.append(name)

    transport = FailedTransfer()
    with pytest.raises(OpenShellError, match="transfer failed"):
        probe(IMAGE, policy, transport)
    assert len(transport.deleted) == 2
    assert all(name.startswith("ivcd-") for name in transport.deleted)
