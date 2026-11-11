"""Fail-closed checks for the experimental OpenShell transport."""

from pathlib import Path

import pytest

from harness.openshell import (
    OpenShellError,
    _check_replay_inputs,
    _credential_check_command,
    main,
    probe,
)


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


def test_credential_check_covers_supported_authentication_inputs():
    command = _credential_check_command()
    for name in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_BEARER_TOKEN_BEDROCK",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        assert f"${{{name}:-}}" in command


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


def test_probe_continues_cleanup_and_reports_cleanup_failure(tmp_path):
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
            if len(self.deleted) == 1:
                raise OSError("gateway unavailable")

    transport = FailedTransfer()
    with pytest.raises(OpenShellError, match="transfer failed.*cleanup errors.*gateway unavailable"):
        probe(IMAGE, policy, transport)
    assert len(transport.deleted) == 2


def test_probe_rejects_unpinned_cli_or_gateway_version(tmp_path):
    policy = _policy(tmp_path / "policy.yaml")

    class WrongVersion:
        def status(self):
            return {"version": "0.1.6"}

        def version(self):
            return "openshell 0.2.0"

    with pytest.raises(OpenShellError, match="CLI must be OpenShell 0.1.6"):
        probe(IMAGE, policy, WrongVersion())


def test_main_serializes_malformed_yaml_as_failure(tmp_path, capsys):
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: [unterminated")
    output = tmp_path / "result.json"

    status = main([
        "--image", IMAGE,
        "--policy", str(policy),
        "--output", str(output),
    ])

    assert status == 1
    result = output.read_text()
    assert '"transport_passed": false' in result
    assert "error" in result
    assert capsys.readouterr().out == result
