# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
import json

from harness.cli import (
    _pin_target_for_existing_batch,
    _record_or_verify_batch_image,
)
from harness.config import TargetConfig


def _target():
    return TargetConfig(
        name="t", dockerfile_dir="/tmp/t", image_tag="t:latest",
        github_url="https://github.com/example/t", commit="a" * 40,
        binary_path="/work/entry", source_root="/work",
    )


def test_fresh_batch_records_immutable_target_image(tmp_path):
    image_id = "sha256:" + "a" * 64
    assert _record_or_verify_batch_image(
        tmp_path, _target(), image_id, is_resume=False
    ) is None
    metadata = json.loads((tmp_path / "batch_metadata.json").read_text())
    assert metadata["target_image_id"] == image_id
    assert metadata["legacy_resume_without_prior_metadata"] is False


def test_resume_rejects_different_target_image(tmp_path):
    first = "sha256:" + "a" * 64
    second = "sha256:" + "b" * 64
    _record_or_verify_batch_image(tmp_path, _target(), first, is_resume=False)
    error = _record_or_verify_batch_image(
        tmp_path, _target(), second, is_resume=True
    )
    assert error is not None
    assert "image mismatch" in error


def test_legacy_resume_establishes_image_pin(tmp_path):
    image_id = "sha256:" + "c" * 64
    assert _record_or_verify_batch_image(
        tmp_path, _target(), image_id, is_resume=True
    ) is None
    metadata = json.loads((tmp_path / "batch_metadata.json").read_text())
    assert metadata["legacy_resume_without_prior_metadata"] is True


def test_existing_batch_is_pinned_to_image_id(tmp_path, monkeypatch):
    image_id = "sha256:" + "d" * 64
    _record_or_verify_batch_image(tmp_path, _target(), image_id, is_resume=False)
    monkeypatch.setattr(
        "harness.cli.docker_ops.image_exists", lambda _tag: True
    )
    monkeypatch.setattr(
        "harness.cli.docker_ops.image_id", lambda _tag: image_id
    )
    monkeypatch.setattr(
        "harness.cli.docker_ops.tag", lambda _source, destination: destination
    )
    pinned, error = _pin_target_for_existing_batch(tmp_path, _target())
    assert error is None
    assert pinned is not None
    assert pinned.image_tag.endswith(image_id.removeprefix("sha256:"))


def test_existing_batch_rejects_rebuilt_different_image(tmp_path, monkeypatch):
    expected = "sha256:" + "d" * 64
    current = "sha256:" + "e" * 64
    _record_or_verify_batch_image(tmp_path, _target(), expected, is_resume=False)
    monkeypatch.setattr(
        "harness.cli.docker_ops.image_exists", lambda _tag: True
    )
    monkeypatch.setattr(
        "harness.cli.docker_ops.image_id", lambda _tag: current
    )
    pinned, error = _pin_target_for_existing_batch(tmp_path, _target())
    assert pinned is None
    assert error is not None and "does not match" in error
