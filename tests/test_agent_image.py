# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Agent images follow immutable target image contents, not mutable tags."""

from harness import agent_image


def test_digest_tag_changes_when_target_image_changes():
    first = agent_image._digest_tag("target:latest", "sha256:" + "a" * 64)
    second = agent_image._digest_tag("target:latest", "sha256:" + "b" * 64)
    assert first != second
    assert "-" + "a" * 16 + "-" in first


def test_digest_tag_changes_when_agent_recipe_changes(monkeypatch):
    original = agent_image._digest_tag("target:latest", "sha256:" + "a" * 64)
    monkeypatch.setattr(
        agent_image,
        "_agent_dockerfile",
        lambda _tag: "FROM target:latest\nRUN changed\n",
    )
    changed = agent_image._digest_tag("target:latest", "sha256:" + "a" * 64)
    assert changed != original


def test_ensure_resolves_current_image_id(monkeypatch):
    seen = []
    monkeypatch.setattr(
        agent_image.docker_ops,
        "image_id",
        lambda tag: "sha256:" + "c" * 64,
    )
    monkeypatch.setattr(
        agent_image,
        "_ensure_for_image",
        lambda tag, image_id: seen.append((tag, image_id)) or "derived:fresh",
    )
    assert agent_image.ensure("target:latest") == "derived:fresh"
    assert seen == [("target:latest", "sha256:" + "c" * 64)]


def test_latest_alias_is_stable_across_rebuilds():
    assert agent_image.latest_tag("target:latest") == "target-latest-agent:latest"


def test_build_uses_sampled_image_when_target_tag_changes(monkeypatch):
    first = "sha256:" + "a" * 64
    second = "sha256:" + "b" * 64
    images = {"target:latest": first}
    built = []

    def sample_image_id(tag):
        sampled = images[tag]
        images[tag] = second  # another batch rebuilds the mutable tag
        return sampled

    def tag_image(source, destination):
        images[destination] = source
        return destination

    def build(dockerfile, tag):
        base = dockerfile.splitlines()[0].removeprefix("FROM ")
        built.append((base, images[base], tag))

    monkeypatch.setattr(agent_image.docker_ops, "image_id", sample_image_id)
    monkeypatch.setattr(agent_image.docker_ops, "image_exists", lambda _tag: False)
    monkeypatch.setattr(agent_image.docker_ops, "tag", tag_image)
    monkeypatch.setattr(agent_image.docker_ops, "command", lambda *args: list(args))
    monkeypatch.setattr(agent_image, "_build", build)
    monkeypatch.setattr(agent_image.subprocess, "run", lambda *args, **kwargs: None)
    agent_image._ensure_for_image.cache_clear()
    try:
        derived = agent_image.ensure("target:latest")
    finally:
        agent_image._ensure_for_image.cache_clear()

    assert images["target:latest"] == second
    assert built == [(agent_image._base_image_tag(first), first, derived)]
