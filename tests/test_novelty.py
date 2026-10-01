# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0

from harness.novelty import _validated_upstream_url, upstream_log


def test_accepts_credential_free_github_https_url():
    value = "https://github.com/example/project.git"
    assert _validated_upstream_url(value) == value


def test_rejects_local_ssh_credentials_and_unapproved_hosts():
    rejected = (
        "file:///tmp/repo",
        "ssh://git@github.com/example/project",
        "https://token@github.com/example/project",
        "https://example.com/example/project",
    )
    for value in rejected:
        assert "rejected" in upstream_log(value, "a" * 40, "/work/a.c")


def test_rejects_non_hex_commit_before_git_is_invoked():
    result = upstream_log(
        "https://github.com/example/project", "--all", "/work/a.c"
    )
    assert "commit rejected" in result


def test_explicit_host_allowlist(monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_NOVELTY_HOSTS", "git.example.com")
    value = "https://git.example.com/team/project"
    assert _validated_upstream_url(value) == value
