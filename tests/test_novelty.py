# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0

import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from harness.novelty import _ensure_clone, _validated_upstream_url, upstream_log


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


@pytest.mark.parametrize("cached", [False, True], ids=["clone", "fetch"])
def test_git_does_not_follow_cross_host_redirect(tmp_path, cached):
    """Exercise Git itself; HTTP is used only for the loopback test server."""
    initial_requests = []
    redirected_requests = []

    class RedirectDestination(BaseHTTPRequestHandler):
        def do_GET(self):
            redirected_requests.append(self.path)
            self.send_error(404)

        def log_message(self, *_args):
            pass

    try:
        destination = HTTPServer(("127.0.0.1", 0), RedirectDestination)
    except PermissionError:
        pytest.skip("loopback listeners are unavailable in this sandbox")
    destination_url = f"http://localhost:{destination.server_port}/other/repo"

    class ApprovedHost(BaseHTTPRequestHandler):
        def do_GET(self):
            initial_requests.append(self.path)
            self.send_response(302)
            self.send_header("Location", destination_url)
            self.end_headers()

        def log_message(self, *_args):
            pass

    try:
        approved = HTTPServer(("127.0.0.1", 0), ApprovedHost)
    except PermissionError:
        destination.server_close()
        pytest.skip("loopback listeners are unavailable in this sandbox")
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (destination, approved)
    ]
    for thread in threads:
        thread.start()
    try:
        # _validated_upstream_url is tested separately; _ensure_clone accepts
        # loopback HTTP here to avoid certificate setup in this Git regression.
        url = f"http://127.0.0.1:{approved.server_port}/team/repo"
        repo_dir = tmp_path / "repo"
        if cached:
            subprocess.run(["git", "init", "-q", str(repo_dir)], check=True)
            subprocess.run(
                ["git", "-C", str(repo_dir), "remote", "add", "origin", url],
                check=True,
            )
        ok, _message = _ensure_clone(url, repo_dir)
        assert not ok
        assert initial_requests
        assert redirected_requests == []
    finally:
        for server in (approved, destination):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()
