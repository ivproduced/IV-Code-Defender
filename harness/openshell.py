"""Experimental OpenShell transport probe; not an active pipeline backend.

This module exercises the pinned-image, credential-free replay path before any
agent or target execution is routed away from the existing gVisor boundary.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml


_DIGEST_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_SANDBOX_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_PROBE_BYTES = bytes(range(256)) * 1024


class OpenShellError(RuntimeError):
    """The OpenShell transport or a required invariant failed."""


def _check_replay_inputs(image: str, policy_path: Path) -> None:
    if not _DIGEST_IMAGE.fullmatch(image):
        raise OpenShellError("image must use an immutable @sha256:<64 hex> reference")
    if not policy_path.is_file():
        raise OpenShellError(f"policy does not exist: {policy_path}")
    policy = yaml.safe_load(policy_path.read_text())
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise OpenShellError("replay policy must use OpenShell schema version 1")
    landlock = policy.get("landlock")
    if not isinstance(landlock, dict) or landlock.get("compatibility") != "hard_requirement":
        raise OpenShellError("replay policy must require Landlock enforcement")
    if policy.get("network_policies") != {}:
        raise OpenShellError("replay probe requires an explicit empty network_policies map")


class OpenShellTransport:
    """Bounded CLI operations used only by the transport probe for now."""

    def __init__(self, binary: str = "openshell", gateway: str | None = None):
        self.binary = binary
        self.gateway = gateway

    def _call(
        self, args: list[str], *, timeout: int = 30, input_bytes: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        command = [self.binary, *(["-g", self.gateway] if self.gateway else []), *args]
        try:
            return subprocess.run(
                command, input=input_bytes, capture_output=True, timeout=timeout, check=False
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise OpenShellError(f"OpenShell command unavailable or timed out: {args[0]}") from exc

    @staticmethod
    def _require_ok(result: subprocess.CompletedProcess[bytes], operation: str) -> None:
        if result.returncode:
            detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
            raise OpenShellError(f"{operation} failed (exit {result.returncode}): {detail}")

    def version(self) -> str:
        result = self._call(["--version"])
        self._require_ok(result, "version")
        return result.stdout.decode("utf-8", "replace").strip()

    def status(self) -> dict:
        result = self._call(["status", "--output", "json"])
        self._require_ok(result, "gateway status")
        data = json.loads(result.stdout)
        if data.get("status") != "connected" or data.get("authentication", {}).get("status") != "authenticated":
            raise OpenShellError("gateway is not connected and authenticated")
        return data

    def get(self, name: str) -> dict:
        result = self._call(["sandbox", "get", name, "-o", "json"])
        self._require_ok(result, "sandbox inspection")
        return json.loads(result.stdout)

    def create_replay(self, name: str, image: str, policy_path: Path) -> dict:
        if not _SANDBOX_NAME.fullmatch(name):
            raise OpenShellError("invalid sandbox name")
        _check_replay_inputs(image, policy_path)
        result = self._call(
            [
                "sandbox", "create", "--name", name, "--from", image,
                "--policy", str(policy_path), "--cpu", "1", "--memory", "1Gi",
                "--detach", "--no-auto-providers", "--", "/bin/sleep", "600",
            ],
            timeout=180,
        )
        self._require_ok(result, "sandbox creation")
        deadline = time.monotonic() + 30
        while True:
            state = self.get(name)
            conditions = {c.get("type"): c.get("status") for c in state.get("conditions", [])}
            if (
                state.get("phase") == "Ready"
                and conditions.get("Ready") == "True"
                and conditions.get("ConfigurationReady") == "True"
                and state.get("configuration_admission", {}).get("state") == "accepted"
                and state.get("policy_source") == "sandbox"
                and state.get("policy", {}).get("network_policies", {}) == {}
            ):
                return state
            if state.get("phase") in {"Error", "Failed", "Completed"} or time.monotonic() >= deadline:
                raise OpenShellError("sandbox did not load the expected replay policy")
            time.sleep(0.5)

    def exec(self, name: str, argv: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[bytes]:
        if not argv or not all(isinstance(arg, str) and arg for arg in argv):
            raise OpenShellError("exec requires nonempty argv")
        return self._call(
            ["sandbox", "exec", "--no-login-shell", "--no-tty", "--timeout", str(timeout), name, "--", *argv],
            timeout=timeout + 15,
        )

    def upload(self, name: str, source: Path, destination: str) -> None:
        if not source.is_file() or not destination.startswith("/sandbox/"):
            raise OpenShellError("uploads require a file and a /sandbox/ destination")
        result = self._call(
            ["sandbox", "upload", "--no-git-ignore", name, str(source), destination], timeout=60
        )
        self._require_ok(result, "upload")

    def download(self, name: str, source: str, destination: Path) -> None:
        if not source.startswith("/sandbox/"):
            raise OpenShellError("downloads require a /sandbox/ source")
        result = self._call(["sandbox", "download", name, source, str(destination)], timeout=60)
        self._require_ok(result, "download")

    def delete(self, name: str) -> None:
        result = self._call(["sandbox", "delete", name], timeout=30)
        self._require_ok(result, "sandbox deletion")
        deadline = time.monotonic() + 15
        while True:
            listed = self._call(["sandbox", "list", "-o", "json"])
            self._require_ok(listed, "sandbox cleanup inspection")
            names = {item.get("name") for item in json.loads(listed.stdout).get("sandboxes", [])}
            if name not in names:
                return
            if time.monotonic() >= deadline:
                raise OpenShellError(f"sandbox deletion did not finish: {name}")
            time.sleep(0.5)


def probe(image: str, policy_path: Path, transport: OpenShellTransport) -> dict:
    """Test transfer, isolation and network denial without a provider."""
    _check_replay_inputs(image, policy_path)
    gateway = transport.status()
    suffix = secrets.token_hex(4)
    first, fresh = f"ivcd-probe-{suffix}", f"ivcd-fresh-{suffix}"
    report = {
        "openshell_version": transport.version(),
        "gateway_version": gateway.get("version"),
        "image": image,
        "qualified_for_pipeline": False,
        "checks": {},
    }
    with tempfile.TemporaryDirectory(prefix="ivcd-openshell-") as directory:
        source = Path(directory) / "probe.bin"
        returned = Path(directory) / "returned.bin"
        source.write_bytes(_PROBE_BYTES)
        try:
            state = transport.create_replay(first, image, policy_path)
            report["policy_hash"] = state["configuration_admission"]["policy_hash"]
            transport.upload(first, source, "/sandbox/probe.bin")
            transport.download(first, "/sandbox/probe.bin", returned)
            report["checks"]["binary_roundtrip"] = (
                returned.read_bytes() == _PROBE_BYTES
            )
            identity = transport.exec(first, ["/usr/bin/id", "-u"])
            report["checks"]["non_root"] = identity.returncode == 0 and identity.stdout.strip() != b"0"
            denied = transport.exec(
                first, ["/bin/bash", "-c", "echo > /dev/tcp/example.com/443"]
            )
            report["checks"]["network_denied"] = (
                denied.returncode != 0 and b"Permission denied" in denied.stderr
            )
            credential_check = transport.exec(
                first,
                ["/bin/bash", "-c", 'test -z "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${GEMINI_API_KEY:-}"'],
            )
            report["checks"]["provider_credentials_absent"] = credential_check.returncode == 0
            transport.create_replay(fresh, image, policy_path)
            clean = transport.exec(fresh, ["/usr/bin/test", "!", "-e", "/sandbox/probe.bin"])
            report["checks"]["fresh_sandbox_isolated"] = clean.returncode == 0
        finally:
            for name in (fresh, first):
                try:
                    transport.delete(name)
                except OpenShellError as exc:
                    report.setdefault("cleanup_errors", []).append(str(exc))
    report["transport_passed"] = all(report["checks"].values()) and not report.get("cleanup_errors")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="immutable image@sha256:digest")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--binary", default=os.environ.get("IVCD_OPENSHELL_BIN", "openshell"))
    parser.add_argument("--gateway")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = probe(args.image, args.policy, OpenShellTransport(args.binary, args.gateway))
    except (OpenShellError, OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"transport_passed": False, "qualified_for_pipeline": False, "error": str(exc)}
    output = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(output + "\n")
    print(output)
    return 0 if result.get("transport_passed") else 1


if __name__ == "__main__":
    sys.exit(main())
