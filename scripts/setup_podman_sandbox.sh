#!/usr/bin/env bash
# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
# One-time rootful Podman + gVisor sandbox setup. See docs/agent-sandbox.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

step() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ok\033[0m  %s\n' "$*"; }
die()  { printf '\033[1;31m  fail\033[0m %s\n' "$*" >&2; exit 1; }

assert_safe_checkout() {
    local unsafe_path
    unsafe_path=$(find -L "$REPO_ROOT" -xdev \( -type f -o -type d \) \
        \( -perm -0020 -o -perm -0002 \) -print -quit)
    [ -z "$unsafe_path" ] || die \
        "refusing to run repository Python with sudo: group/other-writable path: $unsafe_path"
}

[ "$(uname -s)" = "Linux" ] || die "gVisor requires Linux."
command -v podman >/dev/null || die "install Podman first."
case "$(uname -m)" in x86_64|aarch64) ARCH=$(uname -m) ;; *) die "unsupported architecture $(uname -m)" ;; esac
assert_safe_checkout

RUNSC_BIN=/usr/local/bin/runsc
RUNSC_RELEASE=${RUNSC_RELEASE:-20260420}
NET=vp-internal
PROXY_NAME=vp-egress-proxy
PROXY_TAG=vuln-pipeline-egress-proxy:latest
CONF=/etc/containers/containers.conf.d/90-vuln-pipeline-runsc.conf

step "gVisor (runsc)"
if [ ! -x "$RUNSC_BIN" ]; then
    base="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${ARCH}"
    tmp=$(mktemp -d)
    curl -fsSL "${base}/runsc" -o "$tmp/runsc"
    curl -fsSL "${base}/runsc.sha512" -o "$tmp/runsc.sha512"
    (cd "$tmp" && sha512sum -c runsc.sha512)
    sudo install -m 0755 "$tmp/runsc" "$RUNSC_BIN"
    rm -rf "$tmp"
fi
ok "$("$RUNSC_BIN" --version | head -1)"

step "Podman runtime (runsc)"
sudo install -d -m 0755 /etc/containers/containers.conf.d
sudo tee "$CONF" >/dev/null <<EOF
[engine.runtimes]
runsc = ["$RUNSC_BIN", "--overlay2=none"]
EOF
sudo podman run --rm --runtime=runsc alpine:3.21 true \
    || die "Podman could not start runsc. Rootless Podman is unsupported; check $CONF."
ok "runsc registered for rootful Podman"

step "Egress-only network + proxy"
sudo podman network inspect "$NET" >/dev/null 2>&1 || \
    sudo podman network create --internal "$NET" >/dev/null
sudo podman build -q -t "$PROXY_TAG" -f scripts/Dockerfile.proxy scripts >/dev/null
sudo podman rm -f "$PROXY_NAME" >/dev/null 2>&1 || true
[ -x .venv/bin/vuln-pipeline ] || { python3 -m venv .venv; .venv/bin/pip install -q -e .; }
if [ -n "${VP_EGRESS_ALLOW:-}" ]; then
    ALLOW="$VP_EGRESS_ALLOW"
else
    ALLOW=$(.venv/bin/python3 -c \
        'from harness.auth import required_egress_hosts; print(",".join(required_egress_hosts()))') \
        || die "egress allowlist derivation failed (see error above)"
fi
sudo podman run -d --name "$PROXY_NAME" --restart=unless-stopped \
    -e VP_EGRESS_ALLOW="$ALLOW" --network bridge "$PROXY_TAG" >/dev/null
sudo podman network connect "$NET" "$PROXY_NAME"
proxy_ip=$(sudo podman inspect "$PROXY_NAME" --format \
    '{{(index .NetworkSettings.Networks "'"$NET"'").IPAddress}}')
ok "proxy ${PROXY_NAME} up on ${NET} (${proxy_ip}:3128, allow: ${ALLOW})"

step "Target + agent images"
for d in targets/*/; do
    [ -f "$d/config.yaml" ] || continue
    tag=$(.venv/bin/python3 -c 'import sys,yaml;print(yaml.safe_load(open(sys.argv[1]))["image_tag"])' "$d/config.yaml")
    sudo podman build -q -t "$tag" "$d" >/dev/null
    sudo env VULN_PIPELINE_CONTAINER_ENGINE=podman .venv/bin/python3 \
        -c 'import sys; from harness import agent_image; print("  ", agent_image.ensure(sys.argv[1]))' "$tag"
done
ok "target + agent images built"

step "Verification"
ATAG=$(.venv/bin/python3 \
    -c 'import yaml; from harness.agent_image import agent_tag; t=agent_tag(yaml.safe_load(open("targets/canary/config.yaml"))["image_tag"]); print(t.rsplit(":", 1)[0] + ":latest")')
host_kver=$(uname -r)
guest_kver=$(sudo podman run --rm --runtime=runsc "$ATAG" uname -r) \
    || die "runsc container failed"
[ "$guest_kver" != "$host_kver" ] || die "guest kernel == host kernel; gVisor not active"
ok "gVisor active (guest $guest_kver, host $host_kver)"

sudo podman run --rm --runtime=runsc "$ATAG" claude --version >/dev/null \
    || die "claude CLI not runnable in agent image"
ok "claude CLI runs under gVisor"

PROBE=${ALLOW%%,*}
sudo podman run --rm -i --runtime=runsc --network="$NET" \
    -e HTTPS_PROXY="http://${proxy_ip}:3128" "$ATAG" python3 - "$PROBE" <<'PY' \
    || die "egress check failed"
import socket
import sys
import urllib.request

allowed = sys.argv[1]
try:
    urllib.request.urlopen(f"https://{allowed}/", timeout=10).read(1)
except urllib.error.HTTPError:
    pass
try:
    urllib.request.urlopen("https://example.com/", timeout=5)
    sys.exit("example.com reachable")
except Exception:
    pass
try:
    socket.create_connection(("8.8.8.8", 53), timeout=3)
    sys.exit("direct egress reachable")
except OSError:
    pass
PY
ok "egress: ${PROBE} reachable; example.com + direct egress blocked"

sentinel=/tmp/host-sentinel-$$
echo host > "$sentinel"
out=$(sudo podman run --rm --runtime=runsc "$ATAG" cat "$sentinel" 2>&1 || true)
rm -f "$sentinel"
echo "$out" | grep -qi 'no such file' || die "agent container can read host /tmp"
ok "host filesystem unreachable from agent container"

echo
echo "Setup complete. Run the pipeline rootfully:"
echo "  sudo -E env VULN_PIPELINE_CONTAINER_ENGINE=podman bin/vp-sandboxed run canary --model <model>"
