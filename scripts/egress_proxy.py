#!/usr/bin/env python3
# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Allowlist CONNECT proxy for the agent sandbox.

Agent containers sit on the docker --internal vp-internal network with no
default route; this proxy is their only path out. Only CONNECT to allowlisted
host:port tuples is honoured, so the agent (and anything it spawns) can reach
the API and nothing else. Denied attempts are logged — useful signal if an
agent tries to phone home. The orchestrator stays on the trusted host.

Run as a sidecar container dual-homed on vp-internal and the default bridge.

Optional credential gateway (``VP_GATEWAY_UPSTREAM``): a second listener that
accepts plain HTTP from agent containers, strips whatever credential header
they send, injects the real key held only in *this* container's environment,
and forwards to a single fixed upstream. Agent containers then hold only a
placeholder token, so a key exfiltrated from the container that runs target
code is worthless (and the CONNECT allowlist no longer needs the API host).
"""

from __future__ import annotations

import os
import http.client
import re
import select
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ALLOW = {
    h.strip().lower()
    for h in os.environ.get("VP_EGRESS_ALLOW", "api.anthropic.com:443").split(",")
    if h.strip()
}
PORT = int(os.environ.get("VP_EGRESS_PORT") or 3128)

GATEWAY_UPSTREAM = os.environ.get("VP_GATEWAY_UPSTREAM", "").strip()
GATEWAY_PORT = int(os.environ.get("VP_GATEWAY_PORT") or 8080)
GATEWAY_API_KEY = os.environ.get("VP_GATEWAY_API_KEY", "")
GATEWAY_OAUTH_TOKEN = os.environ.get("VP_GATEWAY_OAUTH_TOKEN", "")
GATEWAY_PATHS = ("/v1/messages", "/v1/models")
GATEWAY_MAX_BODY = 32 * 1024 * 1024
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
        "x-api-key", "authorization"}
_RESP_HEADERS = {"content-type", "content-encoding", "cache-control", "retry-after",
                 "request-id", "x-request-id"}
_CTL = re.compile(r"[\x00-\x1f\x7f]")
SOCKET_TIMEOUT = 60
MAX_TUNNEL_SECONDS = int(os.environ.get("VP_EGRESS_MAX_TUNNEL_S") or 4 * 3600)

_HOST_RE = re.compile(r"^[a-z0-9.-]+:\d+$")


def _allowed(target: str, allow: set[str] = ALLOW) -> bool:
    # Keep in sync with harness/auth.py:_host_allowed
    t = target.lower()
    if not _HOST_RE.match(t):
        return False
    return any(t == e or (e.startswith("*.") and t.endswith(e[1:])) for e in allow)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self):  # noqa: N802 — http.server dispatch convention
        target = self.path
        if not _allowed(target):
            sys.stderr.write(f"[egress DENY] {self.client_address[0]} → {target}\n")
            self.send_error(403, f"egress denied: {target}")
            return
        host, _, port = target.rpartition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError as e:
            self.send_error(502, f"upstream connect failed: {e}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        client = self.connection
        sys.stderr.write(f"[egress ok]   {self.client_address[0]} → {target}\n")
        self._pump(client, upstream)

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        """Relay bytes both ways.

        Sockets stay in blocking mode with a timeout: ``sendall`` on a
        non-blocking socket raises BlockingIOError (an OSError) as soon as the
        peer's buffer fills, silently tearing down large streamed responses.
        select() only gates reads; writes block (bounded by SOCKET_TIMEOUT)."""
        a.settimeout(SOCKET_TIMEOUT)
        b.settimeout(SOCKET_TIMEOUT)
        deadline = time.monotonic() + MAX_TUNNEL_SECONDS
        try:
            while time.monotonic() < deadline:
                r, _, _ = select.select([a, b], [], [], SOCKET_TIMEOUT)
                if not r:
                    return
                for src in r:
                    dst = b if src is a else a
                    data = src.recv(65536)
                    if not data:
                        return
                    dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def log_message(self, format, *args):  # noqa: A002 — base sig
        pass



class Gateway(BaseHTTPRequestHandler):
    """Credential-injecting reverse proxy to one fixed HTTPS upstream."""

    protocol_version = "HTTP/1.1"

    def _handle(self):
        path = self.path.split("?", 1)[0]
        if not any(path == p or path.startswith(p + "/") for p in GATEWAY_PATHS):
            sys.stderr.write(f"[gateway DENY] {self.client_address[0]} {self.command} {path}\n")
            self.send_error(403, "gateway: path not allowed")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > GATEWAY_MAX_BODY:
            self.send_error(413, "gateway: bad or oversized body")
            return
        body = self.rfile.read(length) if length else None
        up = urlparse(GATEWAY_UPSTREAM)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
        if GATEWAY_API_KEY:
            headers["x-api-key"] = GATEWAY_API_KEY
        if GATEWAY_OAUTH_TOKEN:
            headers["Authorization"] = f"Bearer {GATEWAY_OAUTH_TOKEN}"
        headers["Host"] = up.netloc
        headers["Accept-Encoding"] = "identity"
        try:
            conn = http.client.HTTPSConnection(
                up.hostname, up.port or 443, timeout=600)
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            self.send_error(502, f"gateway upstream failed: {type(e).__name__}")
            return
        # Close-delimited response: simplest correct way to stream SSE.
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            # Allowlist + CR/LF/control stripping: upstream header text must
            # never be able to split the response we send to the container.
            name = k.lower()
            if name in _RESP_HEADERS or name.startswith("anthropic-"):
                self.send_header(_CTL.sub("", k), _CTL.sub("", v))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            while chunk := resp.read(8192):
                self.wfile.write(chunk)
                self.wfile.flush()
        except OSError:
            pass
        finally:
            conn.close()

    do_GET = do_POST = _handle  # noqa: N815

    def log_message(self, format, *args):  # noqa: A002 — base sig
        pass


def main() -> None:
    sys.stderr.write(f"[egress] listening on :{PORT}, allow={sorted(ALLOW)}\n")
    if GATEWAY_UPSTREAM:
        if not (GATEWAY_API_KEY or GATEWAY_OAUTH_TOKEN):
            sys.exit("VP_GATEWAY_UPSTREAM set but no VP_GATEWAY_API_KEY/OAUTH_TOKEN")
        if urlparse(GATEWAY_UPSTREAM).scheme != "https":
            sys.exit("VP_GATEWAY_UPSTREAM must be an https:// URL")
        threading.Thread(
            target=ThreadingHTTPServer(("", GATEWAY_PORT), Gateway).serve_forever,
            daemon=True,
        ).start()
        sys.stderr.write(f"[gateway] :{GATEWAY_PORT} -> {GATEWAY_UPSTREAM}\n")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
