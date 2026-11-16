# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Helpers for embedding attacker-influenced text in agent prompts.

Untrusted blocks are delimited with a per-prompt random nonce on both the
opening and closing tag. The embedded text (target stderr, ASAN output, text
another agent derived from it) is authored before the nonce exists, so it
cannot contain a matching closing tag; sanitization additionally neutralizes
any closing-tag lookalike so the block cannot even appear to terminate early.
"""

from __future__ import annotations

import re
import secrets

_CLOSING_TAG = re.compile(r"</\s*untrusted_data", re.IGNORECASE)


def make_nonce() -> str:
    """Per-prompt random delimiter id for <untrusted_data> blocks."""
    return secrets.token_hex(16)


def sanitize_untrusted(text: str) -> str:
    """Neutralize anything that could close an <untrusted_data> block early."""
    return _CLOSING_TAG.sub("<untrusted_data", text)


def untrusted_block(text: str, nonce: str) -> str:
    """Wrap attacker-influenced text in nonce-delimited isolation tags."""
    return (
        f'<untrusted_data id="{nonce}">\n'
        f"{sanitize_untrusted(text)}\n"
        f'</untrusted_data id="{nonce}">'
    )


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(text: str, max_len: int = 2000) -> str:
    """Strip control characters and cap length of model-derived text.

    For text produced by another agent (recon focus areas) or derived from
    target/upstream data (git log, crash paths). Newlines and tabs survive;
    everything else non-printable is dropped before the text is fenced."""
    return _CONTROL.sub("", text)[:max_len]
