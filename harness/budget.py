# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
"""Batch-wide spend ceiling (OWASP LLM10 / ASI08 unbounded consumption).

Turn counts bound a single agent; they do not bound a batch of N parallel
agents with up to 20 resumes each. The ledger below is process-global and
shared by every ``run_agent`` call: usage is recorded as assistant messages
stream in, and any agent started or running after the ceiling is crossed is
stopped. ``None`` means "no ceiling" for that dimension.

Limits come from CLI flags (see ``cli.py``) or the environment:
``VULN_PIPELINE_MAX_BATCH_USD``, ``VULN_PIPELINE_MAX_BATCH_TOKENS`` and the
per-agent ``VULN_PIPELINE_MAX_AGENT_USD`` (forwarded to the CLI's own
``--max-budget-usd`` so a single runaway session stops by itself).
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field


MIN_RESERVE_USD = 0.01


class BudgetExhausted(Exception):
    """No spend headroom left to start another agent launch."""


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass
class Ledger:
    max_usd: float | None = None
    max_tokens: float | None = None
    max_agent_usd: float | None = None
    usd: float = 0.0
    reserved: float = 0.0   # dollars held by in-flight CLI launches
    tokens: int = 0
    _seen: set = field(default_factory=set, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_message(self, msg: dict) -> None:
        """Count tokens from an assistant message (deduped by message id —
        stream-json repeats the same usage once per content block)."""
        if msg.get("type") != "assistant":
            return
        inner = msg.get("message") or {}
        usage = inner.get("usage") or {}
        mid = inner.get("id")
        with self._lock:
            if mid:
                if mid in self._seen:
                    return
                self._seen.add(mid)
            self.tokens += sum(
                int(usage.get(k) or 0)
                for k in ("input_tokens", "output_tokens", "cache_creation_input_tokens")
            )

    def begin_launch(self) -> float | None:
        """Reserve spend for one CLI launch and return the cap to pass as
        ``--max-budget-usd`` (None = uncapped).

        Dollar cost only arrives when a session ends, so the batch ceiling is
        enforced *live* by reservation: each launch may spend at most
        min(per-agent cap, ceiling - spent - already reserved), and the CLI
        itself stops at that cap. Raises BudgetExhausted if nothing is left."""
        with self._lock:
            cap = self.max_agent_usd
            if self.max_usd is not None:
                remaining = self.max_usd - self.usd - self.reserved
                if remaining < MIN_RESERVE_USD:
                    raise BudgetExhausted(
                        f"batch spend ${self.usd:.2f} + in-flight ${self.reserved:.2f} "
                        f"reached ceiling ${self.max_usd:.2f}")
                cap = remaining if cap is None else min(cap, remaining)
            if cap is not None:
                self.reserved += cap
            return cap

    def end_launch(self, cap: float | None, actual_usd: float | None) -> None:
        """Release a reservation and book what the launch actually cost."""
        with self._lock:
            if cap is not None:
                self.reserved = max(0.0, self.reserved - cap)
            if actual_usd:
                self.usd += float(actual_usd)

    def exceeded(self) -> str | None:
        with self._lock:
            if self.max_usd is not None and self.usd >= self.max_usd:
                return f"batch spend ${self.usd:.2f} reached ceiling ${self.max_usd:.2f}"
            if self.max_tokens is not None and self.tokens >= self.max_tokens:
                return f"batch tokens {self.tokens} reached ceiling {int(self.max_tokens)}"
        return None


_ledger = Ledger()


def configure(max_usd: float | None = None, max_tokens: float | None = None,
              max_agent_usd: float | None = None) -> Ledger:
    """Reset the process-global ledger. CLI flags win over the environment."""
    global _ledger
    # Without a per-agent cap one launch could reserve the whole ceiling and
    # starve every parallel sibling, so require both.
    _ledger = Ledger(
        max_usd=max_usd if max_usd is not None else _env_float("VULN_PIPELINE_MAX_BATCH_USD"),
        max_tokens=(max_tokens if max_tokens is not None
                    else _env_float("VULN_PIPELINE_MAX_BATCH_TOKENS")),
        max_agent_usd=(max_agent_usd if max_agent_usd is not None
                       else _env_float("VULN_PIPELINE_MAX_AGENT_USD")),
    )
    if _ledger.max_usd is not None and _ledger.max_agent_usd is None:
        raise ValueError(
            "--max-batch-usd requires --max-agent-usd (or VULN_PIPELINE_MAX_AGENT_USD): "
            "dollar cost is only reported when a session ends, so live enforcement "
            "reserves a per-agent share of the ceiling")
    return _ledger


def ledger() -> Ledger:
    return _ledger
