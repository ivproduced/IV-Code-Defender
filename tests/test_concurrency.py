# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
import asyncio

from harness.cli import _gather_bounded


def test_gather_bounded_never_exceeds_limit():
    async def scenario():
        live = 0
        peak = 0
        gate = asyncio.Event()

        async def worker():
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            if peak == 2:
                gate.set()
            await gate.wait()
            await asyncio.sleep(0)
            live -= 1
            return True

        results = await _gather_bounded([worker() for _ in range(8)], 2)
        return peak, results

    peak, results = asyncio.run(scenario())
    assert peak == 2
    assert results == [True] * 8
