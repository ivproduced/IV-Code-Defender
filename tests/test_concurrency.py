# Copyright 2026 IVProduced contributors
# SPDX-License-Identifier: Apache-2.0
import asyncio

from harness.cli import _PriorityCapacity, _gather_bounded


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


def test_ready_report_has_priority_over_queued_runs():
    async def scenario():
        capacity = _PriorityCapacity(1)
        first_started = asyncio.Event()
        release_first = asyncio.Event()
        order = []

        async def first_run():
            async with capacity.slot():
                first_started.set()
                await release_first.wait()
                order.append("first")

        async def queued_run():
            async with capacity.slot():
                order.append("queued-run")

        async def report():
            async with capacity.slot(priority=True):
                order.append("report")

        first = asyncio.create_task(first_run())
        await first_started.wait()
        queued = asyncio.create_task(queued_run())
        ready_report = asyncio.create_task(report())
        await asyncio.sleep(0)
        release_first.set()
        await asyncio.gather(first, queued, ready_report)
        return order

    assert asyncio.run(scenario()) == ["first", "report", "queued-run"]
