"""Benchmark policy engine latency. Run: python benchmarks/latency_bench.py"""

from __future__ import annotations

import asyncio
import statistics
import time

from agentshield import Shield, ToolCallContext


async def bench() -> None:
    """Run a latency micro-benchmark against the default Shield."""
    shield = Shield()
    context = ToolCallContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM users WHERE id = 1"},
    )

    # Warmup
    for _ in range(100):
        await shield.check(context)

    # Benchmark
    latencies: list[float] = []
    for _ in range(10_000):
        start = time.perf_counter_ns()
        await shield.check(context)
        latencies.append((time.perf_counter_ns() - start) / 1_000_000)

    latencies.sort()
    print(f"Samples:  {len(latencies)}")
    print(f"p50:      {latencies[len(latencies) // 2]:.3f} ms")
    print(f"p95:      {latencies[int(len(latencies) * 0.95)]:.3f} ms")
    print(f"p99:      {latencies[int(len(latencies) * 0.99)]:.3f} ms")
    print(f"Mean:     {statistics.mean(latencies):.3f} ms")
    print(f"Std:      {statistics.stdev(latencies):.3f} ms")

    assert (
        latencies[int(len(latencies) * 0.99)] < 1.0
    ), "p99 latency exceeded 1ms target!"
    print("\nAll performance targets met!")


if __name__ == "__main__":
    asyncio.run(bench())
