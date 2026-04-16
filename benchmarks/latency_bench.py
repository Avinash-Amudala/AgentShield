"""Benchmark policy engine latency. Run: python benchmarks/latency_bench.py"""

from __future__ import annotations

import asyncio
import os
import statistics
import sys
import time

from agentshield import Shield, ToolCallContext


async def bench() -> None:
    """Run a latency micro-benchmark against the default Shield."""
    shield = Shield(rules=None, log_file=None)
    context = ToolCallContext(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM users WHERE id = 1"},
    )

    for _ in range(100):
        await shield.check(context)

    latencies: list[float] = []
    for _ in range(10_000):
        start = time.perf_counter_ns()
        await shield.check(context)
        latencies.append((time.perf_counter_ns() - start) / 1_000_000)

    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    print(f"Samples:  {len(latencies)}")
    print(f"p50:      {p50:.3f} ms")
    print(f"p95:      {p95:.3f} ms")
    print(f"p99:      {p99:.3f} ms")
    print(f"Mean:     {statistics.mean(latencies):.3f} ms")
    print(f"Std:      {statistics.stdev(latencies):.3f} ms")

    is_ci = os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"
    threshold = 5.0 if is_ci else 1.0

    if p99 >= threshold:
        msg = f"p99 latency {p99:.3f}ms exceeded {threshold:.1f}ms target"
        if is_ci:
            print(f"\nWARNING: {msg} (CI runner — non-fatal)")
        else:
            print(f"\nFAIL: {msg}")
            sys.exit(1)
    else:
        print(f"\nAll performance targets met (p99 < {threshold:.1f}ms)")


if __name__ == "__main__":
    asyncio.run(bench())
