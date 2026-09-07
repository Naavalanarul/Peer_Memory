"""Measure the BlockManager changes: lock striping and O(1) key removal.

Run:  python bench/bench_blocks.py [--concurrency 256] [--operations 20000]

Two comparisons:

1. stripe_count=1 (equivalent to the previous single global lock, same
   code path) vs the configured stripe count, under concurrent access.
2. free() cost as the number of keyed blocks grows. The previous
   implementation scanned and copied the whole key index on every free,
   so this curve used to be linear; entries now carry their own key, so
   it should be flat.

This is a single-threaded event loop, so striping removes lock queueing
and coupling -- not CPU serialisation. Expect a modest gain that grows
with concurrency, and reproduce it rather than trusting a quoted figure.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memnode import config                  # noqa: E402
from memnode.blocks import BlockManager, Durability     # noqa: E402


async def _worker(bm: BlockManager, ops: int, payload: bytes, tag: int) -> None:
    for i in range(ops):
        bid = await bm.store(payload, durability=Durability.CACHE, key=f"{tag}-{i}")
        await bm.load(bid)
        await bm.free(bid)


async def bench_stripes(stripe_count: int, concurrency: int, operations: int,
                        repeats: int = 3) -> float:
    payload = b"x" * 256
    per_worker = max(1, operations // concurrency)
    times = []
    for _ in range(repeats):
        bm = BlockManager(max_memory_bytes=1 << 30, stripe_count=stripe_count)
        t0 = time.perf_counter()
        await asyncio.gather(*[_worker(bm, per_worker, payload, w)
                               for w in range(concurrency)])
        times.append(time.perf_counter() - t0)
    return min(times)


async def bench_free_scaling(sizes: list[int]) -> list[tuple[int, float]]:
    out = []
    for n in sizes:
        bm = BlockManager(max_memory_bytes=1 << 30)
        ids = [await bm.store(b"y" * 64, key=f"key-{i}") for i in range(n)]
        samples = []
        for bid in ids[-200:]:
            t0 = time.perf_counter()
            await bm.free(bid)
            samples.append((time.perf_counter() - t0) * 1e6)
        out.append((n, statistics.median(samples)))
    return out


async def main(concurrency: int, operations: int) -> None:
    print(f"lock striping: concurrency={concurrency}, ~{operations} store+load+free cycles")
    print(f"{'stripes':>8} {'best of 3 (s)':>15} {'ops/s':>12}")
    baseline = None
    for stripes in (1, 4, config.BLOCK_STRIPE_COUNT, 64):
        elapsed = await bench_stripes(stripes, concurrency, operations)
        total_ops = (operations // concurrency) * concurrency * 3
        if baseline is None:
            baseline = elapsed
        print(f"{stripes:>8} {elapsed:>15.4f} {total_ops / elapsed:>12,.0f}")
    print()

    print("free() cost vs number of keyed blocks (median of 200 frees):")
    print(f"{'blocks':>10} {'microseconds':>14}")
    for n, us in await bench_free_scaling([1_000, 5_000, 20_000, 50_000]):
        print(f"{n:>10,} {us:>14.2f}")
    print("\nA flat column means removal is O(1); the previous implementation")
    print("scanned and copied the whole key index on every free.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--concurrency", type=int, default=256)
    ap.add_argument("--operations", type=int, default=20000)
    a = ap.parse_args()
    asyncio.run(main(a.concurrency, a.operations))
