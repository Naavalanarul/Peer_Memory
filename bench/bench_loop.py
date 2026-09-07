"""Measure the event-loop swap (stdlib asyncio vs uvloop) on the RPC path.

Run:  python bench/bench_loop.py

Runs the same request/response workload under both loops. uvloop helps
socket readiness and callback dispatch, not the crypto or the copying, so
the gain depends on how syscall-bound the workload is. If uvloop is not
installed, this prints a notice and exits 0 -- it is an optional
dependency by design.
"""
from __future__ import annotations

import asyncio
import json
import os
import statistics
import struct
import sys
import time

import msgpack

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memnode import config                     # noqa: E402
from memnode.blocks import BlockManager        # noqa: E402
from memnode.peers import PeerManager          # noqa: E402
from memnode.rpc import RpcServer              # noqa: E402
from memnode.security import NodeIdentity      # noqa: E402

PORT = 17998
ITERATIONS = 2000


async def workload() -> dict:
    rpc = RpcServer(BlockManager(max_memory_bytes=1 << 30),
                    PeerManager(NodeIdentity.generate(), "loopbench", 1 << 30))
    server = await asyncio.start_server(rpc._handle_client, "127.0.0.1", PORT)
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    writer.write(config.RPC_MSGPACK_MAGIC)
    await writer.drain()
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    await reader.readexactly(length)

    payload = os.urandom(4096)
    latencies = []
    for i in range(ITERATIONS):
        raw = msgpack.packb({"op": "store", "data": payload, "key": f"k{i}"},
                            use_bin_type=True)
        t0 = time.perf_counter()
        writer.write(struct.pack(">I", len(raw)) + raw)
        await writer.drain()
        length = struct.unpack(">I", await reader.readexactly(4))[0]
        await reader.readexactly(length)
        latencies.append((time.perf_counter() - t0) * 1000)

    writer.close()
    server.close()
    latencies.sort()
    return {"median_ms": statistics.median(latencies),
            "p95_ms": latencies[int(len(latencies) * 0.95)],
            "rps": ITERATIONS / (sum(latencies) / 1000)}


def run(use_uvloop: bool):
    if use_uvloop:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    else:
        asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    return asyncio.run(workload())


if __name__ == "__main__":
    try:
        import uvloop  # noqa: F401
    except ImportError:
        print("uvloop is not installed -- nothing to compare (pip install uvloop)")
        raise SystemExit(0)

    print(f"{ITERATIONS} binary store requests, 4 KiB payload\n")
    print(f"{'event loop':12} {'median ms':>10} {'p95 ms':>9} {'req/s':>10}")
    results = {}
    for name, flag in (("asyncio", False), ("uvloop", True)):
        run(flag)                       # warm up
        r = run(flag)
        results[name] = r
        print(f"{name:12} {r['median_ms']:10.4f} {r['p95_ms']:9.4f} {r['rps']:10,.0f}")
    speedup = results["asyncio"]["median_ms"] / results["uvloop"]["median_ms"]
    print(f"\nuvloop median latency: {speedup:.2f}x vs stdlib asyncio on this machine")
