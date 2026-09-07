"""Measure the RPC codec change: hex+JSON vs msgpack binary framing.

Run:  python bench/bench_rpc.py [--payload-kb 64] [--iterations 300]

Reports wire bytes and wall-clock latency for the same store/load
workload over both codecs against a real loopback RpcServer. Numbers are
machine-specific -- reproduce them rather than trusting a quoted figure.
"""
from __future__ import annotations

import argparse
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

PORT = 17999


async def _rt(reader, writer, raw: bytes, binary: bool) -> dict:
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    body = await reader.readexactly(length)
    return msgpack.unpackb(body, raw=False) if binary else json.loads(body.decode())


async def run_codec(binary: bool, payload: bytes, iterations: int) -> dict:
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    if binary:
        writer.write(config.RPC_MSGPACK_MAGIC)
        await writer.drain()
        length = struct.unpack(">I", await reader.readexactly(4))[0]
        await reader.readexactly(length)

    latencies = []
    wire_bytes = 0
    for i in range(iterations):
        if binary:
            req = msgpack.packb({"op": "store", "data": payload, "key": f"k{i}"},
                                use_bin_type=True)
        else:
            req = json.dumps({"op": "store", "data_hex": payload.hex(),
                              "key": f"k{i}"}).encode()
        wire_bytes += len(req)
        t0 = time.perf_counter()
        resp = await _rt(reader, writer, req, binary)
        latencies.append((time.perf_counter() - t0) * 1000)
        assert resp["ok"], resp

    for i in range(iterations):
        if binary:
            req = msgpack.packb({"op": "load", "key": f"k{i}"}, use_bin_type=True)
        else:
            req = json.dumps({"op": "load", "key": f"k{i}"}).encode()
        t0 = time.perf_counter()
        resp = await _rt(reader, writer, req, binary)
        latencies.append((time.perf_counter() - t0) * 1000)
        assert resp["ok"], resp

    writer.close()
    latencies.sort()
    return {
        "codec": "msgpack" if binary else "hex+json",
        "request_bytes": wire_bytes,
        "median_ms": statistics.median(latencies),
        "p95_ms": latencies[int(len(latencies) * 0.95)],
        "total_s": sum(latencies) / 1000,
    }


async def main(payload_kb: int, iterations: int) -> None:
    payload = os.urandom(payload_kb * 1024)
    rpc = RpcServer(BlockManager(max_memory_bytes=512 * 1024 * 1024),
                    PeerManager(NodeIdentity.generate(), "bench", 1 << 30))
    server = await asyncio.start_server(rpc._handle_client, "127.0.0.1", PORT)

    results = []
    for binary in (False, True):
        await run_codec(binary, payload, 20)          # warm up
        results.append(await run_codec(binary, payload, iterations))

    print(f"payload={payload_kb} KiB  iterations={iterations} (store+load each)")
    print(f"{'codec':10} {'req bytes':>12} {'median ms':>10} {'p95 ms':>9} {'total s':>9}")
    for r in results:
        print(f"{r['codec']:10} {r['request_bytes']:12,} {r['median_ms']:10.3f} "
              f"{r['p95_ms']:9.3f} {r['total_s']:9.3f}")

    a, b = results
    print(f"\nwire bytes: {a['request_bytes'] / b['request_bytes']:.2f}x smaller with msgpack")
    print(f"median latency: {a['median_ms'] / b['median_ms']:.2f}x faster with msgpack")
    server.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload-kb", type=int, default=64)
    ap.add_argument("--iterations", type=int, default=300)
    a = ap.parse_args()
    asyncio.run(main(a.payload_kb, a.iterations))
