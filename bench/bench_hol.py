"""Quantify head-of-line blocking: chunking + round-robin vs one big frame.

Run:  python bench/bench_hol.py [--block-mb 16]

This measures the structural property directly -- how many bytes an
unrelated control message has to wait behind before it reaches the
socket -- rather than wall-clock time, so the result is exact and does
not vary with the machine. Convert to time by dividing by your link
throughput.

Baseline (pre-Phase-2): one block = one frame on one FIFO queue, so a
control message queued behind it waits for the entire block.
Now: the block is split into PEER_CHUNK_SIZE pieces on their own logical
stream, and mux.ChannelMux round-robins, so the control message waits
for at most one chunk.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memnode import config                       # noqa: E402
from memnode.mux import ChannelMux               # noqa: E402
from memnode.protocol import Message, MsgType    # noqa: E402


class _CountingChannel:
    def __init__(self):
        self.order: list[tuple[int, int]] = []    # (stream_id, payload bytes)

    async def send_msg(self, msg: Message) -> None:
        payload = msg.body.get("chunk") or b""
        self.order.append((msg.stream_id, len(payload)))


async def _flush(mux: ChannelMux, channel: _CountingChannel, expected: int) -> None:
    task = asyncio.create_task(mux._writer_loop())
    for _ in range(100_000):
        if len(channel.order) >= expected:
            break
        await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def measure(block_bytes: int, chunk_size: int) -> tuple[int, int]:
    """Return (bytes_ahead_of_control_msg, frames_ahead)."""
    channel = _CountingChannel()
    mux = ChannelMux(channel, max_queued=100_000)

    chunks = [chunk_size] * (block_bytes // chunk_size)
    if block_bytes % chunk_size:
        chunks.append(block_bytes % chunk_size)
    for i, size in enumerate(chunks):
        await mux.send(Message(MsgType.BLOCK_CHUNK,
                               {"stream_id": 1, "chunk": b"\0" * size, "seq": i}))
    await mux.send(Message(MsgType.PING, {"stream_id": config.CONTROL_STREAM_ID}))

    await _flush(mux, channel, len(chunks) + 1)
    mux.close()

    ahead_bytes = 0
    frames = 0
    for stream_id, size in channel.order:
        if stream_id == config.CONTROL_STREAM_ID:
            break
        ahead_bytes += size
        frames += 1
    return ahead_bytes, frames


async def main(block_mb: int) -> None:
    block_bytes = block_mb * 1024 * 1024

    # Baseline: the whole block is one frame on one stream (what a
    # pre-Phase-2 SecureChannel did), so nothing can be interleaved.
    print(f"block size: {block_mb} MiB, chunk size: {config.PEER_CHUNK_SIZE // 1024} KiB\n")
    print(f"{'configuration':38} {'bytes ahead of control msg':>28} {'frames':>8}")
    print(f"{'one frame, FIFO (before)':38} {block_bytes:>28,} {1:>8}")

    ahead, frames = await measure(block_bytes, config.PEER_CHUNK_SIZE)
    print(f"{'chunked + round-robin (after)':38} {ahead:>28,} {frames:>8}")
    print(f"\nreduction: {block_bytes / max(ahead, 1):,.0f}x fewer bytes of queueing delay")
    print("At 1 Gbit/s that is "
          f"{block_bytes * 8 / 1e9 * 1000:.0f} ms before vs {ahead * 8 / 1e9 * 1000:.2f} ms after.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--block-mb", type=int, default=16)
    a = ap.parse_args()
    asyncio.run(main(a.block_mb))
