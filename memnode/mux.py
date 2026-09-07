"""Connection multiplexing for the peer protocol.

Problem
-------
One ``SecureChannel`` per peer carried every message in strict FIFO
order. A single large transfer therefore blocked everything behind it:
if node A was pulling a 40 MB block from node B, a 200-byte ``Ping`` or
an unrelated ``RequestBlock`` queued behind it waited for the whole
transfer to finish. That is head-of-line blocking, and it is the reason
tail latency on a busy node was dominated by whatever the largest
concurrent transfer happened to be.

Solution
--------
Two co-operating pieces, both in this module:

1. **Logical streams.** Every message carries ``body["stream_id"]``.
   Stream 0 is the control stream (small requests, replies, pings);
   each large transfer gets its own id.
2. **Round-robin writer.** Outbound messages go into a per-stream queue.
   A single writer task takes one message from each non-empty stream in
   rotation. A transfer chunked into 160 pieces therefore yields the
   connection between every piece, and an unrelated message waits at
   most one chunk (256 KB) rather than one whole block.

Chunking (``replication.py``) and multiplexing are complementary: the
chunking decides how finely a transfer can be interleaved, the
multiplexer decides that it *is* interleaved fairly. Neither alone
fixes head-of-line blocking.

Backpressure
------------
A bounded semaphore caps how many messages may sit queued for one
connection. ``send()`` waits when the cap is reached, so a producer that
outruns the socket is slowed instead of growing an unbounded queue in
memory -- the same class of unbounded-allocation bug the framing code
already guards against, just on the outbound side.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Awaitable, Callable, Optional

from . import config
from .protocol import Message

logger = logging.getLogger("memnode.mux")

MessageHandler = Callable[[Message], Awaitable[None]]


class ChannelMux:
    """Fair-scheduled multiplexer over a single SecureChannel."""

    def __init__(self, channel, on_message: Optional[MessageHandler] = None,
                 max_queued: int = config.MUX_MAX_QUEUED_MESSAGES,
                 label: str = ""):
        self.channel = channel
        self.on_message = on_message
        self.label = label
        self._queues: dict[int, deque[Message]] = {}
        self._order: deque[int] = deque()
        self._wake = asyncio.Event()
        self._slots = asyncio.Semaphore(max_queued)
        self._closed = False
        self._writer_task: Optional[asyncio.Task] = None
        self.messages_sent = 0
        self.messages_received = 0
        self.max_queue_depth = 0

    # -- sending ---------------------------------------------------------

    async def send(self, msg: Message, stream_id: Optional[int] = None) -> None:
        """Queue a message for its stream, waiting if the connection is saturated."""
        if self._closed:
            raise ConnectionError("channel multiplexer is closed")
        if stream_id is None:
            stream_id = msg.stream_id
        await self._slots.acquire()          # backpressure
        queue = self._queues.get(stream_id)
        if queue is None:
            queue = deque()
            self._queues[stream_id] = queue
            self._order.append(stream_id)
        queue.append(msg)
        depth = sum(len(q) for q in self._queues.values())
        self.max_queue_depth = max(self.max_queue_depth, depth)
        self._wake.set()

    async def _writer_loop(self) -> None:
        try:
            while not self._closed:
                if not self._order:
                    self._wake.clear()
                    await self._wake.wait()
                    continue

                stream_id = self._order.popleft()
                queue = self._queues.get(stream_id)
                if not queue:
                    self._queues.pop(stream_id, None)
                    continue

                msg = queue.popleft()
                if queue:
                    # Re-queue at the BACK: this is what makes the
                    # schedule round-robin instead of first-come.
                    self._order.append(stream_id)
                else:
                    self._queues.pop(stream_id, None)

                try:
                    await self.channel.send_msg(msg)
                    self.messages_sent += 1
                finally:
                    self._slots.release()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.info("mux writer for %s stopped: %s", self.label or "peer", e)
            self._closed = True

    # -- receiving -------------------------------------------------------

    async def run(self) -> None:
        """Read from the channel until it closes, dispatching each message.

        Starts (and always cleans up) the writer task.
        """
        self._writer_task = asyncio.create_task(self._writer_loop())
        try:
            while True:
                msg = await self.channel.recv_msg()
                self.messages_received += 1
                if self.on_message is None:
                    logger.debug("message on stream %s: %s", msg.stream_id, msg.type)
                    continue
                try:
                    await self.on_message(msg)
                except Exception:
                    # One bad message must not kill the connection.
                    logger.exception("message handler raised for %s -- continuing", msg.type)
        finally:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._wake.set()
        if self._writer_task is not None and not self._writer_task.done():
            self._writer_task.cancel()

    def stats(self) -> dict:
        return {
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "open_streams": len(self._queues),
            "max_queue_depth": self.max_queue_depth,
            "closed": self._closed,
        }
