"""Phase 2: connection multiplexing.

The property under test is fairness: a long transfer on one logical
stream must not delay messages on another, which is what caused tail
latency to track the size of the largest concurrent transfer.
"""
import asyncio

import pytest

from memnode.mux import ChannelMux
from memnode.protocol import Message, MsgType


class _RecordingChannel:
    """Stands in for a SecureChannel, recording send order."""

    def __init__(self, inbound=None, send_delay: float = 0.0):
        self.sent: list[Message] = []
        self.send_delay = send_delay
        self._inbound = asyncio.Queue()
        for msg in inbound or []:
            self._inbound.put_nowait(msg)
        self._closed = False

    async def send_msg(self, msg: Message) -> None:
        if self.send_delay:
            await asyncio.sleep(self.send_delay)
        self.sent.append(msg)

    async def recv_msg(self) -> Message:
        msg = await self._inbound.get()
        if msg is None:
            raise ConnectionError("channel closed")
        return msg

    def feed(self, msg) -> None:
        self._inbound.put_nowait(msg)

    def close(self) -> None:
        self._closed = True


def _msg(stream_id: int, tag: str) -> Message:
    return Message(MsgType.BLOCK_CHUNK, {"stream_id": stream_id, "tag": tag})


async def _drain(mux: ChannelMux, channel: _RecordingChannel, expected: int) -> None:
    task = asyncio.create_task(mux._writer_loop())
    for _ in range(200):
        if len(channel.sent) >= expected:
            break
        await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_writer_round_robins_between_streams():
    """A 6-chunk transfer on stream 1 must not push stream 2 to the back."""
    channel = _RecordingChannel()
    mux = ChannelMux(channel)

    for i in range(6):
        await mux.send(_msg(1, f"big-{i}"))
    await mux.send(_msg(2, "small-0"))
    await mux.send(_msg(2, "small-1"))

    await _drain(mux, channel, 8)

    order = [m.body["tag"] for m in channel.sent]
    # Interleaved, not "all of stream 1, then stream 2".
    assert order[:4] == ["big-0", "small-0", "big-1", "small-1"], order
    assert len(order) == 8


@pytest.mark.asyncio
async def test_small_message_behind_a_large_transfer_is_not_starved():
    channel = _RecordingChannel()
    mux = ChannelMux(channel)

    for i in range(50):
        await mux.send(_msg(7, f"chunk-{i}"))
    await mux.send(_msg(0, "ping"))

    await _drain(mux, channel, 51)

    position = [m.body["tag"] for m in channel.sent].index("ping")
    # FIFO would put it at index 50. Round-robin puts it second.
    assert position <= 2, f"control message waited behind {position} chunks"


@pytest.mark.asyncio
async def test_single_stream_preserves_order():
    channel = _RecordingChannel()
    mux = ChannelMux(channel)
    for i in range(10):
        await mux.send(_msg(3, str(i)))
    await _drain(mux, channel, 10)
    assert [m.body["tag"] for m in channel.sent] == [str(i) for i in range(10)]


@pytest.mark.asyncio
async def test_stream_id_defaults_to_the_message_body():
    channel = _RecordingChannel()
    mux = ChannelMux(channel)
    await mux.send(Message(MsgType.PING, {}))            # no stream_id -> 0
    await mux.send(_msg(5, "x"))
    await _drain(mux, channel, 2)
    assert len(channel.sent) == 2


@pytest.mark.asyncio
async def test_backpressure_blocks_a_runaway_producer():
    """Queueing must be bounded: an unbounded outbound queue is the same
    unbounded-allocation bug the framing code guards against."""
    channel = _RecordingChannel()
    mux = ChannelMux(channel, max_queued=4)
    for i in range(4):
        await mux.send(_msg(1, str(i)))

    blocked = asyncio.create_task(mux.send(_msg(1, "overflow")))
    await asyncio.sleep(0)
    assert not blocked.done(), "5th send should have blocked on the semaphore"

    await _drain(mux, channel, 4)
    await asyncio.wait_for(blocked, timeout=1)
    mux.close()


@pytest.mark.asyncio
async def test_send_after_close_raises():
    mux = ChannelMux(_RecordingChannel())
    mux.close()
    with pytest.raises(ConnectionError):
        await mux.send(_msg(1, "x"))


@pytest.mark.asyncio
async def test_run_dispatches_inbound_messages():
    received = []

    async def handler(msg):
        received.append(msg.body["tag"])

    channel = _RecordingChannel(inbound=[_msg(1, "a"), _msg(2, "b"), None])
    mux = ChannelMux(channel, on_message=handler)
    with pytest.raises(ConnectionError):
        await mux.run()
    assert received == ["a", "b"]


@pytest.mark.asyncio
async def test_handler_exception_does_not_kill_the_connection():
    seen = []

    async def handler(msg):
        seen.append(msg.body["tag"])
        if msg.body["tag"] == "bad":
            raise RuntimeError("boom")

    channel = _RecordingChannel(inbound=[_msg(1, "bad"), _msg(1, "good"), None])
    mux = ChannelMux(channel, on_message=handler)
    with pytest.raises(ConnectionError):
        await mux.run()
    assert seen == ["bad", "good"], "one bad message must not drop the peer"


@pytest.mark.asyncio
async def test_stats_report_traffic():
    channel = _RecordingChannel()
    mux = ChannelMux(channel)
    await mux.send(_msg(1, "a"))
    await _drain(mux, channel, 1)
    stats = mux.stats()
    assert stats["messages_sent"] == 1
    assert stats["max_queue_depth"] >= 1
