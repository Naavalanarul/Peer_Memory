"""Phase 2: chunked, multiplexed block transfer between nodes.

Two coordinators are wired back to back through an in-process router
that preserves per-direction ordering, which is what the real
SecureChannel + ChannelMux pair gives us. That is enough to exercise the
streaming path end to end without sockets or crypto.
"""
import asyncio

import pytest

from memnode import config
from memnode.blocks import BlockManager, Durability
from memnode.protocol import Message, MsgType
from memnode.replication import (
    RemoteOperationFailed,
    ReplicationCoordinator,
    extract_payload,
)

KEY_A = "aa" * 4
KEY_B = "bb" * 4


class _Node:
    """A BlockManager + coordinator pair with a fake peer_manager."""

    def __init__(self, name: str, quota: int, chunk_size: int, chunk_threshold: int):
        self.name = name
        self.blocks = BlockManager(max_memory_bytes=quota)
        self.peer_manager = _FakePeerManager(self)
        self.coordinator = ReplicationCoordinator(
            self.blocks, self.peer_manager,
            chunk_size=chunk_size, chunk_threshold=chunk_threshold)
        self.link: "_Link | None" = None


class _FakePeerManager:
    def __init__(self, node: "_Node"):
        self.node = node
        self.peers: dict[str, object] = {}
        self._lock = asyncio.Lock()
        self.frames_sent = 0
        self.stream_ids: list[int] = []

    async def send_to(self, pubkey_hex, msg, stream_id=None) -> bool:
        link = self.node.link
        if link is None:
            return False
        self.frames_sent += 1
        self.stream_ids.append(stream_id if stream_id is not None else msg.stream_id)
        return await link.deliver(self.node, msg)


class _Link:
    """Ordered in-process delivery between two nodes."""

    def __init__(self, a: _Node, b: _Node):
        self.a, self.b = a, b
        a.link = self
        b.link = self
        a.peer_manager.peers[KEY_B] = object()
        b.peer_manager.peers[KEY_A] = object()
        self._queues = {a: asyncio.Queue(), b: asyncio.Queue()}
        self._tasks = [asyncio.create_task(self._pump(a)), asyncio.create_task(self._pump(b))]

    def _other(self, node: _Node) -> _Node:
        return self.b if node is self.a else self.a

    def _key_of(self, node: _Node) -> str:
        return KEY_A if node is self.a else KEY_B

    async def deliver(self, sender: _Node, msg: Message) -> bool:
        await self._queues[sender].put(msg)
        return True

    async def _pump(self, sender: _Node) -> None:
        queue = self._queues[sender]
        target = self._other(sender)
        sender_key = self._key_of(sender)
        while True:
            msg = await queue.get()
            await target.coordinator.handle_message(sender_key, msg)

    def close(self) -> None:
        for t in self._tasks:
            t.cancel()


@pytest.fixture
async def pair():
    a = _Node("a", 64 * 1024 * 1024, chunk_size=4096, chunk_threshold=8192)
    b = _Node("b", 64 * 1024 * 1024, chunk_size=4096, chunk_threshold=8192)
    link = _Link(a, b)
    yield a, b
    link.close()


# -- payload encoding -------------------------------------------------------

def test_extract_payload_prefers_binary():
    assert extract_payload({"data": b"xyz"}, "data") == b"xyz"


def test_extract_payload_accepts_legacy_hex():
    """An un-upgraded peer sending data_hex must still be understood."""
    assert extract_payload({"data_hex": "616263"}, "data") == b"abc"


def test_extract_payload_missing_is_none():
    assert extract_payload({}, "data") is None
    assert extract_payload({"data_hex": "not-hex"}, "data") is None


# -- small (single-frame) path ---------------------------------------------

@pytest.mark.asyncio
async def test_small_store_and_load_roundtrip(pair):
    a, b = pair
    block_id = await a.coordinator.store_remote(KEY_B, b"small payload", key="k1")
    assert await b.blocks.load(block_id) == b"small payload"

    got = await a.coordinator.load_remote(KEY_B, key="k1")
    assert got == b"small payload"


@pytest.mark.asyncio
async def test_small_transfer_uses_one_frame(pair):
    a, b = pair
    a.peer_manager.frames_sent = 0
    await a.coordinator.store_remote(KEY_B, b"tiny")
    assert a.peer_manager.frames_sent == 1, "a small block must not be chunked"


# -- chunked path -----------------------------------------------------------

@pytest.mark.asyncio
async def test_large_store_is_chunked_and_reassembles_exactly(pair):
    a, b = pair
    payload = bytes(range(256)) * 400          # 102_400 bytes, well over threshold
    a.peer_manager.frames_sent = 0

    block_id = await a.coordinator.store_remote(KEY_B, payload, key="big",
                                                durability=Durability.PINNED)

    stored = await b.blocks.load(block_id)
    assert stored == payload
    assert len(stored) == len(payload)
    # 1 header + ceil(102400/4096) = 1 + 25 frames
    assert a.peer_manager.frames_sent == 26, a.peer_manager.frames_sent


@pytest.mark.asyncio
async def test_chunked_transfer_uses_a_dedicated_stream(pair):
    a, b = pair
    a.peer_manager.stream_ids.clear()
    await a.coordinator.store_remote(KEY_B, b"x" * 40000)
    used = set(a.peer_manager.stream_ids)
    assert used != {config.CONTROL_STREAM_ID}, "a transfer must not run on the control stream"
    assert len(used) == 1, "one transfer should occupy exactly one stream"


@pytest.mark.asyncio
async def test_large_load_is_chunked_and_reassembles_exactly(pair):
    a, b = pair
    payload = bytes(range(256)) * 300
    await b.blocks.store(payload, durability=Durability.PINNED, key="pull-me")

    got = await a.coordinator.load_remote(KEY_B, key="pull-me")
    assert got == payload


@pytest.mark.asyncio
async def test_exceeding_the_block_cap_is_refused_before_transfer(pair):
    """The receiver must reject an oversized declaration up front instead
    of buffering chunks until it runs out of memory."""
    a, b = pair
    msg = Message(MsgType.STORE_BLOCK, {
        "req_id": "deadbeef", "chunked": True,
        "total_size": config.MAX_BLOCK_SIZE + 1, "stream_id": 9})
    await b.coordinator.handle_message(KEY_A, msg)
    assert b.coordinator.stats()["active_transfers"] == 0


@pytest.mark.asyncio
async def test_chunk_overrun_is_aborted(pair):
    """A sender that declares 100 bytes and then sends more must be cut
    off, not allowed to grow the reassembly buffer."""
    a, b = pair
    await b.coordinator.handle_message(KEY_A, Message(MsgType.STORE_BLOCK, {
        "req_id": "r1", "chunked": True, "total_size": 100, "stream_id": 3}))
    assert b.coordinator.stats()["active_transfers"] == 1

    await b.coordinator.handle_message(KEY_A, Message(MsgType.BLOCK_CHUNK, {
        "req_id": "r1", "chunk": b"x" * 500, "final": False}))
    assert b.coordinator.stats()["active_transfers"] == 0


@pytest.mark.asyncio
async def test_concurrent_inbound_transfers_are_capped(pair):
    a, b = pair
    for i in range(config.MAX_INBOUND_STREAMS + 5):
        await b.coordinator.handle_message(KEY_A, Message(MsgType.STORE_BLOCK, {
            "req_id": f"r{i}", "chunked": True, "total_size": 1000, "stream_id": i}))
    assert b.coordinator.stats()["active_transfers"] <= config.MAX_INBOUND_STREAMS


@pytest.mark.asyncio
async def test_chunk_for_unknown_transfer_is_ignored(pair):
    a, b = pair
    await b.coordinator.handle_message(KEY_A, Message(MsgType.BLOCK_CHUNK, {
        "req_id": "never-opened", "chunk": b"x", "final": True}))
    assert b.coordinator.stats()["active_transfers"] == 0


@pytest.mark.asyncio
async def test_stream_abort_releases_the_buffer(pair):
    a, b = pair
    await b.coordinator.handle_message(KEY_A, Message(MsgType.STORE_BLOCK, {
        "req_id": "r9", "chunked": True, "total_size": 1000, "stream_id": 2}))
    await b.coordinator.handle_message(KEY_A, Message(MsgType.STREAM_ABORT, {"req_id": "r9"}))
    assert b.coordinator.stats()["active_transfers"] == 0


# -- unchanged behaviour ----------------------------------------------------

@pytest.mark.asyncio
async def test_missing_key_returns_none(pair):
    a, b = pair
    assert await a.coordinator.load_remote(KEY_B, key="nope") is None


@pytest.mark.asyncio
async def test_free_remote_still_works(pair):
    a, b = pair
    block_id = await a.coordinator.store_remote(KEY_B, b"transient", key="tmp")
    assert await a.coordinator.free_remote(KEY_B, block_id) is True
    assert await b.blocks.load(block_id) is None


@pytest.mark.asyncio
async def test_store_on_a_full_peer_reports_out_of_memory(pair):
    a, b = pair
    b.blocks.max_memory_bytes = 16
    with pytest.raises(Exception):
        await a.coordinator.store_remote(KEY_B, b"y" * 40000, timeout=5)


@pytest.mark.asyncio
async def test_disconnected_peer_fails_fast(pair):
    a, b = pair
    a.link = None
    with pytest.raises(RemoteOperationFailed):
        await a.coordinator.store_remote("cc" * 4, b"data", timeout=1)
