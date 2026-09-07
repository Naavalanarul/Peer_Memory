"""Peer-to-peer block replication -- the piece that actually makes this
a *distributed* RAM pool instead of N independent single-node caches.

Why this module exists
-----------------------
protocol.py defines the wire message types (StoreBlock / RequestBlock /
BlockData / BlockNotFound / Nack); peers.py has the plumbing to pick a
peer with free capacity (`best_peer_for_store`) and to send it a message
(`send_to`). This module is the handler that turns an inbound
StoreBlock/RequestBlock into a BlockManager call, and turns "peer X has
room" into "ask peer X to store this and wait for the reply".

Correlation
-----------
Every outbound request carries a ``req_id`` (uuid4 hex).
``handle_message`` runs for every message from every peer and first
checks whether ``req_id`` matches a pending local request:
  - yes -> it is a *reply*; resolve the waiting Future.
  - no  -> it is an *inbound request*; serve it and reply.

Keying on a random UUID (rather than correlating by message order) means
concurrent requests to multiple peers -- or several in flight to the same
peer -- never get confused, and a slow peer cannot block a fast one.

Phase 2 changes
---------------
**Binary payloads.** Blocks used to travel as ``data_hex``: a hex string
inside a msgpack map. That doubled every payload on the wire and cost a
full ``.hex()`` on the sender plus ``bytes.fromhex()`` on the receiver.
Payloads now travel as msgpack ``bin`` under ``data`` / ``chunk``.
``extract_payload`` still accepts ``data_hex`` on receive, so a node
running the old format is understood rather than dropped.

**Chunked transfers.** A block above ``PEER_CHUNK_THRESHOLD`` is split
into ``PEER_CHUNK_SIZE`` pieces, each its own frame, all on a dedicated
logical stream. Combined with the round-robin writer in ``mux.py``, an
unrelated request now waits at most one chunk instead of one entire
block. It also removes a hard ceiling: a single frame was capped by
``MAX_FRAME_SIZE`` (16 MB), so a 40 MB block could not be transferred at
all in one frame.

**Bounded reassembly.** An inbound transfer declares its total size up
front; it is refused if that exceeds ``MAX_BLOCK_SIZE``, aborted if the
chunks overrun the declaration, capped in count by ``MAX_INBOUND_STREAMS``,
and garbage-collected after ``INBOUND_STREAM_TIMEOUT``. A half-finished
transfer that is never completed must not pin memory forever.
"""
from __future__ import annotations

import asyncio
import itertools
import logging
import time
import uuid
from typing import Optional

from . import config
from .blocks import BlockManager, BlockTooLarge, Durability, OutOfMemory
from .protocol import Message, MsgType

logger = logging.getLogger("memnode.replication")
DEFAULT_TIMEOUT = 30.0


class RemoteOperationFailed(Exception):
    pass


def extract_payload(body: dict, *keys: str) -> Optional[bytes]:
    """Read a payload from a message body in either wire format.

    Prefers the binary field; falls back to the legacy hex field so a
    peer that has not been upgraded still interoperates.
    """
    for key in keys or ("data", "chunk"):
        value = body.get(key)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        hex_value = body.get(f"{key}_hex")
        if isinstance(hex_value, str):
            try:
                return bytes.fromhex(hex_value)
            except ValueError:
                return None
    return None


class _ChunkBuffer:
    """Reassembly state for one chunked transfer.

    ``mode`` is "store" for an inbound push we will hand to the local
    BlockManager, or "pull" for a reply we requested and are waiting on.
    """

    __slots__ = ("mode", "total_size", "parts", "received", "meta", "future",
                 "started_at", "peer")

    def __init__(self, mode: str, total_size: int, peer: str,
                 meta: Optional[dict] = None,
                 future: Optional[asyncio.Future] = None):
        self.mode = mode
        self.total_size = total_size
        self.parts: list[bytes] = []
        self.received = 0
        self.meta = meta or {}
        self.future = future
        self.started_at = time.monotonic()
        self.peer = peer

    def add(self, chunk: bytes) -> None:
        self.received += len(chunk)
        self.parts.append(chunk)

    @property
    def overrun(self) -> bool:
        return self.received > self.total_size

    def assemble(self) -> bytes:
        return b"".join(self.parts)


class ReplicationCoordinator:
    """Bridges PeerManager <-> BlockManager so blocks can live on any
    node in the cluster, not just the one an RPC client happens to be
    talking to."""

    def __init__(self, block_manager: BlockManager, peer_manager,
                 chunk_size: int = config.PEER_CHUNK_SIZE,
                 chunk_threshold: int = config.PEER_CHUNK_THRESHOLD):
        self.block_manager = block_manager
        self.peer_manager = peer_manager
        self.chunk_size = chunk_size
        self.chunk_threshold = chunk_threshold
        self._pending: dict[str, asyncio.Future] = {}
        self._buffers: dict[str, _ChunkBuffer] = {}
        # Completion futures for transfers we are pulling. Kept separately
        # from _buffers because the reassembly buffer is discarded the
        # moment the last chunk lands, which can happen before the
        # requesting coroutine is rescheduled -- looking the future up in
        # _buffers afterwards would find nothing.
        self._pull_futures: dict[str, asyncio.Future] = {}
        # Stream 0 is reserved for control traffic; transfers start at 1.
        self._stream_ids = itertools.count(1)

    def _next_stream(self) -> int:
        return next(self._stream_ids)

    # -- wire this in as PeerManager's message_handler -------------------

    async def handle_message(self, pubkey_hex: str, msg: Message) -> None:
        req_id = msg.body.get("req_id")

        # Chunks are matched against a reassembly buffer, not the pending
        # request table -- the request Future was already resolved by the
        # header message that opened the transfer.
        if msg.type == MsgType.BLOCK_CHUNK:
            await self._handle_chunk(pubkey_hex, msg)
            return

        if msg.type == MsgType.STREAM_ABORT:
            self._abort_buffer(req_id, msg.body.get("error", "peer aborted the transfer"))
            return

        # Case 1: this is the answer to a request *we* sent earlier.
        if req_id is not None and req_id in self._pending:
            if msg.type == MsgType.BLOCK_DATA and msg.body.get("chunked"):
                # Register the collector BEFORE resolving the waiter, so a
                # chunk arriving immediately after the header has somewhere
                # to land. handle_message is called sequentially per peer,
                # so this ordering is sufficient.
                self._open_pull_buffer(pubkey_hex, req_id, msg.body.get("total_size", 0))
            fut = self._pending.pop(req_id)
            if not fut.done():
                fut.set_result(msg)
            return

        # Case 2: this is a fresh request from a peer -- serve it locally.
        if msg.type == MsgType.STORE_BLOCK:
            await self._serve_store_block(pubkey_hex, msg)
        elif msg.type == MsgType.REQUEST_BLOCK:
            await self._serve_request_block(pubkey_hex, msg)
        elif msg.type == MsgType.FREE_BLOCK:
            await self._serve_free_block(pubkey_hex, msg)
        elif msg.type == MsgType.PING:
            await self.peer_manager.send_to(pubkey_hex, Message(MsgType.PONG, {"req_id": req_id}))
        elif msg.type in (MsgType.BLOCK_DATA, MsgType.BLOCK_NOT_FOUND, MsgType.NACK,
                          MsgType.PONG, MsgType.FREED):
            # A reply that arrived after we already timed out and stopped
            # waiting for it. Not an error -- log and drop it.
            logger.debug("dropping stale/unmatched reply %s from %s", msg.type, pubkey_hex[:8])
        else:
            logger.debug("unhandled message type %s from %s", msg.type, pubkey_hex[:8])

    # -- chunk plumbing ---------------------------------------------------

    def _gc_buffers(self) -> None:
        """Drop transfers that stalled, so they cannot pin memory forever."""
        now = time.monotonic()
        stale = [rid for rid, buf in self._buffers.items()
                 if now - buf.started_at > config.INBOUND_STREAM_TIMEOUT]
        for rid in stale:
            buf = self._buffers.pop(rid, None)
            logger.warning("abandoning stalled transfer %s (%d/%d bytes)",
                           rid[:8], buf.received if buf else 0, buf.total_size if buf else 0)
            if buf and buf.future is not None and not buf.future.done():
                buf.future.set_exception(RemoteOperationFailed("transfer stalled"))

    def _open_pull_buffer(self, pubkey_hex: str, req_id: str, total_size: int) -> None:
        self._gc_buffers()
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._buffers[req_id] = _ChunkBuffer("pull", total_size, pubkey_hex, future=future)
        self._pull_futures[req_id] = future

    def _abort_buffer(self, req_id: Optional[str], reason: str) -> None:
        if req_id is None:
            return
        buf = self._buffers.pop(req_id, None)
        if buf is None:
            return
        logger.info("transfer %s aborted: %s", req_id[:8], reason)
        if buf.future is not None and not buf.future.done():
            buf.future.set_exception(RemoteOperationFailed(reason))

    async def _handle_chunk(self, pubkey_hex: str, msg: Message) -> None:
        req_id = msg.body.get("req_id")
        buf = self._buffers.get(req_id) if req_id else None
        if buf is None:
            logger.debug("chunk for unknown transfer %s from %s", req_id, pubkey_hex[:8])
            return

        chunk = extract_payload(msg.body, "chunk")
        if chunk is None:
            self._abort_buffer(req_id, "malformed chunk")
            return

        buf.add(chunk)
        if buf.overrun:
            # The sender declared a size and then exceeded it. Refuse
            # rather than growing the buffer to whatever they send.
            self._buffers.pop(req_id, None)
            logger.warning("transfer %s from %s overran its declared size (%d > %d)",
                           req_id[:8], pubkey_hex[:8], buf.received, buf.total_size)
            if buf.mode == "store":
                await self.peer_manager.send_to(pubkey_hex, Message(
                    MsgType.NACK, {"req_id": req_id, "error": "chunk overrun"}))
            elif buf.future is not None and not buf.future.done():
                buf.future.set_exception(RemoteOperationFailed("peer overran declared size"))
            return

        if not msg.body.get("final"):
            return

        self._buffers.pop(req_id, None)
        data = buf.assemble()

        if buf.mode == "pull":
            if buf.future is not None and not buf.future.done():
                buf.future.set_result(data)
            return

        # mode == "store": the transfer was an inbound push; commit it.
        try:
            block_id = await self.block_manager.store(
                data,
                durability=Durability(buf.meta.get("durability", Durability.CACHE.value)),
                key=buf.meta.get("key"))
        except (BlockTooLarge, OutOfMemory) as e:
            logger.info("chunked store from %s rejected: %s", pubkey_hex[:8], e)
            await self.peer_manager.send_to(pubkey_hex, Message(
                MsgType.NACK, {"req_id": req_id, "error": str(e)}))
            return
        await self.peer_manager.send_to(pubkey_hex, Message(
            MsgType.BLOCK_DATA, {"req_id": req_id, "block_id": block_id}))

    async def _send_chunks(self, pubkey_hex: str, req_id: str, stream_id: int,
                            data: bytes) -> None:
        """Push a payload as a sequence of chunk messages on one stream."""
        total = len(data)
        seq = 0
        for offset in range(0, total, self.chunk_size):
            piece = data[offset:offset + self.chunk_size]
            final = offset + len(piece) >= total
            ok = await self.peer_manager.send_to(pubkey_hex, Message(MsgType.BLOCK_CHUNK, {
                "req_id": req_id,
                "stream_id": stream_id,
                "seq": seq,
                "chunk": piece,
                "final": final,
            }), stream_id=stream_id)
            if not ok:
                raise RemoteOperationFailed(f"peer {pubkey_hex[:8]} disconnected mid-transfer")
            seq += 1

    # -- serving inbound requests from a peer -----------------------------

    async def _serve_store_block(self, pubkey_hex: str, msg: Message) -> None:
        req_id = msg.body.get("req_id")

        if msg.body.get("chunked"):
            total_size = msg.body.get("total_size", 0)
            if not isinstance(total_size, int) or total_size <= 0 or total_size > config.MAX_BLOCK_SIZE:
                await self.peer_manager.send_to(pubkey_hex, Message(
                    MsgType.NACK, {"req_id": req_id,
                                   "error": f"declared transfer size {total_size} is not acceptable"}))
                return
            self._gc_buffers()
            if len(self._buffers) >= config.MAX_INBOUND_STREAMS:
                await self.peer_manager.send_to(pubkey_hex, Message(
                    MsgType.NACK, {"req_id": req_id, "error": "too many concurrent transfers"}))
                return
            self._buffers[req_id] = _ChunkBuffer(
                "store", total_size, pubkey_hex,
                meta={"durability": msg.body.get("durability", Durability.CACHE.value),
                      "key": msg.body.get("key")})
            return   # the reply comes when the final chunk lands

        try:
            data = extract_payload(msg.body, "data")
            if data is None:
                raise ValueError("missing payload")
            durability = Durability(msg.body.get("durability", Durability.CACHE.value))
            key = msg.body.get("key")
            block_id = await self.block_manager.store(data, durability=durability, key=key)
        except (BlockTooLarge, OutOfMemory) as e:
            logger.info("remote store from %s rejected: %s", pubkey_hex[:8], e)
            await self.peer_manager.send_to(
                pubkey_hex, Message(MsgType.NACK, {"req_id": req_id, "error": str(e)}))
            return
        except Exception as e:  # malformed request -- never let this kill the read loop
            logger.exception("bad StoreBlock request from %s", pubkey_hex[:8])
            await self.peer_manager.send_to(
                pubkey_hex, Message(MsgType.NACK, {"req_id": req_id, "error": f"bad request: {e}"}))
            return
        await self.peer_manager.send_to(
            pubkey_hex, Message(MsgType.BLOCK_DATA, {"req_id": req_id, "block_id": block_id}))

    async def _serve_request_block(self, pubkey_hex: str, msg: Message) -> None:
        req_id = msg.body.get("req_id")
        block_id = msg.body.get("block_id")
        key = msg.body.get("key")
        try:
            data = await self.block_manager.load(block_id) if block_id is not None \
                else await self.block_manager.load_by_key(key)
        except Exception:
            logger.exception("bad RequestBlock request from %s", pubkey_hex[:8])
            data = None

        if data is None:
            await self.peer_manager.send_to(
                pubkey_hex, Message(MsgType.BLOCK_NOT_FOUND, {"req_id": req_id}))
            return

        if len(data) <= self.chunk_threshold:
            await self.peer_manager.send_to(
                pubkey_hex, Message(MsgType.BLOCK_DATA, {"req_id": req_id, "data": data}))
            return

        # Large reply: announce the size, then stream it on its own logical
        # stream so the requester's other traffic keeps flowing.
        stream_id = self._next_stream()
        ok = await self.peer_manager.send_to(pubkey_hex, Message(MsgType.BLOCK_DATA, {
            "req_id": req_id, "chunked": True, "total_size": len(data),
            "stream_id": stream_id,
        }), stream_id=stream_id)
        if not ok:
            return
        try:
            await self._send_chunks(pubkey_hex, req_id, stream_id, data)
        except RemoteOperationFailed as e:
            logger.info("streaming reply to %s failed: %s", pubkey_hex[:8], e)

    async def _serve_free_block(self, pubkey_hex: str, msg: Message) -> None:
        req_id = msg.body.get("req_id")
        block_id = msg.body.get("block_id")
        try:
            freed = await self.block_manager.free(block_id)
        except Exception:
            logger.exception("bad FreeBlock request from %s", pubkey_hex[:8])
            freed = False
        await self.peer_manager.send_to(
            pubkey_hex, Message(MsgType.FREED, {"req_id": req_id, "freed": freed}))

    # -- making outbound requests to a peer -------------------------------

    def _register_pending(self, req_id: str) -> asyncio.Future:
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut
        return fut

    async def _await_reply(self, req_id: str, timeout: float) -> Message:
        fut = self._pending.get(req_id) or self._register_pending(req_id)
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as e:
            raise RemoteOperationFailed(f"peer did not respond within {timeout}s") from e
        finally:
            self._pending.pop(req_id, None)

    async def store_remote(self, pubkey_hex: str, data: bytes, *,
                            durability: Durability = Durability.CACHE,
                            key: Optional[str] = None,
                            timeout: float = DEFAULT_TIMEOUT) -> int:
        req_id = uuid.uuid4().hex
        chunked = len(data) > self.chunk_threshold
        stream_id = self._next_stream() if chunked else config.CONTROL_STREAM_ID

        body: dict = {"req_id": req_id, "durability": durability.value}
        if key is not None:
            body["key"] = key
        if chunked:
            body.update({"chunked": True, "total_size": len(data), "stream_id": stream_id})
        else:
            body["data"] = data

        # Register the waiter BEFORE sending the request.
        fut = self._register_pending(req_id)
        try:
            ok = await self.peer_manager.send_to(
                pubkey_hex, Message(MsgType.STORE_BLOCK, body), stream_id=stream_id)
            if not ok:
                raise RemoteOperationFailed(f"peer {pubkey_hex[:8]} is not connected")

            if chunked:
                await self._send_chunks(pubkey_hex, req_id, stream_id, data)

            reply = await asyncio.wait_for(fut, timeout)
            if reply.type == MsgType.NACK:
                raise OutOfMemory(reply.body.get("error", "remote store failed"))
            return reply.body["block_id"]
        except asyncio.TimeoutError as e:
            raise RemoteOperationFailed(f"peer did not respond within {timeout}s") from e
        finally:
            self._pending.pop(req_id, None)

    async def load_remote(self, pubkey_hex: str, *, block_id: Optional[int] = None,
                           key: Optional[str] = None,
                           timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
        """Ask a specific connected peer for a block it holds. Returns
        None if that peer does not have it."""
        req_id = uuid.uuid4().hex
        body: dict = {"req_id": req_id}
        if block_id is not None:
            body["block_id"] = block_id
        if key is not None:
            body["key"] = key

        fut = self._register_pending(req_id)
        try:
            ok = await self.peer_manager.send_to(
                pubkey_hex, Message(MsgType.REQUEST_BLOCK, body))
            if not ok:
                raise RemoteOperationFailed(f"peer {pubkey_hex[:8]} is not connected")

            reply = await asyncio.wait_for(fut, timeout)
            if reply.type == MsgType.BLOCK_NOT_FOUND:
                return None
            if reply.type == MsgType.NACK:
                raise RemoteOperationFailed(reply.body.get("error", "remote load failed"))

            if reply.body.get("chunked"):
                collector = self._pull_futures.get(req_id)
                if collector is None:
                    raise RemoteOperationFailed("chunked reply arrived without a collector")
                try:
                    return await asyncio.wait_for(collector, timeout)
                except asyncio.TimeoutError as e:
                    raise RemoteOperationFailed(
                        f"chunked transfer did not complete within {timeout}s") from e

            data = extract_payload(reply.body, "data")
            if data is None:
                raise RemoteOperationFailed("reply carried no payload")
            return data
        except asyncio.TimeoutError as e:
            raise RemoteOperationFailed(f"peer did not respond within {timeout}s") from e
        finally:
            self._pending.pop(req_id, None)
            self._buffers.pop(req_id, None)
            self._pull_futures.pop(req_id, None)

    async def load_remote_by_key_anywhere(self, key: str,
                                           timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
        """Fan out a by-key lookup to every currently-connected peer and
        return the first hit. Used as the RPC-layer fallback when a key
        is not held on this node."""
        async with self.peer_manager._lock:
            full_pubkeys = list(self.peer_manager.peers.keys())
        for pubkey_hex in full_pubkeys:
            try:
                data = await self.load_remote(pubkey_hex, key=key, timeout=timeout)
            except RemoteOperationFailed:
                continue
            if data is not None:
                return data
        return None

    async def free_remote(self, pubkey_hex: str, block_id: int,
                           timeout: float = DEFAULT_TIMEOUT) -> bool:
        """Ask a specific connected peer to free a block it holds for us.

        This is what lets the RPC layer's "free" semantics reach blocks
        that a store call overflowed onto another node (see rpc.py's
        "remote_free" op).
        """
        req_id = uuid.uuid4().hex
        self._register_pending(req_id)
        ok = await self.peer_manager.send_to(
            pubkey_hex, Message(MsgType.FREE_BLOCK, {"req_id": req_id, "block_id": block_id}))
        if not ok:
            self._pending.pop(req_id, None)
            raise RemoteOperationFailed(f"peer {pubkey_hex[:8]} is not connected")
        reply = await self._await_reply(req_id, timeout)
        return bool(reply.body.get("freed", False))

    def stats(self) -> dict:
        return {
            "pending_requests": len(self._pending),
            "active_transfers": len(self._buffers),
            "pending_pulls": len(self._pull_futures),
            "chunk_size": self.chunk_size,
            "chunk_threshold": self.chunk_threshold,
        }
