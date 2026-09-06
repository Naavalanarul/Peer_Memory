"""Peer-to-peer block replication -- the piece that actually makes this
a *distributed* RAM pool instead of N independent single-node caches.

Why this module exists
-----------------------
protocol.py already defines the wire message types for it
(StoreBlock / RequestBlock / BlockData / BlockNotFound / Nack), and
peers.py already has the plumbing to pick a peer with free capacity
(`best_peer_for_store`) and to send it a message (`send_to`). But
nothing on the receiving end ever turned an incoming StoreBlock/
RequestBlock message into a BlockManager call, and nothing on the
sending end turned "peer X has room" into "ask peer X to store this 
and wait for the reply". PeerManager was built with a
`message_handler` hook specifically for this, but main.py never
supplied one. This module is that missing handler.

Design
------
Every outbound request carries a `req_id` (uuid4 hex) in its body.
`ReplicationCoordinator.handle_message` is registered as the
PeerManager-wide message handler and runs for every message from every
peer. For each message it first checks whether `req_id` matches a
pending local request:
  - yes  -> it's a *reply* to something we asked; resolve the
            waiting asyncio.Future and stop.
  - no   -> it's an *inbound request* from a peer; dispatch it to the
            local BlockManager and reply.

Using a single dict of {req_id: Future} keyed by a random UUID (rather
than, say, correlating by message order) means concurrent requests to
multiple peers -- or multiple in-flight requests to the same peer --
never get confused with each other, and a slow peer can't block
replies from a fast one.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Optional

from .blocks import BlockManager, BlockTooLarge, Durability, OutOfMemory
from .protocol import Message, MsgType

logger = logging.getLogger("memnode.replication")
DEFAULT_TIMEOUT = 30.0


class RemoteOperationFailed(Exception):
    pass


class ReplicationCoordinator:
    """Bridges PeerManager <-> BlockManager so blocks can live on any
    node in the cluster, not just the one an RPC client happens to be
    talking to."""

    def __init__(self, block_manager: BlockManager, peer_manager):
        self.block_manager = block_manager
        self.peer_manager = peer_manager
        self._pending: dict[str, asyncio.Future] = {}

    # -- wire this in as PeerManager's message_handler -------------------

    async def handle_message(self, pubkey_hex: str, msg: Message) -> None:
        req_id = msg.body.get("req_id")

        # Case 1: this is the answer to a request *we* sent earlier.
        if req_id is not None and req_id in self._pending:
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
        elif msg.type in (MsgType.BLOCK_DATA, MsgType.BLOCK_NOT_FOUND, MsgType.NACK, MsgType.PONG,
                          MsgType.FREED):
            # A reply that arrived after we already timed out and stopped
            # waiting for it. Not an error -- just log and drop it.
            logger.debug("dropping stale/unmatched reply %s from %s", msg.type, pubkey_hex[:8])
        else:
            logger.debug("unhandled message type %s from %s", msg.type, pubkey_hex[:8])

    # -- serving inbound requests from a peer -----------------------------

    async def _serve_store_block(self, pubkey_hex: str, msg: Message) -> None:
        req_id = msg.body.get("req_id")
        try:
            data = bytes.fromhex(msg.body["data_hex"])
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
            await self.peer_manager.send_to(pubkey_hex, Message(MsgType.BLOCK_NOT_FOUND, {"req_id": req_id}))
        else:
            await self.peer_manager.send_to(
                pubkey_hex, Message(MsgType.BLOCK_DATA, {"req_id": req_id, "data_hex": data.hex()}))

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

    async def _await_reply(self, req_id: str, timeout: float) -> Message:
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut
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

        body = {
        "req_id": req_id,
        "data_hex": data.hex(),
        "durability": durability.value,
        }

        if key is not None:
            body["key"] = key

        # Register the waiter BEFORE sending the request.
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut

        try:
            ok = await self.peer_manager.send_to(
                pubkey_hex,
                Message(MsgType.STORE_BLOCK, body)
            )

            if not ok:
                raise RemoteOperationFailed(
                    f"peer {pubkey_hex[:8]} is not connected"
            )

            reply = await asyncio.wait_for(fut, timeout)

            if reply.type == MsgType.NACK:
                raise OutOfMemory(
                    reply.body.get("error", "remote store failed")
                )

            return reply.body["block_id"]

        except asyncio.TimeoutError as e:
            raise RemoteOperationFailed(
                f"peer did not respond within {timeout}s"
            ) from e

        finally:
            self._pending.pop(req_id, None)

    async def load_remote(self, pubkey_hex: str, *, block_id: Optional[int] = None,
                           key: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
        """Ask a specific connected peer for a block it holds. Returns
        None if that peer doesn't have it."""
        req_id = uuid.uuid4().hex
        body = {"req_id": req_id}
        if block_id is not None:
            body["block_id"] = block_id
        if key is not None:
            body["key"] = key
        fut = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut

        try:
            ok = await self.peer_manager.send_to(
                pubkey_hex,
                Message(MsgType.REQUEST_BLOCK, body)
            )

            if not ok:
                raise RemoteOperationFailed(
                    f"peer {pubkey_hex[:8]} is not connected"
                )

            reply = await asyncio.wait_for(fut, timeout)

            if reply.type == MsgType.BLOCK_NOT_FOUND:
                return None

            return bytes.fromhex(reply.body["data_hex"])

        except asyncio.TimeoutError as e:
            raise RemoteOperationFailed(
                f"peer did not respond within {timeout}s"
            ) from e

        finally:
            self._pending.pop(req_id, None)

    async def load_remote_by_key_anywhere(self, key: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
        """Fan out a by-key lookup to every currently-connected peer and
        return the first hit. Used as the RPC-layer fallback when a key
        isn't held on this node."""
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

    async def free_remote(self, pubkey_hex: str, block_id: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
        """Ask a specific connected peer to free a block it holds for us.

        This is what lets the RPC layer's "free" semantics reach blocks
        that a store call overflowed onto another node (see rpc.py's
        "remote_free" op) -- without it, a client has no way to release
        memory it caused to be allocated on a peer, and freeing only
        ever worked for blocks held on the node you happen to be talking
        to.
        """
        req_id = uuid.uuid4().hex
        ok = await self.peer_manager.send_to(pubkey_hex, Message(MsgType.FREE_BLOCK,
                                                                   {"req_id": req_id, "block_id": block_id}))
        if not ok:
            raise RemoteOperationFailed(f"peer {pubkey_hex[:8]} is not connected")
        reply = await self._await_reply(req_id, timeout)
        return bool(reply.body.get("freed", False))
