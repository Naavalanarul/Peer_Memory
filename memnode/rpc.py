"""Local RPC server: how the CLI, SDKs, and the React dashboard talk to
this daemon.

Loopback-only (Unix socket + 127.0.0.1 TCP), JSON-over-length-prefixed-
frame -- kept human-debuggable (you can hand-craft a JSON message and
send it with `nc 127.0.0.1 7070`) like the reference design, but every
read is still bounded by MAX_RPC_MESSAGE_SIZE, and every handler error
is caught and turned into an `{"ok": false, ...}` response rather than
an unhandled exception that would kill the connection.

For the React frontend specifically: consider adding a small
websocket/SSE endpoint alongside this for push updates (peer
connect/disconnect, stats changes) rather than having the dashboard
poll `stats`/`peers` in a loop.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
from typing import Optional

from . import config
from .blocks import BlockManager, BlockTooLarge, Durability, OutOfMemory
from .peers import PeerManager
from .replication import ReplicationCoordinator, RemoteOperationFailed

logger = logging.getLogger("memnode.rpc")


async def _read_json_frame(reader: asyncio.StreamReader) -> dict:
    len_bytes = await reader.readexactly(4)
    (length,) = struct.unpack(">I", len_bytes)
    if length > config.MAX_RPC_MESSAGE_SIZE:
        raise ValueError(f"RPC message of {length} bytes exceeds MAX_RPC_MESSAGE_SIZE")
    raw = await reader.readexactly(length)
    return json.loads(raw.decode("utf-8"))


async def _write_json_frame(writer: asyncio.StreamWriter, obj: dict) -> None:
    raw = json.dumps(obj).encode("utf-8")
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()


class RpcServer:
    def __init__(self, block_manager: BlockManager, peer_manager: PeerManager,
                 replication: Optional[ReplicationCoordinator] = None,
                 rpc_port: int = config.RPC_TCP_PORT,
                 rpc_unix_socket: str = config.RPC_UNIX_SOCKET):
        self.block_manager = block_manager
        self.peer_manager = peer_manager
        # Falls back to a private coordinator if none is supplied so the
        # existing test_rpc.py fixture (which builds RpcServer directly,
        # without wiring replication) keeps working unmodified.
        self.replication = replication or ReplicationCoordinator(block_manager, peer_manager)
        self.rpc_port = rpc_port
        self.rpc_unix_socket = rpc_unix_socket

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or "unix-socket"
        try:
            while True:
                try:
                    req = await _read_json_frame(reader)
                except asyncio.IncompleteReadError:
                    break
                except ValueError as e:
                    # Oversized-length rejection lands here. We deliberately
                    # have NOT read the claimed body, so the stream is now
                    # desynced -- send a clean error and close, rather than
                    # trying to keep parsing frames from a socket whose
                    # position we can no longer trust.
                    logger.warning("RPC client %s sent oversized message: %s", peer, e)
                    try:
                        await _write_json_frame(writer, {"ok": False, "error": str(e)})
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                    break
                try:
                    resp = await self._dispatch(req)
                except Exception as e:
                    logger.exception("RPC handler error for op=%s", req.get("op"))
                    resp = {"ok": False, "error": str(e)}
                await _write_json_frame(writer, resp)
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            logger.debug("RPC client %s disconnected", peer)

    async def _dispatch(self, req: dict) -> dict:
        op = req.get("op")

        if op == "store":
            data = bytes.fromhex(req["data_hex"])
            durability = Durability(req.get("durability", "pinned"))
            key = req.get("key")
            try:
                block_id = await self.block_manager.store(data, durability=durability, key=key)
                return {"ok": True, "block_id": block_id, "location": "local"}
            except BlockTooLarge as e:
                return {"ok": False, "error": str(e)}
            except OutOfMemory as local_err:
                # This node's own quota is full -- this is the "pool" part
                # of the RAM pool: try to place the block on whichever
                # connected peer currently has the most free advertised
                # capacity, rather than just failing the write.
                if req.get("allow_remote", True):
                    peer = await self.peer_manager.best_peer_for_store(len(data))
                    if peer is not None:
                        try:
                            block_id = await self.replication.store_remote(
                                peer, data, durability=durability, key=key)
                            return {"ok": True, "block_id": block_id, "location": "remote",
                                    "peer": peer[:8]}
                        except (OutOfMemory, RemoteOperationFailed) as remote_err:
                            return {"ok": False, "error": f"local: {local_err}; remote: {remote_err}"}
                return {"ok": False, "error": str(local_err)}

        elif op == "load":
            if "block_id" in req:
                data = await self.block_manager.load(req["block_id"])
            else:
                key = req["key"]
                data = await self.block_manager.load_by_key(key)
                if data is None and req.get("allow_remote", True):
                    # Not held here -- ask every connected peer in turn.
                    # This is what makes storage location transparent to
                    # the caller: they ask for a key, not a specific node.
                    data = await self.replication.load_remote_by_key_anywhere(key)
            if data is None:
                return {"ok": False, "error": "not found"}
            return {"ok": True, "data_hex": data.hex()}

        elif op == "free":
            freed = await self.block_manager.free(req["block_id"])
            return {"ok": freed}

        elif op == "stats":
            return {"ok": True, "stats": await self.block_manager.stats()}

        elif op == "peers":
            return {"ok": True, "peers": await self.peer_manager.list_peers()}

        elif op == "connect":
            pubkey = await self.peer_manager.connect_to(req["host"], req["port"])
            return {"ok": True, "pubkey": pubkey}

        elif op == "remote_store":
            # Explicit placement on a named peer (by pubkey prefix), for
            # demoing/debugging the cluster rather than relying on
            # automatic best-fit placement.
            data = bytes.fromhex(req["data_hex"])
            durability = Durability(req.get("durability", "cache"))
            pubkey = await self._resolve_peer(req["peer"])
            try:
                block_id = await self.replication.store_remote(
                    pubkey, data, durability=durability, key=req.get("key"))
                return {"ok": True, "block_id": block_id, "peer": pubkey[:8]}
            except (OutOfMemory, RemoteOperationFailed) as e:
                return {"ok": False, "error": str(e)}

        elif op == "remote_load":
            pubkey = await self._resolve_peer(req["peer"])
            try:
                data = await self.replication.load_remote(
                    pubkey, block_id=req.get("block_id"), key=req.get("key"))
            except RemoteOperationFailed as e:
                return {"ok": False, "error": str(e)}
            if data is None:
                return {"ok": False, "error": "not found"}
            return {"ok": True, "data_hex": data.hex()}

        else:
            return {"ok": False, "error": f"unknown op: {op}"}

    async def _resolve_peer(self, prefix: str) -> str:
        """Peers are addressed everywhere in RPC responses by their
        8-char pubkey prefix (list_peers() truncates for display), so
        RPC requests are allowed to use that same short form."""
        async with self.peer_manager._lock:
            for full in self.peer_manager.peers:
                if full == prefix or full.startswith(prefix):
                    return full
        raise KeyError(f"no connected peer matching '{prefix}'")

    async def start(self):
        server_tcp = await asyncio.start_server(self._handle_client, "127.0.0.1", self.rpc_port)
        logger.info("RPC server listening on 127.0.0.1:%d", self.rpc_port)

        server_unix = None
        try:
            if os.path.exists(self.rpc_unix_socket):
                os.remove(self.rpc_unix_socket)
            server_unix = await asyncio.start_unix_server(self._handle_client, self.rpc_unix_socket)
            logger.info("RPC server listening on %s", self.rpc_unix_socket)
        except (OSError, NotImplementedError) as e:
            logger.warning("unix socket RPC unavailable (%s) -- TCP-only", e)

        return server_tcp, server_unix
