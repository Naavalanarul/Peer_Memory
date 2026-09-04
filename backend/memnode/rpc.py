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

from . import config
from .blocks import BlockManager, BlockTooLarge, Durability, OutOfMemory
from .peers import PeerManager

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
    def __init__(self, block_manager: BlockManager, peer_manager: PeerManager):
        self.block_manager = block_manager
        self.peer_manager = peer_manager

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
                return {"ok": True, "block_id": block_id}
            except (BlockTooLarge, OutOfMemory) as e:
                return {"ok": False, "error": str(e)}

        elif op == "load":
            if "block_id" in req:
                data = await self.block_manager.load(req["block_id"])
            else:
                data = await self.block_manager.load_by_key(req["key"])
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

        else:
            return {"ok": False, "error": f"unknown op: {op}"}

    async def start(self):
        server_tcp = await asyncio.start_server(self._handle_client, "127.0.0.1", config.RPC_TCP_PORT)
        logger.info("RPC server listening on 127.0.0.1:%d", config.RPC_TCP_PORT)

        server_unix = None
        try:
            if os.path.exists(config.RPC_UNIX_SOCKET):
                os.remove(config.RPC_UNIX_SOCKET)
            server_unix = await asyncio.start_unix_server(self._handle_client, config.RPC_UNIX_SOCKET)
            logger.info("RPC server listening on %s", config.RPC_UNIX_SOCKET)
        except (OSError, NotImplementedError) as e:
            logger.warning("unix socket RPC unavailable (%s) -- TCP-only", e)

        return server_tcp, server_unix
