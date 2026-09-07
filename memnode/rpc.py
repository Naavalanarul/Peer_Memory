"""Local RPC server: how the CLI, SDKs, and the React dashboard talk to
this daemon.

Loopback-only (Unix socket + 127.0.0.1 TCP), JSON-over-length-prefixed-
frame -- kept human-debuggable (you can hand-craft a JSON message and
send it with `nc 127.0.0.1 7070`) like the reference design, but every
read is still bounded by MAX_RPC_MESSAGE_SIZE, and every handler error
is caught and turned into an `{"ok": false, ...}` response rather than
an unhandled exception that would kill the connection.

Phase 1 hardening
-----------------
This is a *control plane*, not a status API: it can allocate memory,
free other clients' blocks, and dial arbitrary hosts. Two problems are
fixed here.

1. ``start()`` used to bind ``0.0.0.0``, which published that control
   plane to the entire LAN despite the docstring claiming loopback-only.
   It now binds ``config.RPC_BIND_HOST`` and refuses a non-loopback
   bind unless the caller explicitly passes ``allow_remote_bind=True``.
2. There was no authentication at all. TCP clients now complete a
   challenge-response against a shared secret (see ``rpcauth``) before
   any op is dispatched. Unix-socket clients are exempt by default,
   since filesystem permissions already gate that path.

For the React frontend specifically: consider adding a small
websocket/SSE endpoint alongside this for push updates (peer
connect/disconnect, stats changes) rather than having the dashboard
poll `stats`/`peers` in a loop.
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import struct
from typing import Optional

import msgpack

from . import config, rpcauth
from .blocks import BlockManager, BlockTooLarge, Durability, OutOfMemory
from .peers import PeerManager
from .replication import ReplicationCoordinator, RemoteOperationFailed

logger = logging.getLogger("memnode.rpc")


async def _read_json_frame(reader: asyncio.StreamReader,
                           length_bytes: Optional[bytes] = None) -> dict:
    len_bytes = length_bytes if length_bytes is not None else await reader.readexactly(4)
    (length,) = struct.unpack(">I", len_bytes)
    if length > config.MAX_RPC_MESSAGE_SIZE:
        raise ValueError(f"RPC message of {length} bytes exceeds MAX_RPC_MESSAGE_SIZE")
    raw = await reader.readexactly(length)
    return json.loads(raw.decode("utf-8"))


async def _write_json_frame(writer: asyncio.StreamWriter, obj: dict) -> None:
    raw = json.dumps(obj).encode("utf-8")
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()


async def _read_msgpack_frame(reader: asyncio.StreamReader,
                              length_bytes: Optional[bytes] = None) -> dict:
    """Binary sibling of _read_json_frame, with the same size guard.

    The size check happens before the body read, exactly as in the JSON
    path -- switching codecs must not reopen the unbounded-allocation
    hole the framing code exists to close.
    """
    if length_bytes is None:
        length_bytes = await reader.readexactly(4)
    (length,) = struct.unpack(">I", length_bytes)
    if length > config.MAX_RPC_MESSAGE_SIZE:
        raise ValueError(f"RPC message of {length} bytes exceeds MAX_RPC_MESSAGE_SIZE")
    raw = await reader.readexactly(length)
    return msgpack.unpackb(raw, raw=False)


async def _write_msgpack_frame(writer: asyncio.StreamWriter, obj: dict) -> None:
    raw = msgpack.packb(obj, use_bin_type=True)
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()


def request_payload(req: dict) -> Optional[bytes]:
    """Read a request payload in either codec.

    Binary clients send raw bytes under ``data``; JSON clients send hex
    under ``data_hex``. Both are accepted everywhere, so an old client
    and a new client can talk to the same daemon.
    """
    value = req.get("data")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    hex_value = req.get("data_hex")
    if isinstance(hex_value, str):
        return bytes.fromhex(hex_value)
    return None


class RpcServer:
    def __init__(self, block_manager: BlockManager, peer_manager: PeerManager,
                 replication: Optional[ReplicationCoordinator] = None,
                 rpc_port: int = config.RPC_TCP_PORT,
                 rpc_unix_socket: str = config.RPC_UNIX_SOCKET,
                 bind_host: str = config.RPC_BIND_HOST,
                 auth_token: Optional[str] = None,
                 require_auth: bool = config.RPC_REQUIRE_AUTH,
                 unix_socket_exempt: bool = config.RPC_AUTH_UNIX_SOCKET_EXEMPT,
                 allow_remote_bind: bool = False):
        self.block_manager = block_manager
        self.peer_manager = peer_manager
        # Falls back to a private coordinator if none is supplied so the
        # existing test_rpc.py fixture (which builds RpcServer directly,
        # without wiring replication) keeps working unmodified.
        self.replication = replication or ReplicationCoordinator(block_manager, peer_manager)
        self.rpc_port = rpc_port
        self.rpc_unix_socket = rpc_unix_socket
        self.bind_host = bind_host
        self.allow_remote_bind = allow_remote_bind
        self.unix_socket_exempt = unix_socket_exempt
        # require_auth is only meaningful with a token; a "required" auth
        # with no secret to check would be a false sense of security, so
        # it is downgraded loudly rather than silently.
        self.auth_token = auth_token
        if require_auth and not auth_token:
            logger.warning("RPC auth requested but no token supplied -- auth is DISABLED "
                           "for this server instance")
        self.require_auth = bool(require_auth and auth_token)

    # -- authentication --------------------------------------------------

    async def _authenticate(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> bool:
        """Challenge-response against the shared secret. See rpcauth."""
        challenge = rpcauth.new_challenge()
        await _write_json_frame(writer, {
            "memnode_auth": "challenge",
            "version": config.RPC_AUTH_VERSION,
            "challenge": challenge,
        })
        try:
            reply = await asyncio.wait_for(_read_json_frame(reader),
                                           timeout=config.RPC_AUTH_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            logger.warning("RPC client did not answer the auth challenge in %.1fs",
                           config.RPC_AUTH_TIMEOUT_SECONDS)
            return False
        except (asyncio.IncompleteReadError, ValueError, json.JSONDecodeError):
            return False

        if not rpcauth.verify_response(self.auth_token, challenge, reply.get("response")):
            try:
                await _write_json_frame(writer, {"ok": False, "error": "authentication failed"})
            except (ConnectionResetError, BrokenPipeError):
                pass
            return False

        await _write_json_frame(writer, {"ok": True})
        return True

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             require_auth: Optional[bool] = None):
        peer = writer.get_extra_info("peername") or "unix-socket"
        needs_auth = self.require_auth if require_auth is None else require_auth
        if needs_auth:
            try:
                if not await self._authenticate(reader, writer):
                    logger.warning("RPC client %s failed authentication", peer)
                    writer.close()
                    return
            except (ConnectionResetError, BrokenPipeError):
                writer.close()
                return
        # Codec negotiation. A client that opens with the 4-byte magic
        # preamble gets msgpack framing with raw binary payloads; anything
        # else is the length prefix of a classic JSON frame, so the
        # original protocol keeps working untouched. Negotiation happens
        # after auth so that the auth exchange itself is one fixed format.
        binary = False
        pending_length: Optional[bytes] = None
        try:
            prefix = await reader.readexactly(config.RPC_MAGIC_LEN)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            writer.close()
            return
        if prefix == config.RPC_MSGPACK_MAGIC:
            binary = True
            try:
                await _write_msgpack_frame(writer, {"ok": True, "codec": "msgpack"})
            except (ConnectionResetError, BrokenPipeError):
                writer.close()
                return
        else:
            pending_length = prefix

        read_frame = _read_msgpack_frame if binary else _read_json_frame
        write_frame = _write_msgpack_frame if binary else _write_json_frame

        try:
            while True:
                try:
                    req = await read_frame(reader, pending_length)
                    pending_length = None
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
                        await write_frame(writer, {"ok": False, "error": str(e)})
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                    break
                except Exception as e:
                    logger.warning("RPC client %s sent an undecodable frame: %s", peer, e)
                    break
                try:
                    resp = await self._dispatch(req, binary=binary)
                except Exception as e:
                    logger.exception("RPC handler error for op=%s", req.get("op"))
                    resp = {"ok": False, "error": str(e)}
                await write_frame(writer, resp)
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            logger.debug("RPC client %s disconnected", peer)

    def _payload_response(self, data: bytes, binary: bool) -> dict:
        """Return a payload in the codec the client is speaking."""
        if binary:
            return {"ok": True, "data": data}
        return {"ok": True, "data_hex": data.hex()}

    async def _dispatch(self, req: dict, binary: bool = False) -> dict:
        op = req.get("op")

        if op == "store":
            data = request_payload(req)
            if data is None:
                return {"ok": False, "error": "store requires 'data' (bytes) or 'data_hex' (hex)"}
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
            return self._payload_response(data, binary)

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
            data = request_payload(req)
            if data is None:
                return {"ok": False, "error": "remote_store requires 'data' or 'data_hex'"}
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
            return self._payload_response(data, binary)

        elif op == "remote_free":
            # Symmetric with remote_store/remote_load: release a block
            # that was placed on a specific connected peer (by pubkey
            # prefix), most commonly one this node caused to be stored
            # there via automatic overflow when its own quota was full.
            pubkey = await self._resolve_peer(req["peer"])
            try:
                freed = await self.replication.free_remote(pubkey, req["block_id"])
            except RemoteOperationFailed as e:
                return {"ok": False, "error": str(e)}
            return {"ok": freed}

        elif op == "trusted":
            # Inspect the trust store: which identities are known, how
            # each was accepted (tofu vs out-of-band), when first seen.
            return {"ok": True, "trusted": self.peer_manager.trust_store.all()}

        elif op == "verify_peer":
            # Operator confirms out of band ("the six digits match") that
            # a first-contact peer is really who it claims to be. This is
            # what upgrades a TOFU record into a verified one.
            pubkey = await self._resolve_peer(req["peer"])
            ok = self.peer_manager.verify_peer(pubkey, method=req.get("method", "sas"))
            return {"ok": ok, "peer": pubkey[:8]}

        elif op == "revoke_peer":
            pubkey = req.get("pubkey")
            if not pubkey:
                pubkey = await self._resolve_peer(req["peer"])
            return {"ok": self.peer_manager.trust_store.revoke(pubkey)}

        elif op == "pair":
            # Everything a human needs to compare two devices by eye or
            # by camera: the session SAS and a scannable pairing URI.
            from .peers import pairing_uri, render_qr_ascii
            pubkey = await self._resolve_peer(req["peer"])
            async with self.peer_manager._lock:
                info = self.peer_manager.peers.get(pubkey)
            if info is None:
                return {"ok": False, "error": "peer not connected"}
            uri = pairing_uri(info.pubkey_hex, info.sas, info.name)
            resp = {"ok": True, "peer": pubkey[:8], "sas": info.sas, "uri": uri,
                    "verified": info.verified}
            if req.get("qr"):
                qr = render_qr_ascii(uri)
                resp["qr"] = qr
                if qr is None:
                    resp["qr_error"] = "install the optional 'qrcode' package for ASCII QR output"
            return resp

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
        if not rpcauth.is_loopback(self.bind_host) and not self.allow_remote_bind:
            # Hard stop rather than a warning: binding this off-loopback is
            # the difference between "local control plane" and "anyone on
            # the LAN can allocate/free memory on this box".
            raise ValueError(
                f"refusing to bind the RPC control plane to non-loopback address "
                f"{self.bind_host!r}. Keep it on 127.0.0.1 and use SSH port-forwarding "
                f"for remote access, or pass allow_remote_bind=True if you have "
                f"deliberately put an authenticated proxy in front of it.")
        if not self.require_auth and not rpcauth.is_loopback(self.bind_host):
            raise ValueError("refusing to expose an unauthenticated RPC control plane off-loopback")

        server_tcp = await asyncio.start_server(self._handle_client, self.bind_host, self.rpc_port)
        logger.info("RPC server listening on %s:%d (auth=%s)",
                    self.bind_host, self.rpc_port, "on" if self.require_auth else "off")
        server_unix = None
        if hasattr(asyncio, "start_unix_server") and self.rpc_unix_socket:
            try:
                if os.path.exists(self.rpc_unix_socket):
                    os.remove(self.rpc_unix_socket)
                # Filesystem permissions gate the unix socket, so token auth
                # there is optional (config.RPC_AUTH_UNIX_SOCKET_EXEMPT).
                unix_handler = functools.partial(
                    self._handle_client,
                    require_auth=self.require_auth and not self.unix_socket_exempt)
                server_unix = await asyncio.start_unix_server(unix_handler, self.rpc_unix_socket)
                try:
                    os.chmod(self.rpc_unix_socket, 0o600)
                except OSError:
                    logger.warning("could not tighten permissions on %s", self.rpc_unix_socket)
                logger.info("RPC server listening on %s", self.rpc_unix_socket)
            except (OSError, NotImplementedError) as e:
                logger.warning("unix socket RPC unavailable (%s) -- TCP-only", e)
        else:
            logger.info("unix sockets not supported on this platform -- TCP-only RPC")

        return server_tcp, server_unix
