"""Wire protocol: framed, length-prefixed messages between memnode daemons.

Every read from the network goes through read_frame(), which enforces
MAX_FRAME_SIZE *before* allocating a buffer. This is the direct fix for
the bug found in the reference implementation, where the equivalent
Rust function did `vec![0u8; len]` for an attacker-controlled `len`
with no upper bound -- a single malicious/misbehaving peer could force
a multi-gigabyte allocation with one 4-byte length prefix.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from enum import Enum

import msgpack

from . import config


class FrameTooLarge(Exception):
    """Raised when a peer claims a frame size larger than we allow.

    Treat this as hostile input: log it and close the connection.
    Callers must NOT attempt to read the claimed length after this
    is raised.
    """


class ConnectionClosed(Exception):
    pass


async def read_frame(reader, max_size: int = config.MAX_FRAME_SIZE) -> bytes:
    """Read one length-prefixed frame, refusing to allocate past max_size.

    `reader` needs only a `readexactly(n) -> bytes` coroutine method, so
    this works with both asyncio.StreamReader and lightweight test doubles.
    """
    len_bytes = await reader.readexactly(4)
    (length,) = struct.unpack(">I", len_bytes)

    if length > max_size:
        raise FrameTooLarge(f"peer claimed frame size {length} bytes, max allowed is {max_size}")
    if length == 0:
        return b""

    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as e:
        raise ConnectionClosed("peer closed connection mid-frame") from e


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    if len(payload) > config.MAX_FRAME_SIZE:
        raise FrameTooLarge(f"refusing to send frame of {len(payload)} bytes")
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()


class MsgType(str, Enum):
    HELLO = "Hello"
    WELCOME = "Welcome"
    AUTH = "Auth"
    STORE_BLOCK = "StoreBlock"
    REQUEST_BLOCK = "RequestBlock"
    BLOCK_DATA = "BlockData"
    BLOCK_NOT_FOUND = "BlockNotFound"
    SET_KEY = "SetKey"
    GET_KEY = "GetKey"
    KEY_FOUND = "KeyFound"
    PING = "Ping"
    PONG = "Pong"
    QUOTA_UPDATE = "QuotaUpdate"
    NACK = "Nack"          # explicit failure response -- the reference
                            # implementation had a TODO for this and just
                            # left senders hanging on failure.
    FREE_BLOCK = "FreeBlock"    # ask a peer to release a block it holds
                                # for us -- lets the RPC layer's "free"
                                # semantics extend to remotely-placed
                                # blocks (see rpc.py's "remote_free" op),
                                # not just ones stored on this node.
    FREED = "Freed"             # reply to FreeBlock: {"freed": bool}
    BLOCK_CHUNK = "BlockChunk"  # one slice of a chunked transfer -- see
                                # replication.py. Large blocks are split
                                # across many small frames instead of one
                                # giant AEAD frame so they cannot occupy
                                # the connection end-to-end and block
                                # unrelated messages behind them.
    STREAM_ABORT = "StreamAbort"  # sender/receiver gave up on a transfer
    BYE = "Bye"


@dataclass
class Message:
    """A single peer-protocol message.

    Serialized with msgpack: compact, cross-language (the JS/TS SDK can
    read the same bytes), and -- unlike pickle -- safe to deserialize
    from data sent by an untrusted peer.

    Phase 2 conventions
    -------------------
    * ``body["stream_id"]`` names a logical stream inside one encrypted
      connection. The multiplexer (``mux.ChannelMux``) round-robins
      between streams, so a long transfer on one stream cannot starve
      messages on another. Absent means the control stream (0).
    * Payloads travel as msgpack ``bin`` (raw ``bytes``) under ``data``
      / ``chunk``, not as hex under ``data_hex``. Hex doubled every
      payload on the wire and cost a full encode/decode pass on both
      ends. ``data_hex`` is still *accepted* on receive for
      interoperability with older senders -- see
      ``replication.extract_payload``.
    """
    type: MsgType
    body: dict = field(default_factory=dict)

    @property
    def stream_id(self) -> int:
        value = self.body.get("stream_id", 0)
        return value if isinstance(value, int) else 0

    def encode(self) -> bytes:
        return msgpack.packb({"type": self.type.value, "body": self.body}, use_bin_type=True)

    @staticmethod
    def decode(raw: bytes) -> "Message":
        obj = msgpack.unpackb(raw, raw=False)
        return Message(type=MsgType(obj["type"]), body=obj.get("body", {}))


async def send_message(writer: asyncio.StreamWriter, msg: Message) -> None:
    await write_frame(writer, msg.encode())


async def recv_message(reader) -> Message:
    raw = await read_frame(reader)
    return Message.decode(raw)
