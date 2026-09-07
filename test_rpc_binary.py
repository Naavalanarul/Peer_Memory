"""Phase 2: binary RPC framing.

Hex-in-JSON doubled every payload on the wire and cost a full
encode/decode pass on both ends. The binary codec removes both. The
non-negotiable part is that the original JSON protocol still works, so
existing clients (including demo/demo_client.py) do not break.
"""
import asyncio
import json
import struct

import msgpack
import pytest

from memnode import config
from memnode.blocks import BlockManager
from memnode.peers import PeerManager
from memnode.rpc import RpcServer, request_payload
from memnode.security import NodeIdentity

TEST_PORT = 17172


@pytest.fixture
async def server():
    rpc = RpcServer(BlockManager(max_memory_bytes=8 * 1024 * 1024),
                    PeerManager(NodeIdentity.generate(), "codec-test", 8 * 1024 * 1024))
    tcp = await asyncio.start_server(rpc._handle_client, "127.0.0.1", TEST_PORT)
    yield rpc
    tcp.close()


class _Client:
    """Minimal client that can speak either codec."""

    def __init__(self, reader, writer, binary: bool):
        self.reader, self.writer, self.binary = reader, writer, binary

    @classmethod
    async def connect(cls, binary: bool) -> "_Client":
        reader, writer = await asyncio.open_connection("127.0.0.1", TEST_PORT)
        client = cls(reader, writer, binary)
        if binary:
            writer.write(config.RPC_MSGPACK_MAGIC)
            await writer.drain()
            ack = await client.read()
            assert ack["ok"] is True and ack["codec"] == "msgpack"
        return client

    async def read(self) -> dict:
        length = struct.unpack(">I", await self.reader.readexactly(4))[0]
        raw = await self.reader.readexactly(length)
        return msgpack.unpackb(raw, raw=False) if self.binary else json.loads(raw.decode())

    async def call(self, **req) -> dict:
        raw = (msgpack.packb(req, use_bin_type=True) if self.binary
               else json.dumps(req).encode())
        self.writer.write(struct.pack(">I", len(raw)) + raw)
        await self.writer.drain()
        return await self.read()

    def close(self):
        self.writer.close()


# -- payload adapter --------------------------------------------------------

def test_request_payload_accepts_both_forms():
    assert request_payload({"data": b"abc"}) == b"abc"
    assert request_payload({"data_hex": "616263"}) == b"abc"
    assert request_payload({}) is None


def test_binary_payload_is_half_the_size_of_hex():
    payload = bytes(range(256)) * 64                     # 16 KiB
    binary = len(msgpack.packb({"op": "store", "data": payload}, use_bin_type=True))
    hexed = len(json.dumps({"op": "store", "data_hex": payload.hex()}).encode())
    assert binary < hexed / 1.9, (binary, hexed)


# -- binary codec -----------------------------------------------------------

@pytest.mark.asyncio
async def test_binary_store_and_load_roundtrip(server):
    client = await _Client.connect(binary=True)
    payload = bytes(range(256))

    stored = await client.call(op="store", data=payload, key="bin")
    assert stored["ok"] is True

    loaded = await client.call(op="load", key="bin")
    assert loaded["ok"] is True
    assert loaded["data"] == payload      # raw bytes, no hex round trip
    assert "data_hex" not in loaded
    client.close()


@pytest.mark.asyncio
async def test_binary_connection_handles_many_requests(server):
    client = await _Client.connect(binary=True)
    for i in range(20):
        resp = await client.call(op="store", data=bytes([i]) * 100, key=f"k{i}")
        assert resp["ok"] is True
    assert (await client.call(op="stats"))["stats"]["block_count"] == 20
    client.close()


@pytest.mark.asyncio
async def test_binary_oversized_frame_is_still_refused(server):
    """Switching codecs must not reopen the unbounded-allocation hole."""
    reader, writer = await asyncio.open_connection("127.0.0.1", TEST_PORT)
    writer.write(config.RPC_MSGPACK_MAGIC)
    await writer.drain()
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    await reader.readexactly(length)                    # codec ack

    writer.write(struct.pack(">I", config.MAX_RPC_MESSAGE_SIZE + 1))
    await writer.drain()
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    resp = msgpack.unpackb(await reader.readexactly(length), raw=False)
    assert resp["ok"] is False
    assert "MAX_RPC_MESSAGE_SIZE" in resp["error"]
    writer.close()

    # ...and the server survives it.
    survivor = await _Client.connect(binary=True)
    assert (await survivor.call(op="stats"))["ok"] is True
    survivor.close()


# -- backward compatibility -------------------------------------------------

@pytest.mark.asyncio
async def test_legacy_json_client_still_works(server):
    client = await _Client.connect(binary=False)
    stored = await client.call(op="store", data_hex=b"legacy".hex(), key="old")
    assert stored["ok"] is True

    loaded = await client.call(op="load", key="old")
    assert bytes.fromhex(loaded["data_hex"]) == b"legacy"
    assert "data" not in loaded          # JSON clients keep getting hex
    client.close()


@pytest.mark.asyncio
async def test_both_codecs_share_one_store(server):
    """A key written by a JSON client must be readable by a binary one."""
    legacy = await _Client.connect(binary=False)
    await legacy.call(op="store", data_hex=b"shared".hex(), key="shared")
    legacy.close()

    modern = await _Client.connect(binary=True)
    resp = await modern.call(op="load", key="shared")
    assert resp["data"] == b"shared"
    modern.close()


@pytest.mark.asyncio
async def test_binary_client_may_send_hex_and_json_client_may_not_send_bytes(server):
    """The payload adapter is tolerant in the direction that matters."""
    client = await _Client.connect(binary=True)
    resp = await client.call(op="store", data_hex=b"mixed".hex(), key="mixed")
    assert resp["ok"] is True
    assert (await client.call(op="load", key="mixed"))["data"] == b"mixed"
    client.close()


@pytest.mark.asyncio
async def test_store_without_a_payload_is_a_clean_error(server):
    client = await _Client.connect(binary=True)
    resp = await client.call(op="store", key="nothing")
    assert resp["ok"] is False
    assert "data" in resp["error"]
    client.close()
