"""End-to-end tests for the RPC server, run against a real asyncio server
on a loopback port (not mocked) so we exercise the actual framing code.
"""
import asyncio
import json
import struct

import pytest

from memnode import config
from memnode.blocks import BlockManager
from memnode.peers import PeerManager
from memnode.rpc import RpcServer
from memnode.security import NodeIdentity

TEST_PORT = 17070  # avoid clashing with the default 7070 if a daemon is already running


async def _call(port: int, op: str, **kwargs) -> dict:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    req = {"op": op, **kwargs}
    raw = json.dumps(req).encode()
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()
    len_bytes = await reader.readexactly(4)
    (length,) = struct.unpack(">I", len_bytes)
    resp = json.loads((await reader.readexactly(length)).decode())
    writer.close()
    return resp


@pytest.fixture
async def rpc_server():
    block_manager = BlockManager(max_memory_bytes=10 * 1024 * 1024)
    peer_manager = PeerManager(NodeIdentity.generate(), "test-node", 10 * 1024 * 1024)
    server = RpcServer(block_manager, peer_manager)
    tcp_server = await asyncio.start_server(server._handle_client, "127.0.0.1", TEST_PORT)
    async with tcp_server:
        yield server
    tcp_server.close()


@pytest.mark.asyncio
async def test_store_and_load_roundtrip_over_rpc(rpc_server):
    store_resp = await _call(TEST_PORT, "store", data_hex=b"hi".hex(), key="k")
    assert store_resp["ok"] is True

    load_resp = await _call(TEST_PORT, "load", key="k")
    assert load_resp["ok"] is True
    assert bytes.fromhex(load_resp["data_hex"]) == b"hi"


@pytest.mark.asyncio
async def test_oversized_rpc_message_does_not_crash_server(rpc_server):
    """Regression test for a real bug caught while building this scaffold:
    the size check correctly rejected an oversized length prefix, but the
    ValueError wasn't caught in the connection loop, so it surfaced as an
    unhandled exception in the server's background task instead of a
    clean disconnect.

    Once the server closes on an oversized claimed length, the client's
    own send of the (still in-flight) oversized body will typically hit a
    connection reset -- that's expected/correct, since the server should
    not read megabytes of unread body just to send a polite error. What
    this test actually asserts is the thing that matters: the SERVER
    itself must survive the bad request and keep serving other clients,
    not silently die or half-crash the event loop.
    """
    oversized_hex = "ff" * (config.MAX_RPC_MESSAGE_SIZE + 1)
    try:
        await _call(TEST_PORT, "store", data_hex=oversized_hex)
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass  # expected -- the connection is torn down, not gracefully drained

    # The server process/loop must still be alive and responsive.
    resp = await _call(TEST_PORT, "stats")
    assert resp["ok"] is True


@pytest.mark.asyncio
async def test_unknown_op_returns_error_not_crash(rpc_server):
    resp = await _call(TEST_PORT, "not_a_real_op")
    assert resp["ok"] is False
