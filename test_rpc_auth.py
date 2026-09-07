"""Phase 1: the RPC control plane must be authenticated and loopback-bound.

Before this, anything that could reach port 7070 could allocate memory,
free blocks, and make the daemon dial arbitrary hosts.
"""
import asyncio
import json
import struct

import pytest

from memnode import rpcauth
from memnode.blocks import BlockManager
from memnode.peers import PeerManager
from memnode.rpc import RpcServer
from memnode.security import NodeIdentity

TEST_PORT = 17071
TOKEN = "a" * 64


def _build_server(**kwargs) -> RpcServer:
    return RpcServer(BlockManager(max_memory_bytes=1024 * 1024),
                     PeerManager(NodeIdentity.generate(), "auth-test", 1024 * 1024),
                     **kwargs)


async def _read_frame(reader) -> dict:
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    return json.loads((await reader.readexactly(length)).decode())


async def _write_frame(writer, obj: dict) -> None:
    raw = json.dumps(obj).encode()
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()


@pytest.fixture
async def auth_server():
    server = _build_server(auth_token=TOKEN, require_auth=True)
    tcp = await asyncio.start_server(server._handle_client, "127.0.0.1", TEST_PORT)
    yield server
    tcp.close()


# -- token helpers ----------------------------------------------------------

def test_token_file_is_created_with_owner_only_permissions(tmp_path):
    path = tmp_path / "rpc_token"
    token = rpcauth.load_or_create_token(path)
    assert len(token) == 64
    assert path.stat().st_mode & 0o077 == 0, "token file must not be group/world readable"
    assert rpcauth.load_or_create_token(path) == token, "token must be stable across restarts"


def test_response_verification_is_exact():
    challenge = rpcauth.new_challenge()
    good = rpcauth.compute_response(TOKEN, challenge)
    assert rpcauth.verify_response(TOKEN, challenge, good) is True
    assert rpcauth.verify_response(TOKEN, challenge, good[:-1] + "0") is False
    assert rpcauth.verify_response("b" * 64, challenge, good) is False
    assert rpcauth.verify_response(TOKEN, rpcauth.new_challenge(), good) is False
    assert rpcauth.verify_response(TOKEN, challenge, None) is False


def test_challenge_is_fresh_per_connection():
    assert rpcauth.new_challenge() != rpcauth.new_challenge()


def test_loopback_detection():
    assert rpcauth.is_loopback("127.0.0.1") is True
    assert rpcauth.is_loopback("localhost") is True
    assert rpcauth.is_loopback("::1") is True
    assert rpcauth.is_loopback("0.0.0.0") is False
    assert rpcauth.is_loopback("192.168.1.10") is False


# -- bind policy ------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_refuses_non_loopback_bind_by_default():
    server = _build_server(auth_token=TOKEN, bind_host="0.0.0.0", rpc_port=17099,
                           rpc_unix_socket="")
    with pytest.raises(ValueError, match="non-loopback"):
        await server.start()


@pytest.mark.asyncio
async def test_start_refuses_unauthenticated_remote_bind():
    server = _build_server(auth_token=None, require_auth=False, bind_host="0.0.0.0",
                           rpc_port=17098, rpc_unix_socket="", allow_remote_bind=True)
    with pytest.raises(ValueError, match="unauthenticated"):
        await server.start()


def test_auth_downgrades_loudly_without_a_token():
    server = _build_server(auth_token=None, require_auth=True)
    assert server.require_auth is False, "auth cannot be 'required' with no secret to check"


# -- end-to-end over the wire ----------------------------------------------

@pytest.mark.asyncio
async def test_correct_token_is_accepted(auth_server):
    reader, writer = await asyncio.open_connection("127.0.0.1", TEST_PORT)
    challenge = await _read_frame(reader)
    assert challenge["memnode_auth"] == "challenge"

    await _write_frame(writer, {"response": rpcauth.compute_response(TOKEN, challenge["challenge"])})
    assert (await _read_frame(reader))["ok"] is True

    await _write_frame(writer, {"op": "stats"})
    resp = await _read_frame(reader)
    assert resp["ok"] is True
    writer.close()


@pytest.mark.asyncio
async def test_wrong_token_is_rejected_and_no_op_runs(auth_server):
    reader, writer = await asyncio.open_connection("127.0.0.1", TEST_PORT)
    challenge = await _read_frame(reader)
    await _write_frame(writer, {"response": "00" * 32})
    resp = await _read_frame(reader)
    assert resp["ok"] is False

    # The connection must be gone -- not merely "unauthenticated but usable".
    with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
        await _write_frame(writer, {"op": "stats"})
        await _read_frame(reader)
    writer.close()


@pytest.mark.asyncio
async def test_unauthenticated_op_is_not_dispatched(auth_server):
    """Sending an op straight away must not work: the server reads it as
    a (failed) auth response, never as a command."""
    reader, writer = await asyncio.open_connection("127.0.0.1", TEST_PORT)
    await _read_frame(reader)                       # challenge
    await _write_frame(writer, {"op": "store", "data_hex": "ff"})
    resp = await _read_frame(reader)
    assert resp["ok"] is False
    assert "authentication" in resp["error"]
    writer.close()


@pytest.mark.asyncio
async def test_replaying_a_captured_response_on_a_new_connection_fails(auth_server):
    """The challenge is per-connection, so a sniffed response is useless."""
    reader, writer = await asyncio.open_connection("127.0.0.1", TEST_PORT)
    challenge = await _read_frame(reader)
    captured = rpcauth.compute_response(TOKEN, challenge["challenge"])
    await _write_frame(writer, {"response": captured})
    assert (await _read_frame(reader))["ok"] is True
    writer.close()

    reader2, writer2 = await asyncio.open_connection("127.0.0.1", TEST_PORT)
    await _read_frame(reader2)                      # a *different* challenge
    await _write_frame(writer2, {"response": captured})
    assert (await _read_frame(reader2))["ok"] is False
    writer2.close()
