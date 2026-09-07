"""Phase 1 regression tests for the encrypted peer channel.

These cover the three properties the old implicit-counter channel did
not have: replayed frames are dropped, keys roll over on a threshold,
and a peer cannot force unbounded key-derivation work.
"""
import asyncio

import pytest

from memnode import config
from memnode.security import (
    HandshakeFailed,
    NodeIdentity,
    ReplayDetected,
    ReplayWindow,
    SecureChannel,
    perform_handshake,
    short_authentication_string,
)


class _FakeWriter:
    """Writes straight into the peer's StreamReader, recording frames."""

    def __init__(self, target: asyncio.StreamReader):
        self.target = target
        self.frames: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.frames.append(bytes(data))
        self.target.feed_data(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def get_extra_info(self, _name, default=None):
        return default


def _duplex(**kwargs):
    """Two SecureChannels wired back-to-back in memory."""
    reader_a, reader_b = asyncio.StreamReader(), asyncio.StreamReader()
    writer_a, writer_b = _FakeWriter(reader_b), _FakeWriter(reader_a)
    key_a, key_b = b"A" * 32, b"B" * 32
    chan_a = SecureChannel(reader_a, writer_a, send_key=key_a, recv_key=key_b,
                           transcript_hash=b"t" * 32, **kwargs)
    chan_b = SecureChannel(reader_b, writer_b, send_key=key_b, recv_key=key_a,
                           transcript_hash=b"t" * 32, **kwargs)
    return chan_a, writer_a, chan_b, reader_b


# -- ReplayWindow unit tests ------------------------------------------------

def test_replay_window_accepts_monotonic_sequence():
    w = ReplayWindow(size=64)
    assert all(w.check_and_update(i) for i in range(200))
    assert w.highest == 199


def test_replay_window_rejects_exact_duplicate():
    w = ReplayWindow(size=64)
    assert w.check_and_update(5) is True
    assert w.check_and_update(5) is False


def test_replay_window_allows_bounded_reordering():
    w = ReplayWindow(size=64)
    assert w.check_and_update(10) is True
    assert w.check_and_update(8) is True     # reordered, still inside the window
    assert w.check_and_update(9) is True
    assert w.check_and_update(8) is False    # ...but only once each


def test_replay_window_rejects_frames_older_than_the_window():
    w = ReplayWindow(size=8)
    assert w.check_and_update(100) is True
    assert w.check_and_update(50) is False   # 50 more frames of history is not kept


def test_replay_window_large_jump_resets_bitmap_without_false_accepts():
    w = ReplayWindow(size=8)
    assert w.check_and_update(1) is True
    assert w.check_and_update(1000) is True
    assert w.check_and_update(1000) is False
    assert w.check_and_update(999) is True


# -- SecureChannel behaviour ------------------------------------------------

@pytest.mark.asyncio
async def test_channel_roundtrip():
    a, _, b, _ = _duplex()
    await a.send(b"hello")
    assert await b.recv() == b"hello"


@pytest.mark.asyncio
async def test_replayed_frame_is_dropped_not_delivered():
    """The core Phase 1 property: re-injecting a captured frame must not
    produce a second delivery to the application."""
    a, writer_a, b, reader_b = _duplex()
    await a.send(b"transfer-1")
    assert await b.recv() == b"transfer-1"

    captured = writer_a.frames[-1]
    reader_b.feed_data(captured)          # attacker replays it verbatim
    await a.send(b"transfer-2")           # a legitimate frame behind it

    assert await b.recv() == b"transfer-2"
    assert b.replays_dropped == 1


@pytest.mark.asyncio
async def test_sequence_number_is_authenticated():
    """Rewriting the plaintext sequence prefix must break the AEAD tag
    rather than silently shifting the frame to another slot."""
    a, writer_a, b, reader_b = _duplex()
    await a.send(b"payload")
    assert await b.recv() == b"payload"   # consume the genuine copy first

    frame = writer_a.frames[-1]
    # frame = 4-byte length || 8-byte seq || ciphertext; bump the seq so it
    # lands on a slot the replay window has not seen.
    tampered = bytearray(frame)
    tampered[4 + 7] = (tampered[4 + 7] + 1) % 256
    reader_b.feed_data(bytes(tampered))
    with pytest.raises(HandshakeFailed):
        await b.recv()


@pytest.mark.asyncio
async def test_channel_rekeys_on_message_threshold():
    a, _, b, _ = _duplex(rekey_interval_messages=4, rekey_interval_seconds=0)
    for i in range(12):
        await a.send(f"msg-{i}".encode())
    for i in range(12):
        assert await b.recv() == f"msg-{i}".encode()

    assert a.rekeys_sent >= 2, a.stats()
    assert b.rekeys_received == a.rekeys_sent
    assert a.stats()["send_epoch"] == b.stats()["recv_epoch"]


@pytest.mark.asyncio
async def test_rekey_keeps_working_across_many_epochs():
    a, _, b, _ = _duplex(rekey_interval_messages=1, rekey_interval_seconds=0)
    for i in range(20):
        await a.send(bytes([i]))
    for i in range(20):
        assert await b.recv() == bytes([i])
    assert a.stats()["send_epoch"] == 19


@pytest.mark.asyncio
async def test_recv_refuses_an_unbounded_epoch_jump():
    """A peer must not be able to make us run thousands of HKDF steps by
    claiming a huge sequence number."""
    a, _, b, _ = _duplex(rekey_interval_messages=1, rekey_interval_seconds=0)
    with pytest.raises(ReplayDetected):
        b._advance_recv_to(config.MAX_REKEY_EPOCH_SKIP + 5)


@pytest.mark.asyncio
async def test_recv_refuses_expired_epoch():
    a, _, b, _ = _duplex(rekey_interval_messages=1, rekey_interval_seconds=0)
    b._advance_recv_to(3)
    with pytest.raises(ReplayDetected):
        b._advance_recv_to(1)


# -- end-to-end handshake over a real socket --------------------------------

@pytest.mark.asyncio
async def test_handshake_over_loopback_agrees_on_keys_and_sas():
    server_identity = NodeIdentity.generate()
    client_identity = NodeIdentity.generate()
    results: dict = {}
    ready = asyncio.Event()

    async def on_connect(reader, writer):
        try:
            results["server"] = await perform_handshake(
                reader, writer, server_identity, "server-node", 1024, is_initiator=False)
            results["server_writer"] = writer
        except Exception as exc:            # surface it instead of hanging the client
            results["error"] = exc
        finally:
            ready.set()

    server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        c_chan, c_peer_pub, c_info = await asyncio.wait_for(
            perform_handshake(reader, writer, client_identity, "client-node", 2048,
                              is_initiator=True), timeout=5)
        await asyncio.wait_for(ready.wait(), timeout=5)
        assert "error" not in results, results["error"]
        s_chan, s_peer_pub, s_info = results["server"]

        assert c_peer_pub == server_identity.public_bytes
        assert s_peer_pub == client_identity.public_bytes
        assert c_info["sas"] == s_info["sas"]          # same transcript -> same code
        assert c_info["ram_quota"] == 1024
        assert s_info["ram_quota"] == 2048

        await c_chan.send(b"ping")
        assert await asyncio.wait_for(s_chan.recv(), timeout=5) == b"ping"
        await s_chan.send(b"pong")
        assert await asyncio.wait_for(c_chan.recv(), timeout=5) == b"pong"

        writer.close()
        results["server_writer"].close()
    finally:
        server.close()


def test_sas_is_deterministic_and_correct_length():
    h = bytes(range(32))
    assert short_authentication_string(h) == short_authentication_string(h)
    assert len(short_authentication_string(h)) == config.SAS_DIGITS
    assert short_authentication_string(h) != short_authentication_string(bytes(32))
    assert short_authentication_string(h).isdigit()
