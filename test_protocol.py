import asyncio
import struct

import pytest

from memnode import config, protocol


class FakeReader:
    """Minimal stand-in for asyncio.StreamReader -- just readexactly()."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise asyncio.IncompleteReadError(partial=self._data[self._pos:], expected=n)
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk


@pytest.mark.asyncio
async def test_read_frame_roundtrip():
    payload = b"hello memcloud"
    framed = struct.pack(">I", len(payload)) + payload
    reader = FakeReader(framed)
    result = await protocol.read_frame(reader)
    assert result == payload


@pytest.mark.asyncio
async def test_read_frame_rejects_oversized_length():
    """This is the direct regression test for the bug found in the
    reference implementation: a peer claiming an oversized frame length
    must be rejected BEFORE we try to allocate/read that many bytes,
    not after."""
    huge_len = config.MAX_FRAME_SIZE + 1
    framed = struct.pack(">I", huge_len)  # no body -- must fail on the length check alone
    reader = FakeReader(framed)
    with pytest.raises(protocol.FrameTooLarge):
        await protocol.read_frame(reader)


@pytest.mark.asyncio
async def test_read_frame_at_exactly_max_size_is_allowed():
    payload = b"x" * 10  # small stand-in; just checking the boundary logic, not allocating 16MB
    framed = struct.pack(">I", len(payload)) + payload
    reader = FakeReader(framed)
    result = await protocol.read_frame(reader, max_size=10)
    assert result == payload


def test_message_encode_decode_roundtrip():
    msg = protocol.Message(type=protocol.MsgType.PING, body={"ts": 123})
    raw = msg.encode()
    decoded = protocol.Message.decode(raw)
    assert decoded.type == protocol.MsgType.PING
    assert decoded.body == {"ts": 123}
