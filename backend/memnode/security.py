"""Peer-to-peer handshake and secure transport.

Mirrors the Noise-XX-inspired design from the reference implementation:
  1. Hello: exchange nonces + ephemeral X25519 public keys, mixed into a
     running transcript hash.
  2. Auth (still cleartext, but only after Hello is exchanged): each
     side sends its persistent Ed25519 identity plus a signature *over
     the transcript hash*, binding the signature to everything
     exchanged so far. This is what prevents a MITM from swapping in
     their own ephemeral key without detection -- a signature over just
     a nonce would not catch that.
  3. Derive per-direction traffic keys from the ECDH shared secret plus
     the transcript hash, then switch to ChaCha20-Poly1305 AEAD framing
     for all further traffic (SecureChannel).

Ephemeral keys are per-session, giving forward secrecy: compromising a
node's long-term identity key later does not let you decrypt past
sessions.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass

import msgpack
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import config
from .protocol import read_frame, write_frame

logger = logging.getLogger("memnode.security")


class HandshakeFailed(Exception):
    pass


@dataclass
class NodeIdentity:
    """A node's persistent Ed25519 keypair -- its long-term identity."""
    signing_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "NodeIdentity":
        return cls(signing_key=Ed25519PrivateKey.generate())

    @property
    def public_bytes(self) -> bytes:
        return self.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class SecureChannel:
    """Encrypted, framed transport used after a successful handshake.

    Each direction uses its own key and its own monotonic nonce counter,
    so send and receive never share nonce space -- reusing a nonce with
    the same key is what breaks AEAD confidentiality/integrity.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 send_key: bytes, recv_key: bytes):
        self._reader = reader
        self._writer = writer
        self._send_cipher = ChaCha20Poly1305(send_key)
        self._recv_cipher = ChaCha20Poly1305(recv_key)
        self._send_counter = 0
        self._recv_counter = 0

    @staticmethod
    def _nonce(counter: int) -> bytes:
        # 12-byte nonce: 4 zero bytes + 8-byte big-endian counter.
        return (0).to_bytes(4, "big") + counter.to_bytes(8, "big")

    async def send(self, plaintext: bytes) -> None:
        nonce = self._nonce(self._send_counter)
        ciphertext = self._send_cipher.encrypt(nonce, plaintext, None)
        await write_frame(self._writer, ciphertext)
        self._send_counter += 1

    async def recv(self) -> bytes:
        # read_frame already enforces MAX_FRAME_SIZE before allocating,
        # so an oversized-length attack is rejected here too, not just
        # during the cleartext handshake phase.
        ciphertext = await read_frame(self._reader)
        nonce = self._nonce(self._recv_counter)
        try:
            plaintext = self._recv_cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise HandshakeFailed("frame decryption/authentication failed") from e
        self._recv_counter += 1
        return plaintext

    async def send_msg(self, msg) -> None:
        await self.send(msg.encode())

    async def recv_msg(self):
        from .protocol import Message
        return Message.decode(await self.recv())

    def close(self):
        self._writer.close()


def _derive_traffic_keys(shared_secret: bytes, transcript_hash: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=transcript_hash,
        info=b"memnode-traffic-keys-v1",
    ).derive(shared_secret)
    return okm[:32], okm[32:]


async def perform_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             identity: NodeIdentity, node_name: str, ram_quota: int,
                             is_initiator: bool) -> tuple[SecureChannel, bytes, dict]:
    """Run the Hello -> Auth handshake and return (channel, peer_pubkey, peer_info).

    Both cleartext messages (Hello, Auth) are read via read_frame(),
    which enforces MAX_FRAME_SIZE, so a malicious peer can't force an
    oversized allocation even before encryption is established -- this
    was a gap in the reference implementation.
    """
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    my_nonce = os.urandom(16)

    hello = msgpack.packb({"nonce": my_nonce, "eph_pub": eph_pub_bytes,
                            "name": node_name, "version": config.PROTOCOL_VERSION})
    await write_frame(writer, hello)
    peer_hello_raw = await read_frame(reader)
    peer_hello = msgpack.unpackb(peer_hello_raw, raw=False)

    # Deterministic ordering regardless of who spoke first, so both
    # sides compute an identical transcript hash.
    transcript = hashlib.sha256()
    first, second = (hello, peer_hello_raw) if is_initiator else (peer_hello_raw, hello)
    transcript.update(first)
    transcript.update(second)
    t_hash = transcript.digest()

    my_sig = identity.signing_key.sign(t_hash)
    auth = msgpack.packb({"identity_pubkey": identity.public_bytes, "signature": my_sig,
                           "ram_quota": ram_quota})
    await write_frame(writer, auth)
    peer_auth_raw = await read_frame(reader)
    peer_auth = msgpack.unpackb(peer_auth_raw, raw=False)

    peer_pubkey_bytes = peer_auth["identity_pubkey"]
    peer_pub = Ed25519PublicKey.from_public_bytes(peer_pubkey_bytes)
    try:
        peer_pub.verify(peer_auth["signature"], t_hash)
    except InvalidSignature as e:
        writer.close()
        raise HandshakeFailed("peer signature over transcript did not verify (possible MITM)") from e

    peer_eph_pub = X25519PublicKey.from_public_bytes(peer_hello["eph_pub"])
    shared_secret = eph_priv.exchange(peer_eph_pub)
    key_a, key_b = _derive_traffic_keys(shared_secret, t_hash)
    send_key, recv_key = (key_a, key_b) if is_initiator else (key_b, key_a)

    channel = SecureChannel(reader, writer, send_key=send_key, recv_key=recv_key)
    peer_info = {"name": peer_hello.get("name"), "ram_quota": peer_auth.get("ram_quota", 0)}
    return channel, peer_pubkey_bytes, peer_info
