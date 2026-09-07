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

Phase 1 hardening added on top of the above
-------------------------------------------
* Explicit per-frame sequence numbers + a sliding replay window
  (``ReplayWindow``). Duplicate or out-of-window frames are dropped
  before decryption is even attempted, and the sequence number is
  authenticated as AEAD associated data so it cannot be rewritten in
  flight.
* Automatic session rekeying (``config.REKEY_INTERVAL_MESSAGES`` /
  ``config.REKEY_INTERVAL_SECONDS``). Keys advance in "epochs" derived
  by chaining HKDF; the epoch is a pure function of the frame sequence
  number, so both ends stay in sync with zero extra round trips and no
  new message types.
* Handshake-level checks: protocol version match, self-connection
  detection, and nonce/key reflection detection.
* A short authentication string (SAS) derived from the transcript hash,
  for out-of-band ("read me the 6 digits") verification on first
  contact -- see ``peers.TrustStore``.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import struct
import time
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

SEQ_STRUCT = struct.Struct(">Q")
SEQ_LEN = SEQ_STRUCT.size  # 8
AEAD_TAG_LEN = 16


class HandshakeFailed(Exception):
    pass


class ReplayDetected(Exception):
    """A frame was a duplicate, or older than the replay window allows."""


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


class ReplayWindow:
    """IPsec-style anti-replay window over 64-bit sequence numbers.

    Keeps the highest sequence number seen plus a bitmap of which of the
    previous ``size`` sequence numbers have already been accepted. This
    tolerates reordering up to ``size`` frames while making a replayed
    frame -- or a frame an attacker held back and re-injected later --
    a hard reject.

    ``check_and_update`` returns True if the sequence number is fresh
    and has been recorded, False if the frame must be dropped.
    """

    __slots__ = ("size", "_highest", "_bitmap", "_seen_any")

    def __init__(self, size: int = config.REPLAY_WINDOW_SIZE):
        if size < 1:
            raise ValueError("replay window size must be >= 1")
        self.size = size
        self._highest = 0
        self._bitmap = 0
        self._seen_any = False

    @property
    def highest(self) -> int:
        return self._highest if self._seen_any else -1

    def check_and_update(self, seq: int) -> bool:
        if seq < 0 or seq > 0xFFFFFFFFFFFFFFFF:
            return False

        if not self._seen_any:
            self._seen_any = True
            self._highest = seq
            self._bitmap = 1
            return True

        if seq > self._highest:
            shift = seq - self._highest
            if shift >= self.size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & ((1 << self.size) - 1)
            self._highest = seq
            return True

        offset = self._highest - seq
        if offset >= self.size:
            return False                      # too old to judge -> drop
        mask = 1 << offset
        if self._bitmap & mask:
            return False                      # already accepted -> replay
        self._bitmap |= mask
        return True


def _derive_traffic_keys(shared_secret: bytes, transcript_hash: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=transcript_hash,
        info=b"memnode-traffic-keys-v1",
    ).derive(shared_secret)
    return okm[:32], okm[32:]


def _advance_key(key: bytes, transcript_hash: bytes, epoch: int, direction: bytes) -> bytes:
    """One rekey step: k_n = HKDF(k_(n-1)).

    Chaining (rather than deriving every epoch straight from the
    original shared secret) means an attacker who recovers the epoch-N
    key cannot walk *backwards* to epoch N-1, so traffic sent before the
    most recent rekey stays protected.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_hash,
        info=b"memnode-rekey-v1|" + direction + b"|" + str(epoch).encode(),
    ).derive(key)


def short_authentication_string(transcript_hash: bytes, digits: int = config.SAS_DIGITS) -> str:
    """Derive a short code both peers can read aloud / scan to confirm
    they completed the *same* handshake.

    The transcript hash already covers both ephemeral keys and both
    nonces, so a MITM running two separate handshakes cannot make the
    two ends produce the same SAS. Comparing it out of band (voice, QR,
    a chat message) is what upgrades bare TOFU into real authentication
    on first contact.
    """
    if digits < 4 or digits > 18:
        raise ValueError("SAS digits must be between 4 and 18")
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=8,
        salt=b"memnode-sas-v1",
        info=b"short-authentication-string",
    ).derive(transcript_hash)
    value = int.from_bytes(okm, "big") % (10 ** digits)
    return str(value).zfill(digits)


class SecureChannel:
    """Encrypted, framed transport used after a successful handshake.

    Wire format of every frame body (inside protocol.write_frame):

        seq: 8 bytes big-endian || ChaCha20-Poly1305 ciphertext

    * ``seq`` is authenticated as AEAD associated data, so flipping it
      in flight breaks the tag.
    * ``seq`` is also the nonce input, so a nonce is never reused under
      one key.
    * ``seq // REKEY_INTERVAL_MESSAGES`` selects the key epoch, which is
      how both ends rekey in lockstep without any signalling message.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 send_key: bytes, recv_key: bytes,
                 transcript_hash: bytes = b"",
                 replay_window_size: int = config.REPLAY_WINDOW_SIZE,
                 rekey_interval_messages: int = config.REKEY_INTERVAL_MESSAGES,
                 rekey_interval_seconds: float = config.REKEY_INTERVAL_SECONDS,
                 max_epoch_skip: int = config.MAX_REKEY_EPOCH_SKIP):
        if rekey_interval_messages < 1:
            raise ValueError("rekey_interval_messages must be >= 1")
        self._reader = reader
        self._writer = writer
        self.transcript_hash = transcript_hash

        self._send_key = send_key
        self._recv_key = recv_key
        self._send_cipher = ChaCha20Poly1305(send_key)
        self._recv_cipher = ChaCha20Poly1305(recv_key)

        self._send_seq = 0
        self._send_epoch = 0
        self._recv_epoch = 0
        self._replay = ReplayWindow(replay_window_size)

        self._rekey_messages = rekey_interval_messages
        self._rekey_seconds = rekey_interval_seconds
        self._max_epoch_skip = max_epoch_skip
        self._last_rekey_at = time.monotonic()
        self.rekeys_sent = 0
        self.rekeys_received = 0
        self.replays_dropped = 0
        self._send_lock = asyncio.Lock()

    # -- key schedule ----------------------------------------------------

    def _epoch_for(self, seq: int) -> int:
        return seq // self._rekey_messages

    def _advance_send_to(self, epoch: int) -> None:
        while self._send_epoch < epoch:
            self._send_epoch += 1
            self._send_key = _advance_key(self._send_key, self.transcript_hash,
                                          self._send_epoch, b"send")
            self._send_cipher = ChaCha20Poly1305(self._send_key)
            self.rekeys_sent += 1
        self._last_rekey_at = time.monotonic()

    def _advance_recv_to(self, epoch: int) -> None:
        if epoch < self._recv_epoch:
            # An old-epoch frame after we already rekeyed forward: this
            # is either a very stale reordered frame or a replay attempt.
            raise ReplayDetected(
                f"frame from expired key epoch {epoch} (current {self._recv_epoch})")
        if epoch - self._recv_epoch > self._max_epoch_skip:
            raise ReplayDetected(
                f"peer jumped {epoch - self._recv_epoch} key epochs at once "
                f"(max {self._max_epoch_skip}) -- refusing")
        while self._recv_epoch < epoch:
            self._recv_epoch += 1
            # NOTE: the label is b"send" here on purpose. Our recv key IS
            # the peer's send key, so we must reproduce exactly the chain
            # the peer computes in _advance_send_to. The two chains stay
            # distinct because their *base* keys differ (key_a vs key_b),
            # not because of the label.
            self._recv_key = _advance_key(self._recv_key, self.transcript_hash,
                                          self._recv_epoch, b"send")
            self._recv_cipher = ChaCha20Poly1305(self._recv_key)
            self.rekeys_received += 1

    def _maybe_time_rekey(self) -> None:
        """Time-triggered rekey.

        Implemented by jumping the send sequence number to the next
        epoch boundary rather than by sending a control message. The
        receiver's replay window tolerates gaps (it only rejects old and
        duplicate sequence numbers), and the receiver derives the epoch
        straight from the sequence number, so the two ends stay in sync
        with no extra traffic.
        """
        if self._rekey_seconds <= 0:
            return
        if (time.monotonic() - self._last_rekey_at) < self._rekey_seconds:
            return
        boundary = (self._send_epoch + 1) * self._rekey_messages
        if self._send_seq < boundary:
            self._send_seq = boundary

    @staticmethod
    def _nonce(seq: int) -> bytes:
        # 12-byte nonce: 4 zero bytes + 8-byte big-endian sequence number.
        return b"\x00\x00\x00\x00" + SEQ_STRUCT.pack(seq)

    # -- data path -------------------------------------------------------

    async def send(self, plaintext: bytes) -> None:
        async with self._send_lock:
            self._maybe_time_rekey()
            seq = self._send_seq
            epoch = self._epoch_for(seq)
            if epoch != self._send_epoch:
                self._advance_send_to(epoch)
            seq_bytes = SEQ_STRUCT.pack(seq)
            ciphertext = self._send_cipher.encrypt(self._nonce(seq), plaintext, seq_bytes)
            await write_frame(self._writer, seq_bytes + ciphertext)
            self._send_seq = seq + 1

    async def recv(self) -> bytes:
        # read_frame already enforces MAX_FRAME_SIZE before allocating,
        # so an oversized-length attack is rejected here too, not just
        # during the cleartext handshake phase.
        while True:
            frame = await read_frame(self._reader)
            if len(frame) < SEQ_LEN + AEAD_TAG_LEN:
                raise HandshakeFailed("truncated secure frame")
            seq_bytes = frame[:SEQ_LEN]
            (seq,) = SEQ_STRUCT.unpack(seq_bytes)
            ciphertext = frame[SEQ_LEN:]

            if not self._replay.check_and_update(seq):
                # Drop and keep reading: a replayed frame must not tear
                # down a healthy connection (that would itself be a DoS
                # lever for anyone who can inject one packet).
                self.replays_dropped += 1
                logger.warning("dropping replayed/out-of-window frame seq=%d", seq)
                continue

            self._advance_recv_to(self._epoch_for(seq))
            try:
                return self._recv_cipher.decrypt(self._nonce(seq), ciphertext, seq_bytes)
            except Exception as e:
                raise HandshakeFailed("frame decryption/authentication failed") from e

    async def send_msg(self, msg) -> None:
        await self.send(msg.encode())

    async def recv_msg(self):
        from .protocol import Message
        return Message.decode(await self.recv())

    def stats(self) -> dict:
        return {
            "send_seq": self._send_seq,
            "send_epoch": self._send_epoch,
            "recv_epoch": self._recv_epoch,
            "highest_recv_seq": self._replay.highest,
            "rekeys_sent": self.rekeys_sent,
            "rekeys_received": self.rekeys_received,
            "replays_dropped": self.replays_dropped,
        }

    def close(self):
        self._writer.close()


async def perform_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             identity: NodeIdentity, node_name: str, ram_quota: int,
                             is_initiator: bool) -> tuple[SecureChannel, bytes, dict]:
    """Run the Hello -> Auth handshake and return (channel, peer_pubkey, peer_info).

    Both cleartext messages (Hello, Auth) are read via read_frame(),
    which enforces MAX_FRAME_SIZE, so a malicious peer can't force an
    oversized allocation even before encryption is established -- this
    was a gap in the reference implementation.

    ``peer_info`` carries ``transcript_hash`` and ``sas`` so the caller
    (peers.PeerManager) can drive out-of-band verification without
    re-deriving anything.
    """
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    my_nonce = os.urandom(16)

    hello = msgpack.packb({"nonce": my_nonce, "eph_pub": eph_pub_bytes,
                            "name": node_name, "version": config.PROTOCOL_VERSION})
    await write_frame(writer, hello)
    peer_hello_raw = await read_frame(reader)
    peer_hello = msgpack.unpackb(peer_hello_raw, raw=False)

    peer_version = peer_hello.get("version")
    if peer_version != config.PROTOCOL_VERSION:
        writer.close()
        raise HandshakeFailed(
            f"protocol version mismatch: peer speaks {peer_version}, we speak "
            f"{config.PROTOCOL_VERSION}")

    peer_nonce = peer_hello.get("nonce")
    if not isinstance(peer_nonce, (bytes, bytearray)) or len(peer_nonce) != len(my_nonce):
        writer.close()
        raise HandshakeFailed("peer sent a malformed handshake nonce")
    if hmac.compare_digest(bytes(peer_nonce), my_nonce):
        # Our own Hello reflected back at us: a mirror attack, and also
        # what you see if a misconfigured node dials itself.
        writer.close()
        raise HandshakeFailed("peer reflected our own handshake nonce -- refusing")

    peer_eph_raw = peer_hello.get("eph_pub")
    if not isinstance(peer_eph_raw, (bytes, bytearray)) or len(peer_eph_raw) != 32:
        writer.close()
        raise HandshakeFailed("peer sent a malformed ephemeral public key")
    if hmac.compare_digest(bytes(peer_eph_raw), eph_pub_bytes):
        writer.close()
        raise HandshakeFailed("peer reflected our own ephemeral key -- refusing")

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

    peer_pubkey_bytes = peer_auth.get("identity_pubkey")
    if not isinstance(peer_pubkey_bytes, (bytes, bytearray)) or len(peer_pubkey_bytes) != 32:
        writer.close()
        raise HandshakeFailed("peer sent a malformed identity public key")
    peer_pubkey_bytes = bytes(peer_pubkey_bytes)

    if hmac.compare_digest(peer_pubkey_bytes, identity.public_bytes):
        writer.close()
        raise HandshakeFailed(
            "peer presented our own identity key -- refusing self/mirror connection")

    peer_pub = Ed25519PublicKey.from_public_bytes(peer_pubkey_bytes)
    try:
        peer_pub.verify(peer_auth["signature"], t_hash)
    except InvalidSignature as e:
        writer.close()
        raise HandshakeFailed("peer signature over transcript did not verify (possible MITM)") from e

    peer_eph_pub = X25519PublicKey.from_public_bytes(bytes(peer_eph_raw))
    shared_secret = eph_priv.exchange(peer_eph_pub)
    key_a, key_b = _derive_traffic_keys(shared_secret, t_hash)
    send_key, recv_key = (key_a, key_b) if is_initiator else (key_b, key_a)

    channel = SecureChannel(reader, writer, send_key=send_key, recv_key=recv_key,
                            transcript_hash=t_hash)
    peer_info = {
        "name": peer_hello.get("name"),
        "ram_quota": peer_auth.get("ram_quota", 0),
        "transcript_hash": t_hash,
        "sas": short_authentication_string(t_hash),
    }
    return channel, peer_pubkey_bytes, peer_info
