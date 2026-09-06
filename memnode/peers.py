"""Peer connection management: TOFU trust model, consent flow, and the
registry of currently-connected peers.

Every per-connection coroutine (`handle_incoming`, the read loop) is
wrapped in try/except so a single malformed message or handshake
failure logs a warning and drops that one connection, instead of
propagating as an unhandled exception that could silently kill an
asyncio task (the Python analogue of the reference implementation's
panic-on-unwrap problem).
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .security import NodeIdentity, SecureChannel, perform_handshake

logger = logging.getLogger("memnode.peers")

TRUSTED_DEVICES_PATH = Path.home() / ".memcloud" / "trusted_devices.json"


@dataclass
class PeerInfo:
    pubkey_hex: str
    name: str
    addr: str
    channel: SecureChannel
    remote_quota: int = 0


class TrustStore:
    """Persists which peer identities the user has said 'always trust' to,
    mirroring the reference implementation's ~/.memcloud/trusted_devices.json."""

    def __init__(self, path: Path = TRUSTED_DEVICES_PATH):
        self.path = path
        self._trusted: dict[str, str] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self._trusted = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("could not read trusted_devices.json (%s), starting fresh", e)
                self._trusted = {}

    def is_trusted(self, pubkey_hex: str) -> bool:
        return pubkey_hex in self._trusted

    def trust(self, pubkey_hex: str, name: str) -> None:
        self._trusted[pubkey_hex] = name
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._trusted, indent=2))


ConsentCallback = Callable[[str, str, str], "bool | asyncio.Future"]


class PeerManager:
    def __init__(self, identity: NodeIdentity, node_name: str, ram_quota: int,
                 consent_callback: Optional[ConsentCallback] = None,
                 message_handler: Optional[Callable] = None):
        self.identity = identity
        self.node_name = node_name
        self.ram_quota = ram_quota
        self.trust_store = TrustStore()
        self.peers: dict[str, PeerInfo] = {}
        # Defaults to auto-approve so the daemon is usable headless / in
        # tests. Swap in a real prompt (CLI confirm, UI toast, etc.) for
        # anything demoed to strangers on a shared network.
        self.consent_callback: ConsentCallback = consent_callback or (lambda *_: True)
        self.message_handler = message_handler
        self._lock = asyncio.Lock()

    async def handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        try:
            channel, peer_pubkey, peer_info = await perform_handshake(
                reader, writer, self.identity, self.node_name, self.ram_quota, is_initiator=False)
        except Exception as e:
            logger.warning("handshake with %s failed: %s", addr, e)
            writer.close()
            return

        pubkey_hex = peer_pubkey.hex()
        try:
            if not await self._check_consent(pubkey_hex, peer_info.get("name", "unknown"), str(addr)):
                logger.info("connection from %s (%s) denied by consent policy", addr, pubkey_hex[:8])
                channel.close()
                return

            await self._register(pubkey_hex, peer_info.get("name", "unknown"), str(addr), channel, peer_info)
            await self._read_loop(pubkey_hex, channel)
        except Exception:
            logger.exception("unexpected error handling peer %s -- dropping connection", addr)
            channel.close()

    async def connect_to(self, host: str, port: int) -> str:
        reader, writer = await asyncio.open_connection(host, port)
        channel, peer_pubkey, peer_info = await perform_handshake(
            reader, writer, self.identity, self.node_name, self.ram_quota, is_initiator=True)

        pubkey_hex = peer_pubkey.hex()
        await self._register(pubkey_hex, peer_info.get("name", "unknown"), f"{host}:{port}", channel, peer_info)
        asyncio.create_task(self._read_loop(pubkey_hex, channel))
        return pubkey_hex

    async def _check_consent(self, pubkey_hex: str, name: str, addr: str) -> bool:
        if self.trust_store.is_trusted(pubkey_hex):
            return True
        approved = self.consent_callback(pubkey_hex, name, addr)
        if asyncio.iscoroutine(approved):
            approved = await approved
        approved = bool(approved)
        if approved:
            # This is the actual "trust on first use" step: remember this
            # identity so future connections skip the consent prompt
            # entirely (is_trusted() above short-circuits next time).
            # Without this call the TrustStore/trusted_devices.json file
            # is inert -- every single connection re-runs consent_callback
            # from scratch, even from a peer approved a moment ago.
            self.trust_store.trust(pubkey_hex, name)
        return approved

    async def _register(self, pubkey_hex, name, addr, channel, peer_info):
        async with self._lock:
            self.peers[pubkey_hex] = PeerInfo(
                pubkey_hex=pubkey_hex, name=name, addr=addr, channel=channel,
                remote_quota=peer_info.get("ram_quota", 0),
            )
        logger.info("peer connected: %s (%s) at %s", name, pubkey_hex[:8], addr)

    async def _read_loop(self, pubkey_hex: str, channel: SecureChannel):
        try:
            while True:
                msg = await channel.recv_msg()
                if self.message_handler is not None:
                    try:
                        await self.message_handler(pubkey_hex, msg)
                    except Exception:
                        logger.exception("message handler raised for msg from %s -- continuing", pubkey_hex[:8])
                else:
                    logger.debug("message from %s: %s", pubkey_hex[:8], msg.type)
        except Exception as e:
            logger.info("peer %s disconnected: %s", pubkey_hex[:8], e)
        finally:
            async with self._lock:
                self.peers.pop(pubkey_hex, None)

    async def send_to(self, pubkey_hex: str, msg) -> bool:
        async with self._lock:
            peer = self.peers.get(pubkey_hex)
        if peer is None:
            return False
        await peer.channel.send_msg(msg)
        return True

    async def best_peer_for_store(self, size: int) -> Optional[str]:
        """Pick the connected peer with the most free remote quota --
        capacity-aware placement instead of requiring a manual peer
        selection for every store call."""
        async with self._lock:
            candidates = [(pid, p.remote_quota) for pid, p in self.peers.items() if p.remote_quota >= size]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c[1])[0]

    async def list_peers(self) -> list[dict]:
        async with self._lock:
            return [{"pubkey": p.pubkey_hex[:8], "name": p.name, "addr": p.addr,
                     "remote_quota": p.remote_quota} for p in self.peers.values()]
