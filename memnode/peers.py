"""Peer connection management: trust store, consent flow, and the
registry of currently-connected peers.

Every per-connection coroutine (`handle_incoming`, the read loop) is
wrapped in try/except so a single malformed message or handshake
failure logs a warning and drops that one connection, instead of
propagating as an unhandled exception that could silently kill an
asyncio task (the Python analogue of the reference implementation's
panic-on-unwrap problem).

Phase 1 hardening
-----------------
* ``HandshakeGuard`` admission control + a hard ``asyncio.wait_for``
  timeout around the handshake, so an attacker cannot flood the peer
  listener with half-open or crypto-burning connections.
* ``TrustStore`` v2: records are structured (first seen, last seen,
  verification method, observed addresses) instead of a bare
  ``pubkey -> name`` map, and a *known identity presenting a new
  display name* or *a known name presenting a new identity* is
  surfaced rather than silently accepted.
* Out-of-band verification: the handshake now yields a short
  authentication string (SAS) derived from the transcript hash, plus a
  ``memcloud://pair`` URI that can be rendered as a QR code. Bare TOFU
  is still the default, but ``config.REQUIRE_SAS_VERIFICATION`` turns
  first contact into an explicit "do these six digits match?" step.
* Optional mTLS underneath the handshake, with certificate pinning.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import quote

from . import config
from .ratelimit import HandshakeGuard, HandshakeRejected, peer_ip
from .security import NodeIdentity, SecureChannel, perform_handshake
from .tlsmode import TlsPinMismatch, TlsSettings, build_client_context, build_server_context, enforce_pin

logger = logging.getLogger("memnode.peers")

TRUSTED_DEVICES_PATH = Path.home() / ".memcloud" / "trusted_devices.json"


@dataclass
class PeerInfo:
    pubkey_hex: str
    name: str
    addr: str
    channel: SecureChannel
    remote_quota: int = 0
    sas: str = ""
    verified: bool = False


def pairing_uri(pubkey_hex: str, sas: str = "", name: str = "") -> str:
    """A scannable representation of 'this identity, this session code'.

    Rendered as a QR code (see ``render_qr_ascii``) this is the
    out-of-band channel: you compare what your screen shows against what
    the other device's screen shows. An attacker sitting in the middle
    completes two *different* handshakes and therefore cannot produce a
    matching ``sas``.
    """
    uri = f"memcloud://pair?pk={pubkey_hex}"
    if sas:
        uri += f"&sas={sas}"
    if name:
        uri += f"&name={quote(name)}"
    return uri


def render_qr_ascii(text: str) -> Optional[str]:
    """Render ``text`` as an ASCII QR code, or None if unavailable.

    ``qrcode`` is an optional dependency on purpose: a daemon that
    cannot start because a *display* helper is missing would be a worse
    bug than not having QR output. Callers fall back to showing the URI
    and the digits.
    """
    try:
        import qrcode  # type: ignore
    except ImportError:
        return None
    try:
        import io
        qr = qrcode.QRCode(border=1)
        qr.add_data(text)
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf)
        return buf.getvalue()
    except Exception:  # pragma: no cover - display helper must never crash us
        logger.debug("QR rendering failed", exc_info=True)
        return None


class TrustStore:
    """Persistent record of which peer identities this node accepts.

    On-disk format (v2)::

        {"version": 2,
         "peers": {"<pubkey_hex>": {"name": ..., "first_seen": ...,
                                     "last_seen": ..., "verified": bool,
                                     "method": "tofu"|"sas"|"qr"|"manual",
                                     "addresses": [...]}}}

    v1 files (a flat ``{pubkey_hex: name}`` map) are migrated on load,
    marked ``method="tofu"``, ``verified=False``.

    Why the extra fields matter: bare TOFU on a hex string tells you
    "I have seen this key before" and nothing else. Recording *how* the
    key was accepted lets a deployment require that sensitive peers were
    confirmed out of band, and recording names/addresses lets the daemon
    flag the two substitution cases plain TOFU misses -- a familiar name
    arriving on a brand-new key, or a known key suddenly renaming itself.
    """

    def __init__(self, path: Path = TRUSTED_DEVICES_PATH):
        self.path = path
        self._peers: dict[str, dict] = {}
        self._load()

    # -- persistence -----------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("could not read %s (%s), starting fresh", self.path.name, e)
            self._peers = {}
            return

        if isinstance(raw, dict) and raw.get("version") == config.TRUST_STORE_VERSION:
            peers = raw.get("peers", {})
            self._peers = {k: v for k, v in peers.items() if isinstance(v, dict)}
            return

        if isinstance(raw, dict):
            # v1 migration: {pubkey_hex: name}
            now = time.time()
            migrated = {}
            for pubkey, name in raw.items():
                if isinstance(name, str):
                    migrated[pubkey] = {"name": name, "first_seen": now, "last_seen": now,
                                        "verified": False, "method": "tofu", "addresses": []}
            if migrated:
                logger.info("migrated %d trusted device(s) from v1 trust store", len(migrated))
            self._peers = migrated
            self._save()
            return

        logger.warning("unrecognised trust store format in %s -- starting fresh", self.path)
        self._peers = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": config.TRUST_STORE_VERSION, "peers": self._peers}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(self.path)   # atomic: never leave a half-written trust file

    # -- queries ---------------------------------------------------------

    def is_trusted(self, pubkey_hex: str) -> bool:
        return pubkey_hex in self._peers

    def is_verified(self, pubkey_hex: str) -> bool:
        return bool(self._peers.get(pubkey_hex, {}).get("verified"))

    def get(self, pubkey_hex: str) -> Optional[dict]:
        entry = self._peers.get(pubkey_hex)
        return dict(entry) if entry else None

    def all(self) -> dict[str, dict]:
        return {k: dict(v) for k, v in self._peers.items()}

    def identity_conflicts(self, pubkey_hex: str, name: str) -> list[str]:
        """Substitution warnings plain TOFU would miss.

        Two cases, both worth a human's attention:
          * a *different* stored key already uses this display name --
            someone may be impersonating a device you know;
          * this key is stored under a different name -- a known device
            renamed itself, which is usually benign but is also what a
            key-reuse attack looks like.
        """
        warnings: list[str] = []
        for other_key, entry in self._peers.items():
            if other_key == pubkey_hex:
                continue
            if entry.get("name") == name:
                warnings.append(
                    f"display name {name!r} is already pinned to a different identity "
                    f"({other_key[:16]}...)")
        existing = self._peers.get(pubkey_hex)
        if existing and existing.get("name") not in (None, name):
            warnings.append(
                f"known identity {pubkey_hex[:16]}... previously called itself "
                f"{existing.get('name')!r}, now {name!r}")
        return warnings

    # -- mutations -------------------------------------------------------

    def trust(self, pubkey_hex: str, name: str, *, verified: bool = False,
              method: str = "tofu", addr: Optional[str] = None) -> None:
        now = time.time()
        entry = self._peers.get(pubkey_hex)
        if entry is None:
            entry = {"name": name, "first_seen": now, "addresses": []}
            self._peers[pubkey_hex] = entry
        entry["name"] = name
        entry["last_seen"] = now
        # Verification is sticky: a peer confirmed out of band once stays
        # confirmed, and a later plain-TOFU reconnect must not silently
        # downgrade it.
        entry["verified"] = bool(entry.get("verified")) or verified
        if verified or "method" not in entry:
            entry["method"] = method
        if addr:
            addrs = entry.setdefault("addresses", [])
            if addr not in addrs:
                addrs.append(addr)
                del addrs[:-8]      # keep the last 8 observed addresses
        self._save()

    def mark_verified(self, pubkey_hex: str, method: str = "sas") -> bool:
        entry = self._peers.get(pubkey_hex)
        if entry is None:
            return False
        entry["verified"] = True
        entry["method"] = method
        self._save()
        return True

    def revoke(self, pubkey_hex: str) -> bool:
        if self._peers.pop(pubkey_hex, None) is None:
            return False
        self._save()
        return True


ConsentCallback = Callable[..., Any]


class PeerManager:
    def __init__(self, identity: NodeIdentity, node_name: str, ram_quota: int,
                 consent_callback: Optional[ConsentCallback] = None,
                 message_handler: Optional[Callable] = None,
                 tls_settings: Optional[TlsSettings] = None,
                 handshake_guard: Optional[HandshakeGuard] = None,
                 handshake_timeout: float = config.HANDSHAKE_TIMEOUT_SECONDS,
                 require_sas_verification: bool = config.REQUIRE_SAS_VERIFICATION):
        self.identity = identity
        self.node_name = node_name
        self.ram_quota = ram_quota
        self.trust_store = TrustStore()
        self.peers: dict[str, PeerInfo] = {}
        # Defaults to auto-approve so the daemon is usable headless / in
        # tests. Swap in a real prompt (CLI confirm, UI toast, etc.) for
        # anything demoed to strangers on a shared network.
        self.consent_callback: ConsentCallback = consent_callback or (lambda *_a, **_k: True)
        self.message_handler = message_handler
        self.tls_settings = tls_settings or TlsSettings()
        self.handshake_guard = handshake_guard or HandshakeGuard()
        self.handshake_timeout = handshake_timeout
        self.require_sas_verification = require_sas_verification
        self._lock = asyncio.Lock()

    # -- server side -----------------------------------------------------

    def server_ssl_context(self):
        """SSL context for the peer listener, or None when TLS is off."""
        return build_server_context(self.tls_settings)

    async def handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        ip = peer_ip(addr)

        # Admission control happens BEFORE any crypto: the whole point is
        # that a flood must be cheap to refuse.
        try:
            self.handshake_guard.acquire(ip)
        except HandshakeRejected as e:
            logger.warning("refusing connection from %s: %s", addr, e)
            writer.close()
            return

        try:
            try:
                enforce_pin(writer, self.tls_settings)
            except TlsPinMismatch as e:
                logger.warning("TLS pin check failed for %s: %s", addr, e)
                writer.close()
                return

            try:
                channel, peer_pubkey, peer_info = await asyncio.wait_for(
                    perform_handshake(reader, writer, self.identity, self.node_name,
                                      self.ram_quota, is_initiator=False),
                    timeout=self.handshake_timeout)
            except asyncio.TimeoutError:
                # A peer that opens a socket and then stalls used to park
                # a task forever; now it costs us one timeout.
                logger.warning("handshake with %s timed out after %.1fs",
                               addr, self.handshake_timeout)
                writer.close()
                return
            except Exception as e:
                logger.warning("handshake with %s failed: %s", addr, e)
                writer.close()
                return
        finally:
            self.handshake_guard.release(ip)

        pubkey_hex = peer_pubkey.hex()
        try:
            if not await self._check_consent(pubkey_hex, peer_info.get("name", "unknown"),
                                             str(addr), peer_info.get("sas", "")):
                logger.info("connection from %s (%s) denied by consent policy", addr, pubkey_hex[:8])
                channel.close()
                return

            await self._register(pubkey_hex, peer_info.get("name", "unknown"), str(addr),
                                 channel, peer_info)
            await self._read_loop(pubkey_hex, channel)
        except Exception:
            logger.exception("unexpected error handling peer %s -- dropping connection", addr)
            channel.close()

    # -- client side -----------------------------------------------------

    async def connect_to(self, host: str, port: int) -> str:
        ssl_ctx = build_client_context(self.tls_settings)
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)

        try:
            enforce_pin(writer, self.tls_settings)
        except TlsPinMismatch:
            writer.close()
            raise

        try:
            channel, peer_pubkey, peer_info = await asyncio.wait_for(
                perform_handshake(reader, writer, self.identity, self.node_name,
                                  self.ram_quota, is_initiator=True),
                timeout=self.handshake_timeout)
        except asyncio.TimeoutError as e:
            writer.close()
            raise TimeoutError(
                f"handshake with {host}:{port} timed out after {self.handshake_timeout}s") from e

        pubkey_hex = peer_pubkey.hex()
        if not await self._check_consent(pubkey_hex, peer_info.get("name", "unknown"),
                                         f"{host}:{port}", peer_info.get("sas", "")):
            channel.close()
            raise PermissionError(f"outbound connection to {pubkey_hex[:8]} denied by consent policy")

        await self._register(pubkey_hex, peer_info.get("name", "unknown"),
                             f"{host}:{port}", channel, peer_info)
        asyncio.create_task(self._read_loop(pubkey_hex, channel))
        return pubkey_hex

    # -- consent / trust -------------------------------------------------

    async def _invoke_consent(self, pubkey_hex: str, name: str, addr: str, sas: str):
        """Call the consent callback, tolerating 3-arg and 4-arg callbacks.

        The pre-Phase-1 signature was ``(pubkey_hex, name, addr)``.
        Existing callbacks keep working; new ones can take a fourth
        ``sas`` argument to show the out-of-band code.
        """
        cb = self.consent_callback
        try:
            params = inspect.signature(cb).parameters
            takes_varargs = any(p.kind is inspect.Parameter.VAR_POSITIONAL for p in params.values())
            positional = sum(
                1 for p in params.values()
                if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                              inspect.Parameter.POSITIONAL_OR_KEYWORD))
        except (TypeError, ValueError):
            takes_varargs, positional = True, 4

        if takes_varargs or positional >= 4:
            return cb(pubkey_hex, name, addr, sas)
        return cb(pubkey_hex, name, addr)

    async def _check_consent(self, pubkey_hex: str, name: str, addr: str, sas: str = "") -> bool:
        entry = self.trust_store.get(pubkey_hex)

        if entry is not None:
            if self.require_sas_verification and not entry.get("verified"):
                logger.warning(
                    "peer %s is known but was never verified out of band; "
                    "REQUIRE_SAS_VERIFICATION is on -- re-prompting", pubkey_hex[:8])
            else:
                # Refresh last_seen / observed address without re-prompting.
                self.trust_store.trust(pubkey_hex, name, addr=addr)
                return True

        for warning in self.trust_store.identity_conflicts(pubkey_hex, name):
            logger.warning("trust conflict for %s: %s", addr, warning)

        if sas:
            logger.info("first contact with %s (%s) -- verification code %s | %s",
                        name, pubkey_hex[:16], sas, pairing_uri(pubkey_hex, sas, name))

        approved = await self._invoke_consent(pubkey_hex, name, addr, sas)
        if inspect.isawaitable(approved):
            approved = await approved
        approved = bool(approved)

        if approved:
            # This is the actual "trust on first use" step: remember this
            # identity so future connections skip the consent prompt
            # entirely. Without this call the TrustStore file is inert --
            # every connection would re-run consent from scratch.
            method = "sas" if self.require_sas_verification else "tofu"
            self.trust_store.trust(pubkey_hex, name, verified=self.require_sas_verification,
                                   method=method, addr=addr)
        return approved

    def verify_peer(self, pubkey_hex: str, method: str = "sas") -> bool:
        """Record that a peer's SAS/QR was confirmed out of band."""
        ok = self.trust_store.mark_verified(pubkey_hex, method=method)
        if ok and pubkey_hex in self.peers:
            self.peers[pubkey_hex].verified = True
        return ok

    # -- registry --------------------------------------------------------

    async def _register(self, pubkey_hex, name, addr, channel, peer_info):
        async with self._lock:
            self.peers[pubkey_hex] = PeerInfo(
                pubkey_hex=pubkey_hex, name=name, addr=addr, channel=channel,
                remote_quota=peer_info.get("ram_quota", 0),
                sas=peer_info.get("sas", ""),
                verified=self.trust_store.is_verified(pubkey_hex),
            )
        logger.info("peer connected: %s (%s) at %s [verified=%s]",
                    name, pubkey_hex[:8], addr, self.trust_store.is_verified(pubkey_hex))

    async def _read_loop(self, pubkey_hex: str, channel: SecureChannel):
        try:
            while True:
                msg = await channel.recv_msg()
                if self.message_handler is not None:
                    try:
                        await self.message_handler(pubkey_hex, msg)
                    except Exception:
                        logger.exception("message handler raised for msg from %s -- continuing",
                                         pubkey_hex[:8])
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
            candidates = [(pid, p.remote_quota) for pid, p in self.peers.items()
                          if p.remote_quota >= size]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c[1])[0]

    async def list_peers(self) -> list[dict]:
        async with self._lock:
            return [{"pubkey": p.pubkey_hex[:8], "name": p.name, "addr": p.addr,
                     "remote_quota": p.remote_quota, "verified": p.verified,
                     "sas": p.sas} for p in self.peers.values()]
