"""Optional mutual-TLS transport for the peer protocol.

Position in the stack
---------------------
TLS here is *underneath* the existing Noise-style handshake, never a
replacement for it::

    TCP  ->  [optional mTLS tunnel]  ->  Hello/Auth handshake  ->  SecureChannel

Rationale: the Noise handshake is what actually authenticates a peer
identity in this system (Ed25519 identity keys, TOFU/pinning, SAS
verification). Swapping it for TLS would mean trusting a CA chain to
say who a peer is, which is a weaker and more operationally fragile
claim on a LAN of personal devices. But "must be TLS" is a real
procurement/compliance requirement in a lot of environments, so this
module makes TLS available as an extra outer layer that satisfies that
box without weakening anything.

What it gives you beyond the Noise layer:
  * a standard, auditable transport an enterprise middlebox can attest
  * client-certificate authentication at connection admission time, so
    a peer without a valid cert never even reaches the handshake code
  * optional SPKI/cert pinning, so a compromised or rogue CA in the
    trust store is not sufficient to impersonate a peer

Everything here is off by default (``config.TLS_ENABLED``).
"""
from __future__ import annotations

import hashlib
import logging
import ssl
from dataclasses import dataclass, field
from typing import Optional

from . import config

logger = logging.getLogger("memnode.tls")


class TlsPinMismatch(Exception):
    """The peer presented a valid chain but not the pinned certificate."""


class TlsConfigError(Exception):
    pass


@dataclass
class TlsSettings:
    """Everything needed to build the optional TLS layer.

    ``pinned_sha256`` holds lowercase hex SHA-256 fingerprints of the
    *DER-encoded peer certificates* that are acceptable. An empty set
    means "chain validation only, no pinning".
    """
    enabled: bool = config.TLS_ENABLED
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    cafile: Optional[str] = None
    require_client_cert: bool = config.TLS_REQUIRE_CLIENT_CERT
    pinned_sha256: set[str] = field(default_factory=set)

    def validate(self) -> None:
        if not self.enabled:
            return
        if not self.certfile or not self.keyfile:
            raise TlsConfigError("TLS enabled but --tls-cert/--tls-key were not supplied")
        if self.require_client_cert and not self.cafile:
            raise TlsConfigError(
                "mTLS requires --tls-ca (the CA that signs peer client certificates)")


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def build_server_context(settings: TlsSettings) -> Optional[ssl.SSLContext]:
    """Server side of the peer listener."""
    if not settings.enabled:
        return None
    settings.validate()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=settings.certfile, keyfile=settings.keyfile)
    if settings.require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=settings.cafile)
    return ctx


def build_client_context(settings: TlsSettings) -> Optional[ssl.SSLContext]:
    """Client side when dialling another node."""
    if not settings.enabled:
        return None
    settings.validate()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=settings.certfile, keyfile=settings.keyfile)
    if settings.cafile:
        ctx.load_verify_locations(cafile=settings.cafile)
        ctx.verify_mode = ssl.CERT_REQUIRED
    # Peers are identified by pinned cert + Ed25519 identity key, not by
    # DNS name -- nodes on a LAN routinely have no resolvable hostname
    # and their IP changes with DHCP. Hostname checking is therefore off
    # by design here; pinning is what replaces it.
    ctx.check_hostname = False
    return ctx


def peer_cert_fingerprint(writer) -> Optional[str]:
    """SHA-256 of the peer's DER certificate, or None if not a TLS transport."""
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return None
    return fingerprint_der(der)


def enforce_pin(writer, settings: TlsSettings) -> Optional[str]:
    """Raise TlsPinMismatch unless the peer cert matches a configured pin.

    Returns the observed fingerprint (useful for logging / first-run
    pin capture). A no-op when TLS or pinning is not configured.
    """
    if not settings.enabled or not settings.pinned_sha256:
        return None
    observed = peer_cert_fingerprint(writer)
    if observed is None:
        raise TlsPinMismatch("certificate pinning is configured but the peer sent no certificate")
    if observed.lower() not in {p.lower() for p in settings.pinned_sha256}:
        raise TlsPinMismatch(
            f"peer certificate {observed[:16]}... is not in the pin set "
            f"({len(settings.pinned_sha256)} pins configured)")
    return observed
