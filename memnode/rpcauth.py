"""Authentication for the local RPC control plane.

Why this exists
---------------
The RPC surface is not a read-only status API. It exposes ``store``,
``free``, ``connect``, ``remote_store`` and ``remote_free`` -- i.e. the
ability to allocate memory on this node, dial arbitrary hosts, and
delete other people's blocks. Before Phase 1 it had *no* authentication
at all and ``RpcServer.start()`` bound ``0.0.0.0``, so anything that
could reach port 7070 owned the daemon.

Two changes close that:

1. ``rpc.RpcServer`` now binds a loopback address and refuses a
   non-loopback bind unless explicitly forced.
2. Every TCP client must prove knowledge of a shared secret before any
   op is dispatched (this module).

Protocol
--------
Challenge-response over the existing length-prefixed JSON framing, so
the request/response shape of every op is unchanged:

    server -> client   {"memnode_auth": "challenge", "version": 1,
                        "challenge": "<64 hex chars>"}
    client -> server   {"response": "<hmac-sha256 hex>"}
    server -> client   {"ok": true}          (or {"ok": false, "error": ...})

The response is ``HMAC-SHA256(token, challenge_bytes)``. The challenge is
32 fresh random bytes per connection, so a captured response is useless
on any other connection -- this is a bearer secret, but not a replayable
one. Comparison uses ``hmac.compare_digest`` (constant time).

Unix-socket clients are exempt by default
(``config.RPC_AUTH_UNIX_SOCKET_EXEMPT``): access there is already gated
by filesystem permissions on the socket path, and requiring a token as
well mostly just pushes people to store the token somewhere worse.

Token storage
-------------
``~/.memcloud/rpc_token``, created 0600 on first run. This is the same
pattern used by Docker/BuildKit-style local daemons: the secret is
readable by the user who owns the daemon and nobody else.
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets
import stat
from hashlib import sha256
from pathlib import Path
from typing import Optional

from . import config

logger = logging.getLogger("memnode.rpcauth")

TOKEN_DIR = Path.home() / ".memcloud"
CHALLENGE_BYTES = 32


class RpcAuthError(Exception):
    pass


def default_token_path() -> Path:
    return TOKEN_DIR / config.RPC_TOKEN_FILENAME


def load_or_create_token(path: Optional[Path] = None) -> str:
    """Return the hex shared secret, generating it on first run.

    The file is created with mode 0600. If an existing token file is
    group- or world-readable we log a warning rather than silently
    trusting it -- a secret everyone can read is not a secret, and
    failing closed here would brick an existing deployment on upgrade.
    """
    path = Path(path) if path is not None else default_token_path()
    if path.exists():
        token = path.read_text().strip()
        if token:
            try:
                mode = stat.S_IMODE(path.stat().st_mode)
                if mode & 0o077:
                    logger.warning(
                        "RPC token file %s is mode %o -- readable beyond its owner; "
                        "run: chmod 600 %s", path, mode, path)
            except OSError:
                pass
            return token
        logger.warning("RPC token file %s was empty -- regenerating", path)

    token = secrets.token_hex(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with restrictive permissions from the start; writing then
    # chmod'ing leaves a window where the secret is world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)
    logger.info("generated new RPC token at %s", path)
    return token


def new_challenge() -> str:
    return secrets.token_hex(CHALLENGE_BYTES)


def compute_response(token: str, challenge: str) -> str:
    """HMAC-SHA256(token, challenge) as hex. Same function on both ends."""
    return hmac.new(token.encode("utf-8"), challenge.encode("ascii"), sha256).hexdigest()


def verify_response(token: str, challenge: str, response: object) -> bool:
    if not isinstance(response, str):
        return False
    expected = compute_response(token, challenge)
    return hmac.compare_digest(expected, response)


def is_loopback(host: str) -> bool:
    """True for addresses that are only reachable from this machine."""
    if not host:
        return False
    host = host.strip("[]")
    if host in ("localhost", "::1"):
        return True
    if host.startswith("127."):
        return True
    return False
