"""memnode entrypoint: wires together blocks, peers, discovery, and RPC.

Every background task/callback is wrapped so a single unhandled
exception logs and stops cleanly rather than disappearing silently --
the Python equivalent of the reference implementation's
"panic-on-unwrap kills the daemon" problem. An asyncio task that raises
without anyone awaiting it just vanishes unless you install an
exception handler on the loop, so we do that explicitly below.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import uuid

from . import config, rpcauth
from .blocks import BlockManager
from .discovery import Discovery
from .peers import PeerManager
from .ratelimit import HandshakeGuard
from .replication import ReplicationCoordinator
from .rpc import RpcServer
from .security import NodeIdentity
from .tlsmode import TlsSettings

logger = logging.getLogger("memnode.main")


async def _peer_listener(host: str, port: int, peer_manager: PeerManager):
    ssl_ctx = peer_manager.server_ssl_context()
    server = await asyncio.start_server(peer_manager.handle_incoming, host, port, ssl=ssl_ctx)
    logger.info("peer protocol listening on %s:%d (tls=%s)",
                host, port, "on" if ssl_ctx else "off")
    async with server:
        await server.serve_forever()


def _install_task_exception_logging(loop: asyncio.AbstractEventLoop):
    def handler(loop, context):
        logger.error(
            "unhandled error in background task: %s",
            context.get("message"),
            exc_info=context.get("exception"),
        )
    loop.set_exception_handler(handler)


async def run(args: argparse.Namespace):
    identity = NodeIdentity.generate()
    node_id = str(uuid.uuid4())
    block_manager = BlockManager(max_memory_bytes=args.ram_quota)

    tls_settings = TlsSettings(
        enabled=bool(args.tls_cert and args.tls_key),
        certfile=args.tls_cert,
        keyfile=args.tls_key,
        cafile=args.tls_ca,
        require_client_cert=not args.tls_no_client_cert,
        pinned_sha256=set(args.tls_pin or []),
    )
    tls_settings.validate()

    peer_manager = PeerManager(
        identity, args.name, args.ram_quota,
        tls_settings=tls_settings,
        handshake_guard=HandshakeGuard(
            max_per_ip_per_window=args.handshake_rate,
            max_inflight_per_ip=args.handshake_inflight_per_ip,
        ),
        handshake_timeout=args.handshake_timeout,
        require_sas_verification=args.require_verification,
    )

    # Wires incoming StoreBlock/RequestBlock messages from peers to this
    # node's BlockManager, and gives the RPC layer a way to place/fetch
    # blocks on *other* nodes -- this is what makes it a pool instead of
    # N independent caches. See replication.py for why this exists.
    replication = ReplicationCoordinator(block_manager, peer_manager)
    peer_manager.message_handler = replication.handle_message

    auth_token = None
    if not args.no_rpc_auth:
        auth_token = rpcauth.load_or_create_token(args.rpc_token_file)

    rpc_server = RpcServer(block_manager, peer_manager, replication=replication,
                            rpc_port=args.rpc_port, rpc_unix_socket=args.rpc_socket,
                            bind_host=args.rpc_bind,
                            auth_token=auth_token,
                            require_auth=not args.no_rpc_auth,
                            allow_remote_bind=args.allow_remote_rpc)
    discovery = Discovery(node_id, args.name, args.peer_port, peer_manager)

    logger.info("node id: %s", node_id)
    logger.info("identity pubkey: %s", identity.public_bytes.hex()[:16])
    if auth_token:
        logger.info("RPC auth enabled -- token file: %s",
                    args.rpc_token_file or rpcauth.default_token_path())
    else:
        logger.warning("RPC auth DISABLED (--no-rpc-auth) -- loopback binding is the only "
                       "thing protecting the control plane")

    await rpc_server.start()
    if not args.no_mdns:
        try:
            await discovery.start()
        except Exception:
            logger.exception("mDNS discovery failed to start -- continuing without it "
                              "(use --connect host:port or the RPC 'connect' op instead)")

    await _peer_listener("0.0.0.0", args.peer_port, peer_manager)


def main():
    parser = argparse.ArgumentParser(description="memnode: distributed RAM pool daemon")
    parser.add_argument("--name", default="unnamed-node", help="human-readable node name")
    parser.add_argument("--ram-quota", type=int, default=config.DEFAULT_RAM_QUOTA_BYTES,
                         help="bytes of RAM to advertise/allow peers to use on this node")
    parser.add_argument("--peer-port", type=int, default=config.PEER_TCP_PORT,
                         help="TCP port for the node-to-node protocol (must differ per node "
                              "when running multiple nodes on one machine)")
    parser.add_argument("--rpc-port", type=int, default=config.RPC_TCP_PORT,
                         help="TCP port for local RPC (must differ per node on one machine)")
    parser.add_argument("--rpc-socket", default=None,
                         help="Unix socket path for local RPC (defaults to a name derived "
                              "from --rpc-port so multiple local nodes don't collide)")
    parser.add_argument("--no-mdns", action="store_true",
                         help="skip mDNS auto-discovery (recommended when demoing several "
                              "nodes on localhost -- use the RPC 'connect' op instead)")
    parser.add_argument("--log-level", default="INFO")

    sec = parser.add_argument_group("security (phase 1)")
    sec.add_argument("--rpc-bind", default=config.RPC_BIND_HOST,
                      help="address the RPC control plane binds to (loopback by default; "
                           "binding elsewhere requires --allow-remote-rpc)")
    sec.add_argument("--allow-remote-rpc", action="store_true",
                      help="permit a non-loopback RPC bind -- only with an authenticated "
                           "proxy in front of it")
    sec.add_argument("--no-rpc-auth", action="store_true",
                      help="disable RPC shared-secret auth (loopback only; not recommended)")
    sec.add_argument("--rpc-token-file", default=None,
                      help=f"path to the RPC shared secret "
                           f"(default: ~/.memcloud/{config.RPC_TOKEN_FILENAME})")
    sec.add_argument("--handshake-timeout", type=float, default=config.HANDSHAKE_TIMEOUT_SECONDS,
                      help="seconds before an incomplete peer handshake is dropped")
    sec.add_argument("--handshake-rate", type=int, default=config.HANDSHAKE_MAX_PER_IP_PER_WINDOW,
                      help=f"max handshake attempts per source IP per "
                           f"{config.HANDSHAKE_RATE_WINDOW_SECONDS:g}s")
    sec.add_argument("--handshake-inflight-per-ip", type=int,
                      default=config.HANDSHAKE_MAX_INFLIGHT_PER_IP,
                      help="max concurrent handshakes from one source IP")
    sec.add_argument("--require-verification", action="store_true",
                      help="require out-of-band SAS/QR confirmation on first contact "
                           "instead of bare trust-on-first-use")

    tls = parser.add_argument_group("optional mTLS transport (layered under the Noise handshake)")
    tls.add_argument("--tls-cert", default=None, help="PEM certificate for this node")
    tls.add_argument("--tls-key", default=None, help="PEM private key for this node")
    tls.add_argument("--tls-ca", default=None, help="CA bundle used to verify peer certificates")
    tls.add_argument("--tls-no-client-cert", action="store_true",
                      help="accept peers without a client certificate (drops the 'm' in mTLS)")
    tls.add_argument("--tls-pin", action="append", default=None, metavar="SHA256_HEX",
                      help="pin an acceptable peer certificate fingerprint (repeatable)")

    args = parser.parse_args()

    if args.rpc_socket is None:
        if os.name == "nt":
            # Unix sockets are not available on Windows; the RPC server
            # will fall back to TCP-only mode automatically.
            args.rpc_socket = ""
        else:
            args.rpc_socket = f"/tmp/memcloud-{args.rpc_port}.sock"

    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_task_exception_logging(loop)
    try:
        loop.run_until_complete(run(args))
    except KeyboardInterrupt:
        logger.info("shutting down")


if __name__ == "__main__":
    main()
