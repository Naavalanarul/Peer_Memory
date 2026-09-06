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

from . import config
from .blocks import BlockManager
from .discovery import Discovery
from .peers import PeerManager
from .replication import ReplicationCoordinator
from .rpc import RpcServer
from .security import NodeIdentity

logger = logging.getLogger("memnode.main")


async def _peer_listener(host: str, port: int, peer_manager: PeerManager):
    server = await asyncio.start_server(peer_manager.handle_incoming, host, port)
    logger.info("peer protocol listening on %s:%d", host, port)
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
    peer_manager = PeerManager(identity, args.name, args.ram_quota)

    # Wires incoming StoreBlock/RequestBlock messages from peers to this
    # node's BlockManager, and gives the RPC layer a way to place/fetch
    # blocks on *other* nodes -- this is what makes it a pool instead of
    # N independent caches. See replication.py for why this exists.
    replication = ReplicationCoordinator(block_manager, peer_manager)
    peer_manager.message_handler = replication.handle_message

    rpc_server = RpcServer(block_manager, peer_manager, replication=replication,
                            rpc_port=args.rpc_port, rpc_unix_socket=args.rpc_socket)
    discovery = Discovery(node_id, args.name, args.peer_port, peer_manager)

    logger.info("node id: %s", node_id)
    logger.info("identity pubkey: %s", identity.public_bytes.hex()[:16])

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
