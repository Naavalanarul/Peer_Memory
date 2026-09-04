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
import uuid

from . import config
from .blocks import BlockManager
from .discovery import Discovery
from .peers import PeerManager
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
    rpc_server = RpcServer(block_manager, peer_manager)
    discovery = Discovery(node_id, args.name, config.PEER_TCP_PORT, peer_manager)

    logger.info("node id: %s", node_id)
    logger.info("identity pubkey: %s", identity.public_bytes.hex()[:16])

    await rpc_server.start()
    await discovery.start()

    await _peer_listener("0.0.0.0", config.PEER_TCP_PORT, peer_manager)


def main():
    parser = argparse.ArgumentParser(description="memnode: distributed RAM pool daemon")
    parser.add_argument("--name", default="unnamed-node", help="human-readable node name")
    parser.add_argument("--ram-quota", type=int, default=config.DEFAULT_RAM_QUOTA_BYTES,
                         help="bytes of RAM to advertise/allow peers to use on this node")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

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
