"""mDNS discovery via zeroconf -- the Python equivalent of mdns-sd.

Advertises this node as _memcloud._tcp.local. and listens for other
nodes advertising the same service, auto-connecting via PeerManager
when a new node is found (subject to the peer manager's own consent
flow -- discovery never bypasses trust checks).
"""
from __future__ import annotations

import asyncio
import logging
import socket

from zeroconf import ServiceInfo, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from . import config

logger = logging.getLogger("memnode.discovery")


class Discovery:
    def __init__(self, node_id: str, node_name: str, port: int, peer_manager):
        self.node_id = node_id
        self.node_name = node_name
        self.port = port
        self.peer_manager = peer_manager
        self._azc: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._loop = asyncio.get_event_loop()

    async def start(self):
        self._azc = AsyncZeroconf()
        local_ip = socket.gethostbyname(socket.gethostname())
        info = ServiceInfo(
            config.MDNS_SERVICE_TYPE,
            f"{self.node_id}.{config.MDNS_SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={"name": self.node_name, "id": self.node_id},
        )
        await self._azc.async_register_service(info)
        self._browser = AsyncServiceBrowser(
            self._azc.zeroconf, config.MDNS_SERVICE_TYPE, handlers=[self._on_change])
        logger.info("mDNS discovery started, advertising %s on port %d", self.node_name, self.port)

    def _on_change(self, zeroconf, service_type, name, state_change):
        # The zeroconf callback is synchronous; schedule the actual
        # (async) connect attempt on the running loop instead of
        # blocking the callback.
        self._loop.create_task(self._maybe_connect(zeroconf, service_type, name, state_change))

    async def _maybe_connect(self, zeroconf, service_type, name, state_change):
        if state_change != ServiceStateChange.Added:
            return
        if name.startswith(self.node_id):
            return  # don't connect to ourselves

        try:
            info = AsyncServiceInfo(service_type, name)
            if not await info.async_request(zeroconf, 3000):
                return
            addresses = info.parsed_scoped_addresses()
            if not addresses:
                return
            host, port = addresses[0], info.port
            await self.peer_manager.connect_to(host, port)
        except Exception as e:
            # Discovery must never crash the daemon over one bad/unreachable
            # peer -- log and keep browsing.
            logger.debug("auto-connect for %s failed: %s", name, e)

    async def stop(self):
        if self._browser:
            await self._browser.async_cancel()
        if self._azc:
            await self._azc.async_close()
