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


def _detect_lan_ip() -> str:
    """Find the IP address other machines on the LAN would actually use
    to reach us.

    `socket.gethostbyname(socket.gethostname())` -- the naive approach --
    is unreliable on a lot of real machines: many Linux distros map the
    hostname to 127.0.0.1 or 127.0.1.1 in /etc/hosts, which would make
    this node advertise an address that's only reachable from itself.
    On a hotspot/LAN demo that means every *other* machine's mDNS
    auto-connect attempt fails silently.

    The fix is the standard trick: open a UDP socket and "connect" it to
    an external address. UDP connect() doesn't send any packets -- it
    just asks the kernel to pick which local interface/IP would be used
    to route to that destination, which is exactly the IP we want to
    advertise. Falls back to the naive method if that fails for any
    reason (e.g. no network at all).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return socket.gethostbyname(socket.gethostname())


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
        local_ip = _detect_lan_ip()
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
        logger.info("mDNS discovery started, advertising %s at %s:%d",
                    self.node_name, local_ip, self.port)

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
