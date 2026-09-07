"""Handshake admission control for the peer TCP listener.

Threat being closed
-------------------
Before this, every inbound TCP connection on the peer port went straight
into ``perform_handshake``. That handshake does an X25519 key exchange
and an Ed25519 signature verification -- real asymmetric crypto -- and
it had no timeout, so a connection that opened a socket and then simply
stopped writing would occupy a task forever.

Two cheap attacks followed from that:

1. **CPU flood.** Open connections as fast as you can and complete the
   Hello; each one costs the victim a keygen + ECDH + signature verify.
2. **Task/FD exhaustion.** Open connections and send nothing. Each one
   parks an asyncio task blocked on ``readexactly`` with no deadline.

``HandshakeGuard`` bounds both: a sliding-window attempt rate per source
IP, a concurrency cap per source IP, and a global concurrency cap. The
timeout itself is applied by the caller (``peers.PeerManager``) with
``asyncio.wait_for``.

The limiter's own bookkeeping is bounded too
(``config.HANDSHAKE_GUARD_MAX_TRACKED_IPS``) so that spraying from many
spoofed source addresses cannot turn the defence into the memory leak.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field

from . import config

logger = logging.getLogger("memnode.ratelimit")


class HandshakeRejected(Exception):
    """Connection refused before any crypto was performed."""


@dataclass
class _IpState:
    attempts: deque = field(default_factory=deque)   # monotonic timestamps
    inflight: int = 0
    last_seen: float = 0.0


class HandshakeGuard:
    """Sliding-window rate limit + concurrency cap, keyed by source IP.

    Usage::

        guard = HandshakeGuard()
        guard.acquire(ip)          # raises HandshakeRejected
        try:
            ...run the handshake...
        finally:
            guard.release(ip)

    or, more simply, ``async with guard.slot(ip):``.

    Deliberately synchronous and lock-free: it is only ever touched from
    the event-loop thread, and every operation is O(1) amortised, so
    taking an ``asyncio.Lock`` here would add latency to the exact path
    we are trying to keep cheap.
    """

    def __init__(self,
                 max_per_ip_per_window: int = config.HANDSHAKE_MAX_PER_IP_PER_WINDOW,
                 window_seconds: float = config.HANDSHAKE_RATE_WINDOW_SECONDS,
                 max_inflight_per_ip: int = config.HANDSHAKE_MAX_INFLIGHT_PER_IP,
                 max_inflight_total: int = config.HANDSHAKE_MAX_INFLIGHT_TOTAL,
                 max_tracked_ips: int = config.HANDSHAKE_GUARD_MAX_TRACKED_IPS,
                 time_source=time.monotonic):
        self.max_per_ip_per_window = max_per_ip_per_window
        self.window_seconds = window_seconds
        self.max_inflight_per_ip = max_inflight_per_ip
        self.max_inflight_total = max_inflight_total
        self.max_tracked_ips = max_tracked_ips
        self._now = time_source
        self._ips: dict[str, _IpState] = {}
        self._inflight_total = 0
        self.rejected_rate = 0
        self.rejected_inflight_ip = 0
        self.rejected_inflight_total = 0

    # -- public API ------------------------------------------------------

    def acquire(self, ip: str) -> None:
        """Reserve a handshake slot for ``ip`` or raise HandshakeRejected."""
        now = self._now()
        state = self._ips.get(ip)
        if state is None:
            self._evict_if_needed(now)
            state = _IpState()
            self._ips[ip] = state
        state.last_seen = now

        cutoff = now - self.window_seconds
        while state.attempts and state.attempts[0] < cutoff:
            state.attempts.popleft()

        if self._inflight_total >= self.max_inflight_total:
            self.rejected_inflight_total += 1
            raise HandshakeRejected(
                f"global handshake concurrency limit reached "
                f"({self.max_inflight_total}); refusing {ip}")

        if state.inflight >= self.max_inflight_per_ip:
            self.rejected_inflight_ip += 1
            raise HandshakeRejected(
                f"{ip} already has {state.inflight} handshakes in flight "
                f"(max {self.max_inflight_per_ip})")

        if len(state.attempts) >= self.max_per_ip_per_window:
            self.rejected_rate += 1
            raise HandshakeRejected(
                f"{ip} exceeded {self.max_per_ip_per_window} handshake attempts "
                f"per {self.window_seconds:g}s")

        state.attempts.append(now)
        state.inflight += 1
        self._inflight_total += 1

    def release(self, ip: str) -> None:
        state = self._ips.get(ip)
        if state is None:
            return
        if state.inflight > 0:
            state.inflight -= 1
            self._inflight_total = max(0, self._inflight_total - 1)
        if state.inflight == 0 and not state.attempts:
            self._ips.pop(ip, None)

    def slot(self, ip: str) -> "_GuardSlot":
        return _GuardSlot(self, ip)

    def stats(self) -> dict:
        return {
            "tracked_ips": len(self._ips),
            "inflight_total": self._inflight_total,
            "rejected_rate": self.rejected_rate,
            "rejected_inflight_ip": self.rejected_inflight_ip,
            "rejected_inflight_total": self.rejected_inflight_total,
        }

    # -- internals -------------------------------------------------------

    def _evict_if_needed(self, now: float) -> None:
        """Drop the least-recently-seen idle entries once the table is full.

        Only entries with nothing in flight are evicted, so eviction can
        never lose track of a handshake that is still running.
        """
        if len(self._ips) < self.max_tracked_ips:
            return
        cutoff = now - self.window_seconds
        stale = [ip for ip, st in self._ips.items()
                 if st.inflight == 0 and st.last_seen < cutoff]
        for ip in stale:
            self._ips.pop(ip, None)
        if len(self._ips) < self.max_tracked_ips:
            return
        idle = sorted((st.last_seen, ip) for ip, st in self._ips.items() if st.inflight == 0)
        for _, ip in idle[: max(1, len(idle) // 10)]:
            self._ips.pop(ip, None)
        logger.warning("handshake guard table full (%d IPs) -- evicted idle entries",
                       self.max_tracked_ips)


class _GuardSlot:
    """Async context manager wrapper around acquire()/release()."""

    __slots__ = ("_guard", "_ip", "_held")

    def __init__(self, guard: HandshakeGuard, ip: str):
        self._guard = guard
        self._ip = ip
        self._held = False

    async def __aenter__(self) -> "_GuardSlot":
        self._guard.acquire(self._ip)
        self._held = True
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        if self._held:
            self._guard.release(self._ip)
            self._held = False
        return False


def peer_ip(addr) -> str:
    """Best-effort extraction of a source IP from ``get_extra_info('peername')``.

    Returns a stable placeholder for unix sockets / unknown transports so
    the guard still applies a bucket rather than silently skipping.
    """
    if isinstance(addr, tuple) and addr:
        return str(addr[0])
    if addr is None:
        return "unknown"
    return str(addr)
