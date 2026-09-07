"""Phase 1: handshake-flood admission control.

The guard has to refuse hostile traffic *cheaply* -- before any key
exchange or signature verification -- while never blocking a normal peer
that reconnects a few times.
"""
import pytest

from memnode.ratelimit import HandshakeGuard, HandshakeRejected, peer_ip


class _Clock:
    """Manual time source so rate-window tests do not sleep."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _guard(clock, **kwargs):
    defaults = dict(max_per_ip_per_window=3, window_seconds=60.0,
                    max_inflight_per_ip=2, max_inflight_total=4)
    defaults.update(kwargs)
    return HandshakeGuard(time_source=clock, **defaults)


def test_allows_traffic_under_the_limits():
    clock = _Clock()
    g = _guard(clock)
    for _ in range(3):
        g.acquire("10.0.0.1")
        g.release("10.0.0.1")
    assert g.rejected_rate == 0


def test_rate_limit_trips_per_ip():
    clock = _Clock()
    g = _guard(clock)
    for _ in range(3):
        g.acquire("10.0.0.1")
        g.release("10.0.0.1")
    with pytest.raises(HandshakeRejected):
        g.acquire("10.0.0.1")
    assert g.rejected_rate == 1


def test_rate_limit_window_slides():
    clock = _Clock()
    g = _guard(clock)
    for _ in range(3):
        g.acquire("10.0.0.1")
        g.release("10.0.0.1")
    clock.advance(61)
    g.acquire("10.0.0.1")        # window has rolled over -- allowed again
    g.release("10.0.0.1")


def test_one_noisy_ip_does_not_block_others():
    clock = _Clock()
    g = _guard(clock)
    for _ in range(3):
        g.acquire("10.0.0.1")
        g.release("10.0.0.1")
    with pytest.raises(HandshakeRejected):
        g.acquire("10.0.0.1")
    g.acquire("10.0.0.2")        # a different peer is unaffected
    g.release("10.0.0.2")


def test_per_ip_concurrency_cap():
    clock = _Clock()
    g = _guard(clock, max_per_ip_per_window=100)
    g.acquire("10.0.0.1")
    g.acquire("10.0.0.1")
    with pytest.raises(HandshakeRejected):
        g.acquire("10.0.0.1")    # 3rd simultaneous handshake from one IP
    assert g.rejected_inflight_ip == 1
    g.release("10.0.0.1")
    g.acquire("10.0.0.1")        # a slot freed up


def test_global_concurrency_cap():
    clock = _Clock()
    g = _guard(clock, max_per_ip_per_window=100, max_inflight_per_ip=100,
               max_inflight_total=2)
    g.acquire("10.0.0.1")
    g.acquire("10.0.0.2")
    with pytest.raises(HandshakeRejected):
        g.acquire("10.0.0.3")
    assert g.rejected_inflight_total == 1


def test_release_is_safe_for_unknown_ip():
    g = _guard(_Clock())
    g.release("192.0.2.9")       # must not raise or go negative
    assert g.stats()["inflight_total"] == 0


@pytest.mark.asyncio
async def test_slot_context_manager_releases_on_error():
    clock = _Clock()
    g = _guard(clock, max_per_ip_per_window=100)
    with pytest.raises(RuntimeError):
        async with g.slot("10.0.0.1"):
            raise RuntimeError("handshake blew up")
    assert g.stats()["inflight_total"] == 0


def test_tracking_table_is_bounded():
    """Spraying from many source addresses must not grow the limiter's
    own memory without bound -- otherwise the defence is the DoS."""
    clock = _Clock()
    g = _guard(clock, max_per_ip_per_window=100, max_inflight_per_ip=100,
               max_inflight_total=100_000, max_tracked_ips=64)
    for i in range(500):
        g.acquire(f"10.1.{i // 256}.{i % 256}")
        g.release(f"10.1.{i // 256}.{i % 256}")
        clock.advance(0.1)
    assert g.stats()["tracked_ips"] <= 64


def test_peer_ip_extraction():
    assert peer_ip(("192.0.2.7", 51234)) == "192.0.2.7"
    assert peer_ip(None) == "unknown"
    assert peer_ip("/tmp/memcloud.sock") == "/tmp/memcloud.sock"
