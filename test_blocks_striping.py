"""Phase 2: lock-striped BlockManager.

Striping is a performance change, so the tests here are mostly about
*correctness under the new structure*: quota accounting must stay exact
across stripes, eviction must still respect PINNED, and the O(1) key
removal must not leave dangling index entries.
"""
import asyncio

import pytest

from memnode import config
from memnode.blocks import BlockManager, Durability, OutOfMemory


@pytest.mark.asyncio
async def test_blocks_spread_across_stripes():
    bm = BlockManager(max_memory_bytes=1024 * 1024, stripe_count=8)
    for i in range(64):
        await bm.store(b"x" * 10, key=f"k{i}")
    occupied = sum(1 for s in bm._stripes if s.blocks)
    assert occupied == 8, "sequential block ids should touch every stripe"


@pytest.mark.asyncio
async def test_single_stripe_still_works():
    bm = BlockManager(max_memory_bytes=1024, stripe_count=1)
    bid = await bm.store(b"hello")
    assert await bm.load(bid) == b"hello"


def test_stripe_count_must_be_positive():
    with pytest.raises(ValueError):
        BlockManager(max_memory_bytes=1024, stripe_count=0)


@pytest.mark.asyncio
async def test_quota_accounting_is_exact_across_stripes():
    bm = BlockManager(max_memory_bytes=10_000, stripe_count=16)
    ids = [await bm.store(b"y" * 100) for _ in range(50)]
    assert (await bm.stats())["used_bytes"] == 5000

    for bid in ids[:20]:
        assert await bm.free(bid) is True
    stats = await bm.stats()
    assert stats["used_bytes"] == 3000
    assert stats["block_count"] == 30


@pytest.mark.asyncio
async def test_concurrent_stores_do_not_overshoot_the_quota():
    """The quota check happens under its own short lock, so racing
    coroutines must not each see 'there is room' and both commit."""
    bm = BlockManager(max_memory_bytes=1000, stripe_count=16)
    results = await asyncio.gather(
        *[bm.store(b"z" * 100, durability=Durability.PINNED) for _ in range(30)],
        return_exceptions=True)

    stored = [r for r in results if isinstance(r, int)]
    rejected = [r for r in results if isinstance(r, OutOfMemory)]
    assert len(stored) == 10
    assert len(rejected) == 20
    assert (await bm.stats())["used_bytes"] == 1000


@pytest.mark.asyncio
async def test_concurrent_mixed_operations_stay_consistent():
    bm = BlockManager(max_memory_bytes=1_000_000, stripe_count=16)
    ids = await asyncio.gather(*[bm.store(b"a" * 50, key=f"key{i}") for i in range(200)])

    loads = await asyncio.gather(*[bm.load(bid) for bid in ids])
    assert all(d == b"a" * 50 for d in loads)

    await asyncio.gather(*[bm.free(bid) for bid in ids])
    stats = await bm.stats()
    assert stats["used_bytes"] == 0
    assert stats["block_count"] == 0


# -- key index --------------------------------------------------------------

@pytest.mark.asyncio
async def test_free_removes_the_key_without_scanning():
    bm = BlockManager(max_memory_bytes=10_000)
    bid = await bm.store(b"data", key="gone")
    assert await bm.load_by_key("gone") == b"data"

    await bm.free(bid)
    assert await bm.load_by_key("gone") is None


@pytest.mark.asyncio
async def test_free_by_key():
    bm = BlockManager(max_memory_bytes=10_000)
    await bm.store(b"data", key="bye")
    assert await bm.free_by_key("bye") is True
    assert await bm.free_by_key("bye") is False
    assert (await bm.stats())["used_bytes"] == 0


@pytest.mark.asyncio
async def test_rebinding_a_key_releases_the_old_block():
    """Overwriting a hot key in a loop must not leak the quota."""
    bm = BlockManager(max_memory_bytes=10_000)
    for _ in range(50):
        await bm.store(b"v" * 100, key="hot")
    stats = await bm.stats()
    assert stats["block_count"] == 1
    assert stats["used_bytes"] == 100
    assert await bm.load_by_key("hot") == b"v" * 100


@pytest.mark.asyncio
async def test_freeing_an_unknown_block_is_false():
    bm = BlockManager(max_memory_bytes=1024)
    assert await bm.free(4242) is False


# -- eviction ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_eviction_crosses_stripes_to_make_room():
    bm = BlockManager(max_memory_bytes=1000, stripe_count=16)
    for _ in range(10):
        await bm.store(b"c" * 100, durability=Durability.CACHE)
    assert (await bm.stats())["used_bytes"] == 1000

    pinned = await bm.store(b"p" * 500, durability=Durability.PINNED)
    assert await bm.load(pinned) == b"p" * 500
    assert (await bm.stats())["used_bytes"] <= 1000


@pytest.mark.asyncio
async def test_pinned_blocks_are_never_evicted():
    bm = BlockManager(max_memory_bytes=1000, stripe_count=4)
    pinned = [await bm.store(b"p" * 200, durability=Durability.PINNED) for _ in range(5)]
    with pytest.raises(OutOfMemory):
        await bm.store(b"q" * 100, durability=Durability.PINNED)
    for bid in pinned:
        assert await bm.load(bid) is not None


@pytest.mark.asyncio
async def test_evicted_blocks_drop_their_keys():
    bm = BlockManager(max_memory_bytes=300, stripe_count=4)
    await bm.store(b"c" * 200, durability=Durability.CACHE, key="cached")
    await bm.store(b"p" * 250, durability=Durability.PINNED, key="pinned")
    assert await bm.load_by_key("cached") is None      # evicted, index cleaned
    assert await bm.load_by_key("pinned") == b"p" * 250


@pytest.mark.asyncio
async def test_stats_reports_stripe_count():
    bm = BlockManager(max_memory_bytes=1024, stripe_count=config.BLOCK_STRIPE_COUNT)
    assert (await bm.stats())["stripes"] == config.BLOCK_STRIPE_COUNT
