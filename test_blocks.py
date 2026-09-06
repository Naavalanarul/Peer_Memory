import pytest

from memnode import config
from memnode.blocks import BlockManager, BlockTooLarge, Durability, OutOfMemory


@pytest.mark.asyncio
async def test_store_and_load_roundtrip():
    bm = BlockManager(max_memory_bytes=1024)
    block_id = await bm.store(b"hello", durability=Durability.PINNED)
    data = await bm.load(block_id)
    assert data == b"hello"


@pytest.mark.asyncio
async def test_store_and_load_by_key():
    bm = BlockManager(max_memory_bytes=1024)
    await bm.store(b"value1", key="mykey")
    data = await bm.load_by_key("mykey")
    assert data == b"value1"


@pytest.mark.asyncio
async def test_load_missing_block_returns_none():
    bm = BlockManager(max_memory_bytes=1024)
    assert await bm.load(999) is None
    assert await bm.load_by_key("nope") is None


@pytest.mark.asyncio
async def test_block_too_large_rejected():
    """Regression test for the missing per-block cap in the reference
    implementation -- a single store must not be able to blow through
    the quota in one call."""
    bm = BlockManager(max_memory_bytes=config.MAX_BLOCK_SIZE * 2)
    with pytest.raises(BlockTooLarge):
        await bm.store(b"x" * (config.MAX_BLOCK_SIZE + 1))


@pytest.mark.asyncio
async def test_pinned_store_fails_loudly_when_quota_exceeded():
    bm = BlockManager(max_memory_bytes=10)
    await bm.store(b"12345", durability=Durability.PINNED)
    with pytest.raises(OutOfMemory):
        await bm.store(b"67890abcde", durability=Durability.PINNED)  # would exceed quota, no cache to evict


@pytest.mark.asyncio
async def test_cache_blocks_evicted_to_make_room_for_pinned():
    bm = BlockManager(max_memory_bytes=10)
    cache_id = await bm.store(b"12345", durability=Durability.CACHE)
    pinned_id = await bm.store(b"1234567890", durability=Durability.PINNED)  # forces eviction

    stats = await bm.stats()
    assert stats["used_bytes"] == 10
    assert await bm.load(pinned_id) == b"1234567890"
    assert await bm.load(cache_id) is None  # evicted


@pytest.mark.asyncio
async def test_free_removes_block_and_updates_usage():
    bm = BlockManager(max_memory_bytes=1024)
    block_id = await bm.store(b"hello")
    assert (await bm.stats())["used_bytes"] == 5

    freed = await bm.free(block_id)
    assert freed is True
    assert (await bm.stats())["used_bytes"] == 0
    assert await bm.load(block_id) is None
