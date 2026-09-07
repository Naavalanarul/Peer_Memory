"""In-memory block storage.

Design notes (informed by gaps found in the reference implementation):
  - Blocks are stored as raw `bytes` in plain dicts -- no per-block
    wrapper object beyond a small slotted entry -- to keep memory
    overhead close to the actual payload size.
  - Every store enforces both a per-block size cap and a total quota
    cap *before* accepting data, never after (the reference daemon had
    a total-quota check but no per-block cap, so one huge store call
    could eat the whole quota before eviction had a chance to react).
  - Two durability classes: PINNED (never auto-evicted, write fails if
    it would exceed quota) and CACHE (evictable under pressure via
    random-sample eviction).

Phase 2: lock striping
----------------------
The previous version used one global ``asyncio.Lock`` for every store,
load, free and stats call. Two costs came from that:

* **Queueing.** Under concurrency every operation had to acquire the
  same lock, so N in-flight callers formed one FIFO queue on it.
* **Coupling.** A `stats()` sweep or an eviction pass blocked unrelated
  loads of unrelated blocks.

Blocks are now spread across ``STRIPE_COUNT`` independent sub-maps, each
with its own lock, chosen by ``block_id`` hash. The key index is striped
separately by key hash. Concurrent operations touching different stripes
no longer queue behind each other.

Honest framing of the win: this daemon runs a single-threaded event
loop, and the old critical sections never awaited while holding the
lock. So striping does **not** unlock parallel CPU execution -- it
removes lock-acquisition queueing and the coupling above. Measured
effect is a modest throughput gain that grows with concurrency, not a
step change. See ``bench/bench_blocks.py`` for numbers you can
reproduce, and treat any figure quoted elsewhere as machine-specific.

The other change here is a real algorithmic fix, independent of
locking: ``free()`` used to scan the *entire* key index
(``for k, v in list(self._key_index.items())``) to find the key
pointing at a block, making every free O(number of keyed blocks) and
allocating a full copy of the index each time. Each entry now records
its own key, so removal is O(1).
"""
from __future__ import annotations

import asyncio
import itertools
import logging
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from . import config

logger = logging.getLogger("memnode.blocks")


class Durability(str, Enum):
    PINNED = "pinned"
    CACHE = "cache"


class BlockTooLarge(Exception):
    pass


class OutOfMemory(Exception):
    pass


@dataclass
class _Entry:
    __slots__ = ("data", "durability", "last_access", "key")
    data: bytes
    durability: Durability
    last_access: float
    key: Optional[str]


class _Stripe:
    """One shard of the block map, with its own lock and byte counter."""

    __slots__ = ("lock", "blocks", "used_bytes")

    def __init__(self):
        self.lock = asyncio.Lock()
        self.blocks: dict[int, _Entry] = {}
        self.used_bytes = 0


class _KeyStripe:
    __slots__ = ("lock", "index")

    def __init__(self):
        self.lock = asyncio.Lock()
        self.index: dict[str, int] = {}


class BlockManager:
    """Async-safe block store with quota + eviction.

    Lock ordering (deadlock avoidance): a coroutine may take a stripe
    lock and then the quota lock, but never the reverse. The quota lock
    is only ever held for arithmetic -- there is no ``await`` inside its
    critical section -- so it can never be the thing a stripe lock waits
    behind.
    """

    def __init__(self, max_memory_bytes: int = config.DEFAULT_RAM_QUOTA_BYTES,
                 stripe_count: int = config.BLOCK_STRIPE_COUNT):
        if stripe_count < 1:
            raise ValueError("stripe_count must be >= 1")
        self.max_memory_bytes = max_memory_bytes
        self.stripe_count = stripe_count
        self._stripes = [_Stripe() for _ in range(stripe_count)]
        self._key_stripes = [_KeyStripe() for _ in range(stripe_count)]
        self._quota_lock = asyncio.Lock()
        self._reserved_bytes = 0          # authoritative total usage
        self._id_counter = itertools.count(1)

    # -- stripe selection -------------------------------------------------

    def _stripe(self, block_id: int) -> _Stripe:
        # block_ids come from a counter, so the low bits are already
        # uniformly distributed; a mask is cheaper than hashing.
        return self._stripes[block_id % self.stripe_count]

    def _key_stripe(self, key: str) -> _KeyStripe:
        return self._key_stripes[hash(key) % self.stripe_count]

    # -- public API -----------------------------------------------------

    async def store(self, data: bytes, durability: Durability = Durability.PINNED,
                     key: Optional[str] = None) -> int:
        size = len(data)
        if size > config.MAX_BLOCK_SIZE:
            raise BlockTooLarge(
                f"block of {size} bytes exceeds MAX_BLOCK_SIZE={config.MAX_BLOCK_SIZE}; "
                f"use streaming/chunked upload for larger payloads"
            )

        if not await self._reserve(size):
            freed = await self._evict_to_free(size)
            if not await self._reserve(size):
                raise OutOfMemory(
                    f"cannot store {size} bytes: used={self._reserved_bytes}, "
                    f"max={self.max_memory_bytes}, eviction freed only {freed}"
                )

        block_id = next(self._id_counter)
        stripe = self._stripe(block_id)
        entry = _Entry(data=data, durability=durability,
                       last_access=time.monotonic(), key=key)
        async with stripe.lock:
            stripe.blocks[block_id] = entry
            stripe.used_bytes += size

        if key is not None:
            ks = self._key_stripe(key)
            async with ks.lock:
                previous = ks.index.get(key)
                ks.index[key] = block_id
            if previous is not None and previous != block_id:
                # Re-binding a key orphans the old block; release it so a
                # hot key overwritten in a loop cannot leak the quota.
                await self.free(previous, _drop_key=False)
        return block_id

    async def load(self, block_id: int) -> Optional[bytes]:
        stripe = self._stripe(block_id)
        async with stripe.lock:
            entry = stripe.blocks.get(block_id)
            if entry is None:
                return None
            entry.last_access = time.monotonic()
            return entry.data

    async def load_by_key(self, key: str) -> Optional[bytes]:
        ks = self._key_stripe(key)
        async with ks.lock:
            block_id = ks.index.get(key)
        if block_id is None:
            return None
        return await self.load(block_id)

    async def free(self, block_id: int, _drop_key: bool = True) -> bool:
        stripe = self._stripe(block_id)
        async with stripe.lock:
            entry = stripe.blocks.pop(block_id, None)
            if entry is None:
                return False
            size = len(entry.data)
            stripe.used_bytes -= size
            key = entry.key
        await self._release(size)

        # O(1): the entry knows its own key, so no scan of the key index.
        if _drop_key and key is not None:
            ks = self._key_stripe(key)
            async with ks.lock:
                if ks.index.get(key) == block_id:
                    del ks.index[key]
        return True

    async def free_by_key(self, key: str) -> bool:
        ks = self._key_stripe(key)
        async with ks.lock:
            block_id = ks.index.get(key)
        if block_id is None:
            return False
        return await self.free(block_id)

    async def stats(self) -> dict:
        # Counter reads need no lock: this is a single-threaded event
        # loop and there is no await between the reads below, so the
        # snapshot is consistent by construction.
        used = self._reserved_bytes
        count = sum(len(s.blocks) for s in self._stripes)
        return {
            "used_bytes": used,
            "max_bytes": self.max_memory_bytes,
            "free_bytes": self.max_memory_bytes - used,
            "block_count": count,
            "stripes": self.stripe_count,
        }

    # -- quota accounting -------------------------------------------------

    async def _reserve(self, size: int) -> bool:
        async with self._quota_lock:
            if self._reserved_bytes + size > self.max_memory_bytes:
                return False
            self._reserved_bytes += size
            return True

    async def _release(self, size: int) -> None:
        async with self._quota_lock:
            self._reserved_bytes = max(0, self._reserved_bytes - size)

    # -- eviction ---------------------------------------------------------

    async def _evict_to_free(self, needed: int) -> int:
        """Random-sample eviction among CACHE blocks only.

        PINNED blocks are never touched -- if a PINNED store cannot fit
        even after evicting every evictable CACHE block, it fails loudly
        with OutOfMemory rather than silently dropping data.

        Stripes are visited in a random order and locked one at a time,
        so eviction never freezes the whole store at once.
        """
        freed = 0
        order = list(range(self.stripe_count))
        random.shuffle(order)

        for idx in order:
            stripe = self._stripes[idx]
            async with stripe.lock:
                candidates = [bid for bid, e in stripe.blocks.items()
                              if e.durability == Durability.CACHE]
                random.shuffle(candidates)
                victims = []
                for bid in candidates:
                    entry = stripe.blocks.pop(bid, None)
                    if entry is None:
                        continue
                    size = len(entry.data)
                    stripe.used_bytes -= size
                    freed += size
                    victims.append((bid, size, entry.key))
                    if self._reserved_bytes - freed + needed <= self.max_memory_bytes:
                        break

            for bid, size, key in victims:
                await self._release(size)
                if key is not None:
                    ks = self._key_stripe(key)
                    async with ks.lock:
                        if ks.index.get(key) == bid:
                            del ks.index[key]
                logger.info("evicted block %s (%d bytes) to free space", bid, size)

            if self._reserved_bytes + needed <= self.max_memory_bytes:
                break
        return freed
