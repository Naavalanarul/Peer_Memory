"""In-memory block storage.

Design notes (informed by gaps found in the reference implementation):
  - Blocks are stored as raw `bytes` in a plain dict -- no per-block
    wrapper object -- to keep memory overhead close to the actual
    payload size. Python object overhead adds up fast if you wrap
    every block in a rich class.
  - Every store enforces both a per-block size cap and a total quota
    cap *before* accepting data, never after (the reference daemon had
    a total-quota check but no per-block cap, so one huge store call
    could eat the whole quota before eviction had a chance to react).
  - Two durability classes: PINNED (never auto-evicted, write fails if
    it would exceed quota) and CACHE (evictable under pressure via
    random-sample eviction).
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
    data: bytes
    durability: Durability
    last_access: float


class BlockManager:
    """Async-safe block store with quota + eviction.

    Uses a single asyncio.Lock rather than per-block locking. This is
    fine for I/O-bound workloads (the lock is held only for dict
    mutation, never across an `await` that blocks on the network), and
    keeps the logic simple to reason about for a hackathon timeline.
    """

    def __init__(self, max_memory_bytes: int = config.DEFAULT_RAM_QUOTA_BYTES):
        self.max_memory_bytes = max_memory_bytes
        self._blocks: dict[int, _Entry] = {}
        self._key_index: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._id_counter = itertools.count(1)
        self._used_bytes = 0

    # -- public API -----------------------------------------------------

    async def store(self, data: bytes, durability: Durability = Durability.PINNED,
                     key: Optional[str] = None) -> int:
        size = len(data)
        if size > config.MAX_BLOCK_SIZE:
            raise BlockTooLarge(
                f"block of {size} bytes exceeds MAX_BLOCK_SIZE={config.MAX_BLOCK_SIZE}; "
                f"use streaming/chunked upload for larger payloads"
            )

        async with self._lock:
            if self._used_bytes + size > self.max_memory_bytes:
                freed = self._evict_to_free(size)
                if self._used_bytes + size > self.max_memory_bytes:
                    raise OutOfMemory(
                        f"cannot store {size} bytes: used={self._used_bytes}, "
                        f"max={self.max_memory_bytes}, eviction freed only {freed}"
                    )

            block_id = next(self._id_counter)
            self._blocks[block_id] = _Entry(data=data, durability=durability, last_access=time.monotonic())
            self._used_bytes += size
            if key is not None:
                self._key_index[key] = block_id
            return block_id

    async def load(self, block_id: int) -> Optional[bytes]:
        async with self._lock:
            entry = self._blocks.get(block_id)
            if entry is None:
                return None
            entry.last_access = time.monotonic()
            return entry.data

    async def load_by_key(self, key: str) -> Optional[bytes]:
        async with self._lock:
            block_id = self._key_index.get(key)
        if block_id is None:
            return None
        return await self.load(block_id)

    async def free(self, block_id: int) -> bool:
        async with self._lock:
            entry = self._blocks.pop(block_id, None)
            if entry is None:
                return False
            self._used_bytes -= len(entry.data)
            for k, v in list(self._key_index.items()):
                if v == block_id:
                    del self._key_index[k]
            return True

    async def stats(self) -> dict:
        async with self._lock:
            return {
                "used_bytes": self._used_bytes,
                "max_bytes": self.max_memory_bytes,
                "free_bytes": self.max_memory_bytes - self._used_bytes,
                "block_count": len(self._blocks),
            }

    # -- internal ---------------------------------------------------------

    def _evict_to_free(self, needed: int) -> int:
        """Random-sample eviction among CACHE blocks only.

        Must be called with self._lock already held. Returns bytes freed.
        PINNED blocks are never touched here -- if a PINNED store can't
        fit even after evicting every evictable CACHE block, it fails
        loudly with OutOfMemory rather than silently dropping data.
        """
        candidates = [bid for bid, e in self._blocks.items() if e.durability == Durability.CACHE]
        random.shuffle(candidates)

        freed = 0
        for bid in candidates:
            entry = self._blocks.pop(bid, None)
            if entry is None:
                continue
            freed += len(entry.data)
            self._used_bytes -= len(entry.data)
            logger.info("evicted block %s (%d bytes) to free space", bid, len(entry.data))
            if self._used_bytes + needed <= self.max_memory_bytes:
                break
        return freed
