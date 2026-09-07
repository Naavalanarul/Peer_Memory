# Phase 2 — Latency reduction

Branch: `phase2-latency-reduction` (branched from `phase1-security-hardening`)

Five changes. Every number below was produced by the scripts in `bench/`
on one container — **reproduce them on your hardware rather than quoting
them**. One of the five measured close to zero, and that is reported as
such rather than dressed up.

Test suite: **115 passed** (the 14 original tests and the 52 from Phase 1
unmodified, plus 49 new).

---

## 1. Binary RPC framing — the largest measured win

**Files:** `memnode/rpc.py`, `memnode/cli.py`, `memnode/config.py`

Payloads travelled as hex inside JSON. Hex doubles every byte on the
wire, and each call paid `.hex()` on one side and `bytes.fromhex()` plus
JSON parsing on the other.

A client that opens with the 4-byte preamble `MNB1` gets msgpack framing
with raw binary payloads. Anything else is treated as the length prefix
of a classic JSON frame, so **the original protocol still works
untouched** — including `demo/demo_client.py`, which was not modified.
Negotiation happens after the Phase 1 auth exchange, so the auth handshake
stays one fixed format.

`python bench/bench_rpc.py --payload-kb 64 --iterations 300`:

| codec | request bytes | median ms | p95 ms |
|---|---:|---:|---:|
| hex+json | 39,335,290 | 0.514 | 0.601 |
| msgpack | 19,669,390 | 0.058 | 0.091 |

**2.00x smaller on the wire, 8.8x lower median latency** at a 64 KiB
payload. The latency gain is far larger than the size gain because the
hex+JSON path also parses a 128 KB hex string per call. Expect the ratio
to shrink toward 2x as payloads get small.

The size guard is unchanged: the length check still happens before the
body read in both codecs (`test_binary_oversized_frame_is_still_refused`).

## 2. Chunked transfers — head-of-line blocking

**Files:** `memnode/replication.py`, `memnode/protocol.py`, `memnode/config.py`

A block was one AEAD frame. While it was written, every other message on
that connection waited. Blocks are now split into 256 KiB chunks on a
dedicated logical stream, and payloads moved from `data_hex` to msgpack
`bin` (`extract_payload` still accepts `data_hex`, so an un-upgraded peer
is understood rather than dropped).

`python bench/bench_hol.py --block-mb 16`:

| configuration | bytes ahead of a control message |
|---|---:|
| one frame, FIFO (before) | 16,777,216 |
| chunked + round-robin (after) | 262,144 |

**64x less queueing delay** — at 1 Gbit/s, 134 ms before vs 2.1 ms after.
This metric is exact and machine-independent; divide by your link rate
for time.

Chunking also removes a hard ceiling: a single frame was capped at
`MAX_FRAME_SIZE` (16 MB), so a 40 MB block could not be transferred at
all. Verified end to end with a 4 MB block pushed and pulled between two
live daemons with exact byte match.

Reassembly is bounded on purpose: the sender declares a total size, which
is refused above `MAX_BLOCK_SIZE`, aborted if the chunks overrun it,
capped in count by `MAX_INBOUND_STREAMS`, and garbage-collected after
`INBOUND_STREAM_TIMEOUT`.

## 3. Connection multiplexing

**File:** `memnode/mux.py` (new), wired through `peers.py`

Chunking decides how finely a transfer *can* be interleaved; the
multiplexer decides that it *is*. Every message carries
`body["stream_id"]` (0 = control), outbound messages queue per stream,
and one writer task takes one message from each non-empty stream in
rotation.

In `test_small_message_behind_a_large_transfer_is_not_starved`, a control
message queued behind 50 chunks reaches the socket at **position 2**
instead of position 50.

Outbound queueing is bounded by a semaphore, so a producer that outruns
the socket is slowed rather than growing an unbounded in-memory queue —
the same class of bug the framing size guards exist to prevent, on the
outbound side.

## 4. uvloop

**File:** `memnode/main.py`

A policy swap, not a code change; every `await` is unchanged. Optional by
design — an `ImportError` is logged and ignored, because a daemon that
refuses to start without an accelerator is a worse problem than a slower
one. `--no-uvloop` forces the stdlib loop.

`python bench/bench_loop.py` (2000 binary store requests, 4 KiB payload):

| event loop | median ms | p95 ms | req/s |
|---|---:|---:|---:|
| asyncio | 0.0414 | 0.0673 | 22,353 |
| uvloop | 0.0263 | 0.0473 | 31,318 |

**1.57x lower median latency, ~40% more requests/s** on this machine.
uvloop helps socket readiness and callback dispatch, not crypto or
copying, so the gain shrinks as a workload becomes CPU-bound.

## 5. Lock striping — implemented, but it did not measurably help

**File:** `memnode/blocks.py`

Blocks are now spread across 16 independent lock-striped sub-maps keyed
by `block_id`, with the key index striped separately, a short quota lock
holding no `await`, and eviction that locks one stripe at a time instead
of freezing the whole store.

`python bench/bench_blocks.py` (256 concurrent workers, ~20 000
store+load+free cycles, best of 3):

| stripes | seconds | ops/s |
|---:|---:|---:|
| 1 | 0.1159 | 516,946 |
| 4 | 0.1131 | 529,711 |
| 16 | 0.1136 | 527,407 |
| 64 | 0.1180 | 507,592 |

**That is a ~2% difference at best, inside the noise.** The honest reason:
this daemon runs a single-threaded event loop and the original critical
sections never `await`ed while holding the lock, so the global lock was
never actually serialising work — it was only ever contended for the
duration of a few dict operations. Striping removes lock queueing and the
coupling between unrelated operations, which is structurally better and
will matter more if a future version moves the store off the event-loop
thread or adds `await`s inside those sections. Today it buys close to
nothing, and the table above is the evidence.

**The real win in this file was an algorithmic fix, not the locking.**
`free()` used to run `for k, v in list(self._key_index.items())` to find
the key pointing at a block — copying and scanning the entire key index
on every free. Each entry now records its own key, so removal is O(1):

| keyed blocks | old scan (median) | new (median) |
|---:|---:|---:|
| 1,000 | 72.1 µs | 2.09 µs |
| 5,000 | 524.3 µs | 2.21 µs |
| 20,000 | 2,182.6 µs | 2.29 µs |
| 50,000 | 5,717.9 µs | 2.31 µs |

At 50,000 keyed blocks that step went from **5.7 ms to 2.3 µs** — roughly
2,500x, and it stops growing. The "old scan" column was measured by
running the previous code's loop in isolation over an index of that size;
the "new" column comes from `bench/bench_blocks.py`.

A second correctness fix landed here too: re-binding a key now releases
the block it previously pointed at, so overwriting a hot key in a loop no
longer leaks quota (`test_rebinding_a_key_releases_the_old_block`).

---

## Summary of measured effects

| Change | Measured effect |
|---|---|
| Binary RPC framing | 2.0x smaller wire, 8.8x lower median latency @ 64 KiB |
| Chunked transfers + mux | 64x less head-of-line queueing; removes the 16 MB per-block ceiling |
| uvloop | 1.57x lower median latency, ~40% more req/s |
| O(1) key removal | 5.7 ms → 2.3 µs per free at 50k keyed blocks |
| Lock striping | ~0 (within noise) — see above for why |

## Compatibility

* **RPC:** fully backward compatible. JSON clients are untouched;
  `demo/demo_client.py` was not modified and still works. Both codecs
  share one store (`test_both_codecs_share_one_store`).
* **Peer protocol:** `BlockChunk` and `StreamAbort` are new message types,
  and payloads moved to binary. Receiving still accepts `data_hex`, but a
  Phase 2 node sending a chunked transfer needs a Phase 2 peer. Combined
  with Phase 1's wire change, treat this as a cluster-wide upgrade.
* **`BlockManager`:** the public API is unchanged; `free_by_key()` and a
  `stripe_count` argument are added.

## Known limits

* The chunk size (256 KiB) is a fixed constant. The right value depends
  on link bandwidth-delay product; it is not adaptive.
* Round-robin is equal-weight. There is no priority class, so a control
  message shares the rotation with transfers rather than pre-empting them.
* Backpressure is a message count, not a byte count, so many large
  messages can still queue more bytes than many small ones.
* `bench/bench_hol.py` measures the structural property (bytes queued
  ahead), not wall-clock time on a real link.
* uvloop is not available on Windows.
