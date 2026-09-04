# memnode (Python backend)

A Python/asyncio reimplementation of the memcloud daemon: peers pool RAM
across a LAN, discover each other via mDNS, and talk over an encrypted
peer protocol. A local JSON RPC server exposes store/load/stats/peers
to the CLI, SDKs, and (next) a React dashboard.

This scaffold was written specifically to avoid a set of issues found
by auditing the reference (Rust) implementation:

| Issue in reference impl | Fix here |
|---|---|
| Unbounded frame allocation (`vec![0u8; len]` with no cap) → DoS | `protocol.read_frame()` checks `MAX_FRAME_SIZE` before allocating, for both the peer protocol and the RPC layer (`config.py`) |
| No per-block size cap | `blocks.py` enforces `MAX_BLOCK_SIZE` before accepting a store |
| 34 `.unwrap()`/`.expect()` calls that could panic the daemon | Every connection handler / read loop / RPC dispatch is wrapped in try/except that logs and degrades gracefully instead of crashing |
| Only 3 unit tests, no test CI | 14 tests covering framing, block quotas/eviction, and end-to-end RPC (see `tests/`) |
| No replication | `peers.py` tracks remote quota per peer and picks the peer with the most headroom (`best_peer_for_store`) — a first step toward replication, still single-copy today |
| No load-aware placement | Same `best_peer_for_store` mechanism |

## Setup

```bash
pip install -r requirements.txt
```

## Run a node

```bash
python -m memnode.main --name my-node --ram-quota 536870912
```

This starts:
- the peer protocol listener on `0.0.0.0:8080`
- the local RPC server on `127.0.0.1:7070` (TCP) and `/tmp/memcloud.sock` (Unix socket)
- mDNS advertisement/discovery (`_memcloud._tcp.local.`)

## Talk to it

The RPC protocol is a 4-byte big-endian length prefix + JSON body, so
you can test it without any client library:

```python
import asyncio, json, struct

async def call(op, **kwargs):
    reader, writer = await asyncio.open_connection("127.0.0.1", 7070)
    raw = json.dumps({"op": op, **kwargs}).encode()
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    return json.loads((await reader.readexactly(length)).decode())

asyncio.run(call("store", data_hex=b"hello".hex(), key="greeting"))
```

Supported ops: `store`, `load`, `free`, `stats`, `peers`, `connect`.

## Run tests

```bash
python -m pytest -v
```

## Not done yet (intentionally scoped out for now)

- Actual replication (storing a block on N peers) — the groundwork
  (per-peer remote quota tracking) is there, but stores still land on
  one peer.
- A push channel (websocket/SSE) for the React dashboard — right now
  it would have to poll `stats`/`peers`.
- NACK responses on the peer protocol for failed StoreBlock/RequestBlock.
- A real consent UI — `PeerManager.consent_callback` currently
  auto-approves; wire in a prompt before demoing to an untrusted network.
