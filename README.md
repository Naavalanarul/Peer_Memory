# memnode

> A distributed in-memory RAM pool — peers share RAM across a LAN, discover each other via mDNS, and communicate over an encrypted peer-to-peer protocol. Built with Python & asyncio.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Module Reference](#module-reference)
- [Getting Started](#getting-started)
- [CLI Usage](#cli-usage)
- [RPC API Reference](#rpc-api-reference)
- [Security Model](#security-model)
- [Testing](#testing)
- [Improvements Over Reference Implementation](#improvements-over-reference-implementation)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

**memnode** is a Python/asyncio reimplementation of a distributed RAM pooling daemon. Multiple nodes on a local network each contribute a configurable amount of RAM. When one node's quota is full, data automatically overflows to the peer with the most available capacity — creating a unified memory pool across machines.

### Key Features

- **Distributed RAM pooling** — store data across multiple machines transparently
- **Automatic overflow** — when local quota is full, blocks are placed on the best available peer
- **Zero-config discovery** — nodes find each other via mDNS (`_memcloud._tcp.local.`)
- **End-to-end encryption** — Noise-XX-inspired handshake with X25519 ECDH + ChaCha20-Poly1305 AEAD
- **TOFU trust model** — Trust-On-First-Use with persistent identity storage
- **Quota & eviction** — per-block size caps, total quota enforcement, and cache eviction under pressure
- **CLI & RPC interface** — JSON-over-length-prefixed-frame protocol for easy integration

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          memnode daemon                              │
│                                                                      │
│  ┌──────────┐   ┌──────────────┐   ┌────────────────────────────┐   │
│  │   CLI    │──▶│  RPC Server  │──▶│     Block Manager          │   │
│  │ (cli.py) │   │  (rpc.py)    │   │  (blocks.py)               │   │
│  └──────────┘   │ TCP:7070     │   │  • quota enforcement       │   │
│                 │ Unix socket  │   │  • PINNED / CACHE blocks   │   │
│                 └──────┬───────┘   │  • random-sample eviction  │   │
│                        │           └────────────────────────────┘   │
│                        ▼                                            │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │           Replication Coordinator (replication.py)           │    │
│  │  • req_id-correlated request/reply over peer protocol       │    │
│  │  • store_remote / load_remote / free_remote                 │    │
│  │  • fan-out key lookups across all connected peers           │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐    │
│  │             Peer Manager (peers.py)                          │    │
│  │  • TOFU trust store + consent flow                          │    │
│  │  • per-peer remote quota tracking                           │    │
│  │  • capacity-aware placement (best_peer_for_store)           │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                       │
│  ┌──────────────┐  ┌───────▼────────┐  ┌────────────────────────┐  │
│  │  Discovery   │  │ Secure Channel │  │   Wire Protocol        │  │
│  │ (discovery.py│  │ (security.py)  │  │   (protocol.py)        │  │
│  │  mDNS/       │  │  X25519 + AEAD │  │   msgpack framing      │  │
│  │  zeroconf)   │  │  forward secr. │  │   bounded reads        │  │
│  └──────────────┘  └────────────────┘  └────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
memnode_project/
├── memnode/                     # Core package
│   ├── __init__.py              # Package metadata & version
│   ├── config.py                # Central configuration & safety limits
│   ├── protocol.py              # Wire framing & message types (msgpack)
│   ├── blocks.py                # In-memory block store, quota & eviction
│   ├── security.py              # Noise-XX handshake + ChaCha20-Poly1305 channel
│   ├── peers.py                 # Peer registry, TOFU trust, consent flow
│   ├── discovery.py             # mDNS auto-discovery via zeroconf
│   ├── replication.py           # Peer-to-peer block replication coordinator
│   ├── rpc.py                   # Local JSON RPC server (TCP + Unix socket)
│   ├── cli.py                   # Command-line RPC client
│   └── main.py                  # Entrypoint — wires all components together
│
├── demo/                        # Hackathon demo utilities
│   ├── DEMO_GUIDE.md            # Step-by-step demo walkthrough
│   └── demo_client.py           # Chunked upload/download client for demos
│
├── test_blocks.py               # Unit tests — block storage & eviction
├── test_protocol.py             # Unit tests — wire framing & message codec
├── test_rpc.py                  # Integration tests — end-to-end RPC
│
├── pyproject.toml               # Project metadata & dependencies
├── requirements.txt             # Pip-installable dependencies
├── LICENSE                      # MIT License
└── .gitignore
```

---

## Module Reference

### `config.py` — Central Configuration

All tunable limits and defaults in one place. These exist specifically to prevent unbounded memory allocation attacks:

| Constant | Value | Purpose |
|---|---|---|
| `MAX_FRAME_SIZE` | 16 MB | Max bytes per wire frame (peer protocol + handshake) |
| `MAX_BLOCK_SIZE` | 64 MB | Max bytes per single stored block |
| `MAX_RPC_MESSAGE_SIZE` | 8 MB | Max bytes per local RPC message |
| `PEER_TCP_PORT` | 8080 | Node-to-node protocol port |
| `RPC_TCP_PORT` | 7070 | Local RPC port (loopback only) |
| `DEFAULT_RAM_QUOTA_BYTES` | 512 MB | Default advertised RAM quota per node |

### `protocol.py` — Wire Protocol

- **Length-prefixed framing** — 4-byte big-endian length prefix + payload
- **Bounded reads** — `read_frame()` checks `MAX_FRAME_SIZE` *before* allocating a buffer
- **msgpack serialization** — compact, cross-language, safe to deserialize from untrusted peers
- **16 message types**: `Hello`, `Welcome`, `Auth`, `StoreBlock`, `RequestBlock`, `BlockData`, `BlockNotFound`, `SetKey`, `GetKey`, `KeyFound`, `Ping`, `Pong`, `QuotaUpdate`, `Nack`, `FreeBlock`, `Freed`, `Bye`

### `blocks.py` — Block Storage Engine

- **Two durability classes**: `PINNED` (never auto-evicted) and `CACHE` (evictable under memory pressure)
- **Quota enforcement** — checks both per-block size cap and total quota *before* accepting data
- **Random-sample eviction** — evicts `CACHE` blocks to make room; `PINNED` stores fail with `OutOfMemory` if quota is exceeded
- **Key-based lookups** — optional string keys for human-friendly addressing
- **Async-safe** — single `asyncio.Lock` for dict mutation (held only during in-memory ops, never across network awaits)

### `security.py` — Encrypted Transport

- **Noise-XX-inspired 2-phase handshake**:
  1. **Hello** — exchange nonces + ephemeral X25519 public keys, build running transcript hash
  2. **Auth** — each side sends persistent Ed25519 identity + signature over transcript hash (MITM detection)
- **Traffic encryption** — per-direction ChaCha20-Poly1305 AEAD keys derived via HKDF from ECDH shared secret + transcript hash
- **Forward secrecy** — ephemeral keys are per-session; compromising long-term identity keys doesn't decrypt past sessions
- **Monotonic nonce counters** — separate send/receive counters prevent nonce reuse

### `peers.py` — Peer Management

- **TOFU (Trust-On-First-Use)** — persists trusted identities to `~/.memcloud/trusted_devices.json`
- **Consent flow** — pluggable callback for approve/deny decisions (defaults to auto-approve for headless operation)
- **Per-peer quota tracking** — records each peer's advertised remote quota
- **Capacity-aware placement** — `best_peer_for_store()` picks the peer with the most free headroom

### `replication.py` — Distributed Block Operations

- **Request/reply correlation** — each outbound request carries a `req_id` (UUID4); replies are matched via `asyncio.Future` dict
- **Inbound request handling** — serves `StoreBlock`, `RequestBlock`, `FreeBlock` from peers against the local `BlockManager`
- **Outbound operations** — `store_remote()`, `load_remote()`, `free_remote()` with configurable timeouts
- **Fan-out key lookups** — `load_remote_by_key_anywhere()` queries all connected peers sequentially and returns the first hit
- **Stale reply handling** — late replies (after timeout) are logged and dropped, not treated as errors

### `discovery.py` — mDNS Auto-Discovery

- Advertises this node as `_memcloud._tcp.local.` via zeroconf
- Listens for other nodes and auto-connects (subject to the consent flow)
- **Reliable LAN IP detection** — uses the UDP-connect trick to find the routable LAN IP, not just `gethostbyname()` (which often returns `127.0.0.1`)

### `rpc.py` — Local RPC Server

- **Dual transport** — TCP on `127.0.0.1:7070` + Unix socket at `/tmp/memcloud-<port>.sock`
- **Bounded reads** — enforces `MAX_RPC_MESSAGE_SIZE` before allocating
- **Graceful error handling** — every handler error becomes `{"ok": false, "error": "..."}`, never crashes the server
- **Automatic overflow** — `store` tries local first; on `OutOfMemory`, falls back to the best available peer

### `cli.py` — Command-Line Client

A thin RPC client wrapping the length-prefixed JSON protocol into ergonomic CLI commands.

### `main.py` — Daemon Entrypoint

Wires together all components and installs a global asyncio exception handler so background task failures are logged instead of silently swallowed.

---

## Getting Started

### Prerequisites

- Python 3.10+

### Installation

```bash
# Clone the repo
git clone https://github.com/naavalanarul/memnode.git
cd memnode

# Install dependencies
pip install -r requirements.txt

# Or install as editable package (recommended for development)
pip install -e ".[dev]"
```

### Run a Node

```bash
python -m memnode.main --name my-node --ram-quota 536870912
```

This starts:
- **Peer protocol** listener on `0.0.0.0:8080`
- **Local RPC** server on `127.0.0.1:7070` (TCP) and `/tmp/memcloud-7070.sock` (Unix)
- **mDNS** advertisement & discovery (`_memcloud._tcp.local.`)

### Configuration Flags

| Flag | Default | Description |
|---|---|---|
| `--name` | `unnamed-node` | Human-readable node name |
| `--ram-quota` | `536870912` (512 MB) | Bytes of RAM to offer to the pool |
| `--peer-port` | `8080` | TCP port for node-to-node protocol |
| `--rpc-port` | `7070` | TCP port for local RPC |
| `--rpc-socket` | auto | Unix socket path for local RPC |
| `--no-mdns` | off | Skip mDNS discovery (use manual `connect` instead) |
| `--log-level` | `INFO` | Logging verbosity |

---

## CLI Usage

Talk to a running daemon using the built-in CLI:

```bash
# Check node status
python -m memnode.cli stats

# Store data
python -m memnode.cli store --text "hello cluster" --key greeting

# Load data
python -m memnode.cli load --key greeting --as-text

# Connect to another node
python -m memnode.cli connect --peer-host 192.168.1.42 --peer-port 8080

# List connected peers
python -m memnode.cli peers

# Store on a specific peer
python -m memnode.cli remote-store --peer <pubkey-prefix> --text "hi" --key k2

# Load from a specific peer
python -m memnode.cli remote-load --peer <pubkey-prefix> --key k2

# Free a block
python -m memnode.cli free --block-id 1
```

---

## RPC API Reference

The RPC protocol uses a **4-byte big-endian length prefix + JSON body**. You can test it programmatically:

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

### Supported Operations

| Operation | Description | Key Parameters |
|---|---|---|
| `store` | Store data locally (auto-overflows to peer if full) | `data_hex`, `key`, `durability`, `allow_remote` |
| `load` | Load data by key or block ID (checks peers if not local) | `key` or `block_id`, `allow_remote` |
| `free` | Free a locally-held block | `block_id` |
| `stats` | Returns local quota usage | — |
| `peers` | List connected peers | — |
| `connect` | Dial another node's peer-protocol port | `host`, `port` |
| `remote_store` | Store data on a specific peer | `peer`, `data_hex`, `key`, `durability` |
| `remote_load` | Load data from a specific peer | `peer`, `key` or `block_id` |
| `remote_free` | Free a block on a specific peer | `peer`, `block_id` |

All responses include `"ok": true/false`. Failed operations include an `"error"` field.

---

## Security Model

```
  Node A                                              Node B
    │                                                    │
    │──── Hello (nonce + ephemeral X25519 pubkey) ──────▶│
    │◀─── Hello (nonce + ephemeral X25519 pubkey) ───────│
    │                                                    │
    │        ┌── transcript hash = SHA256(both Hellos)   │
    │                                                    │
    │──── Auth (Ed25519 identity + sig(transcript)) ────▶│
    │◀─── Auth (Ed25519 identity + sig(transcript)) ─────│
    │                                                    │
    │     ┌── ECDH shared secret + HKDF → traffic keys   │
    │                                                    │
    │◀═══ ChaCha20-Poly1305 encrypted channel ══════════▶│
```

- **Identity**: Each node has a persistent Ed25519 keypair
- **Key Exchange**: Ephemeral X25519 Diffie-Hellman (forward secrecy)
- **Authentication**: Signatures over transcript hash (MITM detection)
- **Transport**: ChaCha20-Poly1305 AEAD with per-direction keys and monotonic nonces
- **Trust**: TOFU model with persistent trust store at `~/.memcloud/trusted_devices.json`

---

## Testing

```bash
# Run all tests
python -m pytest -v

# Run specific test files
python -m pytest test_blocks.py -v      # Block storage & eviction (7 tests)
python -m pytest test_protocol.py -v    # Wire framing & message codec (4 tests)
python -m pytest test_rpc.py -v         # End-to-end RPC integration (3 tests)
```

### Test Coverage

| Area | Tests | What's Covered |
|---|---|---|
| **Block Storage** | 7 | Store/load roundtrip, key lookups, per-block size cap, quota enforcement, cache eviction, free & usage tracking |
| **Wire Protocol** | 4 | Frame roundtrip, oversized frame rejection, boundary size check, message encode/decode |
| **RPC Server** | 3 | End-to-end store/load over real TCP, oversized message resilience, unknown op handling |

---

## Improvements Over Reference Implementation

This codebase was written to address specific issues found by auditing a reference (Rust) implementation:

| Issue in Reference | Fix in memnode |
|---|---|
| Unbounded frame allocation (`vec![0u8; len]` with no cap) → DoS | `read_frame()` checks `MAX_FRAME_SIZE` before allocating, everywhere |
| No per-block size cap | `blocks.py` enforces `MAX_BLOCK_SIZE` before accepting a store |
| 34 `.unwrap()`/`.expect()` calls that could panic the daemon | Every handler is wrapped in try/except — logs and degrades gracefully |
| Only 3 unit tests, no test CI | 14 tests covering framing, block quotas/eviction, and end-to-end RPC |
| No replication | `replication.py` implements full request/reply block operations across peers |
| No load-aware placement | `best_peer_for_store()` picks the peer with the most free capacity |
| No NACK for failed peer operations | `Nack` message type with error details on failed `StoreBlock`/`RequestBlock` |
| No remote block freeing | `FreeBlock`/`Freed` messages let RPC free blocks held on other nodes |

---

## Roadmap

- [ ] **Multi-copy replication** — store a block on N peers for redundancy (groundwork is in place)
- [ ] **Push channel** — WebSocket/SSE endpoint for real-time dashboard updates (currently requires polling)
- [ ] **Consent UI** — real approval prompt for untrusted networks (currently auto-approves)
- [ ] **React dashboard** — web UI for monitoring cluster stats, peers, and block placement
- [ ] **Streaming/chunked uploads** — first-class support for payloads larger than `MAX_BLOCK_SIZE`

---

## Demo

See [`demo/DEMO_GUIDE.md`](demo/DEMO_GUIDE.md) for a step-by-step walkthrough of:

- **Part A** — Single machine: store data, watch RAM spike in Activity Monitor, free it, watch it drop
- **Part B** — Two computers: fill one node's quota, watch overflow automatically appear on the second machine's memory monitor

A helper client (`demo/demo_client.py`) handles chunked transfers and cleanup.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

**Copyright © 2026 Naavalan A**

---

## Hardening & performance phases

| Phase | Branch | Document |
| --- | --- | --- |
| Phase 1 — security hardening | `phase1-security-hardening` | [docs/PHASE1_SECURITY.md](docs/PHASE1_SECURITY.md) |
| Phase 2 — latency reduction | `phase2-latency-reduction` | [docs/PHASE2_LATENCY.md](docs/PHASE2_LATENCY.md) |

Phase 1 adds per-frame replay protection and session rekeying, handshake
rate limiting and timeouts on the peer listener, an authenticated
loopback-only RPC control plane, optional mTLS with certificate pinning,
and a trust store with out-of-band (SAS/QR) verification instead of bare
pubkey-hex TOFU.

Phase 2 adds msgpack binary RPC framing (JSON clients keep working),
chunked block transfer with per-transfer logical streams, a round-robin
connection multiplexer, optional uvloop, and a lock-striped block store
with O(1) key removal. Reproduce the numbers with `python bench/bench_rpc.py`,
`bench/bench_hol.py`, `bench/bench_loop.py` and `bench/bench_blocks.py` —
and note that the lock striping measured close to zero on a single-threaded
event loop, which is documented rather than glossed over.
