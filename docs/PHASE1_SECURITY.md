# Phase 1 — Security hardening

Branch: `phase1-security-hardening`

Five changes, each closing a concrete gap in the pre-existing daemon.
Every item below is implemented and covered by tests
(`test_secure_channel.py`, `test_handshake_guard.py`, `test_rpc_auth.py`,
`test_trust.py` — 66 tests total, including the 14 that already existed).

---

## 1. Replay window + session rekeying

**Files:** `memnode/security.py`, `memnode/config.py`

**Before.** `SecureChannel` kept an implicit `_recv_counter` and derived the
nonce from it. Nothing was carried on the wire, so the receiver simply
assumed the Nth frame it read was frame N. That assumption holds only for a
perfectly ordered, never-replayed byte stream, and it silently breaks the
moment the channel is carried over anything weaker or resumed.

**After.** Each frame body is now:

```
seq (8 bytes, big-endian) || ChaCha20-Poly1305 ciphertext
```

* `seq` is passed as AEAD associated data, so rewriting it in flight breaks
  the Poly1305 tag (`test_sequence_number_is_authenticated`).
* `ReplayWindow` is an IPsec-style 1024-slot sliding bitmap: duplicates and
  frames older than the window are dropped *before* decryption, and a
  replayed frame is dropped rather than tearing down the connection —
  tearing down would itself hand an attacker a one-packet DoS.
* `seq // REKEY_INTERVAL_MESSAGES` selects the key epoch. Keys advance by
  chained HKDF (`k_n = HKDF(k_{n-1})`), so recovering the epoch-N key does
  not reveal epoch N-1.
* Time-based rekeying is implemented by jumping the send sequence to the
  next epoch boundary — no new message type, no round trip, and the
  receiver stays in sync because the epoch is a pure function of `seq`.
* `MAX_REKEY_EPOCH_SKIP` bounds how much HKDF work a peer can force with a
  single frame.

**Defaults:** 1024-frame window, rekey every 100 000 frames or 900 s.

## 2. Handshake rate limiting and timeouts

**Files:** `memnode/ratelimit.py` (new), `memnode/peers.py`

**Before.** Every inbound TCP connection went straight into
`perform_handshake` — X25519 keygen + ECDH + Ed25519 verify — with no
timeout. Two cheap attacks followed: a CPU flood, and task/FD exhaustion
from connections that opened a socket and then stalled forever on
`readexactly`.

**After.** `HandshakeGuard` admits or refuses **before any crypto runs**:

| Control | Default | Config key |
|---|---|---|
| Attempts per source IP per 60 s | 20 | `HANDSHAKE_MAX_PER_IP_PER_WINDOW` |
| Concurrent handshakes per IP | 4 | `HANDSHAKE_MAX_INFLIGHT_PER_IP` |
| Concurrent handshakes total | 128 | `HANDSHAKE_MAX_INFLIGHT_TOTAL` |
| Handshake wall-clock timeout | 10 s | `HANDSHAKE_TIMEOUT_SECONDS` |

The limiter's own IP table is bounded (`HANDSHAKE_GUARD_MAX_TRACKED_IPS`)
and evicts only idle entries, so spraying spoofed sources cannot turn the
defence into a memory leak. Every path releases its slot in a `finally`.

## 3. RPC control-plane authentication and loopback binding

**Files:** `memnode/rpcauth.py` (new), `memnode/rpc.py`, `memnode/cli.py`, `memnode/main.py`

**Before.** `RpcServer.start()` bound `0.0.0.0` — despite the module
docstring claiming loopback-only — and there was no authentication. Anyone
who could reach port 7070 could `store`, `free`, `connect` to arbitrary
hosts, and `remote_free` other nodes' blocks.

**After.**

* Binds `config.RPC_BIND_HOST` (`127.0.0.1`). A non-loopback bind raises
  unless `allow_remote_bind=True` is passed deliberately, and an
  *unauthenticated* non-loopback bind is refused outright.
* Challenge–response before any op is dispatched: the server sends 32 fresh
  random bytes, the client returns `HMAC-SHA256(token, challenge)`,
  compared with `hmac.compare_digest`. A sniffed response is useless on the
  next connection (`test_replaying_a_captured_response_on_a_new_connection_fails`).
* Token lives in `~/.memcloud/rpc_token`, created 0600 via `os.open` (never
  written world-readable and then chmod'ed). The CLI reads it automatically;
  `--token` / `--token-file` override.
* The Unix socket is exempt by default and chmod'ed 0600 — filesystem
  permissions already gate it.
* `require_auth=True` with no token downgrades **loudly** rather than
  pretending to be protected.

## 4. Optional mTLS transport

**File:** `memnode/tlsmode.py` (new), wired through `peers.py` / `main.py`

Layered *underneath* the existing handshake, never instead of it:

```
TCP -> [optional mTLS] -> Hello/Auth handshake -> SecureChannel
```

TLS 1.3 minimum, client certificates required by default, plus optional
SHA-256 pinning of the peer's DER certificate so a rogue CA in the trust
store is not sufficient to impersonate a peer. Hostname checking is off by
design — LAN nodes rarely have resolvable names and pinning replaces it.

```bash
python -m memnode.main --tls-cert node.pem --tls-key node.key \
                       --tls-ca ca.pem --tls-pin <sha256-hex>
```

Off unless `--tls-cert` and `--tls-key` are both supplied.

## 5. Trust store beyond bare TOFU

**File:** `memnode/peers.py`

**Before.** `trusted_devices.json` was a flat `{pubkey_hex: name}` map. It
answered "have I seen this key?" and nothing else.

**After.** v2 records carry `first_seen`, `last_seen`, `verified`, `method`
(`tofu` / `sas` / `qr` / `manual`) and observed addresses. v1 files are
migrated on load; writes are atomic (temp file + `replace`).

* **SAS.** The handshake now yields a 6-digit code derived from the
  transcript hash. Both ends compute the same code; a MITM running two
  separate handshakes cannot. Compare it out of band, then record it:

  ```bash
  python -m memnode.cli pair   --peer <prefix> --qr   # shows code + memcloud:// URI
  python -m memnode.cli verify --peer <prefix>        # after the codes match
  python -m memnode.cli trusted
  ```

  QR rendering uses the optional `qrcode` package and returns `None` if it
  is absent — a display helper must never break pairing.

* **Substitution detection.** `identity_conflicts()` surfaces the two cases
  plain TOFU misses: a familiar display name arriving on a brand-new key,
  and a known key that renamed itself.

* **Sticky verification.** A peer confirmed out of band stays confirmed; a
  later plain-TOFU reconnect cannot silently downgrade it.

* `--require-verification` makes out-of-band confirmation mandatory on
  first contact instead of accepting bare TOFU.

---

## Compatibility notes

* **Wire format changed.** The 8-byte sequence prefix means a Phase 1 node
  cannot talk to a pre-Phase-1 node. `PROTOCOL_VERSION` is checked during
  Hello, so the mismatch fails fast with a clear error instead of
  garbage-decrypting.
* **Consent callbacks.** The old `(pubkey, name, addr)` signature still
  works; a 4-argument callback additionally receives the SAS. Arity is
  detected via `inspect.signature`.
* **Existing tests.** All 14 original tests pass unmodified. `test_rpc.py`
  builds `RpcServer` without a token, which now disables auth for that
  instance (with a warning) rather than breaking.

## Known limits (deliberately not solved here)

* The RPC token is a bearer secret. Any process running as the daemon's
  user can read it. Per-client identities would need a real local
  credential mechanism (`SO_PEERCRED` on Linux, for example).
* Rate limiting is per source IP, so it does not help against a distributed
  flood or a spoofed-source SYN flood — those belong in the firewall.
* The SAS is only meaningful if a human actually compares it. Nothing here
  can force that.
* mTLS certificate rotation/expiry is not automated.
