"""memnode: Python implementation of the memcloud daemon.

Package layout:
  config.py     - all tunable limits/ports in one place, including the
                   size caps that fix the unbounded-allocation bug found
                   in the reference Rust implementation.
  protocol.py   - wire framing + message types (msgpack-based).
  blocks.py     - in-memory block store, quota enforcement, eviction.
  security.py   - Noise-XX-inspired handshake + ChaCha20-Poly1305 channel.
  peers.py      - peer registry, TOFU trust store, consent flow.
  discovery.py  - mDNS peer discovery via zeroconf.
  rpc.py        - local RPC server for the CLI/SDKs.
  main.py       - entrypoint wiring everything together.
"""

__version__ = "0.0.1"
