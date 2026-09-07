"""Central configuration and safety limits for memnode.

These limits exist specifically to avoid the unbounded-allocation class
of bug found in the reference (Rust) implementation, where a peer could
send a 4-byte length prefix claiming a multi-GB payload and the reader
would blindly allocate a buffer that size before validating anything.
Every network read in this codebase must go through a path that checks
one of these limits BEFORE allocating memory.
"""

# --- Network framing limits ---
MAX_FRAME_SIZE = 16 * 1024 * 1024        # 16 MB per wire frame (handshake + peer protocol)
MAX_BLOCK_SIZE = 64 * 1024 * 1024        # 64 MB per single stored block (chunk/stream above this)
MAX_RPC_MESSAGE_SIZE = 8 * 1024 * 1024   # 8 MB per local RPC message

# --- Ports ---
PEER_TCP_PORT = 8080          # node-to-node protocol
RPC_TCP_PORT = 7070           # local JSON RPC (loopback only)
RPC_UNIX_SOCKET = "/tmp/memcloud.sock"

# --- mDNS ---
MDNS_SERVICE_TYPE = "_memcloud._tcp.local."

# --- Memory ---
DEFAULT_RAM_QUOTA_BYTES = 512 * 1024 * 1024   # default 512MB advertised quota

# --- Protocol ---
PROTOCOL_VERSION = 1


# ---------------------------------------------------------------------------
# Phase 1 -- security hardening
# ---------------------------------------------------------------------------

# --- Secure channel: replay protection ---
# Each encrypted frame carries an explicit 8-byte sequence number. The
# receiver keeps an IPsec-style sliding bitmap so a frame that is a
# duplicate, or older than the window, is dropped without ever being
# handed to the application. Implicit counters (the previous design)
# only work if the transport is a perfectly ordered, never-replayed
# byte stream; an explicit window is what makes the guarantee hold even
# if the channel is later carried over something weaker (UDP, a relay,
# a resumed session).
REPLAY_WINDOW_SIZE = 1024          # frames of reordering tolerated

# --- Secure channel: session rekeying ---
# Long-lived connections re-run HKDF on a counter/time threshold so a
# single traffic key never protects an unbounded amount of data, and so
# a key recovered at time T cannot decrypt traffic from before the most
# recent rekey (forward secrecy *within* a session).
REKEY_INTERVAL_MESSAGES = 100_000  # rekey every N frames per direction
REKEY_INTERVAL_SECONDS = 900.0     # ...or every 15 minutes, whichever first
MAX_REKEY_EPOCH_SKIP = 64          # refuse a peer that jumps this many epochs
                                    # ahead in one frame (bounds the amount of
                                    # HKDF work an attacker can force on us)

# --- Handshake DoS protection (peer TCP listener) ---
HANDSHAKE_TIMEOUT_SECONDS = 10.0        # hard cap on a full handshake
HANDSHAKE_RATE_WINDOW_SECONDS = 60.0    # sliding window for the rate limit
HANDSHAKE_MAX_PER_IP_PER_WINDOW = 20    # completed+attempted handshakes / IP / window
HANDSHAKE_MAX_INFLIGHT_PER_IP = 4       # concurrent handshakes from one IP
HANDSHAKE_MAX_INFLIGHT_TOTAL = 128      # concurrent handshakes across all IPs
HANDSHAKE_GUARD_MAX_TRACKED_IPS = 8192  # bound the limiter's own memory

# --- RPC control plane ---
# The RPC server used to bind 0.0.0.0, which exposed an *unauthenticated*
# control plane (store/load/free/connect) to the whole LAN. It is now
# loopback-only by default and refuses to bind a non-loopback address
# unless explicitly forced, and every TCP client must authenticate.
RPC_BIND_HOST = "127.0.0.1"
RPC_REQUIRE_AUTH = True
RPC_AUTH_UNIX_SOCKET_EXEMPT = True   # unix socket perms already gate access
RPC_AUTH_TIMEOUT_SECONDS = 5.0
RPC_TOKEN_FILENAME = "rpc_token"     # under ~/.memcloud/
RPC_AUTH_VERSION = 1

# --- Optional mTLS transport (interop / compliance) ---
# Layered *underneath* the Noise-style handshake, never instead of it:
# the peer handshake and SecureChannel run unchanged inside the TLS
# tunnel. Off by default.
TLS_ENABLED = False
TLS_REQUIRE_CLIENT_CERT = True

# --- Trust store / out-of-band verification ---
SAS_DIGITS = 6                       # short authentication string length
REQUIRE_SAS_VERIFICATION = False     # when True, first contact needs an
                                      # explicit out-of-band confirmation
TRUST_STORE_VERSION = 2
