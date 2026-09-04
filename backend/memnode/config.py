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
