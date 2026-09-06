# Hackathon demo: watch RAM actually spike when you "transfer" a file in

Two versions of this demo are below:

- **Part A — single machine:** transfer a file into one node, watch its RAM
  climb in Task Manager/Activity Monitor, then free it and watch it drop.
- **Part B — two computers:** the real "distributed RAM pool" demo. Node A's
  quota fills up mid-transfer and the rest spills over onto Node B
  automatically — you'll watch RAM climb on *both* machines' monitors from
  a single upload command, then watch both drop back down on cleanup.

Do Part A first to get comfortable with the tool; Part B is the one to
actually show judges.

Why this works at all: memnode stores data as raw Python `bytes` in the
node process's own memory (`memnode/blocks.py`). There's no disk write, no
compression, no simulation — the process's resident memory (RSS) grows by
almost exactly the number of bytes you store, and shrinks by almost exactly
that number when you free it. Your OS monitor is reading that same number.

The local RPC frame is capped at 8MB and data is hex-encoded (2x size) over
the wire, so a single "store this whole file" call would get rejected as
oversized — that's a safety feature, not a bug. `demo/demo_client.py`
chunks the transfer for you, the way any real SDK should.

## One-time setup (on every machine you'll use)

```bash
pip install -e .
```

---

# Part A — single machine

### 1. Start a node (Terminal 1)

```bash
python -m memnode.main --name demo-node --ram-quota 600000000 --no-mdns
```

`600000000` bytes ≈ 572MB — plenty of headroom for a ~400MB demo file.
Leave this running.

### 2. Open your OS memory monitor

- **Windows:** Task Manager → Details tab → sort by Memory → find `python.exe`
- **macOS:** Activity Monitor → Memory tab → find `Python`
- **Linux:** `htop` (press `M` to sort by memory) or find `python3`

Note the baseline — a few tens of MB.

### 3. Transfer a file in (Terminal 2)

```bash
python demo/demo_client.py upload --file /path/to/your_video.mp4
```

No file handy? Generate synthetic data instead — it behaves identically
from the node's point of view, since it's just bytes either way:

```bash
python demo/demo_client.py upload --synthetic-mb 400 --name demo-payload
```

Watch the RAM number climb in your OS monitor as the progress bar fills.

### 4. Release it and watch RAM drop

```bash
python demo/demo_client.py cleanup --name demo-payload
```

(use whatever `--name` you uploaded under — defaults to the filename).

---

# Part B — two computers (the real pool demo)

You need two machines on the same Wi-Fi/LAN, each with this project set up.
Call them **Machine A** and **Machine B**.

### 1. Find each machine's LAN IP

- **Windows:** `ipconfig` → "IPv4 Address"
- **macOS/Linux:** `ifconfig` or `ip addr` → look for something like `192.168.x.x`

Write down Machine B's IP — you'll need it from Machine A.

### 2. Allow the peer port through the firewall

Both machines need to accept inbound TCP on the peer port (default `8080`).
On first run your OS will likely prompt "Allow Python to accept incoming
connections?" — click **Allow**. If nothing prompts and the connect step
below fails, open port 8080 manually in your firewall settings.

### 3. Start a node on each machine

**On Machine A** — give it a **small** quota so it fills up quickly and
you get to see the overflow happen live:

```bash
python -m memnode.main --name node-A --ram-quota 41943040 --no-mdns
```

(that's 40MB — small on purpose, for the demo)

**On Machine B** — give it a big quota, since it's the "overflow target":

```bash
python -m memnode.main --name node-B --ram-quota 600000000 --no-mdns
```

Leave both running and visible.

### 4. Open the OS memory monitor on BOTH machines

Same as Part A, step 2 — Task Manager / Activity Monitor / htop — one
window per machine, both visible if you're screen-sharing or presenting
side by side.

### 5. Connect Machine A to Machine B (run on Machine A)

```bash
python demo/demo_client.py connect --peer-host <MACHINE_B_IP> --peer-port 8080
```

Confirm it worked:

```bash
python demo/demo_client.py peers
```

You should see `node-B` listed with its advertised quota.

### 6. Upload — from Machine A (this is the whole demo, one command)

```bash
python demo/demo_client.py upload --file /path/to/your_video.mp4
```

or with synthetic data sized to comfortably exceed Machine A's 40MB quota:

```bash
python demo/demo_client.py upload --synthetic-mb 150 --name pool-demo
```

**What you'll see:**
- RAM on **Machine A** climbs first
- once Machine A's 40MB quota is full, the script prints a line like
  `-> local quota is now full; overflowing onto peer ...`
- from that point on, **RAM on Machine B starts climbing instead** — all
  driven by the one command you ran on Machine A
- the final summary reports how many blocks landed locally vs. remotely

This is the moment to narrate: *"I'm only touching Machine A. Machine B's
memory is rising because the pool is placing overflow blocks there over
the network, automatically, based on which peer has free capacity."*

### 7. Cleanup — watch both drop back down (still on Machine A)

```bash
python demo/demo_client.py cleanup --name pool-demo
```

This frees every block, wherever it landed — locally-freed blocks are
released directly, remotely-placed ones are released via a peer-to-peer
free request. Watch RAM fall back toward baseline on **both** machines'
monitors.

---

## Talking points

- "This is real OS-level memory allocation on two separate machines, not a
  simulation — I have Activity Monitor/Task Manager open on both."
- "memnode enforces a per-block size cap and a total quota cap *before*
  accepting data — that's why the client chunks the file instead of
  sending it in one shot (see `memnode/config.py`)."
- "When Machine A's quota fills, it automatically finds the peer with the
  most free capacity and places the overflow there — that's the 'pool'
  part of 'distributed RAM pool,' not just per-node storage."
- "Freeing releases memory back to the OS on whichever machine actually
  held each piece — including across the network — watch both monitors
  drop."

## Troubleshooting

- **"Could not connect to memnode RPC"** — the node isn't running on the
  machine you're targeting, or `--port` doesn't match its `--rpc-port`.
- **`connect` hangs or fails** — almost always a firewall blocking the
  peer port (default 8080) on Machine B, or the two machines aren't
  actually on the same LAN/subnet (e.g. one is on a guest Wi-Fi network
  that isolates clients from each other — try a phone hotspot as a
  fallback network).
- **Everything stays local; nothing overflows to Machine B** — Machine
  A's `--ram-quota` wasn't actually small enough to fill up before your
  file finished uploading; lower it or upload more data.
- **A chunk store fails with "exceeds MAX_RPC_MESSAGE_SIZE"** — you passed
  `--chunk-kb` bigger than the RPC frame limit allows; drop the flag and
  let the client pick a safe default.
- **RAM doesn't fully return to baseline after cleanup** — a few MB of
  residual growth (interpreter/allocator overhead) is normal; the bulk of
  the spike should still clearly reverse. Restarting a node is a full
  reset if you want a clean slate between demo runs.
