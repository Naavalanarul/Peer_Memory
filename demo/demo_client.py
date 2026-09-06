"""Hackathon demo client: transfer a file into a running memnode daemon and
watch its RAM usage spike in your OS's Task Manager / Activity Monitor.

WHY THIS EXISTS
----------------
memnode's local RPC server enforces MAX_RPC_MESSAGE_SIZE (8MB by default,
see memnode/config.py) on every request, and data is hex-encoded on the
wire (doubling its size), so a single giant `store` call for a 300MB file
would just get rejected as "oversized" -- that rejection is a *safety
feature*, not a bug. This client does what any real SDK/CLI should do:
it splits your file into safe-sized chunks and stores each one under a
manifest, so the node's total resident memory grows chunk-by-chunk as
the transfer proceeds. That growth is what you'll see climb in Task
Manager / Activity Monitor / htop while this script runs.

USAGE
-----
1. In one terminal, start a node with a RAM quota big enough for your
   demo file (quota is in bytes):

     python -m memnode.main --name demo-node --ram-quota 600000000 --no-mdns

   Leave it running. Open Task Manager (Windows) / Activity Monitor
   (macOS) / htop (Linux), sort by memory, and find the python process
   running memnode.main. Note its baseline RAM.

2. In a second terminal, "transfer" a file into the pool:

     python demo/demo_client.py upload --file /path/to/big_video.mp4

   or, if you don't have a big file handy, generate synthetic data to
   upload instead:

     python demo/demo_client.py upload --synthetic-mb 400 --name demo-payload

   Watch the RAM number in Task Manager / Activity Monitor climb as
   this runs. A live progress bar and the node's own reported memory
   usage (pulled straight from its `stats` RPC) print in this terminal
   too, so you have two independent confirmations of the same number.

3. To prove it's not a fluke -- and that memnode manages memory
   properly instead of just leaking -- release the data and watch RAM
   drop back down:

     python demo/demo_client.py cleanup --name big_video.mp4

4. `python demo/demo_client.py watch` runs on its own and just prints a
   live bar of the node's memory usage; run it in a third terminal (or
   instead of Task Manager, if you're demoing on a machine/projector
   where switching windows is awkward).

All commands accept --host/--port if your node isn't on the default
127.0.0.1:7070 (see memnode/config.py RPC_TCP_PORT).
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
import socket
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from memnode import config  # noqa: E402

MANIFEST_DIR = Path.home() / ".memnode_demo"

# Hex-encoding doubles the payload, and the JSON wrapper (op/durability/key
# fields) adds a little more on top -- stay comfortably under the RPC frame
# cap rather than hugging the exact limit.
SAFE_CHUNK_BYTES = min(config.MAX_BLOCK_SIZE, config.MAX_RPC_MESSAGE_SIZE // 2 - 4096)
DEFAULT_CHUNK_BYTES = min(SAFE_CHUNK_BYTES, 3 * 1024 * 1024)


def _call(host: str, port: int, req: dict) -> dict:
    s = socket.create_connection((host, port))
    try:
        raw = json.dumps(req).encode("utf-8")
        s.sendall(struct.pack(">I", len(raw)) + raw)
        len_bytes = _recv_exact(s, 4)
        (length,) = struct.unpack(">I", len_bytes)
        body = _recv_exact(s, length)
        return json.loads(body.decode("utf-8"))
    finally:
        s.close()


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed mid-message")
        buf.extend(chunk)
    return bytes(buf)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _print_bar(label: str, used: int, total: int, width: int = 30, as_bytes: bool = True):
    frac = 0 if total <= 0 else min(1.0, used / total)
    filled = int(frac * width)
    bar = "#" * filled + "-" * (width - filled)
    used_s = _fmt_bytes(used) if as_bytes else str(used)
    total_s = _fmt_bytes(total) if as_bytes else str(total)
    sys.stdout.write(f"\r{label} [{bar}] {used_s}/{total_s} ({frac*100:5.1f}%)   ")
    sys.stdout.flush()


def cmd_upload(args):
    host, port = args.host, args.port
    name = args.name or (Path(args.file).name if args.file else "synthetic-payload")

    if args.file:
        total_size = os.path.getsize(args.file)
        source = open(args.file, "rb")
        read = source.read
    else:
        total_size = args.synthetic_mb * 1024 * 1024
        remaining = [total_size]

        def read(n):
            take = min(n, remaining[0])
            remaining[0] -= take
            return os.urandom(take) if take > 0 else b""
        source = None

    chunk_bytes = args.chunk_kb * 1024 if args.chunk_kb else DEFAULT_CHUNK_BYTES
    chunk_bytes = min(chunk_bytes, SAFE_CHUNK_BYTES)

    print(f"Uploading '{name}': {_fmt_bytes(total_size)} in ~{chunk_bytes//1024}KB chunks "
          f"to {host}:{port}")
    print("Switch to Task Manager / Activity Monitor now and find the memnode python "
          "process (on every machine in the pool, if you connected peers).\n")

    # allow_remote left at the server default (True): if no peer is
    # connected this behaves exactly like the single-machine demo (the
    # local OutOfMemory just fails, since best_peer_for_store finds no
    # candidates). If a peer *is* connected and this node's quota fills
    # up mid-transfer, remaining chunks spill over onto that peer
    # automatically -- that's the two-computer demo.
    chunks = []  # [{"block_id":, "location": "local"/"remote", "peer": str|None}]
    sent = 0
    idx = 0
    remote_seen = False
    t0 = time.time()
    try:
        while sent < total_size:
            data = read(chunk_bytes)
            if not data:
                break
            resp = _call(host, port, {
                "op": "store",
                "data_hex": data.hex(),
                "durability": "pinned",
            })
            if not resp.get("ok"):
                print(f"\n! chunk {idx} failed: {resp.get('error')}")
                sys.exit(1)
            location = resp.get("location", "local")
            peer = resp.get("peer")
            if location == "remote" and not remote_seen:
                remote_seen = True
                print(f"\n  -> local quota is now full; overflowing onto peer {peer} "
                      f"(watch RAM start climbing on *that* machine too)\n")
            chunks.append({"block_id": resp["block_id"], "location": location, "peer": peer})
            sent += len(data)
            idx += 1
            _print_bar("upload", sent, total_size)
            if args.pace:
                time.sleep(args.pace)
    finally:
        if source:
            source.close()

    manifest = {"name": name, "total_bytes": sent, "chunk_count": idx, "chunks": chunks}
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    (MANIFEST_DIR / f"{name}.json").write_text(json.dumps(manifest))

    elapsed = time.time() - t0
    local_n = sum(1 for c in chunks if c["location"] == "local")
    remote_n = idx - local_n
    print(f"\n\nDone: stored {_fmt_bytes(sent)} across {idx} blocks in {elapsed:.1f}s "
          f"({local_n} local, {remote_n} remote).")
    _show_stats(host, port)
    print(f"\nRun this to release it and watch RAM drop back down on every machine "
          f"that holds a piece of it:\n"
          f"  python demo/demo_client.py cleanup --name {name}")


def cmd_cleanup(args):
    host, port = args.host, args.port
    manifest_path = MANIFEST_DIR / f"{args.name}.json"
    if not manifest_path.exists():
        print(f"No local manifest found for '{args.name}' at {manifest_path} "
              f"(already freed, wrong --name, or run from a different directory/machine "
              f"than the upload?)")
        return
    manifest = json.loads(manifest_path.read_text())
    chunks = manifest["chunks"]

    print(f"Freeing {len(chunks)} chunks for '{args.name}' "
          f"({_fmt_bytes(manifest['total_bytes'])})...")
    print("Keep an eye on Task Manager / Activity Monitor on every machine involved -- "
          "RAM should drop back down on each one.\n")
    failures = 0
    for i, c in enumerate(chunks):
        if c["location"] == "remote":
            resp = _call(host, port, {"op": "remote_free", "peer": c["peer"], "block_id": c["block_id"]})
        else:
            resp = _call(host, port, {"op": "free", "block_id": c["block_id"]})
        if not resp.get("ok"):
            failures += 1
        _print_bar("freeing", i + 1, len(chunks), as_bytes=False)
    print()
    if failures:
        print(f"! {failures} block(s) failed to free (peer disconnected mid-demo?) -- "
              f"restarting that node's process is the fallback reset.")
    else:
        manifest_path.unlink(missing_ok=True)
    _show_stats(host, port)


def cmd_stats(args):
    _show_stats(args.host, args.port)


def _show_stats(host, port):
    resp = _call(host, port, {"op": "stats"})
    if not resp.get("ok"):
        print("stats call failed:", resp.get("error"))
        return
    s = resp["stats"]
    _print_bar("node RAM", s["used_bytes"], s["max_bytes"])
    print(f"\n  blocks stored: {s['block_count']}   free: {_fmt_bytes(s['free_bytes'])}")


def cmd_watch(args):
    print("Live node memory (Ctrl+C to stop):\n")
    try:
        while True:
            resp = _call(args.host, args.port, {"op": "stats"})
            if resp.get("ok"):
                s = resp["stats"]
                _print_bar("node RAM", s["used_bytes"], s["max_bytes"])
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()


def cmd_connect(args):
    resp = _call(args.host, args.port, {"op": "connect", "host": args.peer_host, "port": args.peer_port})
    if resp.get("ok"):
        print(f"Connected to peer {resp['pubkey'][:8]} at {args.peer_host}:{args.peer_port}")
    else:
        print("Connect failed:", resp.get("error"))


def cmd_peers(args):
    resp = _call(args.host, args.port, {"op": "peers"})
    if not resp.get("ok"):
        print("peers call failed:", resp.get("error"))
        return
    peers = resp["peers"]
    if not peers:
        print("No peers connected.")
        return
    for p in peers:
        print(f"  {p['pubkey']}  {p['name']:<20} {p['addr']:<22} "
              f"remote_quota={_fmt_bytes(p['remote_quota'])}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=config.RPC_TCP_PORT)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_up = sub.add_parser("upload", help="chunk-upload a file (or synthetic data) into the pool")
    g = p_up.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="path to a real file to transfer")
    g.add_argument("--synthetic-mb", type=int, help="generate N MB of random data instead")
    p_up.add_argument("--name", help="label to store/free this transfer under "
                                      "(defaults to the filename)")
    p_up.add_argument("--chunk-kb", type=int, default=None,
                       help=f"chunk size in KB (default {DEFAULT_CHUNK_BYTES//1024}KB, "
                            f"capped at {SAFE_CHUNK_BYTES//1024}KB by the RPC frame limit)")
    p_up.add_argument("--pace", type=float, default=0.05,
                       help="seconds to sleep between chunks, so the RAM climb is visible "
                            "in real time on a 1s-refresh monitor (default 0.05)")
    p_up.set_defaults(func=cmd_upload)

    p_clean = sub.add_parser("cleanup", help="release a previously uploaded transfer")
    p_clean.add_argument("--name", required=True)
    p_clean.set_defaults(func=cmd_cleanup)

    p_stats = sub.add_parser("stats", help="print current node memory usage once")
    p_stats.set_defaults(func=cmd_stats)

    p_watch = sub.add_parser("watch", help="live-print node memory usage in a loop")
    p_watch.add_argument("--interval", type=float, default=0.5)
    p_watch.set_defaults(func=cmd_watch)

    p_connect = sub.add_parser("connect", help="dial another node's peer-protocol port "
                                                 "(needed once, before a cross-machine demo)")
    p_connect.add_argument("--peer-host", required=True, help="the OTHER machine's LAN IP")
    p_connect.add_argument("--peer-port", type=int, default=config.PEER_TCP_PORT)
    p_connect.set_defaults(func=cmd_connect)

    p_peers = sub.add_parser("peers", help="list currently connected peers")
    p_peers.set_defaults(func=cmd_peers)

    args = parser.parse_args()
    try:
        args.func(args)
    except ConnectionRefusedError:
        print(f"Could not connect to memnode RPC at {args.host}:{args.port}. "
              f"Is the node running? (python -m memnode.main ...)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
