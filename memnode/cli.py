"""Tiny RPC client / CLI for demoing a running memnode daemon.

This just speaks the same length-prefixed-JSON protocol rpc.py serves
(see rpc.py's module docstring) -- it's the same thing test_rpc.py's
`_call()` helper does, wrapped into a command-line tool so a hackathon
demo doesn't need `nc` and hand-typed JSON.

Examples:
    python -m memnode.cli --port 7070 stats
    python -m memnode.cli --port 7070 store --text "hello cluster" --key greeting
    python -m memnode.cli --port 7070 load --key greeting
    python -m memnode.cli --port 7070 connect --host 127.0.0.1 --peer-port 8081
    python -m memnode.cli --port 7070 peers
    python -m memnode.cli --port 7070 remote-store --peer <pubkey-prefix> --text "hi" --key k2
    python -m memnode.cli --port 7070 remote-load --peer <pubkey-prefix> --key k2
"""
from __future__ import annotations

import argparse
import asyncio
import json
import struct
import sys

from . import config


async def _call(host: str, port: int, req: dict) -> dict:
    reader, writer = await asyncio.open_connection(host, port)
    raw = json.dumps(req).encode("utf-8")
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()
    len_bytes = await reader.readexactly(4)
    (length,) = struct.unpack(">I", len_bytes)
    resp = json.loads((await reader.readexactly(length)).decode("utf-8"))
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return resp


def _print(resp: dict) -> None:
    print(json.dumps(resp, indent=2))


async def _run(args: argparse.Namespace) -> int:
    if args.op == "store":
        payload = args.text.encode("utf-8") if args.text is not None else bytes.fromhex(args.hex)
        req = {"op": "store", "data_hex": payload.hex(), "durability": args.durability}
        if args.key:
            req["key"] = args.key
        resp = await _call(args.host, args.port, req)

    elif args.op == "load":
        req = {"op": "load"}
        if args.key:
            req["key"] = args.key
        elif args.block_id is not None:
            req["block_id"] = args.block_id
        else:
            print("load needs --key or --block-id", file=sys.stderr)
            return 2
        resp = await _call(args.host, args.port, req)
        if resp.get("ok") and args.as_text:
            resp["text"] = bytes.fromhex(resp["data_hex"]).decode("utf-8", errors="replace")

    elif args.op == "remote-store":
        payload = args.text.encode("utf-8") if args.text is not None else bytes.fromhex(args.hex)
        req = {"op": "remote_store", "peer": args.peer, "data_hex": payload.hex(),
               "durability": args.durability}
        if args.key:
            req["key"] = args.key
        resp = await _call(args.host, args.port, req)

    elif args.op == "remote-load":
        req = {"op": "remote_load", "peer": args.peer}
        if args.key:
            req["key"] = args.key
        elif args.block_id is not None:
            req["block_id"] = args.block_id
        resp = await _call(args.host, args.port, req)
        if resp.get("ok") and args.as_text:
            resp["text"] = bytes.fromhex(resp["data_hex"]).decode("utf-8", errors="replace")

    elif args.op == "free":
        resp = await _call(args.host, args.port, {"op": "free", "block_id": args.block_id})

    elif args.op == "stats":
        resp = await _call(args.host, args.port, {"op": "stats"})

    elif args.op == "peers":
        resp = await _call(args.host, args.port, {"op": "peers"})

    elif args.op == "connect":
        resp = await _call(args.host, args.port,
                            {"op": "connect", "host": args.peer_host, "port": args.peer_port})

    else:
        print(f"unknown command: {args.op}", file=sys.stderr)
        return 2

    _print(resp)
    return 0 if resp.get("ok") else 1


def main():
    parser = argparse.ArgumentParser(description="memnode RPC CLI (talks to a running daemon)")
    parser.add_argument("--host", default="127.0.0.1", help="RPC host of the daemon to talk to")
    parser.add_argument("--port", type=int, default=config.RPC_TCP_PORT, help="RPC port of the daemon")
    sub = parser.add_subparsers(dest="op", required=True)

    p_store = sub.add_parser("store", help="store data locally (auto-overflows to a peer if full)")
    g = p_store.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="UTF-8 text to store")
    g.add_argument("--hex", help="raw bytes to store, as hex")
    p_store.add_argument("--key", help="optional lookup key")
    p_store.add_argument("--durability", choices=["pinned", "cache"], default="pinned")

    p_load = sub.add_parser("load", help="load data (checks peers by key if not held locally)")
    p_load.add_argument("--key")
    p_load.add_argument("--block-id", type=int)
    p_load.add_argument("--as-text", action="store_true", help="also decode result as UTF-8")

    p_rstore = sub.add_parser("remote-store", help="store data on one specific connected peer")
    p_rstore.add_argument("--peer", required=True, help="pubkey (prefix) of a connected peer")
    g2 = p_rstore.add_mutually_exclusive_group(required=True)
    g2.add_argument("--text")
    g2.add_argument("--hex")
    p_rstore.add_argument("--key")
    p_rstore.add_argument("--durability", choices=["pinned", "cache"], default="cache")

    p_rload = sub.add_parser("remote-load", help="load data from one specific connected peer")
    p_rload.add_argument("--peer", required=True)
    p_rload.add_argument("--key")
    p_rload.add_argument("--block-id", type=int)
    p_rload.add_argument("--as-text", action="store_true")

    p_free = sub.add_parser("free", help="free a locally-held block")
    p_free.add_argument("--block-id", type=int, required=True)

    sub.add_parser("stats", help="show this node's local quota/usage")
    sub.add_parser("peers", help="list connected peers")

    p_connect = sub.add_parser("connect", help="dial another node's peer-protocol port")
    p_connect.add_argument("--peer-host", required=True)
    p_connect.add_argument("--peer-port", type=int, required=True)

    args = parser.parse_args()
    try:
        sys.exit(asyncio.run(_run(args)))
    except ConnectionRefusedError:
        print(f"could not connect to daemon RPC at {args.host}:{args.port} -- is it running?",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
