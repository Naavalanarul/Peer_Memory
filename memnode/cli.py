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

Out-of-band peer verification (phase 1):
    python -m memnode.cli --port 7070 pair --peer <pubkey-prefix> --qr
    # compare the 6-digit code with the one shown on the other device, then:
    python -m memnode.cli --port 7070 verify --peer <pubkey-prefix>
    python -m memnode.cli --port 7070 trusted

Authentication: the daemon writes a shared secret to ~/.memcloud/rpc_token
on first run and this CLI reads it automatically. Override with --token or
--token-file when the daemon runs as a different user.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import struct
import sys
from pathlib import Path
from typing import Optional

import msgpack

from . import config, rpcauth

# How long to wait for the server's auth challenge before assuming the
# daemon was started with --no-rpc-auth. Only paid when this client has a
# token but the server does not want one.
AUTH_PROBE_TIMEOUT = 2.0


def _resolve_token(explicit: Optional[str], token_file: Optional[str]) -> Optional[str]:
    """Token precedence: --token, then --token-file, then the default path."""
    if explicit:
        return explicit
    path = Path(token_file) if token_file else rpcauth.default_token_path()
    try:
        if path.exists():
            value = path.read_text().strip()
            return value or None
    except OSError:
        return None
    return None


async def _read_frame(reader) -> dict:
    len_bytes = await reader.readexactly(4)
    (length,) = struct.unpack(">I", len_bytes)
    if length > config.MAX_RPC_MESSAGE_SIZE:
        raise ValueError(f"server sent an oversized frame ({length} bytes)")
    return json.loads((await reader.readexactly(length)).decode("utf-8"))


async def _write_frame(writer, obj: dict) -> None:
    raw = json.dumps(obj).encode("utf-8")
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()


async def _authenticate(reader, writer, token: Optional[str]) -> None:
    """Complete the challenge-response if the daemon asks for one.

    With no token we send nothing and let the server decide: if it wants
    auth it will close the connection, and the caller reports that
    clearly rather than hanging.
    """
    if token is None:
        return
    try:
        first = await asyncio.wait_for(_read_frame(reader), timeout=AUTH_PROBE_TIMEOUT)
    except asyncio.TimeoutError:
        return                      # daemon running with --no-rpc-auth
    if first.get("memnode_auth") != "challenge":
        raise RuntimeError(f"unexpected greeting from daemon: {first}")
    await _write_frame(writer, {"response": rpcauth.compute_response(token, first["challenge"])})
    result = await _read_frame(reader)
    if not result.get("ok"):
        raise PermissionError(
            f"RPC authentication failed: {result.get('error', 'unknown error')}. "
            f"Check that this client is reading the same token file the daemon wrote.")


async def _read_binary_frame(reader) -> dict:
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    if length > config.MAX_RPC_MESSAGE_SIZE:
        raise ValueError(f"server sent an oversized frame ({length} bytes)")
    return msgpack.unpackb(await reader.readexactly(length), raw=False)


async def _write_binary_frame(writer, obj: dict) -> None:
    raw = msgpack.packb(obj, use_bin_type=True)
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()


def _to_binary_request(req: dict) -> dict:
    """Hex payload -> raw bytes. Halves the payload and skips a hex pass."""
    if "data_hex" in req:
        req = dict(req)
        req["data"] = bytes.fromhex(req.pop("data_hex"))
    return req


def _normalise_response(resp: dict) -> dict:
    """Present a binary reply the same way the JSON one is printed."""
    data = resp.get("data")
    if isinstance(data, (bytes, bytearray)):
        resp = dict(resp)
        resp["data_hex"] = bytes(data).hex()
        del resp["data"]
    return resp


async def _call(host: str, port: int, req: dict, token: Optional[str] = None,
                binary: bool = True) -> dict:
    reader, writer = await asyncio.open_connection(host, port)
    await _authenticate(reader, writer, token)

    if binary:
        # Codec negotiation: the magic preamble switches the connection to
        # msgpack framing with raw binary payloads. The server falls back
        # to JSON for any client that does not send it.
        writer.write(config.RPC_MSGPACK_MAGIC)
        await writer.drain()
        ack = await _read_binary_frame(reader)
        if not ack.get("ok"):
            raise RuntimeError(f"server refused binary framing: {ack}")
        await _write_binary_frame(writer, _to_binary_request(req))
        resp = _normalise_response(await _read_binary_frame(reader))
    else:
        await _write_frame(writer, req)
        resp = await _read_frame(reader)

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return resp


def _print(resp: dict) -> None:
    print(json.dumps(resp, indent=2))


async def _run(args: argparse.Namespace) -> int:
    token = _resolve_token(getattr(args, "token", None), getattr(args, "token_file", None))

    async def call(req: dict) -> dict:
        return await _call(args.host, args.port, req, token=token,
                           binary=not getattr(args, "json", False))

    if args.op == "store":
        payload = args.text.encode("utf-8") if args.text is not None else bytes.fromhex(args.hex)
        req = {"op": "store", "data_hex": payload.hex(), "durability": args.durability}
        if args.key:
            req["key"] = args.key
        resp = await call(req)

    elif args.op == "load":
        req = {"op": "load"}
        if args.key:
            req["key"] = args.key
        elif args.block_id is not None:
            req["block_id"] = args.block_id
        else:
            print("load needs --key or --block-id", file=sys.stderr)
            return 2
        resp = await call(req)
        if resp.get("ok") and args.as_text:
            resp["text"] = bytes.fromhex(resp["data_hex"]).decode("utf-8", errors="replace")

    elif args.op == "remote-store":
        payload = args.text.encode("utf-8") if args.text is not None else bytes.fromhex(args.hex)
        req = {"op": "remote_store", "peer": args.peer, "data_hex": payload.hex(),
               "durability": args.durability}
        if args.key:
            req["key"] = args.key
        resp = await call(req)

    elif args.op == "remote-load":
        req = {"op": "remote_load", "peer": args.peer}
        if args.key:
            req["key"] = args.key
        elif args.block_id is not None:
            req["block_id"] = args.block_id
        resp = await call(req)
        if resp.get("ok") and args.as_text:
            resp["text"] = bytes.fromhex(resp["data_hex"]).decode("utf-8", errors="replace")

    elif args.op == "free":
        resp = await call({"op": "free", "block_id": args.block_id})

    elif args.op == "stats":
        resp = await call({"op": "stats"})

    elif args.op == "peers":
        resp = await call({"op": "peers"})

    elif args.op == "connect":
        resp = await call({"op": "connect", "host": args.peer_host, "port": args.peer_port})

    elif args.op == "trusted":
        resp = await call({"op": "trusted"})

    elif args.op == "pair":
        resp = await call({"op": "pair", "peer": args.peer, "qr": args.qr})
        if resp.get("ok"):
            print(f"verification code: {resp['sas']}")
            print(f"pairing uri     : {resp['uri']}")
            if resp.get("qr"):
                print(resp["qr"])
            elif resp.get("qr_error"):
                print(resp["qr_error"], file=sys.stderr)
            print("Compare this code with the code shown on the other device BEFORE "
                  "running 'verify'.", file=sys.stderr)

    elif args.op == "verify":
        resp = await call({"op": "verify_peer", "peer": args.peer, "method": args.method})

    elif args.op == "revoke":
        req = {"op": "revoke_peer"}
        if args.pubkey:
            req["pubkey"] = args.pubkey
        else:
            req["peer"] = args.peer
        resp = await call(req)

    else:
        print(f"unknown command: {args.op}", file=sys.stderr)
        return 2

    _print(resp)
    return 0 if resp.get("ok") else 1


def main():
    parser = argparse.ArgumentParser(description="memnode RPC CLI (talks to a running daemon)")
    parser.add_argument("--host", default="127.0.0.1", help="RPC host of the daemon to talk to")
    parser.add_argument("--port", type=int, default=config.RPC_TCP_PORT, help="RPC port of the daemon")
    parser.add_argument("--token", default=None,
                        help="RPC shared secret (default: read ~/.memcloud/rpc_token)")
    parser.add_argument("--token-file", default=None,
                        help="file to read the RPC shared secret from")
    parser.add_argument("--json", action="store_true",
                        help="use the legacy hex+JSON framing instead of msgpack binary")
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

    sub.add_parser("trusted", help="show the trust store (who is known, and how)")

    p_pair = sub.add_parser("pair", help="show the out-of-band verification code for a peer")
    p_pair.add_argument("--peer", required=True, help="pubkey (prefix) of a connected peer")
    p_pair.add_argument("--qr", action="store_true", help="also render an ASCII QR code")

    p_verify = sub.add_parser("verify", help="record that a peer's code matched out of band")
    p_verify.add_argument("--peer", required=True)
    p_verify.add_argument("--method", default="sas", choices=["sas", "qr", "manual"])

    p_revoke = sub.add_parser("revoke", help="remove a peer from the trust store")
    p_revoke.add_argument("--peer", help="pubkey prefix of a connected peer")
    p_revoke.add_argument("--pubkey", help="full pubkey hex (works when not connected)")

    args = parser.parse_args()
    try:
        sys.exit(asyncio.run(_run(args)))
    except ConnectionRefusedError:
        print(f"could not connect to daemon RPC at {args.host}:{args.port} -- is it running?",
              file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        print("daemon closed the connection -- if RPC auth is enabled, pass --token/--token-file "
              "or make sure ~/.memcloud/rpc_token is readable by this user.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
