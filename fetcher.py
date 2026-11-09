#!/usr/bin/env python3
"""Remote BSC creation fetcher (built 2026-11-05).

Runs on a datacenter host (GitHub Actions runner): scans BSC blocks at full
speed, extracts contract creations (tx.to == null), fingerprints the deployed
bytecode against the PEARL / PoW selector sets, and appends DISTILLED
candidate lines to feed.jsonl — a few KB per run instead of ~160 KB per
block, so the throttled home pipe only ever pulls the feed.

State: state.json {"last_block": N} beside this script. The watermark only
advances over a contiguous fully-fetched prefix (gapless rule, same as the
local deploy_watch). Feed line schema (one JSON object per candidate):
  {"block": int, "ts": int, "contract": "0x..", "creator": "0x..",
   "kind": "PEARL-FAMILY"|"POW-SUSPECT", "name": str|null, "symbol": str|null}

Usage: python3 fetcher.py [--max-blocks 20000] [--state state.json]
                          [--feed feed.jsonl]
Stdlib only. RPC failover across public BSC endpoints.
"""
import json, sys, os, argparse, urllib.request, urllib.error
from Crypto.Hash import keccak

def sel(sig):
    k = keccak.new(digest_bits=256); k.update(sig.encode()); return k.hexdigest()[:8]

# Synced with ~/workspace/scripts/deploy_watch.py (2026-11-05 expansion).
POW_SIGS = ["mine(uint256)","mine(uint256,uint256)","mine(uint256,uint256,uint256)",
            "mine(address,uint256)","mineBatch(uint256,uint256[],uint256)",
            "mineBatch(uint256[],uint256)","submitProof(uint256)","submitProof(uint256,uint256)",
            "submitWork(uint256)","prove(uint256)","grind(uint256)",
            "mine(uint256,bytes32,uint256,uint256,uint256)","mine(uint256,bytes32)",
            "mine(bytes32)","mine(bytes32,uint256)","mine(address)","mine(uint256,address)",
            "mineFor(address,uint256)","mineBatch(uint256)","mineBatch(uint256,bytes32[],uint256)",
            "submitProof(bytes32)","submitProof(uint256,bytes32)","submitWork(uint256,uint256)",
            "submit(uint256)","submitSolution(uint256)","submitSolution(uint256,uint256)",
            "solve(uint256)","solve(uint256,uint256)","prove(uint256,uint256)","prove(bytes32)",
            "dig(uint256)","dig(uint256,uint256)","excavate(uint256)","harvest(uint256)",
            "work(uint256)","pow(uint256)","mintWithProof(uint256,bytes32)",
            "mintPow(uint256,uint256)","workOf(address,uint256,bytes32)",
            "challengeFor(uint256,uint256)","targetFor(address)"]
POW_SELS = [sel(s) for s in POW_SIGS]
PEARL_SELS = ["39148c53", "fd76c4eb", "d2e3ae76"]  # currentTarget/proofDigest/puzzleSeed

RPCS = ["https://bsc-dataseed.binance.org", "https://bsc-dataseed1.defibit.io",
        "https://bsc-dataseed3.binance.org", "https://bsc-dataseed4.binance.org",
        "https://bsc-rpc.publicnode.com", "https://bsc-dataseed1.ninicoin.io"]
UA = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}

def _post(url, payload, timeout):
    req = urllib.request.Request(url, data=payload.encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def rpc(method, params, timeout=20):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params})
    for url in RPCS:
        try:
            d = _post(url, body, timeout)
            if d and not d.get("error"):
                return d.get("result")
        except Exception:
            continue
    return None

def rpc_batch(calls, timeout=30):
    payload = json.dumps([{"jsonrpc": "2.0", "id": i, "method": m,
                           "params": p} for i, (m, p) in enumerate(calls)])
    for url in RPCS:
        try:
            d = _post(url, payload, timeout)
            if not isinstance(d, list):
                continue
            res = [None] * len(calls)
            for item in d:
                i = item.get("id")
                if isinstance(i, int) and 0 <= i < len(calls) \
                        and not item.get("error"):
                    res[i] = item.get("result")
            if any(x is not None for x in res):
                return res
        except Exception:
            continue
    return [None] * len(calls)

def create_address(sender, nonce):
    def enc_len(n, off):
        if n < 56:
            return bytes([off + n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([off + 55 + len(b)]) + b
    addr_b = bytes.fromhex(sender[2:] if sender.startswith("0x") else sender)
    if nonce == 0:
        nonce_enc = b"\x80"
    else:
        nb = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        nonce_enc = enc_len(len(nb), 0x80) + nb
    body = b"\x94" + addr_b + nonce_enc
    payload = enc_len(len(body), 0xc0) + body
    k = keccak.new(digest_bits=256); k.update(payload)
    return "0x" + k.hexdigest()[-40:]

def call_str(to, data):
    r = rpc("eth_call", [{"to": to, "data": data}, "latest"], 10)
    if not r or r == "0x":
        return None
    try:
        if len(r) > 128:
            ln = int(r[66:130], 16)
            return bytes.fromhex(r[130:130 + ln * 2]).decode("utf-8", "replace")
        return bytes.fromhex(r[2:66]).rstrip(b"\x00").decode("utf-8", "replace")
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-blocks", type=int, default=20000)
    ap.add_argument("--state", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "state.json"))
    ap.add_argument("--feed", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "feed.jsonl"))
    args = ap.parse_args()

    state = {"last_block": 0}
    if os.path.exists(args.state):
        with open(args.state) as f:
            state = json.load(f)
    cur = int(state.get("last_block", 0))
    latest = rpc("eth_blockNumber", [], 15)
    if latest is None:
        print("FATAL: cannot read eth_blockNumber from any RPC")
        return 1
    latest = int(latest, 16)
    if cur == 0:
        cur = latest  # first ever run: start at head, never backfill blindly
    end = min(latest, cur + args.max_blocks)
    print(f"range {cur + 1}..{end} (latest={latest})", flush=True)
    if end <= cur:
        print("already at head")
        return 0

    scanned_to = cur
    n_cand = 0
    CHUNK = 1000
    while scanned_to < end:
        chunk_end = min(scanned_to + CHUNK, end)
        bns = list(range(scanned_to + 1, chunk_end + 1))
        blocks = {}
        B = 50
        for i in range(0, len(bns), B):
            part = bns[i:i + B]
            res = rpc_batch([("eth_getBlockByNumber", [hex(bn), True])
                             for bn in part])
            for bn, blk in zip(part, res):
                if blk is not None:
                    blocks[bn] = blk
        missing = [bn for bn in bns if bn not in blocks]
        for bn in missing:  # single retry per missing block
            blk = rpc("eth_getBlockByNumber", [hex(bn), True], 20)
            if blk is not None:
                blocks[bn] = blk
        missing = [bn for bn in bns if bn not in blocks]
        if missing:
            # gapless rule: stop the whole run at the first gap; progress
            # before the gap is NOT committed either (chunk is atomic),
            # matching deploy_watch semantics.
            print(f"STOP: {len(missing)} blocks unfetchable in chunk "
                  f"{bns[0]}..{bns[-1]} (first {missing[0]}); "
                  f"watermark stays {scanned_to}")
            with open(args.state, "w") as f:
                json.dump({"last_block": scanned_to}, f)
            return 0

        creations = []  # (block, ts, contract_addr, creator)
        for bn in bns:
            blk = blocks[bn]
            ts = int(blk.get("timestamp", "0x0"), 16)
            for tx in blk.get("transactions", []):
                if tx.get("to") is None:
                    nonce = tx.get("nonce")
                    addr = create_address(
                        tx.get("from"),
                        int(nonce, 16) if nonce else 0)
                    creations.append((bn, ts, addr, (tx.get("from") or "").lower()))

        # fingerprint all creations in this chunk (batched getCode)
        hits = []
        for i in range(0, len(creations), 50):
            part = creations[i:i + 50]
            codes = rpc_batch([("eth_getCode", [a, "latest"])
                               for _bn, _ts, a, _cr in part])
            for (bn, ts, addr, creator), code in zip(part, codes):
                if not code or len(code) < 200:
                    continue
                hexcode = code[2:]
                pearl_hits = sum(1 for s in PEARL_SELS if s in hexcode)
                pow_hits = sum(1 for s in POW_SELS if s in hexcode)
                if pearl_hits >= 2:
                    kind = "PEARL-FAMILY"
                elif pow_hits >= 2:
                    kind = "POW-SUSPECT"
                else:
                    continue
                hits.append({"block": bn, "ts": ts, "contract": addr,
                             "creator": creator, "kind": kind,
                             "name": None, "symbol": None})
        for h in hits:
            h["name"] = call_str(h["contract"], "0x06fdde03")
            h["symbol"] = call_str(h["contract"], "0x95d89b41")
        if hits:
            with open(args.feed, "a") as f:
                for h in hits:
                    f.write(json.dumps(h) + "\n")
            n_cand += len(hits)

        scanned_to = chunk_end
        with open(args.state, "w") as f:
            json.dump({"last_block": scanned_to}, f)
        print(f"chunk -> {scanned_to} creations={len(creations)} "
              f"candidates={len(hits)}", flush=True)

    print(f"DONE watermark={scanned_to} candidates_this_run={n_cand}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
