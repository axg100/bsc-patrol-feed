#!/usr/bin/env python3
"""Remote BSC creation fetcher (built 2026-11-05; parallelised 2026-11-10).

Runs on a datacenter host (GitHub Actions runner): scans BSC blocks at full
speed, extracts contract creations (tx.to == null), fingerprints the deployed
bytecode against the PEARL / PoW selector sets, and appends DISTILLED
candidate lines to feed.jsonl — a few KB per run instead of ~160 KB per
block, so the throttled home pipe only ever pulls the feed.

State: state.json {"last_block": N} beside this script. The watermark only
advances over a contiguous fully-fetched prefix (gapless rule, same as the
local deploy_watch). Feed line schema (one JSON object per candidate):
  {"block": int, "ts": int, "contract": "0x..", "creator": "0x..",
   "kind": "PEARL-FAMILY"|"PEARL-SUSPECT"|"POW-SUSPECT"|"POW-SINGLE"|"SHARE-SUSPECT",
   "name": str|null, "symbol": str|null}  (SUSPECT/SINGLE = one selector)

Performance notes (2026-11-10): the original fetched block batches strictly
serially (~125 blocks/s end-to-end; 60k blocks ≈ 7.5 min). This version
fetches the 50-block RPC batches concurrently (16 workers, endpoints rotated
per batch) and loops over scan windows inside the job until it is near the
head or a soft time budget (--budget-secs) expires, committing state after
every 1000-block chunk exactly like the original. Classification, the
gapless/chunk-atomic stop rule, the feed schema and state semantics are
UNCHANGED — this is a throughput change only.

Usage: python3 fetcher.py [--max-blocks 400000] [--budget-secs 480]
                          [--state state.json] [--feed feed.jsonl]
Stdlib + pycryptodome. RPC failover across public BSC endpoints.
"""
import json, sys, os, argparse, time, threading, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
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
            "solve(uint256)","solve(uint256,uint256)","solve(uint256,address)",
            "prove(uint256,uint256)","prove(bytes32)",
            "dig(uint256)","dig(uint256,uint256)","excavate(uint256)","harvest(uint256)",
            "work(uint256)","pow(uint256)","mintWithProof(uint256,bytes32)",
            "mintPow(uint256,uint256)","workOf(address,uint256,bytes32)",
            "challengeFor(uint256,uint256)","targetFor(address)"]
POW_SELS = [sel(s) for s in POW_SIGS]
PEARL_SELS = ["39148c53", "fd76c4eb", "d2e3ae76"]  # currentTarget/proofDigest/puzzleSeed

# Single-hit tier (user-approved 2026-11-10): these PoW signatures are rare
# enough that ONE match is meaningful (solve(uint256,address) is the BASKET
# sale shape, proven first-hand). Generic colliders (submit/prove/work/pow/
# dig/plain mine) still need >= 2 hits. PEARL single-hit is PEARL-SUSPECT:
# currentTarget() is essentially unique to the Pearl family.
POW_RARE_SIGS = ["mineBatch(uint256,uint256[],uint256)",
                 "mineBatch(uint256[],uint256)", "mineBatch(uint256)",
                 "mineBatch(uint256,bytes32[],uint256)",
                 "submitProof(uint256)", "submitProof(uint256,uint256)",
                 "submitProof(bytes32)", "submitProof(uint256,bytes32)",
                 "submitSolution(uint256)", "submitSolution(uint256,uint256)",
                 "solve(uint256)", "solve(uint256,uint256)",
                 "solve(uint256,address)",
                 "mintWithProof(uint256,bytes32)", "mintPow(uint256,uint256)"]
POW_RARE_SELS = set(sel(s) for s in POW_RARE_SIGS)

# Share-template lane (2026-11-10 patch, pending push): our #1 money class
# (DOG/FLOKI/PIG share clones) was invisible to this fetcher -- it only knew
# PEARL/PoW selector sets. BASKET's sale is the specimen: a share-style
# contract (shares()/freeShares()/FreeUsed()) whose PoW entry has a
# project-specific name no selector set will ever match, but whose SHARE
# fingerprint is plain. >=2 share hits -> SHARE-SUSPECT (same class name the
# local candidates file already uses). agent_gate = the code references the
# SPACE ID registry address (Agent-ID gate marker), carried as a boolean.
SHARE_SIGS = ["totalShares()", "TOTAL_SHARES()", "shares()", "freeShares()",
              "mintPrice()", "pricePerShare()", "PRICE_PER_SHARE()",
              "poolPrice()", "openPrice()", "POOL_PRICE()", "totalMinted()",
              "opened()", "basePrice()", "tokensPerShare()", "TOKENS_PER_LOT()"]
SHARE_SELS = [sel(s) for s in SHARE_SIGS]
REGISTRY_HEX = "60b9262456de011f7d15a54cdd8c48baaa8b022f"

RPCS = ["https://bsc-dataseed.binance.org", "https://bsc-dataseed1.defibit.io",
        "https://bsc-dataseed3.binance.org", "https://bsc-dataseed4.binance.org",
        "https://bsc-rpc.publicnode.com", "https://bsc-dataseed1.ninicoin.io"]
UA = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
WORKERS = 16

_rot_lock = threading.Lock()
_rot_idx = 0

def _rotated_rpcs():
    """RPCS rotated by a shared counter so concurrent batch calls spread
    across endpoints instead of all queueing on the first one."""
    global _rot_idx
    with _rot_lock:
        i = _rot_idx
        _rot_idx += 1
    i %= len(RPCS)
    return RPCS[i:] + RPCS[:i]

def _post(url, payload, timeout):
    req = urllib.request.Request(url, data=payload.encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def rpc(method, params, timeout=20):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params})
    for url in _rotated_rpcs():
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
    for url in _rotated_rpcs():
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

def parse_str(r):
    if not r or r == "0x":
        return None
    try:
        if len(r) > 128:
            ln = int(r[66:130], 16)
            return bytes.fromhex(r[130:130 + ln * 2]).decode("utf-8", "replace")
        return bytes.fromhex(r[2:66]).rstrip(b"\x00").decode("utf-8", "replace")
    except Exception:
        return None

def call_str(to, data):
    return parse_str(rpc("eth_call", [{"to": to, "data": data}, "latest"], 10))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-blocks", type=int, default=20000)
    ap.add_argument("--budget-secs", type=int, default=0,
                    help="soft wall-clock budget; 0 = no budget (scan the "
                         "full --max-blocks range in one run)")
    ap.add_argument("--state", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "state.json"))
    ap.add_argument("--feed", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "feed.jsonl"))
    args = ap.parse_args()

    t0 = time.time()
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
    # Canary (2026-11-10): prove the eth_getCode path works BEFORE scanning.
    # A night of output was silently zeroed when code reads failed while
    # block reads kept succeeding and the watermark advanced anyway.
    canary = rpc("eth_getCode",
                 ["0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "latest"], 15)
    if not canary or len(canary) < 200:
        print("FATAL: eth_getCode canary (WBNB) failed on all RPCs — "
              "refusing to scan blind")
        return 1
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
    B = 50
    pool = ThreadPoolExecutor(max_workers=WORKERS)
    while scanned_to < end:
        if args.budget_secs and time.time() - t0 > args.budget_secs:
            print(f"BUDGET STOP: {args.budget_secs}s budget reached at "
                  f"watermark {scanned_to} (head {latest})")
            break
        chunk_end = min(scanned_to + CHUNK, end)
        bns = list(range(scanned_to + 1, chunk_end + 1))
        parts = [bns[i:i + B] for i in range(0, len(bns), B)]
        batch_calls = [[("eth_getBlockByNumber", [hex(bn), True])
                        for bn in part] for part in parts]
        blocks = {}
        for part, res in zip(parts, pool.map(rpc_batch, batch_calls)):
            for bn, blk in zip(part, res):
                if blk is not None:
                    blocks[bn] = blk
        missing = [bn for bn in bns if bn not in blocks]
        if missing:  # parallel single retry per missing block
            retry = list(pool.map(
                lambda bn: rpc("eth_getBlockByNumber", [hex(bn), True], 20),
                missing))
            for bn, blk in zip(missing, retry):
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
            pool.shutdown(wait=False)
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

        # Fingerprint all creations in this chunk. Code reads use small
        # batches (10) + one leftover re-batch + a capped serial fill:
        # public endpoints return PARTIAL batch responses under load, and
        # the old code silently skipped every None code — the failure that
        # zeroed output while the watermark advanced (2026-11-10).
        codes_by_addr = {}

        def _fetch_codes(addrs):
            parts = [addrs[i:i + 10] for i in range(0, len(addrs), 10)]
            calls = [[("eth_getCode", [a, "latest"]) for a in part]
                     for part in parts]
            for part, codes in zip(parts, pool.map(rpc_batch, calls)):
                for a, code in zip(part, codes):
                    if code is not None:
                        codes_by_addr[a] = code

        all_addrs = [a for _bn, _ts, a, _cr in creations]
        _fetch_codes(all_addrs)
        leftover = [a for a in all_addrs if a not in codes_by_addr]
        if leftover:
            _fetch_codes(leftover)  # one re-batch of the leftovers
            leftover = [a for a in all_addrs if a not in codes_by_addr]
        for a in leftover[:15]:  # capped serial completion
            code = rpc("eth_getCode", [a, "latest"], 10)
            if code is not None:
                codes_by_addr[a] = code
        codes_ok = len(codes_by_addr)
        if len(creations) >= 10 and codes_ok == 0:
            print(f"STOP: code path dead — {len(creations)} creations, "
                  f"0 getCode results in chunk {bns[0]}..{bns[-1]}; "
                  f"watermark stays {scanned_to}")
            with open(args.state, "w") as f:
                json.dump({"last_block": scanned_to}, f)
            pool.shutdown(wait=False)
            return 1
        if creations and codes_ok < len(creations) * 0.5:
            print(f"STOP: code path degraded — {codes_ok}/"
                  f"{len(creations)} getCode results in chunk "
                  f"{bns[0]}..{bns[-1]}; watermark stays {scanned_to}")
            with open(args.state, "w") as f:
                json.dump({"last_block": scanned_to}, f)
            pool.shutdown(wait=False)
            return 1

        hits = []
        for (bn, ts, addr, creator) in creations:
            code = codes_by_addr.get(addr)
            if not code or len(code) < 200:
                continue
            hexcode = code[2:]
            pearl_hits = sum(1 for s in PEARL_SELS if s in hexcode)
            pow_hit_sels = [s for s in POW_SELS if s in hexcode]
            pow_hits = len(pow_hit_sels)
            share_hits = sum(1 for s in SHARE_SELS if s in hexcode)
            agent_gate = REGISTRY_HEX in hexcode
            if pearl_hits >= 2:
                kind = "PEARL-FAMILY"
            elif pow_hits >= 2:
                kind = "POW-SUSPECT"
            elif pearl_hits == 1:
                kind = "PEARL-SUSPECT"
            elif pow_hits == 1 and pow_hit_sels[0] in POW_RARE_SELS:
                kind = "POW-SINGLE"
            elif share_hits >= 2:
                kind = "SHARE-SUSPECT"
            else:
                continue
            hits.append({"block": bn, "ts": ts, "contract": addr,
                         "creator": creator, "kind": kind,
                         "share_hits": share_hits, "agent_gate": agent_gate,
                         "name": None, "symbol": None})
        if hits:  # name()/symbol() for all hits in one batch round-trip
            ns_calls = []
            for h in hits:
                ns_calls.append(("eth_call", [{"to": h["contract"],
                                               "data": "0x06fdde03"}, "latest"]))
                ns_calls.append(("eth_call", [{"to": h["contract"],
                                               "data": "0x95d89b41"}, "latest"]))
            ns_res = rpc_batch(ns_calls, timeout=20)
            for i, h in enumerate(hits):
                h["name"] = parse_str(ns_res[2 * i])
                h["symbol"] = parse_str(ns_res[2 * i + 1])
            with open(args.feed, "a") as f:
                for h in hits:
                    f.write(json.dumps(h) + "\n")
            n_cand += len(hits)

        scanned_to = chunk_end
        with open(args.state, "w") as f:
            json.dump({"last_block": scanned_to}, f)
        print(f"chunk -> {scanned_to} creations={len(creations)} "
              f"codes_ok={codes_ok} candidates={len(hits)} "
              f"elapsed={time.time() - t0:.0f}s",
              flush=True)

    pool.shutdown(wait=False)
    print(f"DONE watermark={scanned_to} candidates_this_run={n_cand} "
          f"elapsed={time.time() - t0:.0f}s")
    return 0

if __name__ == "__main__":
    sys.exit(main())
