#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Randomized Ready-Set Selection Test — priority-tier aware (admin-utils sudo)

What it asserts
---------------
1) High-priority extrinsics (sudo-wrapped AdminUtils setter and drand `write_pulse`, if present)
   appear before priority-0 extrinsics (Balances transfers) in the same block.
2) Within the priority-0 tier (transfers), the order varies across rounds,
   demonstrating per-block randomized selection within priority tiers.

Requires: pip install substrate-interface
"""

import sys
import time
import hashlib
from typing import Any, Dict, List, Tuple, Optional
from collections import Counter

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException
from scalecodec.base import ScaleBytes

# -----------------------------
# Endpoint & timing
# -----------------------------
WS_ENDPOINT = "ws://127.0.0.1:9945"

BLOCK_POLL_SEC = 0.6              # polling interval for new heads
AFTER_BROADCAST_GRACE_SEC = 1.0   # grace after async broadcast (gossip -> pool)
MAX_BLOCKS_TO_SCAN = 120          # how many future blocks to scan

# Experiment parameters
ROUNDS = 8
TXS_PER_ROUND = 5
INCLUDE_SUDO_PER_ROUND = True
USE_SUDO_UNCHECKED_WEIGHT = False  # True to prefer sudo_unchecked_weight (falls back to sudo)

# Accounts & funding
FAUCET_URI    = "//Alice"          # also Root
RECIPIENT_URI = "//Alice"          # receive transfers
SENDER_URIS   = ["//Bob", "//Charlie", "//Dave", "//Eve", "//Ferdie", "//George", "//Hannah"]

MIN_TAO_SENDER = 5.0
MIN_TAO_RECIP  = 1.0


# -----------------------------
# Helpers
# -----------------------------
def connect() -> SubstrateInterface:
    return SubstrateInterface(url=WS_ENDPOINT)

def token_decimals(substrate: SubstrateInterface) -> int:
    dec = substrate.token_decimals
    if isinstance(dec, list) and dec and isinstance(dec[0], int):
        return dec[0]
    if isinstance(dec, int):
        return dec
    return 9

def to_planck(amount_tau: float, decimals: int) -> int:
    return int(round(amount_tau * (10 ** decimals)))

def get_best_block(substrate: SubstrateInterface) -> Tuple[int, str]:
    bh = substrate.get_chain_head()
    bn = substrate.get_block_number(bh)
    return int(bn), str(bh)

def wait_next_block(substrate: SubstrateInterface) -> Tuple[int, str]:
    start_bn, _ = get_best_block(substrate)
    while True:
        time.sleep(BLOCK_POLL_SEC)
        bn, bh = get_best_block(substrate)
        if bn > start_bn:
            return bn, bh

def compose_transfer_call(substrate: SubstrateInterface, dest_ss58: str, amount: int):
    try:
        return substrate.compose_call(
            call_module="Balances", call_function="transfer_keep_alive",
            call_params={"dest": dest_ss58, "value": amount}
        )
    except Exception:
        return substrate.compose_call(
            call_module="Balances", call_function="transfer",
            call_params={"dest": dest_ss58, "value": amount}
        )

def compose_adminutils_set_network_rate_limit_zero(substrate: SubstrateInterface):
    return substrate.compose_call(
        call_module="AdminUtils",
        call_function="sudo_set_network_rate_limit",
        call_params={"rate_limit": 0}
    )

def compose_sudo_wrapper(substrate: SubstrateInterface, inner_call, prefer_unchecked: bool = False):
    if prefer_unchecked:
        # Weight as struct
        try:
            return substrate.compose_call(
                "Sudo", "sudo_unchecked_weight",
                {"call": inner_call, "weight": {"ref_time": 0, "proof_size": 0}}
            )
        except Exception:
            pass
        # Weight as plain number
        try:
            return substrate.compose_call(
                "Sudo", "sudo_unchecked_weight",
                {"call": inner_call, "weight": 0}
            )
        except Exception:
            pass
    # Fallback: standard sudo
    return substrate.compose_call("Sudo", "sudo", {"call": inner_call})

def account_free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0

def ensure_funded(substrate: SubstrateInterface, from_kp: Keypair, to_ss58: str,
                  min_tau: float, decimals: int):
    have = account_free_balance(substrate, to_ss58)
    need = to_planck(min_tau, decimals)
    if have >= need:
        return
    delta = int((need - have) * 1.1) + 1  # headroom
    call = compose_transfer_call(substrate, to_ss58, delta)
    xt = substrate.create_signed_extrinsic(call=call, keypair=from_kp)
    rec = substrate.submit_extrinsic(xt, wait_for_inclusion=True, wait_for_finalization=True)
    if not rec.is_success:
        raise RuntimeError(f"Funding failed in block {rec.block_hash}: {rec.error_message}")

# --- Hash utilities ---
def blake2b256(data: bytes) -> str:
    h = hashlib.blake2b(digest_size=32)
    h.update(data)
    return "0x" + h.hexdigest()

def normalize_hash(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, (bytes, bytearray)):
        return "0x" + bytes(val).hex()
    if isinstance(val, str):
        s = val.lower()
        if s.startswith("0x"):
            try:
                bytes.fromhex(s[2:])
                return s
            except Exception:
                return None
        try:
            bytes.fromhex(s)
            return "0x" + s.lower()
        except Exception:
            return None
    if hasattr(val, "hex"):
        try:
            return "0x" + val.hex()
        except Exception:
            return None
    return None

def block_extrinsic_hexes(substrate: SubstrateInterface, block_hash: str) -> List[str]:
    resp = substrate.rpc_request("chain_getBlock", [block_hash])
    if not resp or "result" not in resp or resp["result"] is None:
        return []
    xs = resp["result"]["block"]["extrinsics"]
    return [x for x in xs if isinstance(x, str) and x.startswith("0x")]

# --- Name normalization & matching ---
def _norm_ident(s: Optional[str]) -> str:
    """Lowercase and strip all non-letters to normalize pallet/function names."""
    if not isinstance(s, str):
        return ""
    s = s.lower()
    return "".join(ch for ch in s if ch.isalpha())

def _extract_top_call(call_dict: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    mod = (call_dict.get("call_module") or call_dict.get("module") or
           call_dict.get("pallet") or call_dict.get("pallet_name") or
           call_dict.get("section"))
    fun = (call_dict.get("call_function") or call_dict.get("function") or
           call_dict.get("call_name") or call_dict.get("method"))
    return mod, fun

def _extract_inner_call(call_dict: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    args = call_dict.get("call_args")
    if isinstance(args, list):
        # Sudo: single 'call'
        for arg in args:
            try:
                name = (arg.get("name") or "").lower()
                val = arg.get("value")
                if name == "call" and isinstance(val, dict):
                    return _extract_top_call(val)
            except Exception:
                pass
        # Utility.batch: 'calls' list
        for arg in args:
            try:
                name = (arg.get("name") or "").lower()
                val = arg.get("value")
                if name == "calls" and isinstance(val, list) and val:
                    first = val[0]
                    if isinstance(first, dict):
                        return _extract_top_call(first)
            except Exception:
                pass
    return None, None

def _decode_extrinsic_call(substrate: SubstrateInterface, extrinsic_hex: str) -> Dict[str, Optional[str]]:
    out = {"module": None, "function": None, "inner_module": None, "inner_function": None}
    try:
        extrinsic = substrate.create_scale_object('Extrinsic')
        extrinsic.decode(ScaleBytes(extrinsic_hex))
        val = extrinsic.value or {}
        call = val.get("call")
        if isinstance(call, dict):
            mod, fun = _extract_top_call(call)
            out["module"], out["function"] = mod, fun
            inner_mod, inner_fun = _extract_inner_call(call)
            out["inner_module"], out["inner_function"] = inner_mod, inner_fun
    except Exception:
        pass
    return out

def is_drand_write_info(info: Dict[str, Optional[str]]) -> bool:
    m = _norm_ident(info.get("module"))
    f = _norm_ident(info.get("function"))
    im = _norm_ident(info.get("inner_module"))
    inf = _norm_ident(info.get("inner_function"))

    def match(mo: str, fn: str) -> bool:
        return ("drand" in mo) and (fn == "writepulse")

    return match(m, f) or match(im, inf)

def block_extrinsics_info(substrate: SubstrateInterface, block_hash: str) -> List[Dict[str, Optional[str]]]:
    """
    Return a list of dicts for each extrinsic in the block:
      {
        "index": int,
        "hash": "0x...",
        "module": str|None, "function": str|None,
        "inner_module": str|None, "inner_function": str|None,
      }
    """
    infos: List[Dict[str, Optional[str]]] = []
    hexes = block_extrinsic_hexes(substrate, block_hash)
    for i, hx in enumerate(hexes):
        row: Dict[str, Optional[str]] = {
            "index": i,
            "hash": None,
            "module": None,
            "function": None,
            "inner_module": None,
            "inner_function": None,
        }
        try:
            raw = bytes.fromhex(hx[2:])
            row["hash"] = blake2b256(raw)
        except Exception:
            row["hash"] = "(bad-hex)"
        callinfo = _decode_extrinsic_call(substrate, hx)
        row.update(callinfo)
        infos.append(row)
    return infos

# --- Build + submit (returns canonical hash) ---
def build_and_submit_get_hash(
    substrate: SubstrateInterface,
    keypair: Keypair,
    call,
    tip: int = 0
) -> str:
    xt = substrate.create_signed_extrinsic(call=call, keypair=keypair, tip=tip)

    # Prefer rehash from SCALE bytes, else normalized library hash
    can_hex = None
    try:
        if hasattr(xt, "data"):
            raw_hex = xt.data.to_hex() if hasattr(xt.data, "to_hex") else None
            if isinstance(raw_hex, str) and raw_hex.startswith("0x"):
                raw = bytes.fromhex(raw_hex[2:])
                can_hex = blake2b256(raw)
    except Exception:
        pass

    if not can_hex:
        can_hex = normalize_hash(getattr(xt, "extrinsic_hash", None)) or "(unavailable)"

    try:
        substrate.submit_extrinsic(xt, wait_for_inclusion=False)
    except SubstrateRequestException as e:
        raise RuntimeError(f"submit_async failed: {e}") from e

    return can_hex


# -----------------------------
# Round runner
# -----------------------------
def run_round(
    substrate: SubstrateInterface,
    senders: List[Keypair],
    recipient: Keypair,
    amount_planck: int,
    round_id: int,
    submit_sudo: bool = True,
) -> Dict[str, Any]:
    # Align to a fresh block
    wait_next_block(substrate)

    # High-priority sudo call (AdminUtils setter)
    sudo_hash: Optional[str] = None
    if submit_sudo:
        inner = compose_adminutils_set_network_rate_limit_zero(substrate)
        sudo_call = compose_sudo_wrapper(substrate, inner, prefer_unchecked=USE_SUDO_UNCHECKED_WEIGHT)
        sudo_hash = build_and_submit_get_hash(substrate, Keypair.create_from_uri("//Alice"), sudo_call, tip=0)

    # Priority-0 transfers
    chosen = senders[:TXS_PER_ROUND]
    label_by_hash: Dict[str, str] = {}
    for kp, uri in zip(chosen, SENDER_URIS[:TXS_PER_ROUND]):
        call = compose_transfer_call(substrate, recipient.ss58_address, amount_planck)
        h = build_and_submit_get_hash(substrate, kp, call, tip=0)
        label_by_hash[h] = uri

    time.sleep(AFTER_BROADCAST_GRACE_SEC)

    # Find first block including any of our txs
    found_block = None
    last_bn, _ = get_best_block(substrate)
    scanned = 0
    our_hashes = set(label_by_hash.keys())
    if sudo_hash:
        our_hashes.add(sudo_hash)
    our_hashes = {h for h in our_hashes if isinstance(h, str) and h.startswith("0x")}

    while scanned < MAX_BLOCKS_TO_SCAN and our_hashes:
        cur_bn, cur_bh = get_best_block(substrate)
        if cur_bn <= last_bn:
            time.sleep(BLOCK_POLL_SEC)
            continue
        scanned += 1
        last_bn = cur_bn

        infos = block_extrinsics_info(substrate, cur_bh)
        hashes_in_block = [x["hash"] for x in infos]
        matches = [hh for hh in hashes_in_block if hh in our_hashes]
        if matches:
            found_block = (cur_bn, cur_bh, infos)
            break

    if not found_block:
        return {
            "round": round_id,
            "block": None,
            "block_hash": None,
            "labels_in_block_order": [],
            "missing": list(label_by_hash.values()),
            "permutation_key": "(none)",
            "sudo_first_ok": False,
            "drand_first_ok": False,
        }

    bn, bh, infos = found_block
    hashes_in_block = [x["hash"] for x in infos]

    # Ordered labels for our transfers in this block
    ordered_labels: List[str] = []
    ours_transfer_hashes = set(label_by_hash.keys())
    for x in infos:
        if x["hash"] in ours_transfer_hashes:
            ordered_labels.append(label_by_hash[x["hash"]])

    # Missing (landed later)
    block_hash_set = set(hashes_in_block)
    missing = [lbl for h, lbl in label_by_hash.items() if h not in block_hash_set]

    # ---- Priority assertions ----
    # First transfer index
    first_transfer_idx = None
    for i, x in enumerate(infos):
        if x["hash"] in ours_transfer_hashes:
            first_transfer_idx = i
            break

    # SUDO before transfers (if both landed in same block)
    sudo_first_ok = True
    if sudo_hash and first_transfer_idx is not None:
        sudo_idx = next((i for i, h in enumerate(hashes_in_block) if h == sudo_hash), None)
        if sudo_idx is not None:
            assert sudo_idx < first_transfer_idx, \
                f"[round {round_id}] SUDO not before transfers (sudo_idx={sudo_idx}, first_transfer_idx={first_transfer_idx})."
        else:
            sudo_first_ok = False

    # DRAND before transfers (if present in this block)
    drand_first_ok = True
    drand_present = False
    drand_idx = None
    if first_transfer_idx is not None:
        drand_idx = next((i for i, it in enumerate(infos) if is_drand_write_info(it)), None)
        if drand_idx is not None:
            drand_present = True
            assert drand_idx < first_transfer_idx, \
                f"[round {round_id}] Drand write_pulse not before transfers (drand_idx={drand_idx}, first_transfer_idx={first_transfer_idx})."
        else:
            drand_first_ok = False

    # Print flags BEFORE order
    flags = []
    flags.append("[SUDO ok]" if sudo_first_ok else "[SUDO late/absent]")
    if drand_present:
        flags.append("[DRAND ok]" if drand_first_ok else "[DRAND late]")
    else:
        flags.append("[DRAND absent]")

    print(f"[round {round_id:02d}] block #{bn} {bh[:14]}…  {' '.join(flags)}  "
          f"transfers order: {ordered_labels if ordered_labels else '()'}  "
          f"{'(missing: ' + ','.join(missing) + ')' if missing else ''}")

    return {
        "round": round_id,
        "block": bn,
        "block_hash": bh,
        "labels_in_block_order": ordered_labels,
        "missing": missing,
        "permutation_key": ">".join(ordered_labels) if ordered_labels else "(none)",
        "sudo_first_ok": sudo_first_ok,
        "drand_first_ok": (drand_first_ok if drand_present else False),
    }


# -----------------------------
# Main
# -----------------------------
def main():
    substrate = connect()
    decimals = token_decimals(substrate)
    print(f"[i] Connected to {WS_ENDPOINT} (decimals={decimals})")

    faucet    = Keypair.create_from_uri(FAUCET_URI)   # also Root
    recipient = Keypair.create_from_uri(RECIPIENT_URI)
    senders   = [Keypair.create_from_uri(uri) for uri in SENDER_URIS]

    # Ensure funding
    ensure_funded(substrate, faucet, recipient.ss58_address, MIN_TAO_RECIP, decimals)
    for kp in senders[:TXS_PER_ROUND]:
        ensure_funded(substrate, faucet, kp.ss58_address, MIN_TAO_SENDER, decimals)

    transfer_amount = max(1, to_planck(0.01, decimals))  # small, nonzero

    print(f"[i] Running {ROUNDS} rounds, {TXS_PER_ROUND} transfers/round..."
          f"  (sudo per round: {INCLUDE_SUDO_PER_ROUND}, prefer_unchecked: {USE_SUDO_UNCHECKED_WEIGHT})")
    results: List[Dict[str, Any]] = []

    for r in range(1, ROUNDS + 1):
        try:
            res = run_round(substrate, senders, recipient, transfer_amount, r, submit_sudo=INCLUDE_SUDO_PER_ROUND)
            results.append(res)
        except KeyboardInterrupt:
            raise
        except AssertionError as ae:
            print(f"[round {r:02d}] ASSERTION FAILED: {ae}", file=sys.stderr)
            results.append({
                "round": r, "block": None, "block_hash": None,
                "labels_in_block_order": [], "missing": [], "permutation_key": "(assertion-failed)",
                "sudo_first_ok": False, "drand_first_ok": False,
            })
        except Exception as e:
            print(f"[round {r:02d}] ERROR: {e}", file=sys.stderr)
            results.append({
                "round": r, "block": None, "block_hash": None,
                "labels_in_block_order": [], "missing": [], "permutation_key": "(error)",
                "sudo_first_ok": False, "drand_first_ok": False,
            })

    # Summary
    perms = [r["permutation_key"] for r in results if r["labels_in_block_order"]]
    counts = Counter(perms)
    total_rounds = len(results)
    complete_rounds = sum(1 for r in results
                          if r["labels_in_block_order"] and len(r["labels_in_block_order"]) == TXS_PER_ROUND)
    sudo_ok_rounds = sum(1 for r in results if r.get("sudo_first_ok"))
    drand_ok_rounds = sum(1 for r in results if r.get("drand_first_ok"))

    print("\n============================ Summary ============================")
    print(f"Total rounds attempted                 : {total_rounds}")
    print(f"Rounds with all {TXS_PER_ROUND} txs in one block : {complete_rounds}")
    print(f"Unique permutations observed           : {len(counts)}")
    for k, v in counts.most_common():
        print(f"  {k}   x {v}")
    print(f"\nPriority assertions:")
    print(f"  SUDO before transfers (rounds)       : {sudo_ok_rounds} / {total_rounds}")
    print(f"  DRAND before transfers (rounds)      : {drand_ok_rounds} / {total_rounds} ")
    print("================================================================\n")

    if complete_rounds >= 3:
        assert len(counts) >= 2, "Expected at least 2 unique transfer permutations across rounds."

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except AssertionError as ae:
        print(f"Assertion failed: {ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Fatal: {e}", file=sys.stderr)
        sys.exit(1)
