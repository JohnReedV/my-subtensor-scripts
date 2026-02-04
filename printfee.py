#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Call set_pending_childkey_cooldown as a NORMAL signed extrinsic (NOT sudo),
so it will FAIL with BadOrigin, and print the ACTUAL fee charged.

Deps:
  pip install py-substrate-interface

Usage:
  python3 printfee_fail.py --ws ws://127.0.0.1:9945 --signer-uri //Alice --cooldown 123

If auto-detection of the pallet fails, pass it explicitly, e.g.:
  python3 printfee_fail.py --module SubtensorModule
"""

import argparse
import time
from decimal import Decimal, getcontext
from typing import Any, Dict, Optional, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

getcontext().prec = 50


# ──────────────────────────────────────────────────────────────────────────────
# Small helpers
# ──────────────────────────────────────────────────────────────────────────────

def connect(url: str) -> SubstrateInterface:
    si = SubstrateInterface(url=url)
    last_err = None
    for _ in range(40):
        try:
            si.init_runtime()
            _ = si.get_metadata()
            return si
        except Exception as e:
            last_err = e
            time.sleep(0.25)
    raise RuntimeError(f"Could not init runtime/metadata from {url}: {last_err}")


def token_decimals(substrate: SubstrateInterface) -> int:
    d = getattr(substrate, "token_decimals", 9)
    if isinstance(d, list) and d and isinstance(d[0], int):
        return int(d[0])
    if isinstance(d, int):
        return int(d)
    return 9


def token_symbol(substrate: SubstrateInterface) -> str:
    s = getattr(substrate, "token_symbol", "TAO")
    if isinstance(s, list) and s and isinstance(s[0], str):
        return s[0]
    if isinstance(s, str) and s.strip():
        return s.strip()
    return "TAO"


def to_token(amount_planck: int, decimals: int) -> Decimal:
    return Decimal(int(amount_planck)) / (Decimal(10) ** int(decimals))


def unwrap_value(x: Any) -> Any:
    if x is None:
        return None
    if isinstance(x, dict) and "value" in x:
        return x["value"]
    if hasattr(x, "value"):
        try:
            return x.value
        except Exception:
            return x
    return x


def as_int(x: Any) -> Optional[int]:
    x = unwrap_value(x)
    if x is None:
        return None
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip().replace(",", "")
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return int(s, 16)
            except Exception:
                return None
        try:
            return int(s)
        except Exception:
            return None
    return None


def dict_first_present(d: Dict[str, Any], keys) -> Any:
    # IMPORTANT: don't use `or` chaining (0 is a valid value!)
    for k in keys:
        if k in d:
            return d[k]
    return None


def normalize_event(rec: Any) -> Tuple[Optional[str], Optional[str], Any]:
    v = getattr(rec, "value", rec)
    if not isinstance(v, dict):
        return None, None, None

    ev = v.get("event", v)
    ev = getattr(ev, "value", ev)
    if not isinstance(ev, dict):
        return None, None, None

    section = (
        ev.get("section")
        or ev.get("module_id")
        or ev.get("pallet")
        or ev.get("module")
        or ev.get("call_module")
    )
    method = (
        ev.get("method")
        or ev.get("event_id")
        or ev.get("event")
        or ev.get("name")
    )

    data = None
    for key in ("data", "attributes", "params", "values"):
        if key in ev:
            data = ev.get(key)
            break

    return (
        str(section) if section is not None else None,
        str(method) if method is not None else None,
        data,
    )


def extract_fee_paid(events) -> Optional[Dict[str, Any]]:
    """
    TransactionPayment::TransactionFeePaid { who, actual_fee, tip }
    Works even if actual_fee == 0 (no falsey bugs).
    """
    for rec in events or []:
        section, method, data = normalize_event(rec)
        if not section or not method:
            continue
        if section.lower() != "transactionpayment":
            continue
        if method != "TransactionFeePaid":
            continue

        who = None
        actual_fee = None
        tip = 0

        if isinstance(data, dict):
            who = dict_first_present(data, ["who", "account", "payer"])
            actual_fee = dict_first_present(
                data,
                ["actual_fee", "actualFee", "fee", "actual"],
            )
            tip = dict_first_present(data, ["tip"])
        elif isinstance(data, list):
            vals = [unwrap_value(x) for x in data]
            if len(vals) >= 1:
                who = vals[0]
            if len(vals) >= 2:
                actual_fee = vals[1]
            if len(vals) >= 3:
                tip = vals[2]

        return {
            "who": unwrap_value(who),
            "actual_fee": as_int(actual_fee),
            "tip": as_int(tip) or 0,
        }

    return None


def extract_dispatch_info(events) -> Optional[Dict[str, Any]]:
    """
    Reads System::ExtrinsicFailed / System::ExtrinsicSuccess dispatch_info
    so you can see pays_fee and weight.
    """
    for rec in events or []:
        section, method, data = normalize_event(rec)
        if not section or section.lower() != "system":
            continue
        if method not in ("ExtrinsicFailed", "ExtrinsicSuccess"):
            continue
        if not isinstance(data, dict):
            continue

        di = data.get("dispatch_info") if "dispatch_info" in data else data.get("dispatchInfo")
        if di is None:
            continue
        di = unwrap_value(di)
        if not isinstance(di, dict):
            continue

        weight = di.get("weight")
        weight = unwrap_value(weight)
        ref_time = None
        proof_size = None
        if isinstance(weight, dict):
            ref_time = as_int(weight.get("ref_time") if "ref_time" in weight else weight.get("refTime"))
            proof_size = as_int(weight.get("proof_size") if "proof_size" in weight else weight.get("proofSize"))

        pays_fee = di.get("pays_fee") if "pays_fee" in di else di.get("paysFee")
        klass = di.get("class")

        return {
            "event": method,
            "class": klass,
            "pays_fee": pays_fee,
            "ref_time": ref_time,
            "proof_size": proof_size,
        }

    return None


def extract_balances_moves(events, who_ss58: str) -> Tuple[int, int]:
    """
    Sum Balances::Withdraw / Balances::Deposit for the payer inside this extrinsic.
    Useful sanity check (Withdraw - Deposit ≈ net paid).
    """
    w = 0
    d = 0
    for rec in events or []:
        section, method, data = normalize_event(rec)
        if not section or section.lower() != "balances":
            continue
        if not isinstance(data, dict):
            continue
        who = unwrap_value(data.get("who"))
        amt = as_int(data.get("amount"))
        if who != who_ss58 or amt is None:
            continue
        if method == "Withdraw":
            w += amt
        elif method == "Deposit":
            d += amt
    return w, d


def resolve_pallet_for_call(substrate: SubstrateInterface, call_function: str, probe_params: Dict[str, Any]) -> str:
    md = substrate.get_metadata()
    for p in getattr(md, "pallets", []) or []:
        name = str(p.name)
        try:
            substrate.compose_call(call_module=name, call_function=call_function, call_params=probe_params)
            return name
        except Exception:
            pass
    raise RuntimeError(f"Could not find a pallet exposing call '{call_function}'. Pass --module explicitly.")


def get_block_number(substrate: SubstrateInterface, block_hash: str) -> int:
    try:
        hdr = substrate.get_block_header(block_hash=block_hash)
    except Exception:
        return 0
    v = getattr(hdr, "value", hdr)
    if isinstance(v, dict) and "header" in v:
        v = v["header"]
    if not isinstance(v, dict):
        return 0
    return as_int(v.get("number")) or 0


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Call root-only extrinsic as normal signer and print the fee charged")
    ap.add_argument("--ws", default="ws://127.0.0.1:9945")
    ap.add_argument("--signer-uri", default="//Alice", help="Regular signer (NOT sudo). Call should fail with BadOrigin.")
    ap.add_argument("--cooldown", type=int, default=123)
    ap.add_argument("--tip-planck", type=int, default=0)
    ap.add_argument("--module", default="", help="Optional pallet/module name (auto-detected if omitted)")
    args = ap.parse_args()

    substrate = connect(args.ws)
    decimals = token_decimals(substrate)
    symbol = token_symbol(substrate)

    signer = Keypair.create_from_uri(args.signer_uri)

    call_fn = "set_pending_childkey_cooldown"
    pallet = args.module.strip() or resolve_pallet_for_call(substrate, call_fn, {"cooldown": 0})

    call = substrate.compose_call(
        call_module=pallet,
        call_function=call_fn,
        call_params={"cooldown": int(args.cooldown)},
    )

    try:
        xt = substrate.create_signed_extrinsic(call=call, keypair=signer, era="00", tip=int(args.tip_planck))
    except TypeError:
        # older py-substrate-interface might not accept tip=
        xt = substrate.create_signed_extrinsic(call=call, keypair=signer, era="00")

    try:
        receipt = substrate.submit_extrinsic(xt, wait_for_inclusion=True, wait_for_finalization=True)
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e

    block_hash = receipt.block_hash
    block_num = get_block_number(substrate, block_hash)

    print(f"[✓] Included in block #{block_num} ({block_hash})")

    is_success = bool(getattr(receipt, "is_success", False))
    err_msg = getattr(receipt, "error_message", None)
    print(f"[i] Dispatch: {'SUCCESS' if is_success else 'FAILED'}" + (f"  error={err_msg}" if err_msg else ""))

    events = getattr(receipt, "triggered_events", None) or []

    di = extract_dispatch_info(events)
    if di:
        print(f"[i] System::{di['event']} dispatch_info:")
        print(f"    class:      {di.get('class')}")
        print(f"    pays_fee:   {di.get('pays_fee')}")
        print(f"    ref_time:   {di.get('ref_time')}")
        print(f"    proof_size: {di.get('proof_size')}")

    fee = extract_fee_paid(events)
    if fee and fee.get("actual_fee") is not None:
        actual_fee = int(fee["actual_fee"])
        tip = int(fee.get("tip") or 0)
        total = actual_fee + tip

        print("[✓] TransactionPayment::TransactionFeePaid")
        print(f"    payer:      {fee.get('who')}")
        print(f"    actual_fee: {actual_fee} ({to_token(actual_fee, decimals)} {symbol})")
        print(f"    tip:        {tip} ({to_token(tip, decimals)} {symbol})")
        print(f"    total:      {total} ({to_token(total, decimals)} {symbol})")
    else:
        print("[!] Could not parse TransactionPayment::TransactionFeePaid from triggered events.")
        print("    Events seen:")
        for ev in events:
            sec, meth, data = normalize_event(ev)
            if sec and meth:
                print(f"      - {sec}::{meth}  data={unwrap_value(data)}")

    w, d = extract_balances_moves(events, signer.ss58_address)
    if w or d:
        net = w - d
        print("[i] Balances movement for payer (sanity check)")
        print(f"    Withdraw total: {w} ({to_token(w, decimals)} {symbol})")
        print(f"    Deposit total:  {d} ({to_token(d, decimals)} {symbol})")
        print(f"    Net (W-D):      {net} ({to_token(net, decimals)} {symbol})")


if __name__ == "__main__":
    main()
