#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Devnet E2E test for the replace_previous() ENV gate.

Target:
  wss://dev.chain.opentensor.ai:443  (default)

What this test checks
---------------------
You patched txpool replacement with:

  if SUBSTRATE_TXPOOL_ENABLE_REPLACE_PREVIOUS != "1" {
      return Ok((vec![], vec![]));
  }

On a remote devnet we cannot toggle that env var ourselves, so the best “black box”
assertion is to submit TWO signed extrinsics with the SAME (signer, nonce) back-to-back:

  tx1: System.remark(payload A)  (nonce = N)
  tx2: System.remark(payload B)  (nonce = N)

Both have (effectively) the same priority in Subtensor.

Observed behavior distinguishes the gate:
  - If replacement logic is ENABLED (env == "1"):
        tx2 is rejected with RPC error:
          code 1014, message contains "Priority is too low"
  - If replacement logic is DISABLED (env != "1"):
        tx2 is ACCEPTED (returns an extrinsic hash), i.e. the replacement path is skipped.

This matches exactly what you saw locally:
  ENV=1 -> 1014 TooLowPriority
  ENV=0 -> tx2 accepted

Configuration (NO FLAGS)
------------------------
Set env vars if needed:

  # Endpoint (optional)
  export OT_DEVNET_WS="wss://dev.chain.opentensor.ai:443"

  # Signer (MUST be funded enough to pay fees). Default is //Alice.
  export TEST_SIGNER_URI="//Alice"
  # or a mnemonic / seed phrase:
  export TEST_SIGNER_URI="bottom drive obey lake curtain smoke basket hold race lonely fit walk"

  # What you EXPECT devnet is configured to do:
  #   0 => expect replacement DISABLED (tx2 accepted)   [default]
  #   1 => expect replacement ENABLED  (tx2 -> 1014)
  export EXPECT_REPLACE_ENABLED="0"

  # Retry attempts if we hit “stale” / timing races
  export MAX_ATTEMPTS="6"

Run:
  python3 ./test_devnet_replace_gate.py

Dependencies:
  pip install substrate-interface
"""

import os
import sys
import time
from typing import Any, Dict, Optional, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException


WS_URL = os.environ.get("OT_DEVNET_WS", "wss://archive.chain.opentensor.ai").strip()
SIGNER_URI = os.environ.get("TEST_SIGNER_URI", "//Alice").strip()
EXPECT_REPLACE_ENABLED = os.environ.get("EXPECT_REPLACE_ENABLED", "0").strip() == "1"
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "6"))


def _hex_u8(data: bytes) -> str:
    return "0x" + data.hex()


def _parse_header_number(hdr: Dict[str, Any]) -> int:
    n = (hdr or {}).get("number")
    if isinstance(n, int):
        return n
    if isinstance(n, str):
        s = n.strip()
        if s.startswith("0x"):
            return int(s, 16)
        return int(s)
    return 0


def head_number(si: SubstrateInterface) -> int:
    r = si.rpc_request("chain_getHeader", [])
    hdr = (r or {}).get("result") or {}
    return _parse_header_number(hdr)


def wait_next_block(si: SubstrateInterface, timeout_s: float = 20.0) -> int:
    start = head_number(si)
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        cur = head_number(si)
        if cur > start:
            return cur
        time.sleep(0.25)
    raise RuntimeError("Timed out waiting for next block (chain head not advancing).")


def connect() -> SubstrateInterface:
    si = SubstrateInterface(url=WS_URL)
    si.init_runtime()

    # Print some basic node/chain info (helps when debugging load balancers)
    try:
        chain = (si.rpc_request("system_chain", []) or {}).get("result")
        name = (si.rpc_request("system_name", []) or {}).get("result")
        ver = (si.rpc_request("system_version", []) or {}).get("result")
        print(f"[i] Connected: chain={chain} node={name} version={ver}")
    except Exception:
        print("[i] Connected (system_* RPCs not fully available, continuing).")

    return si


def xt_to_hex(xt) -> str:
    # py-substrate-interface extrinsic object usually exposes xt.data.to_hex()
    if hasattr(xt, "data") and hasattr(xt.data, "to_hex"):
        hx = xt.data.to_hex()
        return hx if hx.startswith("0x") else "0x" + hx
    if hasattr(xt, "to_hex"):
        hx = xt.to_hex()
        return hx if hx.startswith("0x") else "0x" + hx
    raise RuntimeError("Could not convert extrinsic to hex.")


def author_submit(si: SubstrateInterface, xt_hex: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Return (tx_hash, error_dict). On RPC error, substrate-interface raises SubstrateRequestException.
    """
    try:
        res = si.rpc_request("author_submitExtrinsic", [xt_hex])
        if isinstance(res, dict) and res.get("error"):
            return None, res["error"]
        if isinstance(res, dict) and "result" in res:
            return res["result"], None
        # Unexpected shape, but treat as "ok-ish"
        return str(res), None
    except SubstrateRequestException as e:
        if e.args and isinstance(e.args[0], dict):
            return None, e.args[0]
        return None, {"code": None, "message": str(e), "data": None}


def is_too_low_priority(err: Optional[Dict[str, Any]]) -> bool:
    if not err:
        return False
    return err.get("code") == 1014 and ("Priority is too low" in str(err.get("message") or ""))


def is_stale_or_timing(err: Optional[Dict[str, Any]]) -> bool:
    """
    Heuristic: errors that commonly happen if tx1 got included (or dropped) before tx2 reached the pool.
    We retry on these rather than declaring pass/fail.
    """
    if not err:
        return False
    code = err.get("code")
    msg = str(err.get("message") or "").lower()
    data = str(err.get("data") or "").lower()
    # Common patterns: "Invalid Transaction", "Stale", "Future", "Bad proof", etc.
    if code in (1010, 1011, 1012, 1013):
        return True
    if "stale" in msg or "stale" in data:
        return True
    if "future" in msg or "future" in data:
        return True
    if "already imported" in msg or "already in pool" in msg:
        return True
    if "invalid transaction" in msg:
        return True
    return False


def build_remark_call(si: SubstrateInterface, payload: bytes) -> object:
    return si.compose_call(
        call_module="System",
        call_function="remark",
        call_params={"remark": _hex_u8(payload)},
    )


def run_once(si: SubstrateInterface, signer: Keypair, attempt: int) -> Tuple[bool, str]:
    """
    Returns (observed_replace_enabled, detail_string).

    observed_replace_enabled:
      True  => tx2 rejected with 1014 TooLowPriority (replacement path ran)
      False => tx2 accepted (replacement path skipped)
    """
    # Align to a fresh block so we have max time before the next block
    bn = wait_next_block(si, timeout_s=25.0)
    print(f"[i] Synced to new block #{bn} (attempt {attempt})")

    # Use current nonce; tx2 uses SAME nonce
    nonce = si.get_account_nonce(signer.ss58_address)

    base = f"ot-devnet-replace-gate:{attempt}:{time.time_ns()}".encode("utf-8")
    payload1 = base + b":tx1"
    payload2 = base + b":tx2"

    call1 = build_remark_call(si, payload1)
    call2 = build_remark_call(si, payload2)

    tx1 = si.create_signed_extrinsic(call=call1, keypair=signer, nonce=int(nonce), era="00", tip=0)
    tx2 = si.create_signed_extrinsic(call=call2, keypair=signer, nonce=int(nonce), era="00", tip=0)

    tx1_hex = xt_to_hex(tx1)
    tx2_hex = xt_to_hex(tx2)

    print(f"[DBG] signer={signer.ss58_address} nonce={nonce}")
    print("[i] Submitting tx1 (remark A)")
    h1, e1 = author_submit(si, tx1_hex)
    if e1:
        raise RuntimeError(
            "tx1 was rejected; cannot test gate.\n"
            f"error={e1}\n"
            "Most common cause: signer has insufficient funds to pay fees.\n"
            "Set TEST_SIGNER_URI to a funded devnet account."
        )
    print(f"[✓] tx1 accepted: {h1}")

    # Submit tx2 immediately
    print("[i] Submitting tx2 (remark B, SAME nonce)")
    h2, e2 = author_submit(si, tx2_hex)

    if e2:
        print(f"[i] tx2 rejected: {e2}")
        if is_too_low_priority(e2):
            return True, f"tx2 rejected with 1014 TooLowPriority: {e2}"
        if is_stale_or_timing(e2):
            return False, f"retryable timing error for tx2: {e2}"
        # Non-retryable unexpected error
        raise RuntimeError(f"Unexpected tx2 error (not 1014): {e2}")

    print(f"[i] tx2 accepted: {h2}")
    return False, f"tx2 accepted (hash={h2})"


def main() -> int:
    print(f"[i] WS endpoint: {WS_URL}")
    print(f"[i] Expect replace_enabled={EXPECT_REPLACE_ENABLED}  (set EXPECT_REPLACE_ENABLED=1 to flip)")
    print(f"[i] Signer URI: {SIGNER_URI!r}")

    si = connect()

    # Use chain ss58 format if available
    ss58 = getattr(si, "ss58_format", 42)
    signer = Keypair.create_from_uri(SIGNER_URI, ss58_format=ss58)

    observed: Optional[bool] = None
    detail: str = ""

    for attempt in range(1, MAX_ATTEMPTS + 1):
        obs, det = run_once(si, signer, attempt)
        # If det is retryable timing error, keep trying
        if det.startswith("retryable timing error"):
            print(f"[DBG] {det}  -> retrying")
            time.sleep(0.5)
            continue

        observed = obs
        detail = det
        break

    if observed is None:
        raise RuntimeError(
            f"Could not get a definitive result after {MAX_ATTEMPTS} attempts. "
            "Try increasing MAX_ATTEMPTS, and ensure your signer is funded."
        )

    print("\n=== Result ===")
    print(f"[i] Observed replace_enabled={observed}")
    print(f"[i] Detail: {detail}")

    if observed != EXPECT_REPLACE_ENABLED:
        raise AssertionError(
            "FAIL: devnet behavior does not match EXPECT_REPLACE_ENABLED.\n"
            f"EXPECTED replace_enabled={EXPECT_REPLACE_ENABLED}\n"
            f"OBSERVED replace_enabled={observed}\n"
            f"DETAIL: {detail}\n"
            "\nIf devnet is intentionally configured the other way, set:\n"
            "  export EXPECT_REPLACE_ENABLED=1   # or 0\n"
        )

    print("\n✅ PASS: devnet behavior matches the replace_previous() ENV gate expectation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
