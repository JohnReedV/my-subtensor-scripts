#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
E2E: Validate ChargeTransactionPaymentWrapper priority override (BY SUBMITTING REAL TXs)

We do NOT call TaggedTransactionQueue_validate_transaction.
We do NOT rely on txpool_content (often disabled).

Instead, we test the *real txpool replacement behavior*:

  - Two txs with the SAME (signer, nonce) conflict.
  - The pool accepts a replacement only if the new tx has sufficiently higher priority.
  - Otherwise it rejects with "Priority is too low" (commonly RPC code 1014).

Behavior under test (your wrapper):
  - Normal calls => NORMAL priority
  - Operational calls => OPERATIONAL priority ONLY IF:
        ensure_root(origin) succeeds
     OR (call == MevShield::announce_next_key && ensure_validator(origin) succeeds)
    otherwise => NORMAL priority

Tests:

  Step 1) Validator replacement:
    Submit validator remark @ nonce=N                 -> ACCEPT
    Submit validator announce_next_key @ same nonce=N -> ACCEPT (must replace due to higher prio)
    Submit validator *different* remark @ same nonce=N-> REJECT (PriorityTooLow)

    NOTE: We must use a DIFFERENT remark payload in the final step.
          Re-submitting the exact same remark bytes triggers "Already Imported" (1013),
          which is dedup-by-hash, not a priority test.

  Step 2) Non-validator announce_next_key is NOT elevated (equal to normal):
    Case A: remark then announce (same nonce) -> announce REJECT (PriorityTooLow)
    Case B: announce then remark (same nonce) -> remark   REJECT (PriorityTooLow)

  Step 3) Root-only operational call (AdminUtils::sudo_set_subtoken_enabled) is NOT elevated:
    Case A: remark then admin (same nonce) -> admin  REJECT (PriorityTooLow)
    Case B: admin then remark (same nonce) -> remark REJECT (PriorityTooLow)

Exit codes:
  - 0 PASS
  - 2 ASSERTION FAIL
  - 1 ERROR
"""

import sys
import time
from typing import Any, List, Optional, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException


WS_URL = "ws://127.0.0.1:9944"


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

def strip_0x(s: str) -> str:
    s = (s or "").strip()
    return s[2:] if s.startswith(("0x", "0X")) else s


def is_priority_too_low(msg: str) -> bool:
    s = (msg or "").lower()
    if "priority is too low" in s:
        return True
    if "toolowpriority" in s:
        return True
    if "code': 1014" in s or '"code": 1014' in s or "code: 1014" in s:
        return True
    # loose fallback but still anchored on "priority"
    if "1014" in s and "priority" in s:
        return True
    return False


def is_already_imported(msg: str) -> bool:
    s = (msg or "").lower()
    if "already imported" in s:
        return True
    if "code': 1013" in s or '"code": 1013' in s or "code: 1013" in s:
        return True
    return False


def assert_true(name: str, cond: bool, detail: str = ""):
    if not cond:
        msg = f"[FAIL] {name}"
        if detail:
            msg += f": {detail}"
        raise AssertionError(msg)


# -----------------------------------------------------------------------------
# Connection / metadata helpers
# -----------------------------------------------------------------------------

def connect(url: str) -> SubstrateInterface:
    si = SubstrateInterface(url=url)
    for _ in range(80):
        try:
            si.init_runtime()
            md = si.get_metadata()
            if md and getattr(md, "pallets", None):
                return si
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("Runtime metadata not available on node")


def resolve_pallet(substrate: SubstrateInterface, want: str) -> str:
    md = substrate.get_metadata()
    names = [str(p.name) for p in md.pallets]
    for n in names:
        if n.lower() == want.lower():
            return n
    for n in names:
        if want.lower() in n.lower():
            return n
    raise RuntimeError(f"Pallet '{want}' not found in metadata")


def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


# -----------------------------------------------------------------------------
# Balances + funding
# -----------------------------------------------------------------------------

def account_free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0


def account_nonce(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        n = substrate.get_account_nonce(ss58)
        if isinstance(n, int):
            return n
        if isinstance(n, str):
            return int(n, 0)
    except Exception:
        pass
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["nonce"])
    except Exception:
        return 0


def submit_signed(substrate: SubstrateInterface, signer: Keypair, call, wait_for_inclusion: bool):
    xt = substrate.create_signed_extrinsic(call=call, keypair=signer, era="00")
    try:
        rec = substrate.submit_extrinsic(
            xt,
            wait_for_inclusion=wait_for_inclusion,
            wait_for_finalization=False,
        )
        return rec
    except SubstrateRequestException as e:
        raise RuntimeError(str(e)) from e


def transfer_keep_alive(
    substrate: SubstrateInterface,
    balances_pallet: str,
    faucet: Keypair,
    dest_ss58: str,
    amount: int,
):
    last_err: Optional[Exception] = None
    for fn_name in ("transfer_keep_alive", "transfer"):
        try:
            call = substrate.compose_call(
                call_module=balances_pallet,
                call_function=fn_name,
                call_params={"dest": dest_ss58, "value": int(amount)},
            )
            _ = submit_signed(substrate, faucet, call, wait_for_inclusion=True)
            return
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Funding transfer failed: {last_err}")


def ensure_funded(
    substrate: SubstrateInterface,
    balances_pallet: str,
    faucet: Keypair,
    dest: Keypair,
    min_free: int,
):
    have = account_free_balance(substrate, dest.ss58_address)
    if have >= min_free:
        return
    if faucet.ss58_address == dest.ss58_address:
        raise RuntimeError("Need to fund an account but faucet == dest (cannot self-fund).")
    delta = int((min_free - have) * 1.1) + 1
    print(f"[i] Funding {dest.ss58_address} with {delta} units (have={have}, need={min_free})")
    transfer_keep_alive(substrate, balances_pallet, faucet, dest.ss58_address, delta)


# -----------------------------------------------------------------------------
# Key selection (validator + non-validators + faucet)
# -----------------------------------------------------------------------------

def aura_authorities_hex(substrate: SubstrateInterface, aura_pallet: str) -> List[str]:
    try:
        v = substrate.query(aura_pallet, "Authorities", []).value
    except Exception:
        return []
    out: List[str] = []
    if isinstance(v, list):
        for item in v:
            if isinstance(item, str) and item.startswith("0x") and len(strip_0x(item)) == 64:
                out.append("0x" + strip_0x(item).lower())
            elif isinstance(item, (bytes, bytearray)) and len(item) == 32:
                out.append("0x" + bytes(item).hex())
    return out


def pick_accounts(substrate: SubstrateInterface, aura_pallet: str) -> Tuple[Keypair, List[Keypair], Keypair]:
    authorities = set(aura_authorities_hex(substrate, aura_pallet))
    # localnet validators are usually //One, //Two; also include standard dev keys.
    candidates = ["//One", "//Two", "//Alice", "//Bob", "//Charlie", "//Dave", "//Eve", "//Ferdie"]

    built: List[Tuple[str, Keypair, str, int]] = []
    for uri in candidates:
        try:
            kp = Keypair.create_from_uri(uri)
            pk = "0x" + kp.public_key.hex()
            bal = account_free_balance(substrate, kp.ss58_address)
            built.append((uri, kp, pk.lower(), bal))
        except Exception:
            continue

    if not built:
        raise RuntimeError("No dev keys available")

    validator: Optional[Keypair] = None
    for _uri, kp, pk_hex, _bal in built:
        if pk_hex in authorities:
            validator = kp
            break
    if validator is None:
        raise RuntimeError("Could not auto-detect an Aura validator among dev keys")

    non_vals: List[Keypair] = []
    seen = {validator.ss58_address}
    for _uri, kp, pk_hex, _bal in built:
        if kp.ss58_address in seen:
            continue
        if pk_hex in authorities:
            continue
        non_vals.append(kp)
        seen.add(kp.ss58_address)

    if len(non_vals) < 2:
        raise RuntimeError("Need at least 2 non-validator dev keys")

    # richest dev key (prefer not the validator)
    built_sorted = sorted(built, key=lambda x: x[3], reverse=True)
    faucet = built_sorted[0][1]
    for _uri, kp, _pk, _bal in built_sorted:
        if kp.ss58_address != validator.ss58_address:
            faucet = kp
            break

    return validator, non_vals, faucet


# -----------------------------------------------------------------------------
# Pool interaction helpers (submit + remove)
# -----------------------------------------------------------------------------

def build_signed_xt(substrate: SubstrateInterface, who: Keypair, call, nonce: int):
    return substrate.create_signed_extrinsic(call=call, keypair=who, era="00", nonce=int(nonce))


def xt_hex(xt) -> str:
    d = getattr(xt, "data", None)
    if d is not None and hasattr(d, "to_hex"):
        hx = d.to_hex()
        if isinstance(hx, str) and hx.startswith("0x"):
            return hx
    raise RuntimeError("Could not extract extrinsic hex")


def submit_xt(substrate: SubstrateInterface, xt) -> Tuple[bool, str]:
    try:
        rec = substrate.submit_extrinsic(xt, wait_for_inclusion=False, wait_for_finalization=False)
        # rec is usually an ExtrinsicReceipt; sometimes printable.
        if isinstance(rec, str) and rec.startswith("0x"):
            return True, rec
        for attr in ("extrinsic_hash", "extrinsic_hash_hex"):
            if hasattr(rec, attr):
                v = getattr(rec, attr)
                if isinstance(v, str) and v.startswith("0x"):
                    return True, v
        return True, str(rec)
    except SubstrateRequestException as e:
        return False, str(e)


def remove_extrinsics_best_effort(substrate: SubstrateInterface, items: List[str]) -> None:
    if not items:
        return
    try:
        _ = substrate.rpc_request("author_removeExtrinsic", [items])
    except Exception:
        pass


def submit_first_with_future_nonce(
    substrate: SubstrateInterface,
    who: Keypair,
    call,
    start_offset: int = 40,
    tries: int = 80,
) -> Tuple[int, Any]:
    """
    Find a future nonce (current_nonce + offset + jitter) where the FIRST tx imports cleanly.
    We do this by actually trying to submit the tx, and if it collides with a leftover pool tx
    we bump nonce and retry.
    """
    base = account_nonce(substrate, who.ss58_address)
    jitter = int(time.time()) % 200  # vary between runs
    last_err: Optional[str] = None

    for i in range(tries):
        n = base + start_offset + jitter + i
        xt = build_signed_xt(substrate, who, call, n)
        ok, msg = submit_xt(substrate, xt)
        if ok:
            return n, xt

        last_err = msg
        # If there is already something at that nonce (or identical tx), try a new nonce.
        if is_priority_too_low(msg) or is_already_imported(msg):
            continue

        # Otherwise: real failure (bad call params, invalid tx, etc.)
        raise RuntimeError(f"First-tx import failed unexpectedly for {who.ss58_address} nonce={n}: {msg}")

    raise RuntimeError(f"Could not find a usable future nonce for {who.ss58_address}. Last error: {last_err}")


def expect_accept(label: str, ok: bool, msg: str):
    assert_true(label, ok, f"expected ACCEPT, got error: {msg}")


def expect_reject_low_prio(label: str, ok: bool, msg: str):
    assert_true(label, (not ok) and is_priority_too_low(msg), f"expected PriorityTooLow reject, got: {msg}")


# -----------------------------------------------------------------------------
# Main test
# -----------------------------------------------------------------------------

def main():
    substrate = connect(WS_URL)

    system = resolve_pallet(substrate, "System")
    balances = resolve_pallet(substrate, "Balances")
    aura = resolve_pallet(substrate, "Aura")
    mev = resolve_pallet(substrate, "MevShield")
    admin = resolve_pallet(substrate, "AdminUtils")

    validator, non_vals, faucet = pick_accounts(substrate, aura)
    nonval_b = non_vals[0]
    nonval_c = non_vals[1]

    print(f"[i] Node: {WS_URL}")
    print("[i] Accounts:")
    print(f"    validator (Aura authority): {validator.ss58_address}")
    print(f"    non-validator B:            {nonval_b.ss58_address}")
    print(f"    non-validator C:            {nonval_c.ss58_address}")
    print(f"    faucet:                     {faucet.ss58_address}")

    # Ensure balances
    unit = 10 ** token_decimals(substrate)
    min_free = 25_000 * unit

    print("\n=== Step 0: Ensure accounts are funded ===")
    ensure_funded(substrate, balances, faucet, validator, min_free)
    ensure_funded(substrate, balances, faucet, nonval_b, min_free)
    ensure_funded(substrate, balances, faucet, nonval_c, min_free)

    # Build reusable calls (we will build distinct remark payloads when needed)
    def make_remark_call(tag: str):
        return substrate.compose_call(
            call_module=system,
            call_function="remark",
            call_params={"remark": f"{tag}-{int(time.time()*1000)}".encode("utf-8")},
        )

    call_announce = substrate.compose_call(
        call_module=mev,
        call_function="announce_next_key",
        call_params={"public_key": b"\x11" * 1184},
    )

    call_admin = substrate.compose_call(
        call_module=admin,
        call_function="sudo_set_subtoken_enabled",
        call_params={"netuid": 1, "subtoken_enabled": True},
    )

    # -------------------------------------------------------------------------
    # Step 1: Validator announce outranks normal
    # -------------------------------------------------------------------------
    print("\n=== Step 1: Validator announce_next_key MUST outrank Normal (replacement test) ===")
    cleanup: List[str] = []

    n1, xt1 = submit_first_with_future_nonce(substrate, validator, make_remark_call("s1-remark-a"))
    hx1 = xt_hex(xt1)
    cleanup.append(hx1)
    print(f"  1) submit validator remark @ nonce={n1}                 => ACCEPT")

    xt2 = build_signed_xt(substrate, validator, call_announce, n1)
    hx2 = xt_hex(xt2)
    ok2, m2 = submit_xt(substrate, xt2)
    cleanup.append(hx2)
    print(f"  2) submit validator announce_next_key @ same nonce={n1} => {'ACCEPT' if ok2 else 'REJECT'}")
    expect_accept("Step1.2 announce accepted (must replace remark)", ok2, m2)

    # IMPORTANT FIX: use a DIFFERENT remark payload (different bytes/hash) but SAME nonce.
    xt3 = build_signed_xt(substrate, validator, make_remark_call("s1-remark-b"), n1)
    hx3 = xt_hex(xt3)
    ok3, m3 = submit_xt(substrate, xt3)
    # hx3 is likely not imported if rejected, but safe to include in cleanup.
    cleanup.append(hx3)
    print(f"  3) submit validator DIFFERENT remark @ same nonce={n1}  => {'ACCEPT' if ok3 else 'REJECT'}")
    expect_reject_low_prio("Step1.3 lower-priority remark rejected (PriorityTooLow)", ok3, m3)

    remove_extrinsics_best_effort(substrate, cleanup)
    print("  [✓] Step 1 passed")

    # -------------------------------------------------------------------------
    # Step 2: Non-validator announce is NOT elevated (equal to normal)
    # -------------------------------------------------------------------------
    print("\n=== Step 2: Non-validator announce_next_key MUST NOT be elevated (equal to Normal) ===")

    # Case A: remark then announce -> announce must be rejected
    cleanup = []
    n2a, xt_a1 = submit_first_with_future_nonce(substrate, nonval_b, make_remark_call("s2a-remark-a"))
    cleanup.append(xt_hex(xt_a1))
    print(f"  Case A (nonce={n2a}): remark then announce")
    print("    1) submit remark   => ACCEPT")

    xt_a2 = build_signed_xt(substrate, nonval_b, call_announce, n2a)
    cleanup.append(xt_hex(xt_a2))
    ok, msg = submit_xt(substrate, xt_a2)
    print(f"    2) submit announce => {'ACCEPT' if ok else 'REJECT'}")
    expect_reject_low_prio("Step2.A.2 announce rejected (PriorityTooLow)", ok, msg)
    remove_extrinsics_best_effort(substrate, cleanup)

    # Case B: announce then remark -> remark must be rejected
    cleanup = []
    n2b, xt_b1 = submit_first_with_future_nonce(substrate, nonval_b, call_announce)
    cleanup.append(xt_hex(xt_b1))
    print(f"  Case B (nonce={n2b}): announce then remark")
    print("    1) submit announce => ACCEPT")

    xt_b2 = build_signed_xt(substrate, nonval_b, make_remark_call("s2b-remark-a"), n2b)
    cleanup.append(xt_hex(xt_b2))
    ok, msg = submit_xt(substrate, xt_b2)
    print(f"    2) submit remark   => {'ACCEPT' if ok else 'REJECT'}")
    expect_reject_low_prio("Step2.B.2 remark rejected (PriorityTooLow)", ok, msg)
    remove_extrinsics_best_effort(substrate, cleanup)

    print("  [✓] Step 2 passed")

    # -------------------------------------------------------------------------
    # Step 3: Root-only operational call is NOT elevated (equal to normal)
    # -------------------------------------------------------------------------
    print("\n=== Step 3: Root-only Operational (non-exception) MUST NOT be elevated (equal to Normal) ===")

    # Case A: remark then admin -> admin must be rejected
    cleanup = []
    n3a, xt_c1 = submit_first_with_future_nonce(substrate, nonval_c, make_remark_call("s3a-remark-a"))
    cleanup.append(xt_hex(xt_c1))
    print(f"  Case A (nonce={n3a}): remark then admin(root-only op)")
    print("    1) submit remark => ACCEPT")

    xt_c2 = build_signed_xt(substrate, nonval_c, call_admin, n3a)
    cleanup.append(xt_hex(xt_c2))
    ok, msg = submit_xt(substrate, xt_c2)
    print(f"    2) submit admin  => {'ACCEPT' if ok else 'REJECT'}")
    expect_reject_low_prio("Step3.A.2 admin rejected (PriorityTooLow)", ok, msg)
    remove_extrinsics_best_effort(substrate, cleanup)

    # Case B: admin then remark -> remark must be rejected
    cleanup = []
    n3b, xt_d1 = submit_first_with_future_nonce(substrate, nonval_c, call_admin)
    cleanup.append(xt_hex(xt_d1))
    print(f"  Case B (nonce={n3b}): admin(root-only op) then remark")
    print("    1) submit admin  => ACCEPT")

    xt_d2 = build_signed_xt(substrate, nonval_c, make_remark_call("s3b-remark-a"), n3b)
    cleanup.append(xt_hex(xt_d2))
    ok, msg = submit_xt(substrate, xt_d2)
    print(f"    2) submit remark => {'ACCEPT' if ok else 'REJECT'}")
    expect_reject_low_prio("Step3.B.2 remark rejected (PriorityTooLow)", ok, msg)
    remove_extrinsics_best_effort(substrate, cleanup)

    print("  [✓] Step 3 passed")

    print(
        "\n=== Summary ===\n"
        "✅ PASS: Replacement behavior matches intended priority rules:\n"
        "  - validator announce_next_key replaces normal remark (higher priority)\n"
        "  - non-validator announce_next_key cannot replace remark (equal normal priority)\n"
        "  - root-only operational call cannot replace remark (equal normal priority)\n"
    )


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(str(e))
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
