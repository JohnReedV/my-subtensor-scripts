#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Registry.clear_identity CanRegister gate regression test (Subtensor)

✅ Asserts your new guard in `clear_identity` works:

1) owner_cold root-registers victim_hot (so CanRegister(owner_cold, victim_hot) == true)
2) owner_cold sets identity for victim_hot (Registry.set_identity) -> MUST succeed
3) attacker_cold tries to clear identity (Registry.clear_identity) -> MUST FAIL with CannotRegister
   and IdentityOf(victim_hot) MUST still exist
4) owner_cold clears identity -> MUST succeed and IdentityOf(victim_hot) MUST be None

Fixes in this revision
----------------------
- WS endpoint default: ws://127.0.0.1:9945
- Robust IdentityInfo encoding (tries multiple shapes)
- Robust error handling:
    substrate-interface may return receipt.error_message as a dict (not a string),
    so we normalize it before calling .lower().

Run:
    python3 clearid_can_register_test.py
or:
    python3 clearid_can_register_test.py --ws ws://127.0.0.1:9945
"""

import argparse
import sys
import time
from typing import Any, Dict, Optional, List, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
DEFAULT_WS = "ws://127.0.0.1:9945"

REGISTRY_PALLET = "Registry"
SUBTENSOR_PALLET = "SubtensorModule"
BALANCES_PALLET = "Balances"


# ─────────────────────────────────────────────
# Generic helpers
# ─────────────────────────────────────────────
def connect(ws: str) -> SubstrateInterface:
    return SubstrateInterface(url=ws)


def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


def to_planck(amount: float, decimals: int) -> int:
    return int(round(amount * (10 ** decimals)))


def sleep_blocks(n: int = 1):
    # we already wait-for-finalization per extrinsic; this is extra slack
    time.sleep(3 * n)


def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def submit_extrinsic(substrate: SubstrateInterface, signer: Keypair, call, sudo: bool = False):
    """
    Submit an extrinsic and return the receipt (even if dispatch failed).
    Raises only on RPC / submission errors.
    """
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})

    xt = substrate.create_signed_extrinsic(call=call, keypair=signer)
    try:
        return substrate.submit_extrinsic(
            xt,
            wait_for_inclusion=True,
            wait_for_finalization=True,
        )
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed (RPC): {e}") from e


def account_free(substrate: SubstrateInterface, ss58: str) -> int:
    info = substrate.query("System", "Account", [ss58]).value
    return int(info["data"]["free"])


def ensure_min_balance(substrate: SubstrateInterface, faucet: Keypair, dest_ss58: str, min_planck: int):
    cur = account_free(substrate, dest_ss58)
    if cur >= min_planck:
        return
    delta = min_planck - cur
    call = compose_call(substrate, BALANCES_PALLET, "transfer_keep_alive", {"dest": dest_ss58, "value": int(delta)})
    rcpt = submit_extrinsic(substrate, faucet, call)
    if not rcpt.is_success:
        raise RuntimeError(f"Funding transfer failed: {rcpt.error_message!r}")


def registry_identity_of(substrate: SubstrateInterface, identified_ss58: str) -> Optional[Any]:
    q = substrate.query(REGISTRY_PALLET, "IdentityOf", [identified_ss58])
    return q.value  # None if missing


def _error_to_text(err: Any) -> str:
    """
    substrate-interface sometimes returns error_message as:
      - str
      - dict (structured dispatch error)
      - other
    We want a stable lowercase-searchable string for assertions/logging.
    """
    if err is None:
        return ""
    if isinstance(err, str):
        return err

    # If it's structured, collect all keys/values recursively as strings.
    if isinstance(err, dict):
        parts: List[str] = []

        def walk(x: Any):
            if x is None:
                return
            if isinstance(x, str):
                parts.append(x)
                return
            if isinstance(x, dict):
                for k, v in x.items():
                    if isinstance(k, str):
                        parts.append(k)
                    else:
                        try:
                            parts.append(str(k))
                        except Exception:
                            pass
                    walk(v)
                return
            if isinstance(x, (list, tuple, set)):
                for i in x:
                    walk(i)
                return
            try:
                parts.append(str(x))
            except Exception:
                parts.append(repr(x))

        walk(err)
        # de-dupe while preserving order
        out = []
        seen = set()
        for p in parts:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return " ".join(out)

    try:
        return str(err)
    except Exception:
        return repr(err)


def assert_succeeded(receipt, ctx: str = ""):
    if receipt.is_success:
        return
    raise AssertionError(f"{ctx} expected success, got error: {_error_to_text(receipt.error_message)!r}")


def assert_failed_with(receipt, needle: str, ctx: str = ""):
    if receipt.is_success:
        raise AssertionError(f"{ctx} expected failure, but extrinsic succeeded.")

    msg_text = _error_to_text(receipt.error_message)
    msg_lower = msg_text.lower()

    if needle.lower() not in msg_lower:
        raise AssertionError(
            f"{ctx} expected error containing '{needle}', got:\n"
            f"  raw error_message={receipt.error_message!r}\n"
            f"  normalized='{msg_text}'"
        )


# ─────────────────────────────────────────────
# Optional: loosen registration limits (best-effort)
# ─────────────────────────────────────────────
def loosen_registration_limits_if_available(substrate: SubstrateInterface, sudo_kp: Keypair):
    try:
        call = compose_call(substrate, "AdminUtils", "sudo_set_network_rate_limit", {"rate_limit": 0})
        _ = submit_extrinsic(substrate, sudo_kp, call, sudo=True)
        sleep_blocks(1)
    except Exception:
        pass

    try:
        call = compose_call(
            substrate,
            "AdminUtils",
            "sudo_set_target_registrations_per_interval",
            {"netuid": 0, "target_registrations_per_interval": 100_000},
        )
        _ = submit_extrinsic(substrate, sudo_kp, call, sudo=True)
        sleep_blocks(1)
    except Exception:
        pass


# ─────────────────────────────────────────────
# Subtensor: ensure hotkey registered on ROOT under coldkey
# ─────────────────────────────────────────────
def ensure_root_registered_hotkey(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str):
    """
    Ensure hotkey is root-registered (owned by coldkey).
    If already registered, ignore.

    Tries a few parameter-name variants just in case metadata differs slightly.
    """
    param_candidates = [
        {"hotkey": hot_ss58},
        {"hot_key": hot_ss58},
        {"hotkey_address": hot_ss58},
    ]

    last_compose_err = None
    for params in param_candidates:
        try:
            call = compose_call(substrate, SUBTENSOR_PALLET, "root_register", params)
        except Exception as e:
            last_compose_err = e
            continue

        rcpt = submit_extrinsic(substrate, cold, call)
        if rcpt.is_success:
            return

        msg = _error_to_text(rcpt.error_message).lower()
        if "already" in msg and "register" in msg:
            return

        raise RuntimeError(f"root_register failed: {_error_to_text(rcpt.error_message)}")

    raise RuntimeError(f"Could not compose root_register with any param shape. Last error: {last_compose_err}")


# ─────────────────────────────────────────────
# IdentityInfo encoding candidates (fix for encoding differences)
# ─────────────────────────────────────────────
def _clone_data(v: Any) -> Any:
    return dict(v) if isinstance(v, dict) else v


def identity_info_candidates() -> List[Tuple[str, Dict[str, Any]]]:
    """
    Build a list of candidate IdentityInfo encodings.

    Common differences across runtimes/metadata:
    - Data::None represented as "None" or {"None": None}
    - additional is a newtype BoundedVec wrapper (needs [[]] instead of [])
    - pgp_fingerprint is Option (None vs {"None": None})
    """
    data_variants: List[Tuple[str, Any]] = [
        ("data='None' (string unit variant)", "None"),
        ("data={'None': None} (dict unit variant)", {"None": None}),
        ("data={'Raw': '0x00'} (Raw one-byte)", {"Raw": "0x00"}),
    ]

    additional_variants: List[Tuple[str, Any]] = [
        ("additional=[[]] (newtype wrapper vec)", [[]]),  # prioritize this
        ("additional=[] (plain vec)", []),
        ("additional={'0': []} (newtype wrapper dict)", {"0": []}),
    ]

    fingerprint_variants: List[Tuple[str, Any]] = [
        ("pgp_fingerprint=None", None),
        ("pgp_fingerprint={'None': None}", {"None": None}),
    ]

    out: List[Tuple[str, Dict[str, Any]]] = []

    for dlabel, dval in data_variants:
        for alabel, aval in additional_variants:
            for flabel, fval in fingerprint_variants:
                # create fresh copies
                if aval == []:
                    additional_val: Any = []
                elif aval == [[]]:
                    additional_val = [[]]
                else:
                    additional_val = {"0": []}

                pgp_val = None if fval is None else dict(fval)

                info = {
                    "additional": additional_val,
                    "display": _clone_data(dval),
                    "legal": _clone_data(dval),
                    "web": _clone_data(dval),
                    "riot": _clone_data(dval),
                    "email": _clone_data(dval),
                    "pgp_fingerprint": pgp_val,
                    "image": _clone_data(dval),
                    "twitter": _clone_data(dval),
                }
                label = f"{dlabel} + {alabel} + {flabel}"
                out.append((label, info))

    # already ordered with additional=[[]] first, but keep it explicit
    out.sort(key=lambda x: (0 if "additional=[[]]" in x[0] else 1))
    return out


def set_identity_best_effort(substrate: SubstrateInterface, signer: Keypair, identified_ss58: str):
    """
    Try multiple IdentityInfo encodings until set_identity succeeds.
    Returns (receipt, encoding_label).
    """
    last_err: Optional[Exception] = None
    for label, info in identity_info_candidates():
        print(f"[i] Trying IdentityInfo encoding: {label}")
        try:
            call = compose_call(
                substrate,
                REGISTRY_PALLET,
                "set_identity",
                {"identified": identified_ss58, "info": info},
            )
        except Exception as e:
            print(f"[i]   compose_call failed: {e}")
            last_err = e
            continue

        try:
            rcpt = submit_extrinsic(substrate, signer, call)
        except Exception as e:
            print(f"[i]   submit_extrinsic failed: {e}")
            last_err = e
            continue

        if rcpt.is_success:
            print(f"[✓] set_identity succeeded with encoding: {label}")
            return rcpt, label

        # Encoding was accepted but dispatch failed at runtime: that's a real failure for the test.
        raise RuntimeError(f"set_identity dispatched but failed: {_error_to_text(rcpt.error_message)}")

    raise RuntimeError(f"Unable to compose/submit set_identity with any candidate. Last error: {last_err}")


# ─────────────────────────────────────────────
# Main test
# ─────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ws", default=DEFAULT_WS, help="WebSocket endpoint (default: %(default)s)")
    args = ap.parse_args()

    substrate = connect(args.ws)
    dec = token_decimals(substrate)
    print(f"[i] Connected to {args.ws} (decimals={dec})")

    # Actors
    sudo = Keypair.create_from_uri("//Alice")
    owner_cold = Keypair.create_from_uri("//OwnerCold")
    attacker_cold = Keypair.create_from_uri("//Staker1Cold")

    # Use a unique hotkey derivation to avoid collisions across runs
    victim_hot = Keypair.create_from_uri("//OwnerHot//registry-clearid-test")

    print(f"[i] owner_cold   = {owner_cold.ss58_address}")
    print(f"[i] attacker     = {attacker_cold.ss58_address}")
    print(f"[i] victim_hot   = {victim_hot.ss58_address}")

    # Funding (generous: deposits + fees)
    ensure_min_balance(substrate, sudo, owner_cold.ss58_address, to_planck(500, dec))
    ensure_min_balance(substrate, sudo, attacker_cold.ss58_address, to_planck(50, dec))
    sleep_blocks(1)

    # Optional: loosen rate limits
    loosen_registration_limits_if_available(substrate, sudo)

    # Ensure CanRegister(owner_cold, victim_hot) becomes true
    print("[i] Ensuring hotkey is root-registered (SubtensorModule.root_register)...")
    ensure_root_registered_hotkey(substrate, owner_cold, victim_hot.ss58_address)
    sleep_blocks(1)

    # Set identity (must succeed)
    print("[i] Setting identity (Registry.set_identity) as owner coldkey...")
    _rcpt_set, enc_label = set_identity_best_effort(substrate, owner_cold, victim_hot.ss58_address)
    sleep_blocks(1)

    # Confirm identity exists
    id_before = registry_identity_of(substrate, victim_hot.ss58_address)
    assert id_before is not None, "Expected identity to exist after set_identity, but IdentityOf is None."
    print("[✓] IdentityOf exists after set_identity.")

    # Unauthorized clear attempt (must fail CannotRegister)
    print("[i] Attempting unauthorized clear (Registry.clear_identity) as attacker...")
    call_clear_bad = compose_call(
        substrate,
        REGISTRY_PALLET,
        "clear_identity",
        {"identified": victim_hot.ss58_address},
    )
    rcpt_bad = submit_extrinsic(substrate, attacker_cold, call_clear_bad)

    assert_failed_with(rcpt_bad, "CannotRegister", ctx="[unauthorized clear_identity]")
    print("[✓] Unauthorized clear_identity failed with CannotRegister (expected).")

    # Ensure identity still exists
    id_after_bad = registry_identity_of(substrate, victim_hot.ss58_address)
    assert id_after_bad is not None, "IdentityOf disappeared after unauthorized clear attempt — guard did not work."
    print("[✓] IdentityOf is still present after unauthorized clear attempt (expected).")

    # Authorized clear (must succeed)
    print("[i] Clearing identity as owner coldkey (Registry.clear_identity)...")
    call_clear_ok = compose_call(
        substrate,
        REGISTRY_PALLET,
        "clear_identity",
        {"identified": victim_hot.ss58_address},
    )
    rcpt_ok = submit_extrinsic(substrate, owner_cold, call_clear_ok)
    assert_succeeded(rcpt_ok, ctx="[authorized clear_identity]")
    sleep_blocks(1)

    # Ensure removed
    id_final = registry_identity_of(substrate, victim_hot.ss58_address)
    assert id_final is None, "Expected IdentityOf to be None after authorized clear_identity, but it still exists."
    print("[✓] Authorized clear_identity succeeded and IdentityOf is removed.")

    print("\n✅ PASS: clear_identity is correctly gated by CanRegister (CannotRegister on unauthorized caller).")
    print(f"[i] set_identity encoding used: {enc_label}")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as ae:
        print(f"\n❌ Assertion failed: {ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)