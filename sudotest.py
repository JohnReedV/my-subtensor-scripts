#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E2E test for SudoTransactionExtension pool validation (with per-test block separation).

This script matches your *current* TransactionExtension logic:

  - Sudo calls are allowed only when signed by the configured sudo key.
  - All DispatchClass::Operational calls are rejected from the tx pool unless:
      * Root origin, OR
      * MevShield::announce_next_key signed by a current Aura validator
        (passes T::AuthorityOrigin::ensure_validator(origin)).

Test cases (each forced onto its OWN block):

A) Sudo green path (Operational + Root-only inner call)
   1) Direct signed submission of SubtensorModule::set_pending_childkey_cooldown
      must be REJECTED by the pool (bad origin, Operational).
   2) The SAME call wrapped in Sudo::sudo must be INCLUDED successfully.  (Block A)

   Then wait for the next block before continuing.

B) MevShield exception (Operational but validator-signed)
   1) MevShield::announce_next_key signed by NON-validator must be REJECTED by the pool.
   2) MevShield::announce_next_key signed by Aura validator must be INCLUDED successfully. (Block B)

   Then wait for the next block before continuing.

C) Normal dispatch is NOT blocked (and works)
   1) A Normal dispatch call (System::remark or System::remark_with_event) signed by a normal
      account must be INCLUDED successfully. (Block C)

Finally, we assert: Block A < Block B < Block C.

Localnet compatibility:
  Your localnet starts validators with `--one` and `--two`, so Aura authorities typically
  correspond to //One / //Two (sometimes with //aura or //session). We try only a SMALL list.

Usage:
  python3 sudotest.py --ws ws://127.0.0.1:9945
  python3 sudotest.py --ws ws://127.0.0.1:9945 --validator-uri "//One"
"""

import argparse
import os
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException
from substrateinterface.utils.ss58 import ss58_decode, ss58_encode


# Keep this list SMALL (no brute forcing).
LOCALNET_VALIDATOR_URIS: Sequence[str] = (
    "//One",
    "//One//aura",
    "//One//session",
    "//one",
    "//one//aura",
    "//one//session",
    "//Two",
    "//Two//aura",
    "//Two//session",
    "//two",
    "//two//aura",
    "//two//session",
)

# Small fallback list for picking a non-validator.
NON_VALIDATOR_FALLBACK_URIS: Sequence[str] = (
    "//Alice",
    "//Bob",
    "//Charlie",
    "//Dave",
    "//Eve",
    "//Ferdie",
)


# ------------------------------------------------------------------------------
# Substrate / metadata helpers
# ------------------------------------------------------------------------------


def connect(ws_url: str) -> SubstrateInterface:
    si = SubstrateInterface(url=ws_url)
    si.init_runtime()
    return si


def pallet_names(si: SubstrateInterface) -> List[str]:
    md = si.get_metadata()
    return [str(p.name) for p in md.pallets]


def resolve_call_pallet(
    si: SubstrateInterface, call_function: str, prefer: Sequence[str] = ()
) -> str:
    """
    Find the pallet name that exposes call `call_function`.
    """
    names = pallet_names(si)

    for p in prefer:
        if p in names:
            try:
                si.get_metadata_call_function(p, call_function)
                return p
            except Exception:
                pass

    for p in names:
        try:
            si.get_metadata_call_function(p, call_function)
            return p
        except Exception:
            continue

    raise RuntimeError(f"Could not find pallet exposing call '{call_function}'")


def resolve_storage_pallet(
    si: SubstrateInterface, storage_item: str, prefer: Sequence[str] = ()
) -> str:
    """
    Find the pallet name that exposes storage `storage_item`.
    """
    names = pallet_names(si)

    for p in prefer:
        if p in names:
            try:
                si.get_metadata_storage_function(p, storage_item)
                return p
            except Exception:
                pass

    for p in names:
        try:
            si.get_metadata_storage_function(p, storage_item)
            return p
        except Exception:
            continue

    raise RuntimeError(f"Could not find pallet exposing storage '{storage_item}'")


# ------------------------------------------------------------------------------
# Block helpers (ensure per-test block separation)
# ------------------------------------------------------------------------------


def _to_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    raise ValueError(f"Cannot parse int from {type(v)}: {v}")


def block_number_from_hash(si: SubstrateInterface, block_hash: str) -> int:
    """
    Robustly extract block number from a block hash.
    """
    header = si.get_block_header(block_hash=block_hash)
    hv = getattr(header, "value", header)

    # Common shapes:
    #  - {"number": "0x..", ...}
    #  - {"header": {"number": "..."}}
    if isinstance(hv, dict):
        if "number" in hv:
            return _to_int(hv["number"])
        if "header" in hv and isinstance(hv["header"], dict) and "number" in hv["header"]:
            return _to_int(hv["header"]["number"])

    raise RuntimeError(f"Could not extract block number for hash {block_hash}: {hv}")


def head_number(si: SubstrateInterface) -> Tuple[int, str]:
    h = si.get_chain_head()
    return block_number_from_hash(si, h), h


def wait_for_next_block(si: SubstrateInterface, after_block_num: int, *, timeout_s: int = 60, poll_s: float = 0.25) -> int:
    """
    Wait until chain head is strictly greater than `after_block_num`.
    Returns the new head number.
    """
    start = time.time()
    while time.time() - start < timeout_s:
        n, _h = head_number(si)
        if n > after_block_num:
            return n
        time.sleep(poll_s)

    raise RuntimeError(
        f"Timed out waiting for next block after #{after_block_num}. "
        "Is the node producing blocks?"
    )


# ------------------------------------------------------------------------------
# Key helpers
# ------------------------------------------------------------------------------


def kp_from_uri(si: SubstrateInterface, uri: str) -> Keypair:
    return Keypair.create_from_uri(uri, ss58_format=si.ss58_format)


def parse_pubkey_bytes(v: Any) -> Optional[bytes]:
    """
    Parse various returned representations into raw 32-byte pubkey.
    """
    if v is None:
        return None

    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return b if len(b) == 32 else None

    if hasattr(v, "value"):
        return parse_pubkey_bytes(v.value)

    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            try:
                b = bytes.fromhex(s[2:])
                return b if len(b) == 32 else None
            except Exception:
                return None
        # maybe SS58
        try:
            hex_pk = ss58_decode(s)
            b = bytes.fromhex(hex_pk)
            return b if len(b) == 32 else None
        except Exception:
            return None

    if isinstance(v, list) and all(isinstance(x, int) for x in v):
        try:
            b = bytes(v)
            return b if len(b) == 32 else None
        except Exception:
            return None

    if isinstance(v, dict):
        for vv in v.values():
            got = parse_pubkey_bytes(vv)
            if got is not None:
                return got

    return None


def read_aura_authorities(si: SubstrateInterface) -> List[bytes]:
    """
    Read Aura::Authorities as raw pubkeys.
    """
    aura_pallet = resolve_storage_pallet(si, "Authorities", prefer=("Aura",))
    raw = si.query(aura_pallet, "Authorities", []).value
    if not isinstance(raw, list):
        raise RuntimeError(f"Unexpected {aura_pallet}::Authorities shape: {type(raw)}")

    out: List[bytes] = []
    for item in raw:
        pk = parse_pubkey_bytes(item)
        if pk is not None:
            out.append(pk)

    if not out:
        raise RuntimeError(f"{aura_pallet}::Authorities decoded but empty/unparseable")
    return out


def aura_authority_addresses(si: SubstrateInterface, auth_pks: List[bytes]) -> List[str]:
    return [ss58_encode(pk, ss58_format=si.ss58_format) for pk in auth_pks]


def pick_validator_from_small_uri_set(
    si: SubstrateInterface,
    auth_pks: List[bytes],
    validator_uri: Optional[str],
) -> Keypair:
    """
    Pick a validator Keypair.

    - If validator_uri is provided: use it (and verify it matches Aura::Authorities).
    - Else: try LOCALNET_VALIDATOR_URIS (small set) and pick first match by pubkey.
    """
    auth_set: Set[bytes] = set(auth_pks)
    auth_ss58 = aura_authority_addresses(si, auth_pks)

    if validator_uri:
        kp = kp_from_uri(si, validator_uri)
        if kp.public_key not in auth_set:
            raise RuntimeError(
                f"--validator-uri {validator_uri} ({kp.ss58_address}) does NOT match any Aura authority.\n"
                f"Aura authorities are: {auth_ss58}"
            )
        return kp

    print(f"[i] Aura authorities (ss58): {auth_ss58}")
    print(f"[i] Trying validator URIs (small set): {list(LOCALNET_VALIDATOR_URIS)}")

    for uri in LOCALNET_VALIDATOR_URIS:
        kp = kp_from_uri(si, uri)
        is_auth = kp.public_key in auth_set
        print(f"    - {uri:14s} -> {kp.ss58_address} {'(MATCH)' if is_auth else ''}")
        if is_auth:
            print(f"[✓] Selected validator: {uri} ({kp.ss58_address})")
            return kp

    raise RuntimeError(
        "Could not find a validator key from the small URI set.\n"
        "Pass a validator seed explicitly, e.g.\n"
        "  --validator-uri \"//One\"  or  --validator-uri \"//One//aura\"  or  --validator-uri \"//Two//aura\"\n"
        f"Aura authorities are: {auth_ss58}"
    )


def pick_non_validator(
    si: SubstrateInterface,
    auth_pks: List[bytes],
    preferred_uri: str,
) -> Keypair:
    """
    Pick a non-validator signer (pubkey NOT in Aura::Authorities).
    """
    auth_set: Set[bytes] = set(auth_pks)

    kp = kp_from_uri(si, preferred_uri)
    if kp.public_key not in auth_set:
        return kp

    for uri in NON_VALIDATOR_FALLBACK_URIS:
        kp2 = kp_from_uri(si, uri)
        if kp2.public_key not in auth_set:
            return kp2

    raise RuntimeError("Could not find a non-validator among the small fallback URIs.")


# ------------------------------------------------------------------------------
# Balances / funding helpers
# ------------------------------------------------------------------------------


def token_decimals(si: SubstrateInterface) -> int:
    d = si.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


def account_free_balance(si: SubstrateInterface, ss58: str) -> int:
    try:
        info = si.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0


def resolve_balances_transfer(si: SubstrateInterface) -> Tuple[str, str]:
    try:
        p = resolve_call_pallet(si, "transfer_keep_alive", prefer=("Balances",))
        return p, "transfer_keep_alive"
    except Exception:
        p = resolve_call_pallet(si, "transfer", prefer=("Balances",))
        return p, "transfer"


def compose_call(si: SubstrateInterface, pallet: str, function: str, params: Dict[str, Any]):
    return si.compose_call(call_module=pallet, call_function=function, call_params=params)


def submit_signed(
    si: SubstrateInterface,
    signer: Keypair,
    call,
    *,
    wait_for_inclusion: bool,
    wait_for_finalization: bool,
):
    xt = si.create_signed_extrinsic(call=call, keypair=signer, era="00")  # immortal
    return si.submit_extrinsic(
        xt, wait_for_inclusion=wait_for_inclusion, wait_for_finalization=wait_for_finalization
    )


def ensure_funded(
    si: SubstrateInterface,
    faucet: Keypair,
    dest: Keypair,
    min_balance_planck: int,
    label: str,
) -> None:
    have = account_free_balance(si, dest.ss58_address)
    if have >= min_balance_planck:
        return

    balances_pallet, fn = resolve_balances_transfer(si)
    delta = int((min_balance_planck - have) * 1.2) + 1
    print(
        f"[i] Funding {label} ({dest.ss58_address}) with {delta} planck "
        f"from faucet {faucet.ss58_address} (have={have}, need={min_balance_planck})"
    )
    call = compose_call(si, balances_pallet, fn, {"dest": dest.ss58_address, "value": int(delta)})
    rec = submit_signed(si, faucet, call, wait_for_inclusion=True, wait_for_finalization=False)
    if not rec.is_success:
        raise RuntimeError(f"Funding transfer failed: {rec.error_message}")


# ------------------------------------------------------------------------------
# Assertions
# ------------------------------------------------------------------------------


def pool_accepts(si: SubstrateInterface, signer: Keypair, call) -> bool:
    """
    True iff author_submitExtrinsic accepts the tx into the pool.
    """
    try:
        _ = submit_signed(si, signer, call, wait_for_inclusion=False, wait_for_finalization=False)
        return True
    except Exception:
        return False


def assert_pool_rejects(si: SubstrateInterface, signer: Keypair, call, label: str) -> None:
    if pool_accepts(si, signer, call):
        raise AssertionError(f"{label}: expected pool rejection, but extrinsic was accepted")
    print(f"[✓] {label}: rejected by pool as expected")


def assert_included_success(
    si: SubstrateInterface,
    signer: Keypair,
    call,
    label: str,
    *,
    wait_for_finalization: bool,
) -> Tuple[str, int]:
    """
    Submit ONCE and wait for inclusion/finalization.
    Success implies: accepted into the pool + included + dispatch OK.
    Returns (block_hash, block_number).
    """
    try:
        receipt = submit_signed(
            si,
            signer,
            call,
            wait_for_inclusion=True,
            wait_for_finalization=wait_for_finalization,
        )
    except SubstrateRequestException as e:
        raise AssertionError(f"{label}: submission failed: {e}") from e
    except Exception as e:
        raise AssertionError(f"{label}: submission failed: {e}") from e

    if not receipt.is_success:
        raise AssertionError(
            f"{label}: included but failed dispatch in block {receipt.block_hash}: {receipt.error_message}"
        )

    bn = block_number_from_hash(si, receipt.block_hash)
    print(f"[✓] {label}: included OK in block #{bn} ({receipt.block_hash})")
    return receipt.block_hash, bn


# ------------------------------------------------------------------------------
# Normal-call selection helper
# ------------------------------------------------------------------------------


def resolve_system_remark(si: SubstrateInterface) -> Tuple[str, str]:
    """
    Prefer System::remark if present, else System::remark_with_event.
    Returns (system_pallet_name, function_name).
    """
    try:
        p = resolve_call_pallet(si, "remark", prefer=("System",))
        return p, "remark"
    except Exception:
        p = resolve_call_pallet(si, "remark_with_event", prefer=("System",))
        return p, "remark_with_event"


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(
        description="E2E test for Operational gating + MevShield exception + Normal-call pass-through (per-test block separation)"
    )
    ap.add_argument("--ws", default="ws://127.0.0.1:9945", help="WebSocket endpoint")

    ap.add_argument(
        "--sudo-uri",
        default=None,
        help="URI for sudo key. If omitted, assumes sudo key is //Alice and verifies against Sudo::Key.",
    )
    ap.add_argument(
        "--validator-uri",
        default=None,
        help="Validator URI for MevShield::announce_next_key (e.g. //One//aura or //Two//aura).",
    )
    ap.add_argument(
        "--spammer-uri",
        default="//Eve",
        help="Non-validator signer used for negative tests (will be overridden if it is a validator).",
    )

    ap.add_argument("--cooldown", type=int, default=123, help="Cooldown value for set_pending_childkey_cooldown")
    ap.add_argument("--finalize", action="store_true", help="Wait for finalization (slower; inclusion-only by default)")
    ap.add_argument(
        "--min-funds-tao",
        type=float,
        default=100.0,
        help="Minimum balance to ensure for signer accounts (TAO units, converted using token_decimals).",
    )

    args = ap.parse_args()

    si = connect(args.ws)
    print(f"[i] Connected: {args.ws}")
    print(f"[i] ss58_format={si.ss58_format}")

    # Resolve pallets / calls
    sudo_pallet = resolve_call_pallet(si, "sudo", prefer=("Sudo",))
    cooldown_pallet = resolve_call_pallet(si, "set_pending_childkey_cooldown", prefer=("SubtensorModule", "Subtensor"))
    mev_pallet = resolve_call_pallet(si, "announce_next_key", prefer=("MevShield", "Shield", "mev_shield", "shield"))
    system_pallet, system_remark_fn = resolve_system_remark(si)

    print("[i] Resolved pallets:")
    print(f"    sudo_pallet       = {sudo_pallet}")
    print(f"    cooldown_pallet   = {cooldown_pallet}")
    print(f"    mev_pallet        = {mev_pallet}")
    print(f"    system_pallet     = {system_pallet}")
    print(f"    system_remark_fn  = {system_remark_fn}")

    # Sudo signer selection (fast)
    sudo_key_addr = si.query(sudo_pallet, "Key", []).value
    if not isinstance(sudo_key_addr, str) or not sudo_key_addr:
        raise RuntimeError(f"Unexpected {sudo_pallet}::Key value: {sudo_key_addr}")

    if args.sudo_uri:
        sudo_signer = kp_from_uri(si, args.sudo_uri)
        if sudo_signer.ss58_address != sudo_key_addr:
            raise RuntimeError(
                f"--sudo-uri {args.sudo_uri} is {sudo_signer.ss58_address}, "
                f"but chain {sudo_pallet}::Key is {sudo_key_addr}"
            )
    else:
        sudo_signer = kp_from_uri(si, "//Alice")
        if sudo_signer.ss58_address != sudo_key_addr:
            raise RuntimeError(
                f"Chain sudo key is {sudo_key_addr} but //Alice is {sudo_signer.ss58_address}. "
                "Pass --sudo-uri explicitly."
            )

    print(f"[i] sudo key address: {sudo_key_addr}")

    # Faucet
    faucet = sudo_signer

    # Aura authorities + validator selection
    aura_pks = read_aura_authorities(si)
    validator = pick_validator_from_small_uri_set(si, aura_pks, validator_uri=args.validator_uri)

    # Pick non-validator for negative tests
    spammer = pick_non_validator(si, aura_pks, preferred_uri=args.spammer_uri)
    if spammer.ss58_address == validator.ss58_address:
        raise RuntimeError("Internal error: spammer == validator")

    print(f"[i] validator: {validator.ss58_address}")
    print(f"[i] spammer:   {spammer.ss58_address}")

    # Funding (avoid false negatives due to transaction payment)
    dec = token_decimals(si)
    min_balance_planck = int(args.min_funds_tao * (10**dec))
    ensure_funded(si, faucet, spammer, min_balance_planck, label="spammer")
    ensure_funded(si, faucet, validator, min_balance_planck, label="validator")

    # Record starting head
    start_bn, _start_h = head_number(si)
    print(f"[i] Current head at start: #{start_bn}")

    # ------------------------------------------------------------------------------
    # TEST A: Sudo green path (Operational Root-only call)
    # ------------------------------------------------------------------------------
    print("\n=== TEST A: Sudo green path for Root-only Operational call ===")

    root_only_call = compose_call(
        si,
        cooldown_pallet,
        "set_pending_childkey_cooldown",
        {"cooldown": int(args.cooldown)},
    )

    assert_pool_rejects(
        si,
        spammer,
        root_only_call,
        label=f"Direct {cooldown_pallet}::set_pending_childkey_cooldown signed by {spammer.ss58_address}",
    )

    sudo_wrapped = compose_call(si, sudo_pallet, "sudo", {"call": root_only_call})
    _h_a, bn_a = assert_included_success(
        si,
        sudo_signer,
        sudo_wrapped,
        label=f"{sudo_pallet}::sudo({cooldown_pallet}::set_pending_childkey_cooldown) signed by sudo key",
        wait_for_finalization=args.finalize,
    )

    # Wait for at least one new block before test B (so B cannot land in A's block).
    nxt = wait_for_next_block(si, bn_a)
    print(f"[i] Advanced to head #{nxt} before starting TEST B")

    # ------------------------------------------------------------------------------
    # TEST B: MevShield exception (Operational validator-signed)
    # ------------------------------------------------------------------------------
    print("\n=== TEST B: MevShield::announce_next_key validator exception ===")

    pk_bad = os.urandom(1184)
    announce_bad = compose_call(si, mev_pallet, "announce_next_key", {"public_key": "0x" + pk_bad.hex()})

    assert_pool_rejects(
        si,
        spammer,
        announce_bad,
        label=f"{mev_pallet}::announce_next_key signed by NON-validator {spammer.ss58_address}",
    )

    pk_good = os.urandom(1184)
    announce_good = compose_call(si, mev_pallet, "announce_next_key", {"public_key": "0x" + pk_good.hex()})

    _h_b, bn_b = assert_included_success(
        si,
        validator,
        announce_good,
        label=f"{mev_pallet}::announce_next_key signed by Aura validator {validator.ss58_address}",
        wait_for_finalization=args.finalize,
    )

    if bn_b <= bn_a:
        raise AssertionError(f"TEST B was included in block #{bn_b} which is not after TEST A block #{bn_a}")

    # Wait for at least one new block before test C (so C cannot land in B's block).
    nxt2 = wait_for_next_block(si, bn_b)
    print(f"[i] Advanced to head #{nxt2} before starting TEST C")

    # ------------------------------------------------------------------------------
    # TEST C: Normal dispatches are not blocked
    # ------------------------------------------------------------------------------
    print("\n=== TEST C: Normal dispatch is NOT blocked (System::remark) ===")

    remark_bytes = b"normal-dispatch-test:" + os.urandom(8)
    remark_call = compose_call(
        si,
        system_pallet,
        system_remark_fn,
        {"remark": "0x" + remark_bytes.hex()},
    )

    _h_c, bn_c = assert_included_success(
        si,
        spammer,
        remark_call,
        label=f"{system_pallet}::{system_remark_fn} signed by {spammer.ss58_address}",
        wait_for_finalization=args.finalize,
    )

    if bn_c <= bn_b:
        raise AssertionError(f"TEST C was included in block #{bn_c} which is not after TEST B block #{bn_b}")

    # Final summary / assertion
    print("\n[i] Block separation summary:")
    print(f"    TEST A included in block #{bn_a}")
    print(f"    TEST B included in block #{bn_b}")
    print(f"    TEST C included in block #{bn_c}")

    if not (bn_a < bn_b < bn_c):
        raise AssertionError("Expected strict block ordering: A < B < C")

    print(
        "\n✅ PASS: "
        "Operational spam is blocked (direct Root-only Operational rejected), "
        "sudo green path works, MevShield validator exception works, Normal dispatches "
        "are accepted and included, and each test ran in its own block."
    )


if __name__ == "__main__":
    main()
