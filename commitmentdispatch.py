#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
End-to-end assertions for the two active commitments checks:

  1) pool-time rejection from CommitmentsTransactionExtension
  2) dispatch-time rejection from Utility.batch([...])
  3) one valid direct Commitments.set_commitment success case

Why this version fixes the previous script
-----------------------------------------
The previous script tried to encode `info.fields` using `ResetBondsFlag` / empty-field shapes.
On this runtime, the robust working encode shape is a sized `RawN` payload, matching the
commitments pallet `Data` type metadata (`Raw0` .. `Raw128`) and a known-good compose example.

This script therefore uses a tiny raw payload and builds `info` as:

    {"fields": [[{"RawN": b"..."}]]}

with a few safe fallbacks around that exact shape.

What this proves
----------------
- A direct signed `Commitments.set_commitment` from an account that is NOT a
  registered hotkey on `netuid` is rejected before entering the pool.
- A `Utility.batch` wrapping `Commitments.set_commitment` bypasses the top-level
  transaction-extension pattern match (because the outer call is `Utility.batch`)
  and is then rejected at dispatch time when the inner call is dispatched.
- A direct signed `Commitments.set_commitment` from a hotkey that IS registered
  on `netuid` succeeds and writes `Commitments.CommitmentOf(netuid, hotkey)`.
"""

from __future__ import annotations

import argparse
import ast
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

from substrateinterface import Keypair, SubstrateInterface


DEFAULT_WS = "ws://127.0.0.1:9945"
PALLET_SUBTENSOR = "SubtensorModule"
PALLET_COMMITMENTS = "Commitments"
PALLET_UTILITY = "Utility"
PALLET_ADMIN = "AdminUtils"

VALID_COLD_FUNDS_TAO = 500.0
VALID_HOT_FUNDS_TAO = 5.0
INVALID_FUNDS_TAO = 5.0
BLOCK_SYNC_SLEEP_SEC = 0.15
COMMITMENT_PAYLOAD = b"commitment-e2e"  # len == 14 => Raw14


# ──────────────────────────────────────────────────────────────────────────────
# Generic helpers
# ──────────────────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(msg, flush=True)


def as_int(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    if isinstance(v, dict):
        for k in ("value", "bits", "index", "raw"):
            if k in v:
                return as_int(v[k])
        if v:
            return as_int(next(iter(v.values())))
        return 0
    if hasattr(v, "value"):
        return as_int(v.value)
    return int(v)


def simplify_error_message(raw: Any) -> str:
    if raw is None:
        return ""

    if isinstance(raw, (list, tuple)):
        parts = [simplify_error_message(x) for x in raw]
        parts = [p for p in parts if p]
        return " | ".join(parts)

    if isinstance(raw, dict):
        name = raw.get("name")
        docs = raw.get("docs")
        if name and docs:
            return f"{name} — {' '.join(str(d) for d in docs)}"
        if name:
            return str(name)
        for key in ("error", "dispatch_error", "dispatchError", "details", "value"):
            if key in raw:
                nested = simplify_error_message(raw[key])
                if nested:
                    return nested
        return str(raw)

    text = str(raw).strip()
    if not text:
        return ""

    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, (dict, list, tuple)):
            parsed_msg = simplify_error_message(parsed)
            if parsed_msg:
                return parsed_msg
    except Exception:
        pass

    return text


def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


def to_planck(tao: float, decimals: int) -> int:
    return int(round(tao * (10 ** decimals)))


def from_planck(value: int, decimals: int) -> float:
    return value / float(10 ** decimals)


def fmt_tao(value: int, decimals: int) -> str:
    return f"{from_planck(value, decimals):.9f} TAO"


def connect(ws: str) -> SubstrateInterface:
    substrate = SubstrateInterface(url=ws, auto_reconnect=True)
    substrate.init_runtime()
    return substrate


def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def safe_query(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
):
    return substrate.query(module, storage, params or [], block_hash=block_hash)


def safe_query_map(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    max_results: Optional[int] = None,
):
    return list(substrate.query_map(module, storage, params=params, max_results=max_results))


def submit(substrate: SubstrateInterface, signer: Keypair, call, sudo: bool = False):
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})

    xt = substrate.create_signed_extrinsic(call=call, keypair=signer)
    rec = substrate.submit_extrinsic(
        xt,
        wait_for_inclusion=True,
        wait_for_finalization=True,
    )
    if not rec.is_success:
        raise RuntimeError(
            f"Extrinsic failed in block {rec.block_hash}: {receipt_error_text(rec)}"
        )
    return rec


def submit_allow_failure(substrate: SubstrateInterface, signer: Keypair, call, sudo: bool = False):
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})

    xt = substrate.create_signed_extrinsic(call=call, keypair=signer)
    return substrate.submit_extrinsic(
        xt,
        wait_for_inclusion=True,
        wait_for_finalization=True,
    )


def produce_one_block(substrate: SubstrateInterface, signer: Keypair, tag: str):
    call = compose_call(substrate, "System", "remark", {"remark": bytes(tag, "utf-8")})
    rec = submit(substrate, signer, call, sudo=False)
    time.sleep(BLOCK_SYNC_SLEEP_SEC)
    return rec


def account_free(substrate: SubstrateInterface, ss58: str) -> int:
    info = safe_query(substrate, "System", "Account", [ss58]).value
    return int(info["data"]["free"])


def transfer_keep_alive(substrate: SubstrateInterface, signer: Keypair, dest_ss58: str, amount_planck: int):
    call = compose_call(
        substrate,
        "Balances",
        "transfer_keep_alive",
        {"dest": dest_ss58, "value": int(amount_planck)},
    )
    submit(substrate, signer, call, sudo=False)


def ensure_min_balance(substrate: SubstrateInterface, funder: Keypair, who: Keypair, min_tao: float, decimals: int):
    target = to_planck(min_tao, decimals)
    current = account_free(substrate, who.ss58_address)
    if current < target:
        transfer_keep_alive(substrate, funder, who.ss58_address, target - current)


# ──────────────────────────────────────────────────────────────────────────────
# Runtime/bootstrap helpers
# ──────────────────────────────────────────────────────────────────────────────

def networks_added(substrate: SubstrateInterface) -> List[int]:
    nets: List[int] = []
    try:
        for key, val in safe_query_map(substrate, PALLET_SUBTENSOR, "NetworksAdded"):
            if bool(val.value):
                kv = getattr(key, "value", key)
                try:
                    if isinstance(kv, int):
                        nets.append(int(kv))
                    elif isinstance(kv, dict) and kv:
                        nets.append(int(next(iter(kv.values()))))
                    else:
                        nets.append(int(str(kv)))
                except Exception:
                    pass
    except Exception:
        pass
    return sorted(set(nets))


def sudo_set_subnet_limit(substrate: SubstrateInterface, sudo: Keypair, max_subnets: int):
    candidates = [
        (PALLET_ADMIN, "sudo_set_subnet_limit", {"max_subnets": int(max_subnets)}),
        (PALLET_SUBTENSOR, "sudo_set_subnet_limit", {"max_subnets": int(max_subnets)}),
    ]
    last: Optional[Exception] = None
    for pallet, fn, params in candidates:
        try:
            call = compose_call(substrate, pallet, fn, params)
            submit(substrate, sudo, call, sudo=True)
            return
        except Exception as e:
            last = e
    if last is not None:
        raise last


def register_network(substrate: SubstrateInterface, signer: Keypair, owner_hot_ss58: str, owner_cold_ss58: str):
    candidates = [
        {"owner_hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"hotkey": owner_hot_ss58, "coldkey": owner_cold_ss58},
        {"owner_hot": owner_hot_ss58, "owner_cold": owner_cold_ss58},
    ]
    last: Optional[Exception] = None
    for params in candidates:
        try:
            call = compose_call(substrate, PALLET_SUBTENSOR, "register_network", params)
            return submit(substrate, signer, call, sudo=False)
        except Exception as e:
            last = e
    if last is not None:
        raise RuntimeError(f"register_network failed with all known parameter shapes: {last}")
    raise RuntimeError("register_network failed")


def ensure_netuid_exists(substrate: SubstrateInterface, sudo: Keypair, netuid: int, decimals: int) -> None:
    if netuid == 0:
        raise RuntimeError("Please use a non-root subnet netuid for this commitments test.")

    existing = set(n for n in networks_added(substrate) if n != 0)
    if netuid in existing:
        return

    desired_limit = max(netuid + 4, len(existing) + 4)
    try:
        sudo_set_subnet_limit(substrate, sudo, desired_limit)
    except Exception as e:
        log(f"ℹ️ Could not raise subnet limit automatically: {simplify_error_message(e)}")

    attempts = 0
    max_attempts = max(8, netuid + 8)
    while netuid not in existing:
        if attempts >= max_attempts:
            raise RuntimeError(f"Failed to create netuid {netuid}; existing={sorted(existing)}")

        owner_cold = Keypair.create_from_uri(f"//Alice//CommitmentsNetOwnerCold//{netuid}//{attempts}")
        owner_hot = Keypair.create_from_uri(f"//Alice//CommitmentsNetOwnerHot//{netuid}//{attempts}")
        ensure_min_balance(substrate, sudo, owner_cold, 5_000.0, decimals)
        ensure_min_balance(substrate, sudo, owner_hot, 5.0, decimals)
        register_network(substrate, owner_cold, owner_hot.ss58_address, owner_cold.ss58_address)
        existing = set(n for n in networks_added(substrate) if n != 0)
        attempts += 1

    log(f"✅ Ensured netuid {netuid} exists")


def registration_allowed(substrate: SubstrateInterface, netuid: int) -> bool:
    try:
        return bool(safe_query(substrate, PALLET_SUBTENSOR, "NetworkRegistrationAllowed", [netuid]).value)
    except Exception:
        return True


def sudo_set_registration_allowed(substrate: SubstrateInterface, sudo: Keypair, netuid: int, allowed: bool):
    candidates = [
        (PALLET_ADMIN, "sudo_set_network_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_ADMIN, "sudo_set_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_SUBTENSOR, "sudo_set_network_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_SUBTENSOR, "sudo_set_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
    ]
    last: Optional[Exception] = None
    for pallet, fn, params in candidates:
        try:
            call = compose_call(substrate, pallet, fn, params)
            submit(substrate, sudo, call, sudo=True)
            return
        except Exception as e:
            last = e
    if last is not None:
        raise last


def ensure_registration_allowed(substrate: SubstrateInterface, sudo: Keypair, netuid: int):
    if not registration_allowed(substrate, netuid):
        sudo_set_registration_allowed(substrate, sudo, netuid, True)
        produce_one_block(substrate, sudo, f"enable-registration-{netuid}")


def burn_for_netuid(substrate: SubstrateInterface, netuid: int) -> int:
    for storage in ("Burn", "NeuronBurn", "RegistrationBurn", "SubnetBurn", "BurnCost"):
        try:
            res = safe_query(substrate, PALLET_SUBTENSOR, storage, [netuid])
            if res is not None and res.value is not None:
                return as_int(res.value)
        except Exception:
            pass
    return 0


def hotkey_uid(substrate: SubstrateInterface, netuid: int, hot_ss58: str) -> Optional[int]:
    res = safe_query(substrate, PALLET_SUBTENSOR, "Uids", [netuid, hot_ss58])
    if res is None or res.value is None:
        return None
    return as_int(res.value)


def hotkey_registered_on_network(substrate: SubstrateInterface, netuid: int, hot_ss58: str) -> bool:
    return hotkey_uid(substrate, netuid, hot_ss58) is not None


def burned_register(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int):
    call = compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "burned_register",
        {"netuid": int(netuid), "hotkey": hot_ss58},
    )
    return submit(substrate, cold, call, sudo=False)


# ──────────────────────────────────────────────────────────────────────────────
# Commitments / batch helpers
# ──────────────────────────────────────────────────────────────────────────────

def build_raw_data_candidates(payload: bytes) -> List[Any]:
    """
    Working shape observed in a successful compose example:

        {"info": {"fields": [[{"Raw121": b"..."}]]}}

    So we try that exact structure first, then a couple of nearby fallbacks.
    """
    raw_variant = f"Raw{len(payload)}"
    return [
        {"fields": [[{raw_variant: payload}]]},
        {"fields": [{raw_variant: payload}]},
        {"fields": [[{raw_variant: list(payload)}]]},
        {"fields": [{raw_variant: list(payload)}]},
    ]


def compose_set_commitment_call(substrate: SubstrateInterface, netuid: int, payload: bytes = COMMITMENT_PAYLOAD):
    errors: List[str] = []
    for info in build_raw_data_candidates(payload):
        try:
            return compose_call(
                substrate,
                PALLET_COMMITMENTS,
                "set_commitment",
                {
                    "netuid": int(netuid),
                    "info": info,
                },
            )
        except Exception as e:
            errors.append(f"info={info!r} -> {e}")

    joined = "\n  - ".join(errors)
    raise RuntimeError(
        "Could not compose Commitments.set_commitment with any known RawN info shape. "
        f"Tried:\n  - {joined}"
    )


def compose_batch_call(substrate: SubstrateInterface, calls: Sequence[Any]):
    return compose_call(substrate, PALLET_UTILITY, "batch", {"calls": list(calls)})


def commitment_of(substrate: SubstrateInterface, netuid: int, who_ss58: str):
    return safe_query(substrate, PALLET_COMMITMENTS, "CommitmentOf", [netuid, who_ss58]).value


def assert_storage_absent(substrate: SubstrateInterface, netuid: int, who_ss58: str, label: str):
    if commitment_of(substrate, netuid, who_ss58) is not None:
        raise AssertionError(
            f"{label}: expected Commitments.CommitmentOf({netuid}, {who_ss58}) to be empty"
        )


def assert_storage_present(substrate: SubstrateInterface, netuid: int, who_ss58: str, label: str):
    value = commitment_of(substrate, netuid, who_ss58)
    if value is None:
        raise AssertionError(
            f"{label}: expected Commitments.CommitmentOf({netuid}, {who_ss58}) to be present"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Receipt / error extraction helpers
# ──────────────────────────────────────────────────────────────────────────────

def _flatten_any(raw: Any) -> List[str]:
    out: List[str] = []
    seen: set[int] = set()

    def walk(value: Any) -> None:
        ident = id(value)
        if ident in seen:
            return
        seen.add(ident)

        if value is None:
            return

        if isinstance(value, (str, int, float, bool)):
            out.append(str(value))
            return

        if isinstance(value, dict):
            for k, v in value.items():
                out.append(str(k))
                walk(v)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
            return

        for attr in ("value", "params", "event", "event_module", "name", "docs", "error_message"):
            if hasattr(value, attr):
                try:
                    walk(getattr(value, attr))
                except Exception:
                    pass

        try:
            out.append(str(value))
        except Exception:
            pass

    walk(raw)
    return [x for x in out if x]


def receipt_error_text(receipt: Any) -> str:
    texts: List[str] = []

    try:
        msg = simplify_error_message(getattr(receipt, "error_message", None))
        if msg:
            texts.append(msg)
    except Exception:
        pass

    try:
        for event in getattr(receipt, "triggered_events", []) or []:
            texts.extend(_flatten_any(event))
    except Exception:
        pass

    joined = " | ".join(simplify_error_message(t) for t in texts if t)
    return joined.strip()


def assert_text_contains_any(text: str, expected_fragments: Iterable[str], label: str):
    text_l = text.lower()
    fragments = [frag.lower() for frag in expected_fragments]
    if not any(frag in text_l for frag in fragments):
        raise AssertionError(
            f"{label}: expected one of {list(expected_fragments)} in error text, got: {text}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Assertions for the two extensions + valid pass case
# ──────────────────────────────────────────────────────────────────────────────

def submit_expect_pool_reject(
    substrate: SubstrateInterface,
    signer: Keypair,
    call,
    expected_fragments: Iterable[str],
    label: str,
) -> str:
    try:
        xt = substrate.create_signed_extrinsic(call=call, keypair=signer)
        rec = substrate.submit_extrinsic(
            xt,
            wait_for_inclusion=True,
            wait_for_finalization=True,
        )
    except Exception as e:
        msg = simplify_error_message(e)
        assert_text_contains_any(msg, expected_fragments, label)
        return msg

    msg = receipt_error_text(rec)
    if not getattr(rec, "is_success", False):
        assert_text_contains_any(msg, expected_fragments, label)
        return msg

    raise AssertionError(
        f"{label}: expected pool-time rejection, but extrinsic reached the chain. "
        f"Receipt success={getattr(rec, 'is_success', None)} block={getattr(rec, 'block_hash', None)}"
    )


def submit_expect_batched_dispatch_error(
    substrate: SubstrateInterface,
    signer: Keypair,
    call,
    expected_error_fragments: Iterable[str],
    label: str,
) -> str:
    try:
        rec = submit_allow_failure(substrate, signer, call, sudo=False)
    except Exception as e:
        msg = simplify_error_message(e)
        assert_text_contains_any(msg, expected_error_fragments, label)
        return msg

    msg = receipt_error_text(rec)

    if not getattr(rec, "is_success", True):
        assert_text_contains_any(msg, expected_error_fragments, label)
        return msg

    assert_text_contains_any(
        msg,
        ["BatchInterrupted", "ItemFailed", "batch interrupted", "item failed"],
        label,
    )
    assert_text_contains_any(msg, expected_error_fragments, label)
    return msg


# ──────────────────────────────────────────────────────────────────────────────
# Main test flow
# ──────────────────────────────────────────────────────────────────────────────

def run_test(ws: str, netuid: int, tag: str) -> None:
    substrate = connect(ws)
    decimals = token_decimals(substrate)
    alice = Keypair.create_from_uri("//Alice")

    ensure_netuid_exists(substrate, alice, netuid, decimals)
    ensure_registration_allowed(substrate, alice, netuid)

    invalid_actor = Keypair.create_from_uri(f"//Alice//CommitInvalidActor//{tag}")
    valid_cold = Keypair.create_from_uri(f"//Alice//CommitValidCold//{tag}")
    valid_hot = Keypair.create_from_uri(f"//Alice//CommitValidHot//{tag}")

    ensure_min_balance(substrate, alice, invalid_actor, INVALID_FUNDS_TAO, decimals)
    ensure_min_balance(substrate, alice, valid_cold, VALID_COLD_FUNDS_TAO, decimals)
    ensure_min_balance(substrate, alice, valid_hot, VALID_HOT_FUNDS_TAO, decimals)

    log("━" * 96)
    log(f"Testing netuid={netuid} on {ws}")
    log(f"Current burn: {fmt_tao(burn_for_netuid(substrate, netuid), decimals)}")
    log(f"invalid_actor = {invalid_actor.ss58_address}")
    log(f"valid_cold = {valid_cold.ss58_address}")
    log(f"valid_hot = {valid_hot.ss58_address}")
    log(f"commitment payload = {COMMITMENT_PAYLOAD!r} (Raw{len(COMMITMENT_PAYLOAD)})")
    log("━" * 96)

    if hotkey_registered_on_network(substrate, netuid, invalid_actor.ss58_address):
        raise RuntimeError(
            "The chosen invalid_actor is already registered on the target subnet; pick a new --tag."
        )
    if hotkey_registered_on_network(substrate, netuid, valid_hot.ss58_address):
        raise RuntimeError(
            "The chosen valid_hot is already registered on the target subnet; pick a new --tag."
        )

    direct_invalid_call = compose_set_commitment_call(substrate, netuid)

    log("\n[1/3] Expecting pool-time rejection from CommitmentsTransactionExtension …")
    pool_error = submit_expect_pool_reject(
        substrate=substrate,
        signer=invalid_actor,
        call=direct_invalid_call,
        expected_fragments=[
            "BadSigner",
            "Invalid Transaction",
            "1010",
            "bad signer",
            "Invalid signing address",
        ],
        label="direct invalid set_commitment",
    )
    assert_storage_absent(substrate, netuid, invalid_actor.ss58_address, "direct invalid set_commitment")
    log(f"✅ Pool rejected the direct invalid commitment as expected: {pool_error}")

    log("\n[2/3] Expecting dispatch-time rejection from Utility.batch(Commitments.set_commitment) …")
    batched_inner = compose_set_commitment_call(substrate, netuid)
    batch_call = compose_batch_call(substrate, [batched_inner])
    batch_error = submit_expect_batched_dispatch_error(
        substrate=substrate,
        signer=invalid_actor,
        call=batch_call,
        expected_error_fragments=["AccountNotAllowedCommit"],
        label="batched invalid set_commitment",
    )
    assert_storage_absent(substrate, netuid, invalid_actor.ss58_address, "batched invalid set_commitment")
    log(f"✅ Batched invalid commitment failed in dispatch as expected: {batch_error}")

    log("\n[3/3] Registering a valid hotkey and expecting a successful direct commitment …")
    burned_register(substrate, valid_cold, valid_hot.ss58_address, netuid)
    produce_one_block(substrate, alice, f"post-register-{tag}")

    if not hotkey_registered_on_network(substrate, netuid, valid_hot.ss58_address):
        raise AssertionError(
            "burned_register succeeded but the hotkey is not registered on the target subnet"
        )

    valid_commit_call = compose_set_commitment_call(substrate, netuid)
    valid_rec = submit(substrate, valid_hot, valid_commit_call, sudo=False)
    assert_storage_present(substrate, netuid, valid_hot.ss58_address, "valid direct set_commitment")
    log(f"✅ Valid direct commitment succeeded in block {valid_rec.block_hash}")

    log("\n🎉 All three assertions passed:")
    log("   1) tx extension rejected the direct invalid signer before pool admission")
    log("   2) Utility.batch exercised the dispatch-time path and rejected the inner invalid commitment")
    log("   3) a registered hotkey successfully committed metadata")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="E2E test for CommitmentsTransactionExtension + batch-based dispatch rejection"
    )
    parser.add_argument(
        "--ws",
        default=DEFAULT_WS,
        help=f"WebSocket endpoint (default: {DEFAULT_WS})",
    )
    parser.add_argument(
        "--netuid",
        type=int,
        default=1,
        help="Non-root subnet to test (default: 1)",
    )
    parser.add_argument(
        "--tag",
        default=str(int(time.time())),
        help="Unique suffix for generated test keypairs (default: current unix timestamp)",
    )
    args = parser.parse_args()

    try:
        run_test(ws=args.ws, netuid=args.netuid, tag=args.tag)
    except Exception as e:
        log(f"\n❌ Test failed: {simplify_error_message(e)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nInterrupted.")
        sys.exit(130)