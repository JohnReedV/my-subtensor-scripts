#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic burned_register pricing test for continuous per-block exponential decay,
run stage-by-stage across multiple subnets concurrently, including automatic
creation of missing requested subnets and a limit-price registration scenario.

Runtime behavior mirrored by this script
----------------------------------------
At on_initialize(current_block):

  1) if BurnHalfLife > 0 and current_block > 1:
       burn *= factor_q32
     where factor_q32 is the largest Q32 value such that:
       factor_q32 ^ BurnHalfLife <= 0.5

  2) interval bookkeeping only:
       last_completed_block = current_block - 1
       intervals_passed =
         (last_completed_block - BurnLastHalvingBlock) / BurnHalfLife

     if intervals_passed > 0:
       BurnLastHalvingBlock += intervals_passed * BurnHalfLife
       RegistrationsThisInterval = 0

  3) if RegistrationsThisBlock from the previous block > 0:
       burn *= BurnIncreaseMult ^ regs_prev_block

  4) RegistrationsThisBlock = 0

Scenarios per network
---------------------
Optional) Default-parameter stress scenario:
   - runs only if --with-default-stress is passed
   - does NOT modify BurnHalfLife or BurnIncreaseMult
   - performs many sequential burned_register calls within the active default interval
   - verifies dynamic burn behavior block by block
   - verifies post-registration bump
   - finishes only the current interval boundary afterward
   - uses a soft burn cap + graceful funding fallback so multi-subnet runs stay stable

1) Default-parameter limit-price scenario:
   - first submits register_limit with limit_price=0 and asserts failure
   - then submits register_limit with a permissive limit and asserts success
   - verifies post-registration bump

2) BurnHalfLife=4, BurnIncreaseMult=2
3) BurnHalfLife=8, BurnIncreaseMult=3

Usage
-----
    python3 neuronreg.py
    python3 neuronreg.py --netuid 1
    python3 neuronreg.py --netuids 1,2,3
    python3 neuronreg.py --netuids 1,2,3 --workers 3
    python3 neuronreg.py --netuids 1,2,3 --with-default-stress
"""

import sys
import time
import ast
import argparse
import traceback
from dataclasses import dataclass, replace
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Sequence, Tuple, Callable

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
DEFAULT_WS = "ws://127.0.0.1:9945"

TEST_CONFIGS: List[Tuple[int, int]] = [
    (4, 2),
    (8, 3),
]

STRESS_TARGET_TOTAL_REGS = 20
EST_BLOCKS_PER_REGISTRATION = 4
NEXT_REG_BALANCE_SAFETY_MULT = 4
NEXT_REG_BALANCE_BUFFER_TAO = 25.0
MIN_FUNDS_TAO_REG_COLD = 500.0

# Keep optional multi-subnet stress runs from blowing up Alice's balance.
STRESS_SOFT_MAX_BURN_TAO = 500.0
MIN_ONE_REG_BUFFER_TAO = 1.0

REGISTER_NETWORK_MIN_OWNER_COLD_TAO = 5000.0
REGISTER_NETWORK_MIN_OWNER_HOT_TAO = 5.0

PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"

U64_MAX = (1 << 64) - 1
ONE_Q32 = 1 << 32
HALF_Q32 = 1 << 31

STAGE_RETRY_ATTEMPTS = 3

ALICE_LOCK = Lock()
PRINT_LOCK = Lock()


# ─────────────────────────────────────────────────────────────
# Context
# ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class NetworkContext:
    ws: str
    netuid: int
    decimals: int
    run_nonce: int
    payer_uri: str


# ─────────────────────────────────────────────────────────────
# Logging helpers
# ─────────────────────────────────────────────────────────────
def safe_print(msg: str):
    with PRINT_LOCK:
        print(msg, flush=True)


def make_logger(netuid: int):
    def _log(msg: str):
        lines = str(msg).splitlines() or [""]
        with PRINT_LOCK:
            for line in lines:
                print(f"[net {netuid}] {line}", flush=True)
    return _log


def short_ss58(ss58: str) -> str:
    return f"{ss58[:6]}…{ss58[-6:]}" if len(ss58) > 16 else ss58


def scenario_banner(log, title: str, subtitle: Optional[str] = None):
    line = "━" * 92
    log(line)
    log(title)
    if subtitle:
        log(subtitle)
    log(line)


def simplify_error_message(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, dict):
        name = raw.get("name")
        docs = raw.get("docs")
        if name and docs:
            return f"{name} — {' '.join(str(d) for d in docs)}"
        if name:
            return str(name)
        return str(raw)

    text = str(raw).strip()
    if not text:
        return ""
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, dict):
            return simplify_error_message(parsed)
    except Exception:
        pass
    return text


def is_retryable_transport_error(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = [
        "broken pipe",
        "connection reset",
        "connection aborted",
        "connection closed",
        "websocketconnectionclosed",
        "cannot write to closing transport",
        "closing transport",
        "transport endpoint is not connected",
        "remote host closed",
        "connection to remote host was lost",
        "connection lost",
        "eof occurred",
        "timed out",
        "timeout",
    ]
    return any(marker in text for marker in markers)


def format_state(
    label: str,
    block: int,
    burn: int,
    anchor: int,
    regs: int,
    decimals: int,
    subnetwork_n: Optional[int] = None,
    icon: str = "🔹",
) -> str:
    parts = [
        f"{icon} {label:<10}",
        f"blk {block:<5}",
        f"burn {fmt_tao(burn, decimals):>15}",
        f"anchor {anchor:<6}",
        f"regs {regs}",
    ]
    if subnetwork_n is not None:
        parts.append(f"n {subnetwork_n}")
    return " │ ".join(parts)


def should_log_progress(idx: int, total: int) -> bool:
    if idx <= 3 or idx == total:
        return True
    if total >= 10 and idx % 5 == 0:
        return True
    return False


def should_log_decay_step(step: int, total_steps: int) -> bool:
    key_steps = {
        1,
        total_steps,
        max(1, total_steps // 4),
        max(1, total_steps // 2),
        max(1, (3 * total_steps) // 4),
    }
    return step in key_steps


# ─────────────────────────────────────────────────────────────
# Substrate helpers
# ─────────────────────────────────────────────────────────────
def connect(ws: str) -> SubstrateInterface:
    return SubstrateInterface(url=ws)


def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


def to_planck(tao: float, decimals: int) -> int:
    return int(round(tao * (10 ** decimals)))


def from_planck(p: int, decimals: int) -> float:
    return p / float(10 ** decimals)


def fmt_tao(p: int, decimals: int) -> str:
    return f"{from_planck(p, decimals):.9f} TAO"


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


def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def submit(substrate: SubstrateInterface, signer: Keypair, call, sudo: bool = False):
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})

    xt = substrate.create_signed_extrinsic(call=call, keypair=signer)
    try:
        rec = substrate.submit_extrinsic(
            xt,
            wait_for_inclusion=True,
            wait_for_finalization=True,
        )
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e

    if not rec.is_success:
        raise RuntimeError(f"Extrinsic failed in block {rec.block_hash}: {rec.error_message}")
    return rec


def submit_allow_failure(substrate: SubstrateInterface, signer: Keypair, call, sudo: bool = False):
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})

    xt = substrate.create_signed_extrinsic(call=call, keypair=signer)
    try:
        rec = substrate.submit_extrinsic(
            xt,
            wait_for_inclusion=True,
            wait_for_finalization=True,
        )
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e
    return rec


def q_int(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
) -> int:
    try:
        res = substrate.query(module, storage, params or [], block_hash=block_hash)
        if res is None:
            return 0
        return as_int(res.value)
    except Exception:
        return 0


def account_free(substrate: SubstrateInterface, ss58: str) -> int:
    info = substrate.query("System", "Account", [ss58]).value
    return int(info["data"]["free"])


def transfer_keep_alive(substrate: SubstrateInterface, signer: Keypair, dest_ss58: str, amount_planck: int):
    call = compose_call(substrate, "Balances", "transfer_keep_alive", {"dest": dest_ss58, "value": int(amount_planck)})
    submit(substrate, signer, call, sudo=False)


def ensure_min_balance(substrate: SubstrateInterface, funder: Keypair, who: Keypair, min_tao: float, decimals: int):
    tgt = to_planck(min_tao, decimals)
    cur = account_free(substrate, who.ss58_address)
    if cur < tgt:
        with ALICE_LOCK:
            cur2 = account_free(substrate, who.ss58_address)
            if cur2 < tgt:
                transfer_keep_alive(substrate, funder, who.ss58_address, tgt - cur2)


def try_prepare_next_registration_balance(
    substrate: SubstrateInterface,
    funder: Keypair,
    who: Keypair,
    reference_burn_planck: int,
    decimals: int,
    safety_mult: int = NEXT_REG_BALANCE_SAFETY_MULT,
    buffer_tao: float = NEXT_REG_BALANCE_BUFFER_TAO,
    min_one_reg_buffer_tao: float = MIN_ONE_REG_BUFFER_TAO,
) -> Tuple[bool, int, str]:
    """
    Best-effort top-up for the next registration.

    Returns:
      (ready, free_balance_after_attempt, message)

    `ready=True` means the payer should still be able to afford at least one
    more registration (plus a small buffer), even if the full top-up target
    could not be reached.
    """
    target = int(reference_burn_planck) * int(max(1, safety_mult)) + to_planck(buffer_tao, decimals)
    min_required = int(reference_burn_planck) + to_planck(min_one_reg_buffer_tao, decimals)

    cur = account_free(substrate, who.ss58_address)
    if cur >= target:
        return True, cur, ""

    msg = ""
    try:
        with ALICE_LOCK:
            cur2 = account_free(substrate, who.ss58_address)
            if cur2 < target:
                transfer_keep_alive(substrate, funder, who.ss58_address, target - cur2)
    except Exception as e:
        msg = simplify_error_message(str(e))

    cur_after = account_free(substrate, who.ss58_address)
    if cur_after >= min_required:
        return True, cur_after, msg

    if not msg:
        msg = (
            f"insufficient payer funding after top-up attempt "
            f"(have {fmt_tao(cur_after, decimals)}, need at least {fmt_tao(min_required, decimals)})"
        )
    return False, cur_after, msg


def ensure_balance_for_next_registration(
    substrate: SubstrateInterface,
    funder: Keypair,
    who: Keypair,
    reference_burn_planck: int,
    decimals: int,
    safety_mult: int = NEXT_REG_BALANCE_SAFETY_MULT,
    buffer_tao: float = NEXT_REG_BALANCE_BUFFER_TAO,
):
    ok, cur_after, msg = try_prepare_next_registration_balance(
        substrate=substrate,
        funder=funder,
        who=who,
        reference_burn_planck=reference_burn_planck,
        decimals=decimals,
        safety_mult=safety_mult,
        buffer_tao=buffer_tao,
    )
    if not ok:
        raise RuntimeError(msg or f"could not prepare payer balance; current={fmt_tao(cur_after, decimals)}")


def produce_one_block(substrate: SubstrateInterface, signer: Keypair, tag: str):
    call = compose_call(substrate, "System", "remark", {"remark": bytes(tag, "utf-8")})
    return submit(substrate, signer, call, sudo=False)


def produce_n_blocks(substrate: SubstrateInterface, signer: Keypair, n: int, tag_prefix: str):
    receipts = []
    for i in range(n):
        receipts.append(produce_one_block(substrate, signer, f"{tag_prefix}-{i}"))
        time.sleep(0.05)
    return receipts


def block_number_at(substrate: SubstrateInterface, block_hash: str) -> int:
    return q_int(substrate, "System", "Number", [], block_hash=block_hash)


def open_network(ctx: NetworkContext):
    substrate = connect(ctx.ws)
    sudo = Keypair.create_from_uri("//Alice")
    reg_cold = Keypair.create_from_uri(ctx.payer_uri)
    log = make_logger(ctx.netuid)
    return substrate, sudo, reg_cold, log


# ─────────────────────────────────────────────────────────────
# Chain queries
# ─────────────────────────────────────────────────────────────
def burn_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    v = q_int(substrate, PALLET_SUBTENSOR, "Burn", [netuid], block_hash=block_hash)
    if v != 0:
        return v
    for alt in ("NeuronBurn", "RegistrationBurn", "SubnetBurn", "BurnCost"):
        vv = q_int(substrate, PALLET_SUBTENSOR, alt, [netuid], block_hash=block_hash)
        if vv != 0:
            return vv
    return 0


def min_burn_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    v = q_int(substrate, PALLET_SUBTENSOR, "MinBurn", [netuid], block_hash=block_hash)
    if v != 0:
        return v
    return q_int(substrate, PALLET_SUBTENSOR, "MinBurn", [], block_hash=block_hash)


def max_burn_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    v = q_int(substrate, PALLET_SUBTENSOR, "MaxBurn", [netuid], block_hash=block_hash)
    if v != 0:
        return v
    return q_int(substrate, PALLET_SUBTENSOR, "MaxBurn", [], block_hash=block_hash)


def burn_half_life_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    return q_int(substrate, PALLET_SUBTENSOR, "BurnHalfLife", [netuid], block_hash=block_hash)


def burn_increase_mult_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    return q_int(substrate, PALLET_SUBTENSOR, "BurnIncreaseMult", [netuid], block_hash=block_hash)


def burn_last_halving_block_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    return q_int(substrate, PALLET_SUBTENSOR, "BurnLastHalvingBlock", [netuid], block_hash=block_hash)


def regs_this_block_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    return q_int(substrate, PALLET_SUBTENSOR, "RegistrationsThisBlock", [netuid], block_hash=block_hash)


def subnetwork_n_at(substrate: SubstrateInterface, netuid: int, block_hash: Optional[str] = None) -> int:
    return q_int(substrate, PALLET_SUBTENSOR, "SubnetworkN", [netuid], block_hash=block_hash)


def max_allowed_uids_at(substrate: SubstrateInterface, netuid: int, block_hash: Optional[str] = None) -> int:
    return q_int(substrate, PALLET_SUBTENSOR, "MaxAllowedUids", [netuid], block_hash=block_hash)


def hotkey_uid_at(
    substrate: SubstrateInterface,
    netuid: int,
    hot_ss58: str,
    block_hash: Optional[str] = None,
) -> Optional[int]:
    try:
        res = substrate.query(PALLET_SUBTENSOR, "Uids", [netuid, hot_ss58], block_hash=block_hash)
        if res is None or res.value is None:
            return None
        return as_int(res.value)
    except Exception:
        return None


def hotkey_registered_on_network_at(
    substrate: SubstrateInterface,
    netuid: int,
    hot_ss58: str,
    block_hash: Optional[str] = None,
) -> bool:
    return hotkey_uid_at(substrate, netuid, hot_ss58, block_hash) is not None


def registration_allowed_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> bool:
    try:
        res = substrate.query(PALLET_SUBTENSOR, "NetworkRegistrationAllowed", [netuid], block_hash=block_hash)
        return bool(res.value)
    except Exception:
        return True


def networks_added(substrate: SubstrateInterface) -> List[int]:
    nets: List[int] = []
    try:
        for key, val in substrate.query_map(PALLET_SUBTENSOR, "NetworksAdded"):
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


def network_exists(substrate: SubstrateInterface, netuid: int) -> bool:
    try:
        res = substrate.query(PALLET_SUBTENSOR, "NetworksAdded", [netuid])
        if res is not None and res.value is not None:
            return bool(res.value)
    except Exception:
        pass
    return netuid in networks_added(substrate)


def read_net_state(substrate: SubstrateInterface, netuid: int, block_hash: str) -> Dict[str, int]:
    block = block_number_at(substrate, block_hash)
    return {
        "hash": block_hash,
        "block": block,
        "burn": burn_at(substrate, netuid, block_hash),
        "anchor": burn_last_halving_block_at(substrate, netuid, block_hash),
        "regs": regs_this_block_at(substrate, netuid, block_hash),
        "n": subnetwork_n_at(substrate, netuid, block_hash),
    }


# ─────────────────────────────────────────────────────────────
# Admin setters
# ─────────────────────────────────────────────────────────────
def sudo_set_network_rate_limit(substrate: SubstrateInterface, sudo: Keypair, rate_limit: int):
    with ALICE_LOCK:
        for pallet in (PALLET_ADMIN, PALLET_SUBTENSOR):
            try:
                call = compose_call(substrate, pallet, "sudo_set_network_rate_limit", {"rate_limit": int(rate_limit)})
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception:
                continue


def sudo_set_registration_allowed(substrate: SubstrateInterface, sudo: Keypair, netuid: int, allowed: bool):
    candidates = [
        (PALLET_ADMIN, "sudo_set_network_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_ADMIN, "sudo_set_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_SUBTENSOR, "sudo_set_network_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_SUBTENSOR, "sudo_set_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn, params in candidates:
            try:
                call = compose_call(substrate, pallet, fn, params)
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    if last is not None:
        raise last


def sudo_set_burn_half_life(substrate: SubstrateInterface, sudo: Keypair, netuid: int, burn_half_life: int):
    candidates = [
        (PALLET_ADMIN, "sudo_set_burn_half_life"),
        (PALLET_SUBTENSOR, "sudo_set_burn_half_life"),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn in candidates:
            try:
                call = compose_call(substrate, pallet, fn, {"netuid": int(netuid), "burn_half_life": int(burn_half_life)})
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    raise RuntimeError(f"Failed to set BurnHalfLife via any known pallet: {last}")


def sudo_set_burn_increase_mult(substrate: SubstrateInterface, sudo: Keypair, netuid: int, burn_increase_mult: int):
    candidates = [
        (PALLET_ADMIN, "sudo_set_burn_increase_mult"),
        (PALLET_SUBTENSOR, "sudo_set_burn_increase_mult"),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn in candidates:
            try:
                call = compose_call(substrate, pallet, fn, {"netuid": int(netuid), "burn_increase_mult": int(burn_increase_mult)})
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    raise RuntimeError(f"Failed to set BurnIncreaseMult via any known pallet: {last}")


def sudo_set_subnet_limit(substrate: SubstrateInterface, sudo: Keypair, max_subnets: int):
    candidates = [
        (PALLET_ADMIN, "sudo_set_subnet_limit", {"max_subnets": int(max_subnets)}),
        (PALLET_SUBTENSOR, "sudo_set_subnet_limit", {"max_subnets": int(max_subnets)}),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn, params in candidates:
            try:
                call = compose_call(substrate, pallet, fn, params)
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    raise RuntimeError(f"Failed to set subnet limit via any known pallet: {last}")


# ─────────────────────────────────────────────────────────────
# Registration extrinsics
# ─────────────────────────────────────────────────────────────
def burned_register(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int):
    call = compose_call(substrate, PALLET_SUBTENSOR, "burned_register", {"netuid": int(netuid), "hotkey": hot_ss58})
    return submit(substrate, cold, call, sudo=False)


def burned_register_with_retry(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    last = None
    for i in range(1, max_attempts + 1):
        try:
            return burned_register(substrate, cold, hot_ss58, netuid)
        except Exception as e:
            last = e
            s = str(e).lower()
            if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                produce_n_blocks(substrate, cold, backoff_blocks, "reg-backoff")
                continue
            raise
    if last is not None:
        raise last
    raise RuntimeError("burned_register_with_retry failed unexpectedly")


def register_limit(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int, limit_price: int):
    call = compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "register_limit",
        {
            "netuid": int(netuid),
            "hotkey": hot_ss58,
            "limit_price": int(limit_price),
        },
    )
    return submit(substrate, cold, call, sudo=False)


def register_limit_allow_failure(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    limit_price: int,
):
    call = compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "register_limit",
        {
            "netuid": int(netuid),
            "hotkey": hot_ss58,
            "limit_price": int(limit_price),
        },
    )
    return submit_allow_failure(substrate, cold, call, sudo=False)


def register_limit_with_retry(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    limit_price: int,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    last = None
    for i in range(1, max_attempts + 1):
        try:
            return register_limit(substrate, cold, hot_ss58, netuid, limit_price)
        except Exception as e:
            last = e
            s = str(e).lower()
            if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                produce_n_blocks(substrate, cold, backoff_blocks, "reg-limit-backoff")
                continue
            raise
    if last is not None:
        raise last
    raise RuntimeError("register_limit_with_retry failed unexpectedly")


def register_network(
    substrate: SubstrateInterface,
    signer: Keypair,
    owner_hot_ss58: str,
    owner_cold_ss58: str,
):
    candidates = [
        {"owner_hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"hotkey": owner_hot_ss58, "coldkey": owner_cold_ss58},
        {"owner_hot": owner_hot_ss58, "owner_cold": owner_cold_ss58},
    ]
    last = None
    for params in candidates:
        try:
            call = compose_call(substrate, PALLET_SUBTENSOR, "register_network", params)
            return submit(substrate, signer, call, sudo=False)
        except Exception as e:
            last = e
    raise RuntimeError(f"register_network failed with all candidates: {last}")


def register_network_with_retry(
    substrate: SubstrateInterface,
    signer: Keypair,
    owner_hot_ss58: str,
    owner_cold_ss58: str,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    last = None
    for i in range(1, max_attempts + 1):
        try:
            return register_network(substrate, signer, owner_hot_ss58, owner_cold_ss58)
        except Exception as e:
            last = e
            s = str(e).lower()
            if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                produce_n_blocks(substrate, signer, backoff_blocks, "register-network-backoff")
                continue
            raise
    if last is not None:
        raise last
    raise RuntimeError("register_network_with_retry failed unexpectedly")


# ─────────────────────────────────────────────────────────────
# Exact integer math helpers mirroring the runtime
# ─────────────────────────────────────────────────────────────
def sat_add_u64(a: int, b: int) -> int:
    a = max(0, int(a))
    b = max(0, int(b))
    s = a + b
    return U64_MAX if s > U64_MAX else s


def sat_mul_u64(a: int, b: int) -> int:
    a = max(0, int(a))
    b = max(0, int(b))
    p = a * b
    return U64_MAX if p > U64_MAX else p


def sat_pow_u64(base: int, exp: int) -> int:
    result = 1
    factor = max(0, int(base))
    power = max(0, int(exp))
    while power > 0:
        if (power & 1) == 1:
            result = sat_mul_u64(result, factor)
        power >>= 1
        if power > 0:
            factor = sat_mul_u64(factor, factor)
    return result


def mul_by_q32(value: int, factor_q32: int) -> int:
    value = max(0, int(value))
    factor_q32 = max(0, int(factor_q32))
    product = value * factor_q32
    shifted = product >> 32
    return U64_MAX if shifted > U64_MAX else shifted


def pow_q32(base_q32: int, exp: int) -> int:
    result = ONE_Q32
    factor = max(0, int(base_q32))
    power = max(0, int(exp))
    while power > 0:
        if (power & 1) == 1:
            result = mul_by_q32(result, factor)
        power >>= 1
        if power > 0:
            factor = mul_by_q32(factor, factor)
    return result


def decay_factor_q32(half_life: int) -> int:
    half_life = max(0, int(half_life))
    if half_life == 0:
        return ONE_Q32
    lo = 0
    hi = ONE_Q32
    while (lo + 1) < hi:
        mid = lo + ((hi - lo) // 2)
        mid_pow = pow_q32(mid, half_life)
        if mid_pow > HALF_Q32:
            hi = mid
        else:
            lo = mid
    return lo


# ─────────────────────────────────────────────────────────────
# Exact simulation of the corrected runtime
# ─────────────────────────────────────────────────────────────
def simulate_one_on_initialize_step(
    burn_before: int,
    halving_anchor_before: int,
    entering_block: int,
    burn_half_life: int,
    burn_increase_mult: int,
    regs_prev_block: int,
) -> Tuple[int, int]:
    burn = max(0, int(burn_before))
    anchor = max(0, int(halving_anchor_before))
    current_block = max(0, int(entering_block))
    last_completed_block = current_block - 1 if current_block > 0 else 0

    if burn_half_life > 0 and current_block > 1:
        factor_q32 = decay_factor_q32(burn_half_life)
        burn = mul_by_q32(burn, factor_q32)
        if burn == 0:
            burn = 1

    if burn_half_life > 0:
        delta = max(0, last_completed_block - anchor)
        intervals_passed = delta // int(burn_half_life)
        if intervals_passed > 0:
            anchor = sat_add_u64(anchor, sat_mul_u64(intervals_passed, int(burn_half_life)))

    if regs_prev_block > 0:
        mult = max(1, int(burn_increase_mult))
        bump = sat_pow_u64(mult, int(regs_prev_block))
        burn = sat_mul_u64(burn, bump)
        if burn == 0:
            burn = 1

    return burn, anchor


def simulate_from_block_state(
    start_burn: int,
    start_halving_anchor: int,
    start_block: int,
    end_block: int,
    burn_half_life: int,
    burn_increase_mult: int,
    regs_this_block_map: Dict[int, int],
) -> Tuple[int, int]:
    burn = int(start_burn)
    anchor = int(start_halving_anchor)
    if end_block <= start_block:
        return burn, anchor

    for block_number in range(start_block + 1, end_block + 1):
        regs_prev_block = int(regs_this_block_map.get(block_number - 1, 0))
        burn, anchor = simulate_one_on_initialize_step(
            burn_before=burn,
            halving_anchor_before=anchor,
            entering_block=block_number,
            burn_half_life=burn_half_life,
            burn_increase_mult=burn_increase_mult,
            regs_prev_block=regs_prev_block,
        )
    return burn, anchor


# ─────────────────────────────────────────────────────────────
# Assertion helpers
# ─────────────────────────────────────────────────────────────
def assert_state(
    phase: str,
    actual_burn: int,
    expected_burn: int,
    actual_anchor: int,
    expected_anchor: int,
    decimals: int,
):
    if actual_burn != expected_burn or actual_anchor != expected_anchor:
        raise AssertionError(
            f"[assert] {phase}\n"
            f"  actual burn     = {actual_burn} ({fmt_tao(actual_burn, decimals)})\n"
            f"  expected burn   = {expected_burn} ({fmt_tao(expected_burn, decimals)})\n"
            f"  actual anchor   = {actual_anchor}\n"
            f"  expected anchor = {expected_anchor}\n"
        )


def blocks_left_in_current_interval(current_block: int, halving_anchor: int, half_life: int) -> int:
    if half_life <= 0:
        return 0
    last_completed = max(0, int(current_block) - 1)
    interval_end_completed_block = int(halving_anchor) + int(half_life)
    return max(0, interval_end_completed_block - last_completed)


def assert_sampled_transition(
    prev_state: Dict[str, int],
    cur_state: Dict[str, int],
    burn_half_life: int,
    burn_increase_mult: int,
    regs_map: Dict[int, int],
    decimals: int,
    phase: str,
    require_n_stable: bool = True,
):
    exp_burn, exp_anchor = simulate_from_block_state(
        start_burn=prev_state["burn"],
        start_halving_anchor=prev_state["anchor"],
        start_block=prev_state["block"],
        end_block=cur_state["block"],
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map=regs_map,
    )

    assert_state(
        phase=phase,
        actual_burn=cur_state["burn"],
        expected_burn=exp_burn,
        actual_anchor=cur_state["anchor"],
        expected_anchor=exp_anchor,
        decimals=decimals,
    )

    if require_n_stable and cur_state["n"] != prev_state["n"]:
        raise AssertionError(
            f"[assert] unexpected SubnetworkN change during no-registration decay phase\n"
            f"  prev_n = {prev_state['n']}\n"
            f"  cur_n  = {cur_state['n']}\n"
            f"  prev_block = {prev_state['block']}\n"
            f"  cur_block  = {cur_state['block']}\n"
        )


def step_until_anchor_changes(
    substrate: SubstrateInterface,
    block_signer: Keypair,
    netuid: int,
    decimals: int,
    start_state: Dict[str, int],
    burn_half_life: int,
    burn_increase_mult: int,
    tag_prefix: str,
    print_prefix: str,
    log,
    print_every: int = 25,
    max_steps: int = 5000,
) -> Tuple[Dict[str, int], int]:
    target_anchor = start_state["anchor"]
    prev_state = dict(start_state)
    regs_map: Dict[int, int] = {start_state["block"]: start_state["regs"]}

    for step in range(1, max_steps + 1):
        rec = produce_one_block(substrate, block_signer, f"{tag_prefix}-{step}")
        cur_state = read_net_state(substrate, netuid, rec.block_hash)

        assert_sampled_transition(
            prev_state=prev_state,
            cur_state=cur_state,
            burn_half_life=burn_half_life,
            burn_increase_mult=burn_increase_mult,
            regs_map=regs_map,
            decimals=decimals,
            phase=f"{print_prefix} sampled decay step #{step}",
            require_n_stable=True,
        )

        regs_map[cur_state["block"]] = cur_state["regs"]

        if step == 1 or (step % print_every == 0) or cur_state["anchor"] != target_anchor:
            log(
                format_state(
                    f"{print_prefix}{step:03d}",
                    cur_state["block"],
                    cur_state["burn"],
                    cur_state["anchor"],
                    cur_state["regs"],
                    decimals,
                    cur_state["n"],
                    icon="📉",
                )
            )

        prev_state = cur_state
        if cur_state["anchor"] != target_anchor:
            return cur_state, step

    raise AssertionError(
        f"[assert] anchor did not change after {max_steps} no-registration steps "
        f"(target_anchor={target_anchor}, burn_half_life={burn_half_life})"
    )


def cooldown_to_current_interval_boundary(
    substrate: SubstrateInterface,
    block_signer: Keypair,
    netuid: int,
    decimals: int,
    start_state: Dict[str, int],
    burn_half_life: int,
    burn_increase_mult: int,
    tag_prefix: str,
    log,
) -> Dict[str, int]:
    log(
        f"🧭 Cooling down to the current interval boundary from block {start_state['block']} "
        f"(anchor={start_state['anchor']}, half_life={burn_half_life})"
    )

    boundary_state, steps = step_until_anchor_changes(
        substrate=substrate,
        block_signer=block_signer,
        netuid=netuid,
        decimals=decimals,
        start_state=start_state,
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        tag_prefix=f"{tag_prefix}-rem",
        print_prefix="cd",
        log=log,
    )

    elapsed_blocks = max(0, boundary_state["block"] - start_state["block"])
    actual_ratio = (
        float(boundary_state["burn"]) / float(start_state["burn"])
        if start_state["burn"] > 0 else 0.0
    )
    expected_ratio = (decay_factor_q32(burn_half_life) / float(ONE_Q32)) ** elapsed_blocks

    log(
        f"✅ Interval boundary reached after {steps} sampled step(s) "
        f"| actual ratio ≈ {actual_ratio:.12f} | expected ≈ {expected_ratio:.12f} "
        f"| elapsed blocks = {elapsed_blocks}"
    )
    log(
        format_state(
            "boundary",
            boundary_state["block"],
            boundary_state["burn"],
            boundary_state["anchor"],
            boundary_state["regs"],
            decimals,
            boundary_state["n"],
            icon="🏁",
        )
    )

    return boundary_state


def sample_decay_for_n_blocks(
    substrate: SubstrateInterface,
    block_signer: Keypair,
    netuid: int,
    decimals: int,
    start_state: Dict[str, int],
    burn_half_life: int,
    burn_increase_mult: int,
    num_steps: int,
    tag_prefix: str,
    print_prefix: str,
    log,
) -> Dict[str, int]:
    prev_state = dict(start_state)
    regs_map: Dict[int, int] = {start_state["block"]: start_state["regs"]}

    for step in range(1, num_steps + 1):
        rec = produce_one_block(substrate, block_signer, f"{tag_prefix}-{step}")
        cur_state = read_net_state(substrate, netuid, rec.block_hash)

        assert_sampled_transition(
            prev_state=prev_state,
            cur_state=cur_state,
            burn_half_life=burn_half_life,
            burn_increase_mult=burn_increase_mult,
            regs_map=regs_map,
            decimals=decimals,
            phase=f"{print_prefix} sampled decay step #{step}",
            require_n_stable=True,
        )

        regs_map[cur_state["block"]] = cur_state["regs"]

        if should_log_decay_step(step, num_steps):
            log(
                format_state(
                    f"{print_prefix}{step:03d}",
                    cur_state["block"],
                    cur_state["burn"],
                    cur_state["anchor"],
                    cur_state["regs"],
                    decimals,
                    cur_state["n"],
                    icon="📉",
                )
            )

        prev_state = cur_state

    elapsed_blocks = max(0, prev_state["block"] - start_state["block"])
    actual_ratio = (
        float(prev_state["burn"]) / float(start_state["burn"])
        if start_state["burn"] > 0 else 0.0
    )
    expected_ratio = (decay_factor_q32(burn_half_life) / float(ONE_Q32)) ** elapsed_blocks

    log(
        f"📊 Decay check passed over {num_steps} sampled step(s) "
        f"| actual ratio ≈ {actual_ratio:.12f} | expected ≈ {expected_ratio:.12f} "
        f"| elapsed blocks = {elapsed_blocks}"
    )

    return prev_state


# ─────────────────────────────────────────────────────────────
# Scenario: default-parameter stress
# ─────────────────────────────────────────────────────────────
def run_many_registrations_default_params(ctx: NetworkContext):
    substrate, sudo, reg_cold, log = open_network(ctx)

    sync_rec = produce_one_block(substrate, reg_cold, f"stress-sync-{ctx.run_nonce}")
    sync_hash = sync_rec.block_hash
    sync_block = block_number_at(substrate, sync_hash)

    default_hl = burn_half_life_at(substrate, ctx.netuid, sync_hash)
    default_mult = burn_increase_mult_at(substrate, ctx.netuid, sync_hash)
    default_burn = burn_at(substrate, ctx.netuid, sync_hash)
    default_anchor = burn_last_halving_block_at(substrate, ctx.netuid, sync_hash)
    default_regs = regs_this_block_at(substrate, ctx.netuid, sync_hash)
    default_n = subnetwork_n_at(substrate, ctx.netuid, sync_hash)
    max_allowed = max_allowed_uids_at(substrate, ctx.netuid, sync_hash)

    if default_hl <= 0:
        raise AssertionError("Default BurnHalfLife must be > 0 for the default stress scenario.")
    if default_burn <= 0:
        raise AssertionError("Default burn must be > 0 for the default stress scenario.")

    factor_q32 = decay_factor_q32(default_hl)
    factor_float = factor_q32 / float(ONE_Q32)
    blocks_left = blocks_left_in_current_interval(sync_block, default_anchor, default_hl)
    needed_block_budget = STRESS_TARGET_TOTAL_REGS * EST_BLOCKS_PER_REGISTRATION + 2
    burn_soft_cap = to_planck(STRESS_SOFT_MAX_BURN_TAO, ctx.decimals)

    scenario_banner(
        log,
        f"🚀 Default stress scenario | BurnHalfLife={default_hl} | BurnIncreaseMult={default_mult}",
        f"decay factor ≈ {factor_float:.12f} | blocks left in interval = {blocks_left} | "
        f"target regs = {STRESS_TARGET_TOTAL_REGS} | max allowed uids = {max_allowed} | "
        f"soft burn cap = {STRESS_SOFT_MAX_BURN_TAO:.3f} TAO",
    )
    log(format_state("base", sync_block, default_burn, default_anchor, default_regs, ctx.decimals, default_n, icon="🧪"))

    if blocks_left < needed_block_budget:
        if blocks_left > 0:
            log(f"⏭️  Rolling forward {blocks_left} blocks so the burst starts in a fresh default interval.")
            roll_receipts = produce_n_blocks(substrate, reg_cold, blocks_left, f"stress-roll-{ctx.run_nonce}")
            prep_hash = roll_receipts[-1].block_hash
        else:
            prep_hash = sync_hash
    else:
        prep_hash = sync_hash

    prep_block = block_number_at(substrate, prep_hash)
    burn_prep = burn_at(substrate, ctx.netuid, prep_hash)
    anchor_prep = burn_last_halving_block_at(substrate, ctx.netuid, prep_hash)
    regs_prep = regs_this_block_at(substrate, ctx.netuid, prep_hash)
    n_prep = subnetwork_n_at(substrate, ctx.netuid, prep_hash)
    max_allowed_prep = max_allowed_uids_at(substrate, ctx.netuid, prep_hash)

    blocks_left_after_prep = blocks_left_in_current_interval(prep_block, anchor_prep, default_hl)
    reg_budget_by_interval = max(1, blocks_left_after_prep // EST_BLOCKS_PER_REGISTRATION)
    capacity_budget = max(0, max_allowed_prep - n_prep)
    if capacity_budget == 0:
        raise AssertionError(
            f"[assert] no available uid slots on netuid {ctx.netuid} for default stress scenario\n"
            f"  max_allowed = {max_allowed_prep}\n"
            f"  current_n   = {n_prep}\n"
        )
    total_regs = max(1, min(STRESS_TARGET_TOTAL_REGS, reg_budget_by_interval, capacity_budget))

    log(format_state("prep", prep_block, burn_prep, anchor_prep, regs_prep, ctx.decimals, n_prep, icon="🧭"))
    log(
        f"📦 Burst plan | registrations = {total_regs} | interval budget ≈ {reg_budget_by_interval} "
        f"| capacity budget = {capacity_budget}"
    )

    prev_block = prep_block
    prev_burn = burn_prep
    prev_anchor = anchor_prep
    regs_map: Dict[int, int] = {prep_block: regs_prep}
    stress_hotkeys: List[str] = []
    safety_mult = max(NEXT_REG_BALANCE_SAFETY_MULT, default_mult * 2)
    stop_reason: Optional[str] = None

    for i in range(total_regs):
        if prev_burn >= burn_soft_cap:
            stop_reason = (
                f"soft burn cap reached before registration {i+1}: "
                f"{fmt_tao(prev_burn, ctx.decimals)} >= {STRESS_SOFT_MAX_BURN_TAO:.3f} TAO"
            )
            break

        ready, cur_after, fund_msg = try_prepare_next_registration_balance(
            substrate=substrate,
            funder=sudo,
            who=reg_cold,
            reference_burn_planck=prev_burn,
            decimals=ctx.decimals,
            safety_mult=safety_mult,
            buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
        )
        if not ready:
            stop_reason = (
                f"payer funding exhausted before registration {i+1}: "
                f"payer balance = {fmt_tao(cur_after, ctx.decimals)}"
            )
            if fund_msg:
                stop_reason += f" | {fund_msg}"
            break

        hot = Keypair.create_from_uri(f"//Alice//DynBurnStress//{ctx.netuid}//{ctx.run_nonce}//{i}")
        stress_hotkeys.append(hot.ss58_address)

        reg_rec = burned_register_with_retry(substrate, reg_cold, hot.ss58_address, ctx.netuid)
        reg_hash = reg_rec.block_hash
        reg_block = block_number_at(substrate, reg_hash)

        burn_reg = burn_at(substrate, ctx.netuid, reg_hash)
        anchor_reg = burn_last_halving_block_at(substrate, ctx.netuid, reg_hash)
        regs_reg = regs_this_block_at(substrate, ctx.netuid, reg_hash)
        n_reg = subnetwork_n_at(substrate, ctx.netuid, reg_hash)

        exp_burn_reg, exp_anchor_reg = simulate_from_block_state(
            start_burn=prev_burn,
            start_halving_anchor=prev_anchor,
            start_block=prev_block,
            end_block=reg_block,
            burn_half_life=default_hl,
            burn_increase_mult=default_mult,
            regs_this_block_map=regs_map,
        )

        assert_state(
            phase=f"default stress registration #{i+1} should match continuous-decay runtime logic",
            actual_burn=burn_reg,
            expected_burn=exp_burn_reg,
            actual_anchor=anchor_reg,
            expected_anchor=exp_anchor_reg,
            decimals=ctx.decimals,
        )

        if regs_reg < 1:
            raise AssertionError(
                f"[assert] expected at least one registration in block {reg_block}, "
                f"but RegistrationsThisBlock={regs_reg}"
            )

        expected_n = n_prep + i + 1
        if n_reg != expected_n:
            raise AssertionError(
                f"[assert] unexpected SubnetworkN during default stress registration #{i+1}\n"
                f"  actual   = {n_reg}\n"
                f"  expected = {expected_n}\n"
            )

        if not hotkey_registered_on_network_at(substrate, ctx.netuid, hot.ss58_address, reg_hash):
            raise AssertionError(
                "[assert] newly registered hotkey is not present on the subnet in its registration block\n"
                f"  hotkey = {hot.ss58_address}\n"
                f"  block  = {reg_block}\n"
            )

        if should_log_progress(i + 1, total_regs):
            log(
                format_state(
                    f"reg {i+1:02d}/{total_regs}",
                    reg_block,
                    burn_reg,
                    anchor_reg,
                    regs_reg,
                    ctx.decimals,
                    n_reg,
                    icon="📝",
                )
            )

        regs_map[reg_block] = regs_reg
        prev_block = reg_block
        prev_burn = burn_reg
        prev_anchor = anchor_reg

    completed_regs = len(stress_hotkeys)

    if completed_regs == 0:
        raise AssertionError(
            f"[assert] default stress scenario on net {ctx.netuid} completed zero registrations. "
            f"Stop reason: {stop_reason or 'unknown'}"
        )

    if stop_reason:
        log(f"🛑 Burst stopped early after {completed_regs}/{total_regs} registrations | {stop_reason}")
    elif completed_regs < total_regs:
        log(f"ℹ️  Burst stopped after {completed_regs}/{total_regs} registrations.")
    else:
        log(f"✅ Burst reached planned target of {completed_regs} registrations.")

    post_rec = produce_one_block(substrate, reg_cold, f"stress-post-{ctx.run_nonce}")
    post_state = read_net_state(substrate, ctx.netuid, post_rec.block_hash)

    exp_burn_post, exp_anchor_post = simulate_from_block_state(
        start_burn=prev_burn,
        start_halving_anchor=prev_anchor,
        start_block=prev_block,
        end_block=post_state["block"],
        burn_half_life=default_hl,
        burn_increase_mult=default_mult,
        regs_this_block_map=regs_map,
    )

    assert_state(
        phase="default stress post-registration bump block should match runtime logic",
        actual_burn=post_state["burn"],
        expected_burn=exp_burn_post,
        actual_anchor=post_state["anchor"],
        expected_anchor=exp_anchor_post,
        decimals=ctx.decimals,
    )

    log(format_state("post-bump", post_state["block"], post_state["burn"], post_state["anchor"], post_state["regs"], ctx.decimals, post_state["n"], icon="📈"))

    expected_post_n = n_prep + completed_regs
    if post_state["n"] != expected_post_n:
        raise AssertionError(
            "[assert] expected SubnetworkN to remain at the total after the default stress burst\n"
            f"  actual   = {post_state['n']}\n"
            f"  expected = {expected_post_n}\n"
        )

    latest_hotkey = stress_hotkeys[-1]
    if not hotkey_registered_on_network_at(substrate, ctx.netuid, latest_hotkey, post_state["hash"]):
        raise AssertionError(
            "[assert] the most recently registered hotkey should still be present "
            "immediately after the default stress scenario post block"
        )

    log(f"✅ Burst complete | registrations = {completed_regs} | final subnetwork_n = {post_state['n']}")

    cooldown_to_current_interval_boundary(
        substrate=substrate,
        block_signer=reg_cold,
        netuid=ctx.netuid,
        decimals=ctx.decimals,
        start_state=post_state,
        burn_half_life=default_hl,
        burn_increase_mult=default_mult,
        tag_prefix=f"stress-cool-{ctx.run_nonce}",
        log=log,
    )

    log("✅ Default stress scenario passed.")


# ─────────────────────────────────────────────────────────────
# Scenario: default-parameter limit-price
# ─────────────────────────────────────────────────────────────
def run_register_limit_scenario(ctx: NetworkContext):
    substrate, sudo, reg_cold, log = open_network(ctx)

    sync_rec = produce_one_block(substrate, reg_cold, f"limit-sync-{ctx.run_nonce}")
    sync_state = read_net_state(substrate, ctx.netuid, sync_rec.block_hash)

    half_life = burn_half_life_at(substrate, ctx.netuid, sync_rec.block_hash)
    increase_mult = burn_increase_mult_at(substrate, ctx.netuid, sync_rec.block_hash)
    factor_q32 = decay_factor_q32(half_life)
    factor_float = factor_q32 / float(ONE_Q32)

    scenario_banner(
        log,
        f"🛡️  Limit-price scenario | BurnHalfLife={half_life} | BurnIncreaseMult={increase_mult}",
        f"decay factor ≈ {factor_float:.12f}",
    )
    log(format_state("sync", sync_state["block"], sync_state["burn"], sync_state["anchor"], sync_state["regs"], ctx.decimals, sync_state["n"], icon="🔎"))

    if half_life <= 0:
        raise AssertionError("BurnHalfLife must be > 0 for the limit-price scenario.")
    if sync_state["burn"] <= 0:
        raise AssertionError("Burn must be > 0 for the limit-price scenario.")

    fail_limit = 0
    ensure_balance_for_next_registration(
        substrate=substrate,
        funder=sudo,
        who=reg_cold,
        reference_burn_planck=sync_state["burn"],
        decimals=ctx.decimals,
        safety_mult=max(NEXT_REG_BALANCE_SAFETY_MULT, increase_mult * 2),
        buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
    )

    fail_hot = Keypair.create_from_uri(f"//Alice//DynBurnLimitFail//{ctx.netuid}//{ctx.run_nonce}")
    fail_rec = register_limit_allow_failure(
        substrate=substrate,
        cold=reg_cold,
        hot_ss58=fail_hot.ss58_address,
        netuid=ctx.netuid,
        limit_price=fail_limit,
    )
    fail_state = read_net_state(substrate, ctx.netuid, fail_rec.block_hash)

    if fail_rec.is_success:
        raise AssertionError(
            "[assert] register_limit(limit_price=0) unexpectedly succeeded while burn was positive"
        )

    exp_burn_fail, exp_anchor_fail = simulate_from_block_state(
        start_burn=sync_state["burn"],
        start_halving_anchor=sync_state["anchor"],
        start_block=sync_state["block"],
        end_block=fail_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={sync_state["block"]: sync_state["regs"]},
    )

    assert_state(
        phase="limit scenario failure block should match decay-only runtime logic",
        actual_burn=fail_state["burn"],
        expected_burn=exp_burn_fail,
        actual_anchor=fail_state["anchor"],
        expected_anchor=exp_anchor_fail,
        decimals=ctx.decimals,
    )

    if fail_state["burn"] <= fail_limit:
        raise AssertionError(
            f"[assert] failure block burn should be strictly above the failing limit price\n"
            f"  burn       = {fail_state['burn']}\n"
            f"  limit      = {fail_limit}\n"
        )

    if fail_state["regs"] != 0:
        raise AssertionError(
            f"[assert] failed limit-order registration should not increment RegistrationsThisBlock\n"
            f"  actual regs_this_block = {fail_state['regs']}\n"
        )

    if fail_state["n"] != sync_state["n"]:
        raise AssertionError(
            f"[assert] failed limit-order registration should not change SubnetworkN\n"
            f"  before = {sync_state['n']}\n"
            f"  after  = {fail_state['n']}\n"
        )

    if hotkey_registered_on_network_at(substrate, ctx.netuid, fail_hot.ss58_address, fail_state["hash"]):
        raise AssertionError(
            "[assert] failing limit-order hotkey should not be registered on the subnet"
        )

    err_msg = simplify_error_message(getattr(fail_rec, "error_message", "") or "")
    log(format_state("reject", fail_state["block"], fail_state["burn"], fail_state["anchor"], fail_state["regs"], ctx.decimals, fail_state["n"], icon="🛑"))
    if err_msg:
        log(f"🧾 Rejected exactly as expected: {err_msg}")

    success_limit = fail_state["burn"]

    ensure_balance_for_next_registration(
        substrate=substrate,
        funder=sudo,
        who=reg_cold,
        reference_burn_planck=success_limit,
        decimals=ctx.decimals,
        safety_mult=max(NEXT_REG_BALANCE_SAFETY_MULT, increase_mult * 2),
        buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
    )

    ok_hot = Keypair.create_from_uri(f"//Alice//DynBurnLimitOk//{ctx.netuid}//{ctx.run_nonce}")
    ok_rec = register_limit_with_retry(
        substrate=substrate,
        cold=reg_cold,
        hot_ss58=ok_hot.ss58_address,
        netuid=ctx.netuid,
        limit_price=success_limit,
    )
    ok_state = read_net_state(substrate, ctx.netuid, ok_rec.block_hash)

    exp_burn_ok, exp_anchor_ok = simulate_from_block_state(
        start_burn=fail_state["burn"],
        start_halving_anchor=fail_state["anchor"],
        start_block=fail_state["block"],
        end_block=ok_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={fail_state["block"]: fail_state["regs"]},
    )

    assert_state(
        phase="successful limit-order registration block should match runtime logic",
        actual_burn=ok_state["burn"],
        expected_burn=exp_burn_ok,
        actual_anchor=ok_state["anchor"],
        expected_anchor=exp_anchor_ok,
        decimals=ctx.decimals,
    )

    if ok_state["burn"] > success_limit:
        raise AssertionError(
            "[assert] successful limit-order registration should clear at or below the submitted limit\n"
            f"  actual burn  = {ok_state['burn']}\n"
            f"  limit price  = {success_limit}\n"
        )

    if ok_state["regs"] < 1:
        raise AssertionError(
            f"[assert] successful limit-order registration should increment RegistrationsThisBlock\n"
            f"  actual regs_this_block = {ok_state['regs']}\n"
        )

    if ok_state["n"] != fail_state["n"] + 1:
        raise AssertionError(
            "[assert] successful limit-order registration should increase SubnetworkN by exactly 1\n"
            f"  before = {fail_state['n']}\n"
            f"  after  = {ok_state['n']}\n"
        )

    if not hotkey_registered_on_network_at(substrate, ctx.netuid, ok_hot.ss58_address, ok_state["hash"]):
        raise AssertionError(
            "[assert] successful limit-order hotkey should be registered on the subnet"
        )

    log(format_state("accept", ok_state["block"], ok_state["burn"], ok_state["anchor"], ok_state["regs"], ctx.decimals, ok_state["n"], icon="✅"))
    log(f"💡 Accepted with limit_price = {success_limit} ({fmt_tao(success_limit, ctx.decimals)})")

    post_rec = produce_one_block(substrate, reg_cold, f"limit-post-{ctx.run_nonce}")
    post_state = read_net_state(substrate, ctx.netuid, post_rec.block_hash)

    exp_burn_post, exp_anchor_post = simulate_from_block_state(
        start_burn=ok_state["burn"],
        start_halving_anchor=ok_state["anchor"],
        start_block=ok_state["block"],
        end_block=post_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={ok_state["block"]: ok_state["regs"]},
    )

    assert_state(
        phase="limit scenario post-registration bump block should match runtime logic",
        actual_burn=post_state["burn"],
        expected_burn=exp_burn_post,
        actual_anchor=post_state["anchor"],
        expected_anchor=exp_anchor_post,
        decimals=ctx.decimals,
    )

    if post_state["n"] != ok_state["n"]:
        raise AssertionError(
            "[assert] post-bump block should not change SubnetworkN after successful limit-order registration\n"
            f"  before = {ok_state['n']}\n"
            f"  after  = {post_state['n']}\n"
        )

    log(format_state("bump", post_state["block"], post_state["burn"], post_state["anchor"], post_state["regs"], ctx.decimals, post_state["n"], icon="📈"))
    log("✅ Limit-price scenario passed.")


# ─────────────────────────────────────────────────────────────
# Scenario: explicit burn config
# ─────────────────────────────────────────────────────────────
def run_one_config(ctx: NetworkContext, burn_half_life: int, burn_increase_mult: int, hotkey_tag: str):
    substrate, sudo, reg_cold, log = open_network(ctx)

    sudo_set_burn_half_life(substrate, sudo, ctx.netuid, burn_half_life)
    sudo_set_burn_increase_mult(substrate, sudo, ctx.netuid, burn_increase_mult)

    sync_rec = produce_one_block(substrate, reg_cold, f"sync-{hotkey_tag}-{ctx.run_nonce}")
    sync_hash = sync_rec.block_hash
    sync_state = read_net_state(substrate, ctx.netuid, sync_hash)

    min_burn = min_burn_at(substrate, ctx.netuid, sync_hash)
    max_burn = max_burn_at(substrate, ctx.netuid, sync_hash)

    hl_onchain = burn_half_life_at(substrate, ctx.netuid, sync_hash)
    mult_onchain = burn_increase_mult_at(substrate, ctx.netuid, sync_hash)

    factor_q32 = decay_factor_q32(burn_half_life)
    factor_float = factor_q32 / float(ONE_Q32)

    scenario_banner(
        log,
        f"⚙️  Burn config | BurnHalfLife={burn_half_life} | BurnIncreaseMult={burn_increase_mult}",
        f"decay factor ≈ {factor_float:.12f} | min burn = {fmt_tao(min_burn, ctx.decimals) if min_burn else 'n/a'} | "
        f"max burn = {fmt_tao(max_burn, ctx.decimals) if max_burn else 'n/a'}",
    )
    log(format_state("sync", sync_state["block"], sync_state["burn"], sync_state["anchor"], sync_state["regs"], ctx.decimals, sync_state["n"], icon="🔎"))

    if sync_state["burn"] <= 0:
        raise AssertionError("Burn is 0 at sync block; cannot test dynamic pricing.")

    if hl_onchain not in (0, burn_half_life):
        raise AssertionError(f"BurnHalfLife mismatch: expected {burn_half_life}, on-chain {hl_onchain}")
    if mult_onchain not in (0, burn_increase_mult):
        raise AssertionError(f"BurnIncreaseMult mismatch: expected {burn_increase_mult}, on-chain {mult_onchain}")

    ensure_balance_for_next_registration(
        substrate=substrate,
        funder=sudo,
        who=reg_cold,
        reference_burn_planck=sync_state["burn"],
        decimals=ctx.decimals,
        safety_mult=max(NEXT_REG_BALANCE_SAFETY_MULT, burn_increase_mult * 2),
        buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
    )

    hot = Keypair.create_from_uri(f"//Alice//DynBurnHot{hotkey_tag}//Net{ctx.netuid}//Run{ctx.run_nonce}")
    reg_rec = burned_register_with_retry(substrate, reg_cold, hot.ss58_address, ctx.netuid)
    reg_state = read_net_state(substrate, ctx.netuid, reg_rec.block_hash)

    log(format_state("register", reg_state["block"], reg_state["burn"], reg_state["anchor"], reg_state["regs"], ctx.decimals, reg_state["n"], icon="📝"))

    exp_burn_reg, exp_anchor_reg = simulate_from_block_state(
        start_burn=sync_state["burn"],
        start_halving_anchor=sync_state["anchor"],
        start_block=sync_state["block"],
        end_block=reg_state["block"],
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map={sync_state["block"]: sync_state["regs"]},
    )

    assert_state(
        phase="burn/anchor at registration block should match exact continuous-decay runtime logic",
        actual_burn=reg_state["burn"],
        expected_burn=exp_burn_reg,
        actual_anchor=reg_state["anchor"],
        expected_anchor=exp_anchor_reg,
        decimals=ctx.decimals,
    )

    if reg_state["regs"] < 1:
        raise AssertionError(
            f"[assert] expected at least one registration in block {reg_state['block']}, "
            f"but RegistrationsThisBlock={reg_state['regs']}"
        )

    after_rec = produce_one_block(substrate, reg_cold, f"after-{hotkey_tag}-{ctx.run_nonce}")
    after_state = read_net_state(substrate, ctx.netuid, after_rec.block_hash)

    log(format_state("post-bump", after_state["block"], after_state["burn"], after_state["anchor"], after_state["regs"], ctx.decimals, after_state["n"], icon="📈"))

    exp_burn_after, exp_anchor_after = simulate_from_block_state(
        start_burn=reg_state["burn"],
        start_halving_anchor=reg_state["anchor"],
        start_block=reg_state["block"],
        end_block=after_state["block"],
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map={reg_state["block"]: reg_state["regs"]},
    )

    assert_state(
        phase="burn/anchor after registration should include previous-block bump with exact runtime ordering",
        actual_burn=after_state["burn"],
        expected_burn=exp_burn_after,
        actual_anchor=after_state["anchor"],
        expected_anchor=exp_anchor_after,
        decimals=ctx.decimals,
    )

    sample_decay_for_n_blocks(
        substrate=substrate,
        block_signer=reg_cold,
        netuid=ctx.netuid,
        decimals=ctx.decimals,
        start_state=after_state,
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        num_steps=burn_half_life,
        tag_prefix=f"decay-{hotkey_tag}-{ctx.run_nonce}",
        print_prefix="dc",
        log=log,
    )

    log(f"✅ Burn config passed for half_life={burn_half_life}, mult={burn_increase_mult}.")


# ─────────────────────────────────────────────────────────────
# Bootstrap / creation
# ─────────────────────────────────────────────────────────────
def bootstrap_network(ctx: NetworkContext):
    substrate, sudo, reg_cold, log = open_network(ctx)

    ensure_min_balance(substrate, sudo, reg_cold, MIN_FUNDS_TAO_REG_COLD, ctx.decimals)

    probe_rec = produce_one_block(substrate, reg_cold, f"probe-registration-allowed-{ctx.netuid}")
    probe_hash = probe_rec.block_hash
    if not registration_allowed_at(substrate, ctx.netuid, probe_hash):
        log("⚠️  Registration disabled; enabling via sudo.")
        sudo_set_registration_allowed(substrate, sudo, ctx.netuid, True)
        produce_one_block(substrate, reg_cold, f"probe-after-enable-{ctx.netuid}")

    log(f"🔌 Connected to {ctx.ws} | decimals={ctx.decimals} | payer={short_ss58(reg_cold.ss58_address)}")


def ensure_requested_netuids_exist(ws: str, requested_netuids: List[int], decimals: int):
    requested = sorted(set(n for n in requested_netuids if n != 0))
    if not requested:
        return

    substrate = connect(ws)
    sudo = Keypair.create_from_uri("//Alice")

    try:
        sudo_set_network_rate_limit(substrate, sudo, 0)
    except Exception:
        pass

    existing = {n for n in networks_added(substrate) if n != 0}
    missing = [n for n in requested if n not in existing]
    if not missing:
        safe_print(f"🧩 Requested subnets already exist: {requested}")
        return

    safe_print(f"🧩 Missing requested subnets detected: {missing}")
    try:
        desired_limit = max(max(requested) + 4, len(existing) + len(missing) + 4)
        sudo_set_subnet_limit(substrate, sudo, desired_limit)
        safe_print(f"📈 Raised subnet limit to at least {desired_limit} (best effort).")
    except Exception as e:
        safe_print(f"ℹ️ Could not adjust subnet limit automatically: {e}")

    attempts = 0
    max_attempts = max(requested) + len(requested) + 10

    while True:
        existing = {n for n in networks_added(substrate) if n != 0}
        missing = [n for n in requested if n not in existing]
        if not missing:
            safe_print(f"✅ Requested subnets now exist: {requested}")
            return

        if attempts >= max_attempts:
            raise RuntimeError(
                f"Unable to create requested netuids after {attempts} attempt(s). "
                f"existing={sorted(existing)} missing={missing}"
            )

        target = missing[0]
        owner_cold = Keypair.create_from_uri(f"//Alice//SubnetOwnerCold//Net{target}")
        owner_hot = Keypair.create_from_uri(f"//Alice//SubnetOwnerHot//Net{target}")

        ensure_min_balance(substrate, sudo, owner_cold, REGISTER_NETWORK_MIN_OWNER_COLD_TAO, decimals)
        ensure_min_balance(substrate, sudo, owner_hot, REGISTER_NETWORK_MIN_OWNER_HOT_TAO, decimals)

        before = {n for n in networks_added(substrate) if n != 0}
        register_network_with_retry(
            substrate=substrate,
            signer=owner_cold,
            owner_hot_ss58=owner_hot.ss58_address,
            owner_cold_ss58=owner_cold.ss58_address,
        )
        after = {n for n in networks_added(substrate) if n != 0}
        created = sorted(after - before)

        attempts += 1
        if not created:
            raise RuntimeError(
                f"register_network did not create a visible subnet while targeting missing={missing}"
            )

        safe_print(
            f"🧱 Created subnet(s) {created} "
            f"using owner {short_ss58(owner_cold.ss58_address)} "
            f"while targeting missing {missing}"
        )


# ─────────────────────────────────────────────────────────────
# Stage runner
# ─────────────────────────────────────────────────────────────
def run_stage_across_networks(
    stage_title: str,
    contexts: List[NetworkContext],
    workers: int,
    stage_fn: Callable[[NetworkContext], Any],
):
    netuids = [ctx.netuid for ctx in contexts]
    safe_print(f"\n🚦 Stage: {stage_title} | nets={netuids} | workers={workers}")

    failures: List[Tuple[int, str, str]] = []

    def _run_with_retries(ctx: NetworkContext):
        netlog = make_logger(ctx.netuid)
        last_exc: Optional[Exception] = None

        for attempt in range(STAGE_RETRY_ATTEMPTS):
            attempt_ctx = ctx if attempt == 0 else replace(
                ctx,
                run_nonce=ctx.run_nonce + attempt * 10_000_000,
            )

            if attempt > 0:
                netlog(
                    f"🔁 Retrying stage '{stage_title}' "
                    f"(attempt {attempt + 1}/{STAGE_RETRY_ATTEMPTS})"
                )

            try:
                return stage_fn(attempt_ctx)
            except Exception as e:
                last_exc = e
                if attempt + 1 < STAGE_RETRY_ATTEMPTS and is_retryable_transport_error(e):
                    netlog(f"⚠️  Transport issue detected: {simplify_error_message(e)}")
                    time.sleep(0.75 * (attempt + 1))
                    continue
                raise

        assert last_exc is not None
        raise last_exc

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(_run_with_retries, ctx): ctx.netuid for ctx in contexts}

        for fut in as_completed(future_map):
            netuid = future_map[fut]
            try:
                fut.result()
            except Exception as e:
                tb = traceback.format_exc()
                safe_print(f"❌ Stage '{stage_title}' failed on net {netuid}: {e}")
                safe_print(tb)
                failures.append((netuid, str(e), tb))

    if failures:
        raise RuntimeError(
            f"Stage '{stage_title}' failed on {len(failures)} network(s): "
            + ", ".join(str(netuid) for netuid, _, _ in failures)
        )

    safe_print(f"✅ Stage complete: {stage_title}")


# ─────────────────────────────────────────────────────────────
# Network selection
# ─────────────────────────────────────────────────────────────
def parse_netuids_arg(value: Optional[str]) -> List[int]:
    if not value:
        return []
    out: List[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out


def resolve_existing_netuids(substrate: SubstrateInterface, limit_networks: Optional[int]) -> List[int]:
    nets = [n for n in networks_added(substrate) if n != 0]
    nets = sorted(set(nets))
    if limit_networks is not None:
        nets = nets[: max(0, int(limit_networks))]
    if not nets:
        raise RuntimeError("Could not resolve any non-root netuids to test.")
    return nets


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ws", default=DEFAULT_WS, help=f"WS endpoint (default: {DEFAULT_WS})")
    parser.add_argument("--netuid", type=int, default=None, help="Single netuid to test")
    parser.add_argument("--netuids", default=None, help="Comma-separated list of netuids to test concurrently")
    parser.add_argument("--limit-networks", type=int, default=None, help="Cap the number of auto-discovered non-root networks")
    parser.add_argument("--workers", type=int, default=None, help="Number of concurrent worker threads (default: min(4, number of networks))")
    parser.add_argument("--with-default-stress", action="store_true", help="Run the heavy default-parameter stress scenario before the other tests")
    args = parser.parse_args()

    base = connect(args.ws)
    decimals = token_decimals(base)
    sudo = Keypair.create_from_uri("//Alice")

    try:
        sudo_set_network_rate_limit(base, sudo, 0)
    except Exception:
        pass

    if args.netuid is not None and args.netuids:
        raise RuntimeError("Use either --netuid or --netuids, not both.")

    explicit_request = (args.netuid is not None) or (args.netuids is not None)

    if args.netuid is not None:
        requested_netuids = [int(args.netuid)]
    elif args.netuids is not None:
        requested_netuids = parse_netuids_arg(args.netuids)
    else:
        requested_netuids = []

    if explicit_request:
        ensure_requested_netuids_exist(args.ws, requested_netuids, decimals)
        netuids = sorted(set(n for n in requested_netuids if n != 0))
    else:
        netuids = resolve_existing_netuids(base, args.limit_networks)

    workers = args.workers if args.workers is not None else max(1, min(4, len(netuids)))

    contexts = [
        NetworkContext(
            ws=args.ws,
            netuid=netuid,
            decimals=decimals,
            run_nonce=int(time.time() * 1000) + (netuid * 1_000_000),
            payer_uri=f"//Alice//DynBurnCold//Net{netuid}",
        )
        for netuid in netuids
    ]

    safe_print(f"🌐 Connected to {args.ws} | decimals={decimals}")
    safe_print(
        f"🧪 Testing netuids={netuids} | workers={workers} | "
        f"default_stress={'on' if args.with_default_stress else 'off'}"
    )
    if len(netuids) == 1:
        safe_print("ℹ️  Only one non-root subnet selected. Use --netuids a,b,c to fan out across multiple subnets explicitly.")

    run_stage_across_networks(
        stage_title="bootstrap",
        contexts=contexts,
        workers=workers,
        stage_fn=bootstrap_network,
    )

    if args.with_default_stress:
        run_stage_across_networks(
            stage_title="default stress",
            contexts=contexts,
            workers=workers,
            stage_fn=run_many_registrations_default_params,
        )
    else:
        safe_print("⏭️  Skipping default stress stage (enable with --with-default-stress).")

    run_stage_across_networks(
        stage_title="limit-price scenario",
        contexts=contexts,
        workers=workers,
        stage_fn=run_register_limit_scenario,
    )

    for idx, (hl, mult) in enumerate(TEST_CONFIGS, start=1):
        hotkey_tag = f"C{idx}H{hl}M{mult}"
        run_stage_across_networks(
            stage_title=f"burn config hl={hl}, mult={mult}",
            contexts=contexts,
            workers=workers,
            stage_fn=lambda ctx, _hl=hl, _mult=mult, _tag=hotkey_tag: run_one_config(ctx, _hl, _mult, _tag),
        )

    safe_print("\n🎉 All dynamic burn pricing assertions passed across all requested networks.\n")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as ae:
        print(f"\nAssertion failed:\n{ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"\nError:\n{e}", file=sys.stderr)
        sys.exit(1)