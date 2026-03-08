#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic burned_register pricing test for continuous per-block exponential decay.

This mirrors the corrected runtime behavior exactly:

  on_initialize(current_block):
    1) if BurnHalfLife > 0 and current_block > 1:
         burn *= factor_q32
       where factor_q32 is the largest Q32 value satisfying:
         factor_q32 ^ BurnHalfLife <= 0.5

    2) using the existing BurnLastHalvingBlock anchor:
         intervals_passed =
            (last_completed_block - BurnLastHalvingBlock) / BurnHalfLife
       if intervals_passed > 0:
         BurnLastHalvingBlock += intervals_passed * BurnHalfLife
         RegistrationsThisInterval = 0

    3) if RegistrationsThisBlock from the previous block > 0:
         burn *= BurnIncreaseMult ^ regs_prev_block

    4) RegistrationsThisBlock = 0

This script reproduces the same Q32 root search and integer math, so the burn
assertions are exact integer checks rather than fuzzy float comparisons.

Usage:
  python3 neuronreg.py
  python3 neuronreg.py --ws ws://127.0.0.1:9945
  python3 neuronreg.py --netuid 1
"""

import sys
import time
import argparse
from typing import Any, Dict, List, Optional, Sequence, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
DEFAULT_WS = "ws://127.0.0.1:9945"

# (BurnHalfLife, BurnIncreaseMult)
TEST_CONFIGS: List[Tuple[int, int]] = [
    (4, 2),
    (8, 3),
]

DECAY_BLOCKS_MULTIPLIER = 1
MIN_FUNDS_TAO_REG_COLD = 500.0

PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"

U64_MAX = (1 << 64) - 1
ONE_Q32 = 1 << 32
HALF_Q32 = 1 << 31


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
    cur = account_free(substrate, who.ss58_address)
    tgt = to_planck(min_tao, decimals)
    if cur < tgt:
        transfer_keep_alive(substrate, funder, who.ss58_address, tgt - cur)


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


# ─────────────────────────────────────────────────────────────
# Admin setters
# ─────────────────────────────────────────────────────────────
def sudo_set_network_rate_limit(substrate: SubstrateInterface, sudo: Keypair, rate_limit: int):
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
    for pallet, fn in candidates:
        try:
            call = compose_call(substrate, pallet, fn, {"netuid": int(netuid), "burn_increase_mult": int(burn_increase_mult)})
            submit(substrate, sudo, call, sudo=True)
            return
        except Exception as e:
            last = e
    raise RuntimeError(f"Failed to set BurnIncreaseMult via any known pallet: {last}")


# ─────────────────────────────────────────────────────────────
# Registration extrinsic
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
                alice = Keypair.create_from_uri("//Alice")
                produce_n_blocks(substrate, alice, backoff_blocks, "reg-backoff")
                continue
            raise
    if last is not None:
        raise last
    raise RuntimeError("burned_register_with_retry failed unexpectedly")


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

    # 1a) continuous per-block exponential decay
    if burn_half_life > 0 and current_block > 1:
        factor_q32 = decay_factor_q32(burn_half_life)
        burn = mul_by_q32(burn, factor_q32)
        if burn == 0:
            burn = 1

    # 1b) interval reset schedule (no direct burn change)
    if burn_half_life > 0:
        delta = max(0, last_completed_block - anchor)
        intervals_passed = delta // int(burn_half_life)
        if intervals_passed > 0:
            anchor = sat_add_u64(anchor, sat_mul_u64(intervals_passed, int(burn_half_life)))

    # 2) previous-block bump
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
# Output / assertion helpers
# ─────────────────────────────────────────────────────────────
def print_state(label: str, block: int, burn: int, anchor: int, regs: int, decimals: int):
    print(
        f"[{label}]  block={block:<6} "
        f"burn={burn:<12} ({fmt_tao(burn, decimals)})  "
        f"halving_anchor={anchor:<6}  regs_this_block={regs}"
    )


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


# ─────────────────────────────────────────────────────────────
# Test runner
# ─────────────────────────────────────────────────────────────
def run_one_config(
    substrate: SubstrateInterface,
    sudo: Keypair,
    netuid: int,
    reg_cold: Keypair,
    decimals: int,
    burn_half_life: int,
    burn_increase_mult: int,
    hotkey_tag: str,
    run_nonce: int,
):
    sudo_set_burn_half_life(substrate, sudo, netuid, burn_half_life)
    sudo_set_burn_increase_mult(substrate, sudo, netuid, burn_increase_mult)

    sync_rec = produce_one_block(substrate, sudo, f"sync-{hotkey_tag}-{run_nonce}")
    sync_hash = sync_rec.block_hash
    sync_block = block_number_at(substrate, sync_hash)

    burn_sync = burn_at(substrate, netuid, sync_hash)
    anchor_sync = burn_last_halving_block_at(substrate, netuid, sync_hash)
    regs_sync = regs_this_block_at(substrate, netuid, sync_hash)

    min_burn = min_burn_at(substrate, netuid, sync_hash)
    max_burn = max_burn_at(substrate, netuid, sync_hash)

    hl_onchain = burn_half_life_at(substrate, netuid, sync_hash)
    mult_onchain = burn_increase_mult_at(substrate, netuid, sync_hash)

    factor_q32 = decay_factor_q32(burn_half_life)
    factor_float = factor_q32 / float(ONE_Q32)

    print("\n" + "=" * 96)
    print(f"NETUID={netuid}  BurnHalfLife={burn_half_life}  BurnIncreaseMult={burn_increase_mult}".center(96))
    print("=" * 96)
    print_state("sync", sync_block, burn_sync, anchor_sync, regs_sync, decimals)
    print(
        f"        min_burn={min_burn} ({fmt_tao(min_burn, decimals) if min_burn else 'n/a'})  "
        f"max_burn={max_burn} ({fmt_tao(max_burn, decimals) if max_burn else 'n/a'})  "
        f"decay_factor≈{factor_float:.12f}"
    )

    if burn_sync <= 0:
        raise AssertionError("Burn is 0 at sync block; cannot test dynamic pricing.")

    if hl_onchain not in (0, burn_half_life):
        raise AssertionError(f"BurnHalfLife mismatch: expected {burn_half_life}, on-chain {hl_onchain}")
    if mult_onchain not in (0, burn_increase_mult):
        raise AssertionError(f"BurnIncreaseMult mismatch: expected {burn_increase_mult}, on-chain {mult_onchain}")

    hot = Keypair.create_from_uri(f"//Alice//DynBurnHot{hotkey_tag}//Run{run_nonce}")
    reg_rec = burned_register_with_retry(substrate, reg_cold, hot.ss58_address, netuid)

    reg_hash = reg_rec.block_hash
    reg_block = block_number_at(substrate, reg_hash)

    burn_reg = burn_at(substrate, netuid, reg_hash)
    anchor_reg = burn_last_halving_block_at(substrate, netuid, reg_hash)
    regs_reg = regs_this_block_at(substrate, netuid, reg_hash)

    print_state("reg ", reg_block, burn_reg, anchor_reg, regs_reg, decimals)

    exp_burn_reg, exp_anchor_reg = simulate_from_block_state(
        start_burn=burn_sync,
        start_halving_anchor=anchor_sync,
        start_block=sync_block,
        end_block=reg_block,
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map={
            sync_block: regs_sync,
        },
    )

    assert_state(
        phase="burn/anchor at registration block should match exact continuous-decay runtime logic",
        actual_burn=burn_reg,
        expected_burn=exp_burn_reg,
        actual_anchor=anchor_reg,
        expected_anchor=exp_anchor_reg,
        decimals=decimals,
    )

    if regs_reg < 1:
        raise AssertionError(
            f"[assert] expected at least one registration in block {reg_block}, "
            f"but RegistrationsThisBlock={regs_reg}"
        )

    after_rec = produce_one_block(substrate, sudo, f"after-{hotkey_tag}-{run_nonce}")
    after_hash = after_rec.block_hash
    after_block = block_number_at(substrate, after_hash)

    burn_after = burn_at(substrate, netuid, after_hash)
    anchor_after = burn_last_halving_block_at(substrate, netuid, after_hash)
    regs_after = regs_this_block_at(substrate, netuid, after_hash)

    print_state("+1  ", after_block, burn_after, anchor_after, regs_after, decimals)

    exp_burn_after, exp_anchor_after = simulate_from_block_state(
        start_burn=burn_reg,
        start_halving_anchor=anchor_reg,
        start_block=reg_block,
        end_block=after_block,
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map={
            reg_block: regs_reg,
        },
    )

    assert_state(
        phase="burn/anchor after registration should include previous-block bump with exact runtime ordering",
        actual_burn=burn_after,
        expected_burn=exp_burn_after,
        actual_anchor=anchor_after,
        expected_anchor=exp_anchor_after,
        decimals=decimals,
    )

    decay_n = int(burn_half_life) * int(DECAY_BLOCKS_MULTIPLIER)
    decay_receipts = produce_n_blocks(substrate, sudo, decay_n, f"decay-{hotkey_tag}-{run_nonce}")

    end_hash = decay_receipts[-1].block_hash
    end_block = block_number_at(substrate, end_hash)

    burn_end = burn_at(substrate, netuid, end_hash)
    anchor_end = burn_last_halving_block_at(substrate, netuid, end_hash)
    regs_end = regs_this_block_at(substrate, netuid, end_hash)

    print_state("dec ", end_block, burn_end, anchor_end, regs_end, decimals)

    exp_burn_end, exp_anchor_end = simulate_from_block_state(
        start_burn=burn_after,
        start_halving_anchor=anchor_after,
        start_block=after_block,
        end_block=end_block,
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map={
            after_block: regs_after,
        },
    )

    assert_state(
        phase="burn/anchor after decay blocks should match exact continuous per-block decay",
        actual_burn=burn_end,
        expected_burn=exp_burn_end,
        actual_anchor=anchor_end,
        expected_anchor=exp_anchor_end,
        decimals=decimals,
    )

    actual_ratio = (burn_end / burn_after) if burn_after > 0 else 0.0
    expected_ratio = (factor_q32 / float(ONE_Q32)) ** max(0, end_block - after_block)
    print(f"        ratio actual≈{actual_ratio:.12f}  expected≈{expected_ratio:.12f}  "
          f"(elapsed={max(0, end_block - after_block)} blocks)")
    print(f"[✓] Config BurnHalfLife={burn_half_life}, BurnIncreaseMult={burn_increase_mult} passed.")


def pick_netuid(substrate: SubstrateInterface, requested: Optional[int]) -> int:
    if requested is not None:
        return int(requested)

    nets = networks_added(substrate)
    candidates = [n for n in nets if n != 0]
    if not candidates:
        raise RuntimeError("Could not find any non-root netuids via NetworksAdded; pass --netuid explicitly.")
    return candidates[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ws", default=DEFAULT_WS, help=f"WS endpoint (default: {DEFAULT_WS})")
    parser.add_argument("--netuid", type=int, default=None, help="Netuid to test (default: first non-root netuid)")
    args = parser.parse_args()

    substrate = connect(args.ws)
    decimals = token_decimals(substrate)

    sudo = Keypair.create_from_uri("//Alice")
    reg_cold = Keypair.create_from_uri("//DynBurnCold")

    ensure_min_balance(substrate, sudo, reg_cold, MIN_FUNDS_TAO_REG_COLD, decimals)

    netuid = pick_netuid(substrate, args.netuid)
    if netuid == 0:
        raise RuntimeError("Refusing to run on root subnet (netuid=0). Choose a non-root netuid.")

    try:
        sudo_set_network_rate_limit(substrate, sudo, 0)
    except Exception:
        pass

    probe = produce_one_block(substrate, sudo, "probe-registration-allowed")
    probe_hash = probe.block_hash
    if not registration_allowed_at(substrate, netuid, probe_hash):
        print(f"[i] Registration disabled on netuid={netuid}; enabling via sudo.")
        sudo_set_registration_allowed(substrate, sudo, netuid, True)
        produce_one_block(substrate, sudo, "probe-after-enable")

    run_nonce = int(time.time() * 1000)

    print(f"[i] Connected to {args.ws} (decimals={decimals})")
    print(f"[i] Testing netuid={netuid} with payer coldkey={reg_cold.ss58_address}")

    for idx, (hl, mult) in enumerate(TEST_CONFIGS, start=1):
        hotkey_tag = f"C{idx}H{hl}M{mult}"
        run_one_config(
            substrate=substrate,
            sudo=sudo,
            netuid=netuid,
            reg_cold=reg_cold,
            decimals=decimals,
            burn_half_life=hl,
            burn_increase_mult=mult,
            hotkey_tag=hotkey_tag,
            run_nonce=run_nonce,
        )

    print("\n✅ All dynamic burn pricing assertions passed.\n")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as ae:
        print(f"\nAssertion failed:\n{ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"\nError:\n{e}", file=sys.stderr)
        sys.exit(1)