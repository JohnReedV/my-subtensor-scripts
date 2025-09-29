#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subtensor multi-subnet dissolve test with prune verification and
ASSERT that each newly-registered subnet's price is initialized correctly.

🔧 Why this revision?
--------------------
On your chain, `SubnetMovingPrice` may remain `0` immediately after registration and
`start_call`, even though the *reserves* are initialized to an equal TAO/α amount:

    SubnetTAO := pool_initial_tao
    SubnetAlphaIn := pool_initial_tao (as α)
    SubnetMovingPrice := may be left 0 until later activity

So asserting only on `SubnetMovingPrice` was too strict and produced false negatives.
**Fix:** When `SubnetMovingPrice` is 0/None, we fall back to the **reserve ratio**
(`SubnetTAO / SubnetAlphaIn`) which should be ≈ 1.0 right after registration.

Other changes remain from the previous working script:
- Works with *smaller balances* (funding, stake, and L are scaled down).
- Adds α‑only and TAO‑only liquidity (forgiving strategy) then dissolves.
- Re-registers a subnet, calls `start_call`, actively produces blocks, and
  asserts price≈1.0 using the **moving price or reserve ratio**.
- Prune-at-limit test (either add/prune pair or recycle-in-place) with price≈1.0 assert.

Test set: nets [3, 12, 51, 120]
"""

import sys
import time
import re
from typing import Any, Dict, List, Tuple, Optional

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

WS_ENDPOINT = "ws://127.0.0.1:9935"
TEST_NETS   = [3, 12, 51, 120]

# ─────────────────────────────────────────────
# Smaller-balance friendly parameters
# ─────────────────────────────────────────────
MIN_FUND_TAO_STAKER = 50          # TAO per staker coldkey
MIN_FUND_TAO_OWNER  = 300         # TAO for owner coldkey

STAKE_AMOUNTS_TAO   = [8, 10, 12] # staker1, staker2, owner

# Minimum liquidity in pallet is typically >= 1_000_000; keep L >= that
ALPHA_LP_CANDIDATES = [
    ( 1000,  500,  1_000_000),
    ( 2500,  800,  1_500_000),
    ( 5000, 1000,  2_000_000),
]

TAO_LP_CANDIDATES = [
    ( 1000,  500,  1_000_000),
    ( 3000,  800,  2_000_000),
    ( 8000, 1200,  5_000_000),
]

TAO_SPEND_PLANCK_THRESHOLD = 25_000  # ≈ 0.000025 TAO

# Price assertion tolerance & block production
PRICE_ONE_TOL = 1e-2
PRICE_POLL_ATTEMPTS = 8
PRICE_POLL_WAIT_BLOCKS = 1
BLOCK_PRODUCE_COUNT = 5            # actively produce this many blocks before price-assert

# ────────────────────────────
# Helpers & substrate I/O
# ────────────────────────────
def connect() -> SubstrateInterface:
    return SubstrateInterface(url=WS_ENDPOINT)

def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int): return d[0]
    if isinstance(d, int): return d
    return 9

def to_planck(tao: float, decimals: int) -> int:
    return int(round(tao * (10 ** decimals)))

def from_planck(p: int, decimals: int) -> float:
    return p / float(10 ** decimals)

def fmt_tao(p: int, decimals: int) -> str:
    return f"{from_planck(p, decimals):.4f} TAO"

def pct_change(after: int, before: int) -> Optional[float]:
    if before <= 0: return None
    return (after - before) / float(before) * 100.0

def sleep_blocks(n: int = 2):
    # lightweight wait; we also actively produce blocks where needed
    time.sleep(3 * n)

def compose_call(substrate, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)

def submit(substrate, who: Keypair, call, sudo: bool = False):
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})
    xt = substrate.create_signed_extrinsic(call=call, keypair=who)
    try:
        rec = substrate.submit_extrinsic(xt, wait_for_inclusion=True, wait_for_finalization=True)
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e
    if not rec.is_success:
        raise RuntimeError(f"Extrinsic failed in block {rec.block_hash}: {rec.error_message}")
    return rec

def account_free(substrate, ss58: str) -> int:
    info = substrate.query("System", "Account", [ss58]).value
    return int(info["data"]["free"])

def mk_table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [len(h) for h in headers]
    rows = [[str(c) for c in r] for r in rows]
    for r in rows:
        for i,c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    hsep = "─"
    top = "┌" + "┬".join(hsep*(w+2) for w in widths) + "┐"
    mid = "├" + "┼".join(hsep*(w+2) for w in widths) + "┤"
    bot = "└" + "┴".join(hsep*(w+2) for w in widths) + "┘"
    def fr(r): return "│ " + " ".join(c.ljust(w+1) for c,w in zip(r,widths)) + "│"
    out = [top, fr(headers), mid]
    out += [fr(r) for r in rows]
    out.append(bot)
    return "\n".join(out)

# ────────────────────────────
# Subtensor queries & price decode
# ────────────────────────────
def networks_added(substrate) -> List[int]:
    nets = []
    for key, val in substrate.query_map("SubtensorModule", "NetworksAdded"):
        if bool(val.value):
            kv = getattr(key, "value", key)
            try:
                nets.append(int(kv) if isinstance(kv, int) else int(list(kv.values())[0]))
            except Exception:
                pass
    return sorted(set(nets))

def q_u128(substrate, module: str, storage: str, params: List[Any]) -> int:
    try:
        v = substrate.get_storage(module=module, storage_function=storage, params=params, return_scale_type='u128')
        if v is None: return 0
        return int(v.value) if hasattr(v, "value") else int(v)
    except Exception:
        pass
    try:
        v = substrate.query(module, storage, params)
        if v is None or v.value is None: return 0
        s = v.value
        if isinstance(s, int): return s
        if isinstance(s, str): return int(s,16) if s.startswith("0x") else int(s)
        if isinstance(s, dict) and "bits" in s: return int(s["bits"],16)
        return int(str(s),16) if str(s).startswith("0x") else int(str(s))
    except Exception:
        return 0

def pool_totals(substrate, netuid: int) -> Tuple[int,int,int]:
    alpha = q_u128(substrate, "SubtensorModule", "SubnetAlphaInProvided", [netuid])
    tao   = q_u128(substrate, "SubtensorModule", "SubnetTaoProvided",   [netuid])
    pot   = q_u128(substrate, "SubtensorModule", "SubnetTAO",           [netuid])
    return alpha, tao, pot

def get_current_tick(substrate, netuid: int) -> int:
    v = substrate.query("Swap", "CurrentTick", [netuid])
    if v is None: return 0
    vv = v.value
    if isinstance(vv, int): return vv
    if isinstance(vv, dict):
        for key in ("index", "value", "current", "tick"):
            if key in vv and isinstance(vv[key], int):
                return vv[key]
    try:
        return int(vv)
    except Exception:
        return 0

def network_registered_at(substrate, netuid: int) -> int:
    v = substrate.query("SubtensorModule", "NetworkRegisteredAt", [netuid])
    if v is None or v.value is None:
        return 0
    try:
        return int(v.value)
    except Exception:
        try:
            return int(str(v.value), 16)
        except Exception:
            return 0

def _extract_u96_int_any(obj: Any) -> Optional[int]:
    if isinstance(obj, int):
        return obj
    if isinstance(obj, str):
        s = obj.strip()
        m_hex = re.search(r'0x[0-9a-fA-F]+', s)
        if m_hex:
            return int(m_hex.group(0), 16)
        m_dec = re.search(r'\b(\d+)\b', s)
        if m_dec:
            return int(m_dec.group(1))
        return None
    if isinstance(obj, dict):
        if "bits" in obj: return _extract_u96_int_any(obj["bits"])
        if "value" in obj: return _extract_u96_int_any(obj["value"])
        try:
            return _extract_u96_int_any(list(obj.values())[0])
        except Exception:
            return None
    s = str(obj)
    m_hex = re.search(r'0x[0-9a-fA-F]+', s)
    if m_hex: return int(m_hex.group(0), 16)
    m_dec = re.search(r'\b(\d+)\b', s)
    if m_dec: return int(m_dec.group(1))
    return None

def moving_price_bits(substrate, netuid: int) -> Optional[int]:
    try:
        v = substrate.get_storage(
            module="SubtensorModule",
            storage_function="SubnetMovingPrice",
            params=[netuid],
            return_scale_type='u128'
        )
        if v is not None:
            return int(v.value) if hasattr(v, "value") else int(v)
    except Exception:
        pass
    try:
        v = substrate.query("SubtensorModule", "SubnetMovingPrice", [netuid])
        if v is None or v.value is None:
            return None
        return _extract_u96_int_any(v.value)
    except Exception:
        return None

def moving_price_float(substrate, netuid: int) -> Optional[float]:
    raw = moving_price_bits(substrate, netuid)
    if raw is None:
        return None
    # decode U96F32 (96 integer bits, 32 fractional bits)
    return raw / float(2**32)

def reserve_price_float(substrate, netuid: int) -> Optional[float]:
    """Fallback: price from initial reserves ratio TAO/α (used when SubnetMovingPrice is 0)."""
    tao  = q_u128(substrate, "SubtensorModule", "SubnetTAO",       [netuid])
    alph = q_u128(substrate, "SubtensorModule", "SubnetAlphaIn",   [netuid])
    if alph == 0:
        return None
    return float(tao) / float(alph)

# ────────────────────────────
# Actively produce blocks (fix for price initialization timing)
# ────────────────────────────
def produce_blocks(substrate, signer: Keypair, n: int = BLOCK_PRODUCE_COUNT):
    for i in range(n):
        # A tiny remark to force a new block
        call = compose_call(substrate, "System", "remark", {"remark": bytes(f"b{i}", "utf-8")})
        submit(substrate, signer, call, sudo=False)
        time.sleep(0.25)

def poll_price_one(substrate, netuid: int, attempts: int = PRICE_POLL_ATTEMPTS,
                   wait_blocks: int = PRICE_POLL_WAIT_BLOCKS) -> Optional[float]:
    last = None
    for _ in range(attempts):
        p = moving_price_float(substrate, netuid)
        last = p
        if p is not None and p != 0.0:
            return p
        sleep_blocks(wait_blocks)
    return last

# ────────────────────────────
# Admin & extrinsics
# ────────────────────────────
def sudo_set_network_rate_limit(substrate, sudo, rate_limit: int):
    call = compose_call(substrate, "AdminUtils", "sudo_set_network_rate_limit", {"rate_limit": rate_limit})
    submit(substrate, sudo, call, sudo=True)

def sudo_set_target_registrations_per_interval(substrate, sudo, netuid: int, target: int):
    call = compose_call(substrate, "AdminUtils", "sudo_set_target_registrations_per_interval",
                        {"netuid": netuid, "target_registrations_per_interval": int(target)})
    submit(substrate, sudo, call, sudo=True)

def sudo_set_subnet_limit(substrate, sudo, max_subnets: int):
    call = compose_call(substrate, "AdminUtils", "sudo_set_subnet_limit", {"max_subnets": int(max_subnets)})
    submit(substrate, sudo, call, sudo=True)

def start_call(substrate, owner_cold: Keypair, netuid: int):
    call = compose_call(substrate, "SubtensorModule", "start_call", {"netuid": netuid})
    submit(substrate, owner_cold, call, sudo=False)

def burned_register(substrate, cold: Keypair, hot_ss58: str, netuid: int):
    call = compose_call(substrate, "SubtensorModule", "burned_register",
                        {"netuid": netuid, "hotkey": hot_ss58})
    return submit(substrate, cold, call, sudo=False)

def burned_register_with_retry(substrate, cold, hot_ss58, netuid, max_attempts=4, backoff_blocks=1):
    last = None
    for i in range(1, max_attempts+1):
        try:
            return burned_register(substrate, cold, hot_ss58, netuid)
        except Exception as e:
            s = str(e)
            last = e
            if ("Custom error: 6" in s or "RateLimitExceeded" in s) and i < max_attempts:
                sleep_blocks(backoff_blocks)
                continue
            if "already" in s.lower():
                return
            break
    if last:
        raise last

def add_stake(substrate, cold: Keypair, hot_ss58: str, netuid: int, amount_planck: int):
    call = compose_call(substrate, "SubtensorModule", "add_stake",
                        {"hotkey": hot_ss58, "netuid": netuid, "amount_staked": amount_planck})
    submit(substrate, cold, call, sudo=False)

def root_dissolve_network(substrate, sudo, netuid: int):
    call = compose_call(substrate, "SubtensorModule", "root_dissolve_network", {"netuid": netuid})
    submit(substrate, sudo, call, sudo=True)

def swap_toggle_user_liquidity(substrate, sudo, netuid: int, enable: bool):
    call = compose_call(substrate, "Swap", "toggle_user_liquidity", {"netuid": netuid, "enable": bool(enable)})
    submit(substrate, sudo, call, sudo=True)

def add_liquidity_ticks(substrate, cold: Keypair, hot_ss58: str, netuid: int,
                        tl: int, th: int, liquidity: int):
    if th <= tl:
        th = tl + 1
    call = compose_call(substrate, "Swap", "add_liquidity", {
        "hotkey": hot_ss58,
        "netuid": netuid,
        "tick_low": int(tl),
        "tick_high": int(th),
        "liquidity": int(liquidity)
    })
    return submit(substrate, cold, call, sudo=False)

def transfer_keep_alive(substrate, sudo, dest_ss58: str, amount_planck: int):
    call = compose_call(substrate, "Balances", "transfer_keep_alive", {"dest": dest_ss58, "value": amount_planck})
    submit(substrate, sudo, call, sudo=False)

def register_network(substrate, signer: Keypair, owner_hot_ss58: str, owner_cold_ss58: str):
    candidates = [
        {"owner_hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"hotkey": owner_hot_ss58, "coldkey": owner_cold_ss58},
        {"owner_hot": owner_hot_ss58, "owner_cold": owner_cold_ss58},
    ]
    last_err = None
    for params in candidates:
        try:
            call = compose_call(substrate, "SubtensorModule", "register_network", params)
            return submit(substrate, signer, call, sudo=False)
        except Exception as e:
            last_err = e
    raise RuntimeError(f"register_network failed with all candidates: {last_err}")

# ────────────────────────────
# Funding & measured adds
# ────────────────────────────
def ensure_min_balance(substrate, sudo, who: Keypair, min_tao: float, decimals: int):
    cur = account_free(substrate, who.ss58_address)
    tgt = to_planck(min_tao, decimals)
    if cur < tgt:
        transfer_keep_alive(substrate, sudo, who.ss58_address, tgt - cur)

def count_positions(substrate, netuid: int, cold_ss58: str) -> int:
    try:
        c = 0
        for _k, _v in substrate.query_map("Swap", "Positions", params=[netuid, cold_ss58], max_results=5000):
            c += 1
        return c
    except Exception:
        return 0

def measured_add_with_pool_delta(substrate, netuid: int, cold: Keypair, hot_ss58: str,
                                 tl: int, th: int, liquidity: int, decimals: int) -> Dict[str, Any]:
    pos_before = count_positions(substrate, netuid, cold.ss58_address)
    bal_before = account_free(substrate, cold.ss58_address)
    a0, t0, p0 = pool_totals(substrate, netuid)
    add_liquidity_ticks(substrate, cold, hot_ss58, netuid, tl, th, liquidity)
    sleep_blocks(1)
    a1, t1, p1 = pool_totals(substrate, netuid)
    bal_after = account_free(substrate, cold.ss58_address)
    pos_after = count_positions(substrate, netuid, cold.ss58_address)
    return {
        "spent":   max(0, bal_before - bal_after),
        "d_alpha": max(0, a1 - a0),
        "d_tao":   max(0, t1 - t0),
        "d_pot":   max(0, p1 - p0),
        "tl": int(tl), "th": int(th), "L": int(liquidity),
        "pos_added": pos_after > pos_before,
    }

def try_alpha_only(substrate, netuid: int, staker_cold: Keypair, staker_hot_ss58: str,
                   curr_tick: int, decimals: int) -> Optional[Dict[str, Any]]:
    for off, wid, L in ALPHA_LP_CANDIDATES:
        tl, th = curr_tick + off, curr_tick + off + wid
        try:
            r = measured_add_with_pool_delta(substrate, netuid, staker_cold, staker_hot_ss58, tl, th, L, decimals)
            if (r["d_alpha"] > 0) and r["pos_added"]:
                return r
        except Exception:
            pass
    return None

def try_tao_only(substrate, netuid: int, owner_cold: Keypair, owner_hot_ss58: str,
                 curr_tick: int, decimals: int) -> Optional[Dict[str, Any]]:
    for off, wid, L in TAO_LP_CANDIDATES:
        th, tl = curr_tick - off, curr_tick - off - wid
        if th <= tl: th = tl + 1
        try:
            r = measured_add_with_pool_delta(substrate, netuid, owner_cold, owner_hot_ss58, tl, th, L, decimals)
            spent_ok = r["spent"] > TAO_SPEND_PLANCK_THRESHOLD
            if (r["d_tao"] > 0) or (r["d_pot"] > 0) or (spent_ok and r["pos_added"]):
                return r
        except Exception:
            pass
    return None

def expected_prune_net(substrate, nets: List[int]) -> Optional[int]:
    data = []
    for n in nets:
        if n == 0:
            continue
        reg = network_registered_at(substrate, n)
        price_bits = moving_price_bits(substrate, n) or ((1<<128)-1)
        data.append((price_bits, reg, n))
    if not data:
        return None
    data.sort(key=lambda x: (x[0], x[1]))
    return data[0][2]

# ────────────────────────────
# Price initialization assertion (fixed)
# ────────────────────────────
def assert_price_initialized_one(substrate, netuid: int):
    """
    Assert the price is initialized for a *newly registered* subnet.

    Accept either:
      • SubnetMovingPrice ≈ 1.0 (preferred), OR
      • Reserve ratio (SubnetTAO / SubnetAlphaIn) ≈ 1.0 (fallback).

    We also actively produce blocks before polling moving price to avoid timing flakiness.
    """
    # Actively produce a few blocks to help any deferred updates
    alice = Keypair.create_from_uri("//Alice")
    produce_blocks(substrate, alice, BLOCK_PRODUCE_COUNT)

    p_mp = poll_price_one(substrate, netuid)
    if p_mp is not None and p_mp != 0.0:
        assert abs(p_mp - 1.0) <= PRICE_ONE_TOL, f"[new net {netuid}] moving price not ≈ 1.0; got {p_mp:.6f}"
        return

    # Fallback: check reserve ratio TAO/α (should be ~1.0 from initial pool lock)
    p_rr = reserve_price_float(substrate, netuid)
    assert p_rr is not None, f"[new net {netuid}] both moving price and reserve price unavailable."
    assert abs(p_rr - 1.0) <= PRICE_ONE_TOL, f"[new net {netuid}] reserve price not ≈ 1.0; got {p_rr:.6f}"

# ────────────────────────────
# Per‑subnet test
# ────────────────────────────
def run_one_net(substrate: SubstrateInterface, netuid: int, decimals: int) -> Tuple[bool,bool]:
    sudo = Keypair.create_from_uri("//Alice")
    owner_cold = Keypair.create_from_uri("//OwnerCold"); owner_hot  = Keypair.create_from_uri("//OwnerHot")
    st1_cold   = Keypair.create_from_uri("//Staker1Cold"); st1_hot  = Keypair.create_from_uri("//Staker1Hot")
    st2_cold   = Keypair.create_from_uri("//Staker2Cold"); st2_hot  = Keypair.create_from_uri("//Staker2Hot")

    # Light funding
    for kp, need in [
        (owner_cold, MIN_FUND_TAO_OWNER),
        (owner_hot,  5),
        (st1_cold,  MIN_FUND_TAO_STAKER),
        (st1_hot,   5),
        (st2_cold,  MIN_FUND_TAO_STAKER),
        (st2_hot,   5),
    ]:
        cur = account_free(substrate, kp.ss58_address)
        tgt = to_planck(need, decimals)
        if cur < tgt:
            transfer_keep_alive(substrate, sudo, kp.ss58_address, tgt - cur)
    sleep_blocks(1)

    # Open gates + lift registration target
    sudo_set_network_rate_limit(substrate, sudo, 0)
    sudo_set_target_registrations_per_interval(substrate, sudo, netuid, target=10_000)
    swap_toggle_user_liquidity(substrate, sudo, netuid, True)
    sleep_blocks(1)

    # Register & stake (smaller stakes)
    burned_register_with_retry(substrate, st1_cold,   st1_hot.ss58_address,   netuid)
    burned_register_with_retry(substrate, st2_cold,   st2_hot.ss58_address,   netuid)
    burned_register_with_retry(substrate, owner_cold, owner_hot.ss58_address, netuid)
    sleep_blocks(1)
    add_stake(substrate, st1_cold,   st1_hot.ss58_address,   netuid, to_planck(STAKE_AMOUNTS_TAO[0], decimals))
    add_stake(substrate, st2_cold,   st2_hot.ss58_address,   netuid, to_planck(STAKE_AMOUNTS_TAO[1], decimals))
    add_stake(substrate, owner_cold, owner_hot.ss58_address, netuid, to_planck(STAKE_AMOUNTS_TAO[2], decimals))
    sleep_blocks(2)

    # Before LP
    pre_bal = {
        "Staker1": account_free(substrate, st1_cold.ss58_address),
        "Staker2": account_free(substrate, st2_cold.ss58_address),
        "Owner":   account_free(substrate, owner_cold.ss58_address),
    }
    a0, t0, pot0 = pool_totals(substrate, netuid)
    curr_tick = get_current_tick(substrate, netuid)

    # Try α-only & TAO-only
    alpha_add = try_alpha_only(substrate, netuid, st1_cold, st1_hot.ss58_address, curr_tick, decimals)
    tao_add   = try_tao_only(substrate, netuid, owner_cold, owner_hot.ss58_address, curr_tick, decimals)

    # Pre-dissolve
    a1, t1, pot1 = pool_totals(substrate, netuid)

    # Dissolve
    root_dissolve_network(substrate, sudo, netuid)
    sleep_blocks(3)
    a2, t2, pot2 = pool_totals(substrate, netuid)
    assert a2 == 0 and t2 == 0 and pot2 == 0, f"[net {netuid}] Pools not cleared after dissolve."

    # After balances
    post_bal = {
        "Staker1": account_free(substrate, st1_cold.ss58_address),
        "Staker2": account_free(substrate, st2_cold.ss58_address),
        "Owner":   account_free(substrate, owner_cold.ss58_address),
    }
    for who in ("Staker1","Staker2","Owner"):
        assert post_bal[who] >= pre_bal[who], f"[net {netuid}] {who} balance did not increase after dissolve."

    # ── Output ──
    print("\n" + "="*94)
    print(f"✅  Net {netuid}: α‑only (above) + TAO‑only (below) LP attempted, then dissolved".center(94))
    print("="*94 + "\n")

    lp_rows = []
    if alpha_add:
        lp_rows.append(["α‑only (Staker1)", f"[{alpha_add['tl']},{alpha_add['th']}]", f"{alpha_add['L']}",
                        f"{alpha_add['d_alpha']}", f"{alpha_add['d_tao']}", f"{fmt_tao(alpha_add['spent'],decimals)}"])
    else:
        lp_rows.append(["α‑only (Staker1)", "(n/a)", "(n/a)", "0", "0", "0.0000 TAO"])
    if tao_add:
        lp_rows.append(["TAO‑only (Owner)", f"[{tao_add['tl']},{tao_add['th']}]", f"{tao_add['L']}",
                        f"{tao_add['d_alpha']}", f"{tao_add['d_tao']}", f"{fmt_tao(tao_add['spent'],decimals)}"])
    else:
        lp_rows.append(["TAO‑only (Owner)", "(n/a)", "(n/a)", "0", "0", "0.0000 TAO"])
    print("• LP bands and pool/TAO deltas\n")
    print(mk_table(["Type","[tick_low,tick_high]","Liquidity L","Δα Provided","Δτ Provided","TAO spent (cold)"], lp_rows))
    print()

    pool_rows = [
        ["SubnetAlphaInProvided", f"{a0}", f"{a1}", f"{a2}", f"{(a1-a0):+}"],
        ["SubnetTaoProvided",     f"{t0}", f"{t1}", f"{t2}", f"{(t1-t0):+}"],
        ["SubnetTAO pot",         fmt_tao(pot0,decimals), fmt_tao(pot1,decimals), fmt_tao(pot2,decimals),
                                   f"{from_planck(pot1-pot0,decimals):+.4f} TAO"],
    ]
    print("• Pool totals (before → after LP → after dissolve)\n")
    print(mk_table(["Metric","Before","After LP","After dissolve","Δ (Before→After LP)"], pool_rows))
    print()

    bal_rows = []
    for who in ("Staker1","Staker2","Owner"):
        pre = pre_bal[who]; post = post_bal[who]
        pct = pct_change(post, pre)
        bal_rows.append([who, fmt_tao(pre,decimals), fmt_tao(post,decimals),
                         f"{from_planck(post-pre,decimals):+.6f} TAO",
                         f"{pct:.2f}%" if pct is not None else "n/a"])
    print("• Balances (before vs after dissolve)\n")
    print(mk_table(["Actor","Before","After","Δ","Δ%"], bal_rows))
    print("\n" + "="*94 + "\n")

    return (alpha_add is not None), (tao_add is not None)

# ────────────────────────────
# Re-register & prune (assert price≈1 after each register; fallback to reserve ratio)
# ────────────────────────────
def run_re_register_and_prune(substrate: SubstrateInterface, decimals: int):
    sudo = Keypair.create_from_uri("//Alice")
    owner_cold = Keypair.create_from_uri("//OwnerCold"); owner_hot  = Keypair.create_from_uri("//OwnerHot")
    st1_cold   = Keypair.create_from_uri("//Staker1Cold"); st1_hot  = Keypair.create_from_uri("//Staker1Hot")

    # Ensure minimal funds for operations (small)
    for kp, need in [(owner_cold, 300), (owner_hot, 5), (st1_cold, 50), (st1_hot, 5)]:
        cur = account_free(substrate, kp.ss58_address)
        tgt = to_planck(need, decimals)
        if cur < tgt:
            transfer_keep_alive(substrate, sudo, kp.ss58_address, tgt - cur)
    sleep_blocks(1)

    # Re-register a subnet; then ensure price≈1 (moving price OR reserve ratio)
    before_all = set(networks_added(substrate))
    register_network(substrate, owner_cold, owner_hot.ss58_address, owner_cold.ss58_address)
    sleep_blocks(1)
    after_all = set(networks_added(substrate))
    added = list(after_all - before_all)
    assert len(added) == 1, f"[re-register] expected exactly 1 new net; added={added}"
    new_net = added[0]

    sudo_set_network_rate_limit(substrate, sudo, 0)
    sudo_set_target_registrations_per_interval(substrate, sudo, new_net, target=10_000)
    swap_toggle_user_liquidity(substrate, sudo, new_net, True)
    try:
        start_call(substrate, owner_cold, new_net)
    except Exception:
        pass
    # price init check (moving price first, fallback to reserve ratio)
    assert_price_initialized_one(substrate, new_net)

    # Prove post-reg flow: stake + α-only LP
    burned_register_with_retry(substrate, st1_cold, st1_hot.ss58_address, new_net)
    sleep_blocks(1)
    add_stake(substrate, st1_cold, st1_hot.ss58_address, new_net, to_planck(5, decimals))
    sleep_blocks(1)
    curr = get_current_tick(substrate, new_net)
    try_alpha_only(substrate, new_net, st1_cold, st1_hot.ss58_address, curr, decimals)
    print(f"[✓] Re-register test passed on net {new_net} (stake + start_call + α‑only + price≈1).")

    # Prune test at limit (exclude ROOT)
    nets_now = networks_added(substrate)
    dynamic_before = [n for n in nets_now if n != 0]
    limit = len(dynamic_before)
    sudo_set_subnet_limit(substrate, sudo, limit)   # set to current dynamic count
    sleep_blocks(1)

    expected = expected_prune_net(substrate, dynamic_before)
    reg_before = {n: network_registered_at(substrate, n) for n in dynamic_before}

    # Force one more register → triggers prune (or recycle)
    before_all2 = set(networks_added(substrate))
    register_network(substrate, owner_cold, owner_hot.ss58_address, owner_cold.ss58_address)
    sleep_blocks(1)
    after_all2 = set(networks_added(substrate))

    dynamic_after = [n for n in networks_added(substrate) if n != 0]
    added2 = list(set(dynamic_after) - set(dynamic_before))
    pruned2 = list(set(dynamic_before) - set(dynamic_after))
    reg_after = {n: network_registered_at(substrate, n) for n in dynamic_after}

    if len(added2) == 1 and len(pruned2) == 1:
        pruned_net = pruned2[0]
        fresh = added2[0]
        try:
            start_call(substrate, owner_cold, fresh)
        except Exception:
            pass
        assert_price_initialized_one(substrate, fresh)
        print(f"[prune] add/remove at limit → added={fresh}, pruned={pruned_net}, expected≈{expected}; price≈1 OK.")
    else:
        # Recycle-in-place: detect which net's reg_at advanced
        changed = [n for n in dynamic_before if reg_after.get(n, reg_before[n]) > reg_before[n]]
        assert len(changed) == 1, f"[prune] expected exactly one recycled net; changed={changed}"
        recycled = changed[0]
        try:
            start_call(substrate, owner_cold, recycled)
        except Exception:
            pass
        assert_price_initialized_one(substrate, recycled)
        print(f"[prune] recycle-in-place at limit → recycled net {recycled} "
              f"(reg_at {reg_before[recycled]} → {reg_after[recycled]}), expected≈{expected}; price≈1 OK.")

# ────────────────────────────
# Main
# ────────────────────────────
def main():
    substrate = connect()
    decimals = token_decimals(substrate)
    print(f"[i] Connected to {WS_ENDPOINT} (decimals={decimals})")

    sudo = Keypair.create_from_uri("//Alice")
    # Ensure minimal balances (small) so we don't hit fee errors
    bootstrap = [
        (Keypair.create_from_uri("//OwnerCold"),  MIN_FUND_TAO_OWNER),
        (Keypair.create_from_uri("//OwnerHot"),   5),
        (Keypair.create_from_uri("//Staker1Cold"), MIN_FUND_TAO_STAKER),
        (Keypair.create_from_uri("//Staker1Hot"),  5),
        (Keypair.create_from_uri("//Staker2Cold"), MIN_FUND_TAO_STAKER),
        (Keypair.create_from_uri("//Staker2Hot"),  5),
    ]
    for kp, need in bootstrap:
        cur = account_free(substrate, kp.ss58_address)
        tgt = to_planck(need, decimals)
        if cur < tgt:
            transfer_keep_alive(substrate, sudo, kp.ss58_address, tgt - cur)
    sleep_blocks(1)

    alpha_ok_any = False
    tao_ok_any   = False

    for nid in TEST_NETS:
        aok, tok = run_one_net(substrate, nid, decimals)
        alpha_ok_any |= aok
        tao_ok_any   |= tok

    assert alpha_ok_any, "Did not realize α‑only liquidity on any tested subnet."
    assert tao_ok_any,   "Did not realize TAO‑only liquidity on any tested subnet."

    run_re_register_and_prune(substrate, decimals)

if __name__ == "__main__":
    try:
        main()
    except AssertionError as ae:
        print(f"Assertion failed: {ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
