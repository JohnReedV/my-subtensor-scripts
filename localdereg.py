#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Localnet E2E (tiny balances, register_network(origin, hotkey) signature):
- Clean localnet (ROOT + possibly one seeded subnet from genesis).
- Registers 4 fresh subnets and for each:
  * register_network (SIGNED BY OWNER COLD; param: hotkey only)
  * assert base-reserve price = 1 right after registration
  * start_call (owner) to enable Subtoken
  * open gates (rate_limit=0, user liquidity ON, target regs bumped)
  * register hotkeys (OwnerHot, Staker1Hot, Staker2Hot) with burned_register(cold -> hotkey)
  * stake tiny amounts to mint α (Staker1, Staker2)
  * add α-only LP (above) from Staker1 and TAO-only LP (below) from Owner
  * dissolve (root) and assert positions cleared & balances increased
  * concise logs per subnet
"""

import math
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

# ---------------------------------
# Endpoint
# ---------------------------------
WS_ENDPOINT = "ws://127.0.0.1:9945"

# ---------------------------------
# Tunables for tiny balances
# ---------------------------------
BLOCK_SLEEP_SEC = 0.4
BLOCK_PRODUCE_COUNT = 2

# Minimal balances to pay fees/ops
FUND_MIN_TAO_COLD = 20.0   # coldkeys
FUND_MIN_TAO_HOT  = 2.0    # hotkeys

# Small stakes to mint a bit of α
STAKE_AMOUNTS_TAO = [0.5, 0.5]

# Small LP liquidity values
L_ALPHA_LIQUIDITY = 300_000
L_TAO_LIQUIDITY   = 300_000

# Tick bands (narrow, near current)
ALPHA_OFFSETS = [500, 1000]   # above current (α-only)
ALPHA_WIDTHS  = [200]
TAO_OFFSETS   = [2500, 4000]  # below current (τ-only)
TAO_WIDTHS    = [300]

# Price ≈ 1 tolerance when asserting base-reserve price
PRICE_ONE_TOL = 1e-6

# Relax per-interval registration throttling
REG_TARGET_BUMP = 100

# Number of fresh subnets to register & test
FRESH_NET_COUNT = 4


# ------------------------------
# Substrate helpers
# ------------------------------
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

def fmt_tao(planck: int, decimals: int) -> str:
    base = 10 ** decimals
    return f"{planck / base:.4f} TAO"

def sleep_blocks(n: int = 1):
    time.sleep(BLOCK_SLEEP_SEC * max(1, n))

def produce_blocks(substrate: SubstrateInterface, count: int = BLOCK_PRODUCE_COUNT):
    time.sleep(BLOCK_SLEEP_SEC * max(1, count))


# -------------------------
# Compose + submit
# -------------------------
def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)

def submit(substrate: SubstrateInterface, keypair: Keypair, call, sudo: bool = False, tip: int = 0):
    if sudo:
        call = substrate.compose_call("Sudo", "sudo", {"call": call})
    xt = substrate.create_signed_extrinsic(call=call, keypair=keypair, tip=tip)
    try:
        receipt = substrate.submit_extrinsic(xt, wait_for_inclusion=True, wait_for_finalization=True)
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e
    if not receipt.is_success:
        raise RuntimeError(f"Extrinsic failed in block {receipt.block_hash}: {receipt.error_message}")
    return receipt


# -------------------------
# Storage queries
# -------------------------
def q_u128(substrate: SubstrateInterface, module: str, storage: str, args: List[Any]) -> Optional[int]:
    try:
        v = substrate.query(module, storage, args)
        if v is None or v.value is None:
            return None
        return int(v.value)
    except Exception:
        return None

def subnet_tao(substrate: SubstrateInterface, netuid: int) -> int:
    return q_u128(substrate, "SubtensorModule", "SubnetTAO", [netuid]) or 0

def subnet_alpha_in(substrate: SubstrateInterface, netuid: int) -> int:
    return q_u128(substrate, "SubtensorModule", "SubnetAlphaIn", [netuid]) or 0

def subnet_alpha_in_provided(substrate: SubstrateInterface, netuid: int) -> int:
    return q_u128(substrate, "SubtensorModule", "SubnetAlphaInProvided", [netuid]) or 0

def subnet_tao_provided(substrate: SubstrateInterface, netuid: int) -> int:
    return q_u128(substrate, "SubtensorModule", "SubnetTaoProvided", [netuid]) or 0

def alpha_sqrt_price(substrate: SubstrateInterface, netuid: int) -> Optional[float]:
    try:
        v = substrate.query("SubtensorModule", "AlphaSqrtPrice", [netuid])
        if v and v.value is not None:
            return float(v.value)
    except Exception:
        pass
    return None

def moving_price(substrate: SubstrateInterface, netuid: int) -> Optional[float]:
    sq = alpha_sqrt_price(substrate, netuid)
    return None if sq is None else float(sq) * float(sq)

def count_positions(substrate: SubstrateInterface, netuid: int, cold_ss58: str) -> int:
    try:
        entries = substrate.query_map("Swap", "Positions", [netuid, cold_ss58])
        return sum(1 for _ in entries)
    except Exception:
        return 0

def is_user_liquidity_enabled(substrate: SubstrateInterface, netuid: int) -> bool:
    try:
        v = substrate.query("Swap", "EnabledUserLiquidity", [netuid])
        return bool(v.value) if v and v.value is not None else False
    except Exception:
        return False

def account_free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0

def networks_added_dynamic(substrate: SubstrateInterface) -> List[int]:
    nets = []
    try:
        for (key, val) in substrate.query_map("SubtensorModule", "NetworksAdded"):
            if val and bool(val.value):
                kv = key.value
                n = int(kv["NetUid"]) if isinstance(kv, dict) and "NetUid" in kv else int(kv)
                if n != 0:
                    nets.append(n)
    except Exception:
        pass
    return sorted(set(nets))


# -------------------------
# Admin extrinsics
# -------------------------
def sudo_set_network_rate_limit(substrate: SubstrateInterface, sudo: Keypair, limit: int):
    call = compose_call(substrate, "AdminUtils", "sudo_set_network_rate_limit", {"rate_limit": limit})
    submit(substrate, sudo, call, sudo=True)

def toggle_user_liquidity(substrate: SubstrateInterface, sudo: Keypair, netuid: int, enable: bool):
    call = compose_call(substrate, "Swap", "toggle_user_liquidity", {"netuid": netuid, "enable": enable})
    submit(substrate, sudo, call, sudo=True)

def sudo_set_target_registrations_per_interval(substrate: SubstrateInterface, sudo: Keypair, netuid: int, target: int):
    call = compose_call(substrate, "AdminUtils", "sudo_set_target_registrations_per_interval",
                        {"netuid": netuid, "target_registrations_per_interval": target})
    submit(substrate, sudo, call, sudo=True)

def root_dissolve_network(substrate: SubstrateInterface, sudo: Keypair, netuid: int):
    call = compose_call(substrate, "SubtensorModule", "root_dissolve_network", {"netuid": netuid})
    submit(substrate, sudo, call, sudo=True)

def register_network(substrate: SubstrateInterface, signer_owner_cold: Keypair, owner_hot_ss58: str):
    # register_network(origin, hotkey)
    call = compose_call(substrate, "SubtensorModule", "register_network", {"hotkey": owner_hot_ss58})
    return submit(substrate, signer_owner_cold, call, sudo=False)

def start_call(substrate: SubstrateInterface, owner: Keypair, netuid: int):
    call = compose_call(substrate, "SubtensorModule", "start_call", {"netuid": netuid})
    submit(substrate, owner, call, sudo=False)

def burned_register(substrate: SubstrateInterface, cold_owner: Keypair, netuid: int, hotkey_ss58: str):
    """
    Correct call for new signature:
    burned_register(origin = COLDKEY SIGNER, netuid, hotkey = HOTKEY ACCOUNT)
    """
    call = compose_call(substrate, "SubtensorModule", "burned_register",
                        {"netuid": netuid, "hotkey": hotkey_ss58})
    submit(substrate, cold_owner, call, sudo=False)

def add_stake(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int, amount_planck: int):
    call = compose_call(substrate, "SubtensorModule", "add_stake", {
        "hotkey": hot_ss58,
        "netuid": netuid,
        "amount_staked": amount_planck
    })
    submit(substrate, cold, call, sudo=False)

def add_liquidity(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str,
                  netuid: int, tick_low: int, tick_high: int, liquidity: int):
    call = compose_call(substrate, "Swap", "add_liquidity", {
        "hotkey": hot_ss58,
        "netuid": netuid,
        "tick_low": int(tick_low),
        "tick_high": int(tick_high),
        "liquidity": int(liquidity),
    })
    submit(substrate, cold, call, sudo=False)

def transfer_keep_alive(substrate: SubstrateInterface, signer: Keypair, dest: str, amount: int):
    try:
        call = compose_call(substrate, "Balances", "transfer_keep_alive", {"dest": dest, "value": amount})
        submit(substrate, signer, call, sudo=False)
    except Exception:
        call = compose_call(substrate, "Balances", "transfer", {"dest": dest, "value": amount})
        submit(substrate, signer, call, sudo=False)


# -------------------------
# Funding helpers
# -------------------------
def ensure_funded(substrate: SubstrateInterface, from_kp: Keypair, to_ss58: str,
                  min_tau: float, decimals: int):
    have = account_free_balance(substrate, to_ss58)
    need = to_planck(min_tau, decimals)
    if have < need:
        delta = need - have
        delta = int(delta * 1.1) + 1  # headroom for fees
        try:
            transfer_keep_alive(substrate, from_kp, to_ss58, delta)
            sleep_blocks(1)
        except Exception:
            pass


# -------------------------
# Price assertions
# -------------------------
def reserve_price_float(substrate: SubstrateInterface, netuid: int) -> Optional[float]:
    alpha = subnet_alpha_in(substrate, netuid)
    if alpha == 0:
        return None
    tao = subnet_tao(substrate, netuid)
    return float(tao) / float(alpha)

def assert_price_initialized_one(substrate: SubstrateInterface, netuid: int):
    # Let state settle a tick
    produce_blocks(substrate, BLOCK_PRODUCE_COUNT)
    p_rr = reserve_price_float(substrate, netuid)
    assert p_rr is not None, f"[new net {netuid}] base reserve price unavailable (α reserve = 0)."
    assert abs(p_rr - 1.0) <= PRICE_ONE_TOL, \
        f"[new net {netuid}] base reserve price not ≈ 1.0; got {p_rr:.6f}."
    # Moving price (sqrt-price) may not be initialized until first LP/swap; do not assert here.


# -------------------------
# Formatting helpers
# -------------------------
def fmt_row(cols: List[str], widths: List[int]) -> str:
    parts = [f"{s:<{w}}" for s, w in zip(cols, widths)]
    return "│ " + "  ".join(parts) + " │"

def sep(widths: List[int]) -> str:
    total = sum(widths) + 2 + 2 * (len(widths)-1)
    return "┌" + "─"*(total) + "┐"

def mid(widths: List[int]) -> str:
    total = sum(widths) + 2 + 2 * (len(widths)-1)
    return "├" + "─"*(total) + "┤"

def bot(widths: List[int]) -> str:
    total = sum(widths) + 2 + 2 * (len(widths)-1)
    return "└" + "─"*(total) + "┘"

def print_section(title: str):
    bar = "=" * max(94, len(title) + 10)
    print(f"\n{bar}\n{title.center(len(bar))}\n{bar}\n")


# -------------------------
# LP helpers
# -------------------------
def register_hotkey_with_retry(substrate: SubstrateInterface, cold_owner: Keypair, netuid: int,
                               hotkey_ss58: str, max_tries: int = 6):
    """
    Registers (cold -> hotkey) on netuid handling per-block limits.
    """
    for i in range(1, max_tries+1):
        try:
            burned_register(substrate, cold_owner, netuid, hotkey_ss58)
            sleep_blocks(1)
            return
        except Exception as e:
            # If per-block limit or interval rate, wait and retry
            if "TooManyRegistrationsThisBlock" in str(e) or "TooManyRegistrationsThisInterval" in str(e):
                sleep_blocks(2)
                continue
            # If already registered, we are done
            if "HotKeyAlreadyRegisteredInSubNet" in str(e):
                return
            # Otherwise bubble up
            raise

def try_alpha_only(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int) -> Optional[Tuple[int,int,int]]:
    assert is_user_liquidity_enabled(substrate, netuid), f"[net {netuid}] user liquidity must be enabled before α-only LP."
    for off in ALPHA_OFFSETS:
        for w in ALPHA_WIDTHS:
            tl = -off - w
            th = -off
            try:
                add_liquidity(substrate, cold, hot_ss58, netuid, tl, th, L_ALPHA_LIQUIDITY)
                sleep_blocks(1)
                return (tl, th, L_ALPHA_LIQUIDITY)
            except Exception:
                continue
    return None

def try_tao_only(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int) -> Optional[Tuple[int,int,int]]:
    assert is_user_liquidity_enabled(substrate, netuid), f"[net {netuid}] user liquidity must be enabled before TAO-only LP."
    for off in TAO_OFFSETS:
        for w in TAO_WIDTHS:
            tl = -off - w
            th = -off
            try:
                add_liquidity(substrate, cold, hot_ss58, netuid, tl, th, L_TAO_LIQUIDITY)
                sleep_blocks(1)
                return (tl, th, L_TAO_LIQUIDITY)
            except Exception:
                continue
    return None


# -------------------------
# One-net end-to-end
# -------------------------
def run_one_net(substrate: SubstrateInterface, decimals: int, new_net: int):
    sudo       = Keypair.create_from_uri("//Alice")
    owner_cold = Keypair.create_from_uri("//OwnerCold")
    owner_hot  = Keypair.create_from_uri("//OwnerHot")
    st1_cold   = Keypair.create_from_uri("//Staker1Cold")
    st1_hot    = Keypair.create_from_uri("//Staker1Hot")
    st2_cold   = Keypair.create_from_uri("//Staker2Cold")
    st2_hot    = Keypair.create_from_uri("//Staker2Hot")

    # Fund accounts minimally for fees and small stakes
    for acct, min_amt in [
        (owner_cold.ss58_address, FUND_MIN_TAO_COLD),
        (owner_hot.ss58_address,  FUND_MIN_TAO_HOT),
        (st1_cold.ss58_address,   FUND_MIN_TAO_COLD),
        (st1_hot.ss58_address,    FUND_MIN_TAO_HOT),
        (st2_cold.ss58_address,   FUND_MIN_TAO_COLD),
        (st2_hot.ss58_address,    FUND_MIN_TAO_HOT),
    ]:
        ensure_funded(substrate, sudo, acct, min_amt, decimals)

    # start_call to enable Subtoken (owner-only)
    try:
        start_call(substrate, owner_cold, new_net)
    except Exception:
        pass

    # Open gates: rate limit -> 0, enable user liquidity, bump registration target
    try:
        sudo_set_network_rate_limit(substrate, sudo, 0)
    except Exception:
        pass
    if not is_user_liquidity_enabled(substrate, new_net):
        toggle_user_liquidity(substrate, sudo, new_net, True)
    try:
        sudo_set_target_registrations_per_interval(substrate, sudo, new_net, REG_TARGET_BUMP)
    except Exception:
        pass

    # --- IMPORTANT: register hotkeys on this subnet BEFORE stake/LP ---
    register_hotkey_with_retry(substrate, owner_cold, new_net, owner_hot.ss58_address)
    register_hotkey_with_retry(substrate, st1_cold,   new_net, st1_hot.ss58_address)
    register_hotkey_with_retry(substrate, st2_cold,   new_net, st2_hot.ss58_address)

    # Stake small amounts (Staker1, Staker2) to mint some α
    for (cold, hot), amt in zip([(st1_cold, st1_hot), (st2_cold, st2_hot)], STAKE_AMOUNTS_TAO):
        try:
            add_stake(substrate, cold, hot.ss58_address, new_net, to_planck(amt, decimals))
            sleep_blocks(1)
        except Exception:
            pass

    # Snapshot balances & pool
    pre_bal = {
        "Staker1": account_free_balance(substrate, st1_cold.ss58_address),
        "Staker2": account_free_balance(substrate, st2_cold.ss58_address),
        "Owner":   account_free_balance(substrate, owner_cold.ss58_address),
    }
    alpha_before = subnet_alpha_in_provided(substrate, new_net)
    tao_before   = subnet_tao_provided(substrate, new_net)
    pot_before   = subnet_tao(substrate, new_net)

    # Try to add α-only (Staker1) and τ-only (Owner)
    alpha_band = try_alpha_only(substrate, st1_cold,  st1_hot.ss58_address,  new_net)
    tao_band   = try_tao_only(substrate,  owner_cold, owner_hot.ss58_address, new_net)

    alpha_after = subnet_alpha_in_provided(substrate, new_net)
    tao_after   = subnet_tao_provided(substrate, new_net)
    pot_after   = subnet_tao(substrate, new_net)

    d_alpha = max(alpha_after - alpha_before, 0)
    d_tao   = max(tao_after   - tao_before,   0)
    d_pot   = max(pot_after   - pot_before,   0)

    # Pretty logs (per net)
    print_section(f"✅  Net {new_net}: α‑only (above) + TAO‑only (below) LP attempted, then dissolved")

    widths = [18, 22, 13, 13, 18]
    print("• LP bands and pool/TAO deltas\n")
    print(sep(widths))
    print(fmt_row(["Type", "[tick_low,tick_high]", "Liquidity L", "Δα Provided", "Δτ Provided"], widths))
    print(mid(widths))
    def bstr(b): return f"[{b[0]},{b[1]}]" if b else "(n/a)"
    def Lstr(b): return f"{b[2]}" if b else "(n/a)"
    print(fmt_row(["α‑only (Staker1)", bstr(alpha_band), Lstr(alpha_band), f"{d_alpha}", "0"], widths))
    print(fmt_row(["TAO‑only (Owner)", bstr(tao_band),   Lstr(tao_band),   "0",         f"{d_tao}"], widths))
    print(bot(widths))

    widths2 = [23, 16, 16, 19]
    print("\n• Pool totals (before → after LP → after dissolve)\n")
    print(sep(widths2))
    print(fmt_row(["Metric", "Before", "After LP", "After dissolve  Δ (Before→After LP)"], widths2))
    print(mid(widths2))
    print(fmt_row(["SubnetAlphaInProvided", f"{alpha_before}", f"{alpha_after}", f"0               +{d_alpha}"], widths2))
    print(fmt_row(["SubnetTaoProvided",     f"{tao_before}",   f"{tao_after}",   f"0               +{d_tao}"], widths2))
    print(fmt_row(["SubnetTAO pot",         fmt_tao(pot_before, decimals), fmt_tao(pot_after, decimals),
                   f"0.0000 TAO      +{fmt_tao(d_pot, decimals)}"], widths2))
    print(bot(widths2))

    # Dissolve and assert positions cleared & refunds
    pre_pos_counts = {
        "Staker1": count_positions(substrate, new_net, st1_cold.ss58_address),
        "Staker2": count_positions(substrate, new_net, st2_cold.ss58_address),
        "Owner":   count_positions(substrate, new_net, owner_cold.ss58_address),
    }

    root_dissolve_network(substrate, Keypair.create_from_uri("//Alice"), new_net)
    sleep_blocks(2)

    for who in (st1_cold.ss58_address, st2_cold.ss58_address, owner_cold.ss58_address):
        assert count_positions(substrate, new_net, who) == 0, f"[net {new_net}] positions remained for {who} after dissolve."

    post_bal = {
        "Staker1": account_free_balance(substrate, st1_cold.ss58_address),
        "Staker2": account_free_balance(substrate, st2_cold.ss58_address),
        "Owner":   account_free_balance(substrate, owner_cold.ss58_address),
    }
    for who in ("Staker1","Staker2","Owner"):
        assert post_bal[who] >= pre_bal[who], f"[net {new_net}] {who} balance did not increase after dissolve."

    widths3 = [9, 16, 16, 15, 7]
    print("\n• Balances (before vs after dissolve)\n")
    print(sep(widths3))
    print(fmt_row(["Actor", "Before", "After", "Δ", "Δ%"], widths3))
    print(mid(widths3))
    for who in ("Staker1","Staker2","Owner"):
        pre = pre_bal[who]; post = post_bal[who]
        d = post - pre
        pct = 0.0 if pre == 0 else 100.0 * (post - pre) / pre
        print(fmt_row([who, fmt_tao(pre, decimals), fmt_tao(post, decimals),
                       f"{d/(10**decimals):.6f} TAO", f"{pct:.2f}%"], widths3))
    print(bot(widths3))


# -------------------------
# Register N fresh nets and test each
# -------------------------
def register_fresh_net(substrate: SubstrateInterface, owner_cold: Keypair, owner_hot: Keypair) -> int:
    before = networks_added_dynamic(substrate)
    register_network(substrate, owner_cold, owner_hot.ss58_address)
    sleep_blocks(2)
    after = networks_added_dynamic(substrate)
    added = sorted(set(after) - set(before))
    assert len(added) == 1, f"Expected exactly one new net; got {added}"
    net = added[0]
    # Assert initial price via base reserves immediately after register
    assert_price_initialized_one(substrate, net)
    return net


# -------------------------
# Main
# -------------------------
def main():
    substrate = connect()
    decimals = token_decimals(substrate)
    print(f"[i] Connected to {WS_ENDPOINT} (decimals={decimals})")

    alice      = Keypair.create_from_uri("//Alice")
    owner_cold = Keypair.create_from_uri("//OwnerCold")
    owner_hot  = Keypair.create_from_uri("//OwnerHot")

    # Ensure owner & hot have funds to pay fees/locks (from Alice)
    for acct, min_amt in [
        (owner_cold.ss58_address, FUND_MIN_TAO_COLD),
        (owner_hot.ss58_address,  FUND_MIN_TAO_HOT),
    ]:
        ensure_funded(substrate, alice, acct, min_amt, decimals)

    # 1) Register 4 fresh subnets
    fresh = []
    for _ in range(FRESH_NET_COUNT):
        net = register_fresh_net(substrate, owner_cold, owner_hot)
        fresh.append(net)

    # 2) For each fresh subnet, run the end-to-end LP + dissolve checks
    for net in fresh:
        run_one_net(substrate, decimals, net)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as ae:
        print(f"Assertion failed: {ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
