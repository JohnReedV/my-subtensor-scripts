#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Localnet E2E (tiny balances + auto-fund for dynamic subnet lock cost):

Fixes CannotAffordLockCost by auto-topping-up the registrar coldkey (//OwnerCold)
from //Alice until register_network succeeds (lock cost can be > 20 TAO and can
grow rapidly across consecutive registrations).

Flow:
- Connect localnet
- (sudo) set register-network rate limit to 0
- Register N fresh subnets (auto-fund if needed)
- For each subnet:
  * ensure start_call succeeds (wait/retry if needed)
  * open gates (user liquidity ON, target regs bumped)
  * burned_register hotkeys
  * stake tiny amounts to mint α
  * add α-only LP (above) + TAO-only LP (below) if possible
  * dissolve (root) and assert positions cleared & balances increased
"""

import sys
import time
from decimal import Decimal, ROUND_HALF_UP, getcontext
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

# Increase Decimal precision for large TAO → planck conversions
getcontext().prec = 60

# ---------------------------------
# Endpoint
# ---------------------------------
WS_ENDPOINT = "ws://127.0.0.1:9945"

# ---------------------------------
# Tunables
# ---------------------------------
BLOCK_SLEEP_SEC = 0.40
BLOCK_PRODUCE_COUNT = 2

# Minimal balances to pay fees/ops (NOT including subnet lock)
FUND_MIN_TAO_COLD = 20.0   # coldkeys
FUND_MIN_TAO_HOT  = 2.0    # hotkeys

# Auto-fund parameters for register_network lock cost
# (starts here, doubles on every CannotAffordLockCost retry)
REGISTER_TOPUP_START_TAO = 100.0
REGISTER_TOPUP_MAX_TRIES = 24  # allows very large lock costs safely

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

def to_planck(amount_tao: float, decimals: int) -> int:
    # Use Decimal to avoid float precision issues at large amounts.
    d = Decimal(str(amount_tao)) * (Decimal(10) ** decimals)
    return int(d.to_integral_value(rounding=ROUND_HALF_UP))

def fmt_tao(planck: int, decimals: int) -> str:
    base = Decimal(10) ** decimals
    return f"{(Decimal(planck) / base):.4f} TAO"

def sleep_blocks(n: int = 1):
    time.sleep(BLOCK_SLEEP_SEC * max(1, n))

def produce_blocks(_: SubstrateInterface, count: int = BLOCK_PRODUCE_COUNT):
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
        receipt = substrate.submit_extrinsic(
            xt, wait_for_inclusion=True, wait_for_finalization=True
        )
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e
    if not receipt.is_success:
        raise RuntimeError(
            f"Extrinsic failed in block {receipt.block_hash}: {receipt.error_message}"
        )
    return receipt


# -------------------------
# Storage queries
# -------------------------
def q_any(substrate: SubstrateInterface, module: str, storage: str, args: Optional[List[Any]] = None) -> Any:
    try:
        v = substrate.query(module, storage, args or [])
        return None if v is None else v.value
    except Exception:
        return None

def q_u128(substrate: SubstrateInterface, module: str, storage: str, args: List[Any]) -> Optional[int]:
    v = q_any(substrate, module, storage, args)
    if v is None:
        return None
    try:
        return int(v)
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

def account_free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0

def count_positions(substrate: SubstrateInterface, netuid: int, cold_ss58: str) -> int:
    try:
        entries = substrate.query_map("Swap", "Positions", [netuid, cold_ss58])
        return sum(1 for _ in entries)
    except Exception:
        return 0

def is_user_liquidity_enabled(substrate: SubstrateInterface, netuid: int) -> bool:
    v = q_any(substrate, "Swap", "EnabledUserLiquidity", [netuid])
    return bool(v) if v is not None else False


# -------------------------
# Event parsing
# -------------------------
def extract_network_added_netuid(receipt) -> Optional[int]:
    """
    Reads the emitted NetworkAdded(netuid, mechid) event from the extrinsic receipt.
    Works even if pruning causes netuid reuse (diffing NetworksAdded would fail).
    """
    try:
        for ev in receipt.triggered_events:
            v = getattr(ev, "value", None)
            if not isinstance(v, dict):
                continue
            e = v.get("event") or {}
            mod = e.get("module_id")
            eid = e.get("event_id")
            attrs = e.get("attributes") or []
            if mod == "SubtensorModule" and eid == "NetworkAdded" and len(attrs) >= 1:
                return int(attrs[0])
    except Exception:
        pass
    return None


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
    call = compose_call(
        substrate,
        "AdminUtils",
        "sudo_set_target_registrations_per_interval",
        {"netuid": netuid, "target_registrations_per_interval": target},
    )
    submit(substrate, sudo, call, sudo=True)

def root_dissolve_network(substrate: SubstrateInterface, sudo: Keypair, netuid: int):
    call = compose_call(substrate, "SubtensorModule", "root_dissolve_network", {"netuid": netuid})
    submit(substrate, sudo, call, sudo=True)


# -------------------------
# Core extrinsics
# -------------------------
def register_network(substrate: SubstrateInterface, signer_owner_cold: Keypair, owner_hot_ss58: str):
    """
    Compatible with both call signatures:
      - register_network(hotkey)
      - register_network(hotkey, mechid, identity)  (mechid=1 required by your runtime)
    """
    # Try newer signature first
    try:
        call = compose_call(
            substrate,
            "SubtensorModule",
            "register_network",
            {"hotkey": owner_hot_ss58, "mechid": 1, "identity": None},
        )
    except Exception:
        # Fallback to old signature
        call = compose_call(
            substrate,
            "SubtensorModule",
            "register_network",
            {"hotkey": owner_hot_ss58},
        )
    return submit(substrate, signer_owner_cold, call, sudo=False)

def start_call(substrate: SubstrateInterface, owner: Keypair, netuid: int):
    call = compose_call(substrate, "SubtensorModule", "start_call", {"netuid": netuid})
    submit(substrate, owner, call, sudo=False)

def burned_register(substrate: SubstrateInterface, cold_owner: Keypair, netuid: int, hotkey_ss58: str):
    call = compose_call(substrate, "SubtensorModule", "burned_register", {"netuid": netuid, "hotkey": hotkey_ss58})
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
def ensure_funded(substrate: SubstrateInterface, from_kp: Keypair, to_ss58: str, min_tao: float, decimals: int):
    have = account_free_balance(substrate, to_ss58)
    need = to_planck(min_tao, decimals)
    if have < need:
        delta = need - have
        delta = int(delta * 1.10) + 1  # headroom
        transfer_keep_alive(substrate, from_kp, to_ss58, delta)
        sleep_blocks(1)

def register_network_with_autofund(
    substrate: SubstrateInterface,
    funder: Keypair,
    owner_cold: Keypair,
    owner_hot: Keypair,
    decimals: int,
) -> Tuple[int, Any]:
    """
    Attempts register_network; on CannotAffordLockCost / BalanceWithdrawalError:
    tops up owner_cold from funder (Alice) with exponentially increasing amounts
    until it succeeds.
    """
    topup = REGISTER_TOPUP_START_TAO

    for i in range(1, REGISTER_TOPUP_MAX_TRIES + 1):
        try:
            receipt = register_network(substrate, owner_cold, owner_hot.ss58_address)
            sleep_blocks(2)
            netuid = extract_network_added_netuid(receipt)
            if netuid is None:
                raise RuntimeError("register_network succeeded but could not extract netuid from NetworkAdded event.")
            return netuid, receipt

        except RuntimeError as e:
            msg = str(e)

            # If rate-limited, just wait a bit and retry.
            if "NetworkTxRateLimitExceeded" in msg:
                sleep_blocks(3)
                continue

            # If lock cost / withdraw error, top up and retry.
            if ("CannotAffordLockCost" in msg) or ("BalanceWithdrawalError" in msg):
                planck = to_planck(topup, decimals)
                transfer_keep_alive(substrate, funder, owner_cold.ss58_address, planck)
                sleep_blocks(2)
                topup *= 2.0
                continue

            # Anything else is real failure.
            raise

    raise RuntimeError(
        f"register_network still failing after {REGISTER_TOPUP_MAX_TRIES} top-ups. "
        f"Last topup attempted was ~{topup/2:.2f} TAO. Check chain lock params."
    )


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
    produce_blocks(substrate, BLOCK_PRODUCE_COUNT)
    p_rr = reserve_price_float(substrate, netuid)
    assert p_rr is not None, f"[new net {netuid}] base reserve price unavailable (α reserve = 0)."
    assert abs(p_rr - 1.0) <= PRICE_ONE_TOL, f"[new net {netuid}] base reserve price not ≈ 1.0; got {p_rr:.10f}."


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
# Registration helpers
# -------------------------
def ensure_start_call(substrate: SubstrateInterface, owner_cold: Keypair, netuid: int, max_tries: int = 80):
    """
    start_call can require waiting DurationOfStartCall blocks after registration.
    This retries until success (or already started).
    """
    for _ in range(max_tries):
        try:
            start_call(substrate, owner_cold, netuid)
            sleep_blocks(1)
            return
        except Exception as e:
            s = str(e)
            if "FirstEmissionBlockNumberAlreadySet" in s:
                return
            if "NeedWaitingMoreBlocksToStarCall" in s:
                sleep_blocks(2)
                continue
            # If pallet rejects for another reason, don't hide it.
            raise

    raise RuntimeError(f"[net {netuid}] start_call still not allowed after retries; check DurationOfStartCall.")

def register_hotkey_with_retry(substrate: SubstrateInterface, cold_owner: Keypair, netuid: int,
                               hotkey_ss58: str, max_tries: int = 10):
    """
    Registers (cold -> hotkey) on netuid handling per-block / per-interval limits.
    """
    for _ in range(max_tries):
        try:
            burned_register(substrate, cold_owner, netuid, hotkey_ss58)
            sleep_blocks(1)
            return
        except Exception as e:
            s = str(e)
            if "TooManyRegistrationsThisBlock" in s or "TooManyRegistrationsThisInterval" in s:
                sleep_blocks(2)
                continue
            if "HotKeyAlreadyRegisteredInSubNet" in s:
                return
            raise
    raise RuntimeError(f"[net {netuid}] burned_register retry limit hit for hotkey {hotkey_ss58}.")


# -------------------------
# LP helpers
# -------------------------
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
def run_one_net(substrate: SubstrateInterface, decimals: int, netuid: int):
    sudo       = Keypair.create_from_uri("//Alice")
    owner_cold = Keypair.create_from_uri("//OwnerCold")
    owner_hot  = Keypair.create_from_uri("//OwnerHot")
    st1_cold   = Keypair.create_from_uri("//Staker1Cold")
    st1_hot    = Keypair.create_from_uri("//Staker1Hot")
    st2_cold   = Keypair.create_from_uri("//Staker2Cold")
    st2_hot    = Keypair.create_from_uri("//Staker2Hot")

    # Fund non-registrar accounts minimally for fees and small stakes
    for acct, min_amt in [
        (owner_hot.ss58_address,  FUND_MIN_TAO_HOT),
        (st1_cold.ss58_address,   FUND_MIN_TAO_COLD),
        (st1_hot.ss58_address,    FUND_MIN_TAO_HOT),
        (st2_cold.ss58_address,   FUND_MIN_TAO_COLD),
        (st2_hot.ss58_address,    FUND_MIN_TAO_HOT),
    ]:
        ensure_funded(substrate, sudo, acct, min_amt, decimals)

    # Ensure start_call actually succeeds (wait if required)
    ensure_start_call(substrate, owner_cold, netuid)

    # Open gates: enable user liquidity, bump registration target
    if not is_user_liquidity_enabled(substrate, netuid):
        toggle_user_liquidity(substrate, sudo, netuid, True)
    try:
        sudo_set_target_registrations_per_interval(substrate, sudo, netuid, REG_TARGET_BUMP)
    except Exception:
        pass

    # Register hotkeys on this subnet BEFORE stake/LP
    register_hotkey_with_retry(substrate, owner_cold, netuid, owner_hot.ss58_address)
    register_hotkey_with_retry(substrate, st1_cold,   netuid, st1_hot.ss58_address)
    register_hotkey_with_retry(substrate, st2_cold,   netuid, st2_hot.ss58_address)

    # Stake small amounts (Staker1, Staker2)
    for (cold, hot), amt in zip([(st1_cold, st1_hot), (st2_cold, st2_hot)], STAKE_AMOUNTS_TAO):
        try:
            add_stake(substrate, cold, hot.ss58_address, netuid, to_planck(amt, decimals))
            sleep_blocks(1)
        except Exception:
            pass

    # Snapshot balances & pool before LP
    pre_bal = {
        "Staker1": account_free_balance(substrate, st1_cold.ss58_address),
        "Staker2": account_free_balance(substrate, st2_cold.ss58_address),
        "Owner":   account_free_balance(substrate, owner_cold.ss58_address),
    }
    alpha_before = subnet_alpha_in_provided(substrate, netuid)
    tao_before   = subnet_tao_provided(substrate, netuid)
    pot_before   = subnet_tao(substrate, netuid)

    # Try LP adds
    alpha_band = try_alpha_only(substrate, st1_cold,  st1_hot.ss58_address,   netuid)
    tao_band   = try_tao_only(substrate,  owner_cold, owner_hot.ss58_address, netuid)

    alpha_after = subnet_alpha_in_provided(substrate, netuid)
    tao_after   = subnet_tao_provided(substrate, netuid)
    pot_after   = subnet_tao(substrate, netuid)

    d_alpha = max(alpha_after - alpha_before, 0)
    d_tao   = max(tao_after   - tao_before,   0)
    d_pot   = max(pot_after   - pot_before,   0)

    # Pretty logs
    print_section(f"✅  Net {netuid}: α‑only (above) + TAO‑only (below) LP attempted, then dissolved")

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

    widths2 = [23, 16, 16, 28]
    print("\n• Pool totals (before → after LP)\n")
    print(sep(widths2))
    print(fmt_row(["Metric", "Before", "After LP", "Δ (Before→After LP)"], widths2))
    print(mid(widths2))
    print(fmt_row(["SubnetAlphaInProvided", f"{alpha_before}", f"{alpha_after}", f"+{d_alpha}"], widths2))
    print(fmt_row(["SubnetTaoProvided",     f"{tao_before}",   f"{tao_after}",   f"+{d_tao}"], widths2))
    print(fmt_row(["SubnetTAO pot",         fmt_tao(pot_before, decimals), fmt_tao(pot_after, decimals),
                   f"+{fmt_tao(d_pot, decimals)}"], widths2))
    print(bot(widths2))

    # Dissolve and assert positions cleared & refunds
    root_dissolve_network(substrate, Keypair.create_from_uri("//Alice"), netuid)
    sleep_blocks(2)

    for who in (st1_cold.ss58_address, st2_cold.ss58_address, owner_cold.ss58_address):
        assert count_positions(substrate, netuid, who) == 0, f"[net {netuid}] positions remained for {who} after dissolve."

    post_bal = {
        "Staker1": account_free_balance(substrate, st1_cold.ss58_address),
        "Staker2": account_free_balance(substrate, st2_cold.ss58_address),
        "Owner":   account_free_balance(substrate, owner_cold.ss58_address),
    }
    for who in ("Staker1", "Staker2", "Owner"):
        assert post_bal[who] >= pre_bal[who], f"[net {netuid}] {who} balance did not increase after dissolve."

    widths3 = [9, 16, 16, 15, 7]
    print("\n• Balances (before vs after dissolve)\n")
    print(sep(widths3))
    print(fmt_row(["Actor", "Before", "After", "Δ", "Δ%"], widths3))
    print(mid(widths3))
    for who in ("Staker1", "Staker2", "Owner"):
        pre = pre_bal[who]
        post = post_bal[who]
        d = post - pre
        pct = 0.0 if pre == 0 else 100.0 * (post - pre) / pre
        print(fmt_row([who, fmt_tao(pre, decimals), fmt_tao(post, decimals),
                       f"{Decimal(d) / (Decimal(10) ** decimals):.6f} TAO", f"{pct:.2f}%"], widths3))
    print(bot(widths3))


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

    # Turn off register-network rate limiting up front (so we can register multiple subnets quickly)
    try:
        sudo_set_network_rate_limit(substrate, alice, 0)
    except Exception:
        pass

    # Minimal funding for owner hot/cold for fees (lock cost is handled by auto-funding during registration)
    ensure_funded(substrate, alice, owner_hot.ss58_address,  FUND_MIN_TAO_HOT,  decimals)
    ensure_funded(substrate, alice, owner_cold.ss58_address, FUND_MIN_TAO_COLD, decimals)

    # Register fresh subnets (auto-funds OwnerCold to cover dynamic lock cost)
    fresh: List[int] = []
    for i in range(FRESH_NET_COUNT):
        netuid, _ = register_network_with_autofund(substrate, alice, owner_cold, owner_hot, decimals)
        assert_price_initialized_one(substrate, netuid)
        print(f"[i] Registered subnet {i+1}/{FRESH_NET_COUNT}: netuid={netuid}")
        fresh.append(netuid)

    # Run E2E per subnet
    for netuid in fresh:
        run_one_net(substrate, decimals, netuid)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as ae:
        print(f"Assertion failed: {ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
