
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tao_sandwich.py

MEV-style sandwicher for Bittensor by *targeting add/remove stake* in the mempool,
but executing our two legs with `swap_stake` routed via root (netuid 0) so we avoid
non-root unstake fees.

- Watches the mempool for: add_stake(+_limit) and remove_stake(+_limit) on non-root subnets
- For ADD(netuid N):      front 0->N, then back N->0
- For REMOVE(netuid N):   front N->0, then back 0->N
- Executes exactly ONE sandwich at a time; waits for front inclusion before back
- Avoids SameNetuid (e.g., 0->0) and ignores add/remove against root
- Distinct nonce/tip for legs, proper error decoding, adaptive "AmountTooLow" floors
- Prompts for wallet password only once (or read via --password)

Usage:
  python3 ./tao_sandwich.py \
    --ws wss://entrypoint-finney.opentensor.ai \
    --poll 0.05 \
    --min-tao 2 \
    --min-alpha 20000000000 \
    --ratio 0.08 \
    --cooldown 2.0
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import traceback
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Third-party deps
import getpass as _getpass
import bittensor as bt
from substrateinterface import SubstrateInterface, Keypair
from scalecodec.base import ScaleBytes

###############################################################################
# Logging
###############################################################################

LOG = logging.getLogger("tao_sandwich")


def setup_logging(debug: bool) -> None:
    # Clean, compact format; no noisy mempool spam anywhere
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(level=level, format=fmt)


###############################################################################
# Args
###############################################################################

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Sandwich add/remove stakes with swap_stake legs via root (netuid 0).")

    p.add_argument("--ws", type=str, required=True, help="Substrate WebSocket endpoint, e.g. wss://entrypoint-finney.opentensor.ai")
    p.add_argument("--poll", type=float, default=0.05, help="Polling interval for mempool scan (seconds).")
    p.add_argument("--cooldown", type=float, default=2.0, help="Cooldown between sandwiches (seconds).")

    # Victim filters / sizing
    p.add_argument("--min-tao", type=float, default=0.0, help="Minimum victim TAO for ADDs (whole TAO).")
    p.add_argument("--ratio", type=float, default=0.08, help="Fraction of victim amount to size our leg (REMOVE only).")
    p.add_argument("--min-alpha", type=int, default=20_000_000_000, help="Initial per-leg alpha floor (raw units).")

    # Wallet
    p.add_argument("--wallet-name", type=str, default="mev", help="Bittensor wallet name (coldkey dir).")
    p.add_argument("--hotkey-name", type=str, default="mev_hot", help="Bittensor hotkey name.")
    p.add_argument("--password", type=str, default=None, help="Wallet password (optional; to avoid prompt).")

    # Debug
    p.add_argument("--debug", action="store_true", help="Enable debug logging.")

    return p.parse_args(argv)


###############################################################################
# Single password prompt (patch all import styles of getpass.getpass)
###############################################################################

_PASS_CACHE: Optional[str] = None
_ORIG_GETPASS = _getpass.getpass


def _prompt_password_once(prompt: str = "Enter your password: ") -> str:
    global _PASS_CACHE
    if _PASS_CACHE is None:
        _PASS_CACHE = _ORIG_GETPASS(prompt)
        LOG.info("Decrypting...")
    return _PASS_CACHE


def init_password_flow(args: argparse.Namespace) -> str:
    """
    Ensure we prompt at most ONCE. Patch both the module object and sys.modules entry,
    so downstream libraries that import getpass in different ways all use the cache.
    """
    global _PASS_CACHE

    if args.password is not None:
        _PASS_CACHE = args.password

        def _no_prompt(prompt: str = "") -> str:
            return _PASS_CACHE

        try:
            import getpass
            getpass.getpass = _no_prompt
            sys.modules.get("getpass").getpass = _no_prompt
        except Exception:
            pass
        return _PASS_CACHE

    # Interactive path
    try:
        import getpass
        getpass.getpass = _prompt_password_once
        sys.modules.get("getpass").getpass = _prompt_password_once
    except Exception:
        pass

    # First-time read
    return _prompt_password_once("Enter your password: ")


###############################################################################
# Substrate helpers
###############################################################################

def connect(url: str) -> SubstrateInterface:
    substrate = SubstrateInterface(
        url=url,
        use_remote_preset=True,
        auto_discover=True,
    )
    try:
        chain = substrate.rpc_request("system_chain", []).get("result", None)
        rt = substrate.rpc_request("state_getRuntimeVersion", []).get("result", {})
        head = substrate.rpc_request("chain_getHead", []).get("result", None)
        health = substrate.rpc_request("system_health", []).get("result", {})
        LOG.info("[node] chain=%s specVersion=%s bestHeader=%s", chain, rt.get("specVersion"), (head or "None")[:8] if head else None)
        LOG.info("[hb] health=%s bestHeader=%s", {"peers": health.get("peers"), "isSyncing": health.get("isSyncing"), "shouldHavePeers": health.get("shouldHavePeers")}, (head or "None")[:8] if head else None)
    except Exception as e:
        LOG.debug("node warmup failed: %s", str(e))
    return substrate


def compose_call(substrate: SubstrateInterface, call_module: str, call_function: str, call_params: Dict[str, Any]):
    if hasattr(substrate, "compose_call"):
        return substrate.compose_call(call_module=call_module, call_function=call_function, call_params=call_params)
    if hasattr(substrate, "create_call"):
        return substrate.create_call(call_module=call_module, call_function=call_function, call_params=call_params)
    raise AttributeError("'SubstrateInterface' has no compose_call/create_call")


def get_account_next_index(substrate: SubstrateInterface, address: str) -> int:
    try:
        return substrate.get_account_next_index(address)
    except Exception:
        res = substrate.rpc_request("system_accountNextIndex", [address])
        val = res.get("result", 0)
        if isinstance(val, str):
            try:
                return int(val, 0)
            except Exception:
                return int(val)
        return int(val)


###############################################################################
# Wallet
###############################################################################

@dataclass
class WalletBundle:
    wallet: Any
    cold: Keypair
    hot: Keypair


def load_wallet(args: argparse.Namespace, password: str) -> WalletBundle:
    wallet = bt.wallet(name=args.wallet_name, hotkey=args.hotkey_name)

    # Seed passphrases if the version exposes these fields (prevents extra prompts)
    try:
        if hasattr(wallet, "coldkey_file") and hasattr(wallet.coldkey_file, "passphrase"):
            wallet.coldkey_file.passphrase = password
        if hasattr(wallet, "hotkey_file") and hasattr(wallet.hotkey_file, "passphrase"):
            wallet.hotkey_file.passphrase = password
    except Exception:
        pass

    cold = wallet.coldkey
    hot = wallet.hotkey

    LOG.info("[wallet] loaded bittensor wallet %s/%s", args.wallet_name, args.hotkey_name)
    LOG.info("[i] hotkey=%s coldkey=%s", hot.ss58_address, cold.ss58_address)
    return WalletBundle(wallet=wallet, cold=cold, hot=hot)


###############################################################################
# Mempool decode helpers (no logs here — keep it quiet)
###############################################################################

def rpc_methods(substrate: SubstrateInterface) -> List[str]:
    res = substrate.rpc_request("rpc_methods", [])
    return res.get("result", {}).get("methods", [])


def pick_mempool_method(substrate: SubstrateInterface) -> str:
    methods = rpc_methods(substrate)
    if "author_pendingExtrinsics" in methods:
        return "author_pendingExtrinsics"
    if "txpool_pendingExtrinsics" in methods:
        return "txpool_pendingExtrinsics"
    return "author_pendingExtrinsics"


def extract_calls_from_extrinsic(substrate: SubstrateInterface, xt_hex: str) -> List[Dict[str, Any]]:
    try:
        ext_obj = substrate.create_scale_object("Extrinsic")
        ext_obj.decode(ScaleBytes(xt_hex))
        val = ext_obj.value or {}
    except Exception:
        try:
            ext_obj = substrate.decode_scale("Extrinsic", ScaleBytes(xt_hex))
            val = ext_obj.value or {}
        except Exception:
            return []

    def _walk_call(call: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        if not isinstance(call, dict):
            return
        mod = call.get("call_module") or call.get("module")
        fun = call.get("call_function") or call.get("function") or call.get("method")
        args = call.get("call_args") or call.get("params") or []

        entry = {"call_module": mod, "call_function": fun, "call_args": args}
        yield entry

        # Proxy.proxy
        if mod == "Proxy" and fun == "proxy":
            inner = None
            for a in args:
                if a.get("name") in ("call", "data", "call_data") and isinstance(a.get("value"), dict):
                    inner = a["value"]
                    break
            if inner:
                yield from _walk_call(inner)

        # Utility batch variants
        if mod == "Utility" and fun in ("batch", "batch_all", "force_batch"):
            for a in args:
                if a.get("name") == "calls" and isinstance(a.get("value"), list):
                    for c in a["value"]:
                        if isinstance(c, dict):
                            yield from _walk_call(c)

    call = val.get("call", {})
    return list(_walk_call(call))


###############################################################################
# Victim types & detection (ADD/REMOVE only; ignore root)
###############################################################################

@dataclass
class VictimAdd:
    netuid: int
    tao: int  # raw TAO units (plancks)


@dataclass
class VictimRemove:
    netuid: int
    alpha: int  # raw alpha units


def iter_victims_from_calls(calls: List[Dict[str, Any]], min_raw_tao: int) -> Iterable[Tuple[str, Any]]:
    """
    Yield tuples: ("ADD", VictimAdd) or ("REMOVE", VictimRemove)
    """
    for c in calls:
        mod = c.get("call_module")
        fun = c.get("call_function")
        if mod != "SubtensorModule" or fun is None:
            continue

        # ADD family
        if fun in ("add_stake", "add_stake_limit"):
            netuid = None
            amount_tao = None
            for a in c.get("call_args", []):
                n = a.get("name")
                v = a.get("value")
                if n == "netuid":
                    netuid = int(v)
                elif n in ("amount_staked", "amountStaked"):
                    amount_tao = int(v)
            if netuid is None or amount_tao is None:
                continue
            if netuid == 0:
                continue  # ignore root
            if amount_tao < min_raw_tao:
                continue
            yield ("ADD", VictimAdd(netuid=netuid, tao=amount_tao))

        # REMOVE family
        if fun in ("remove_stake", "remove_stake_limit"):
            netuid = None
            amount_alpha = None
            for a in c.get("call_args", []):
                n = a.get("name")
                v = a.get("value")
                if n == "netuid":
                    netuid = int(v)
                elif n in ("amount_unstaked", "amountUnstaked"):
                    amount_alpha = int(v)
            if netuid is None or amount_alpha is None:
                continue
            if netuid == 0:
                continue  # ignore root
            if amount_alpha <= 0:
                continue
            yield ("REMOVE", VictimRemove(netuid=netuid, alpha=amount_alpha))


###############################################################################
# Planning & execution
###############################################################################

ROOT = 0

@dataclass
class Leg:
    origin: int
    dest: int
    qty: int


def make_plan_add(v: VictimAdd, floor: int) -> Optional[Tuple[Leg, Leg]]:
    # For ADD, victim provides TAO; we trade alpha via swap, so size with alpha floor only
    qty = int(floor)
    if qty <= 0:
        return None
    front = Leg(origin=ROOT, dest=v.netuid, qty=qty)
    back = Leg(origin=v.netuid, dest=ROOT, qty=qty)
    if front.origin == front.dest or back.origin == back.dest:
        return None
    return (front, back)


def make_plan_remove(v: VictimRemove, floor: int, ratio: float) -> Optional[Tuple[Leg, Leg]]:
    # For REMOVE, victim alpha known; size against victim alpha and floor
    qty = max(int(v.alpha * ratio), int(floor))
    qty = min(qty, v.alpha)
    if qty <= 0:
        return None
    front = Leg(origin=v.netuid, dest=ROOT, qty=qty)
    back = Leg(origin=ROOT, dest=v.netuid, qty=qty)
    if front.origin == front.dest or back.origin == back.dest:
        return None
    return (front, back)


def compose_swap_call(substrate: SubstrateInterface, hot_ss58: str, leg: Leg):
    return compose_call(
        substrate,
        call_module="SubtensorModule",
        call_function="swap_stake",
        call_params={
            "hotkey": hot_ss58,
            "origin_netuid": int(leg.origin),
            "destination_netuid": int(leg.dest),
            "alpha_amount": int(leg.qty),
        },
    )


def decode_receipt_error(receipt) -> Tuple[str, Any]:
    """
    Return (canonical, raw) where canonical is a short string ("AmountTooLow", "...")
    """
    raw = getattr(receipt, "error_message", None)
    if isinstance(raw, dict):
        name = raw.get("name") or raw.get("type")
        return (str(name), raw)
    if isinstance(raw, str):
        # Best-effort parse
        for key in ("AmountTooLow", "Priority", "BadOrigin", "Outdated", "Invalid", "Payment"):
            if key.lower() in raw.lower():
                return (key, raw)
        return (raw, raw)
    return ("UnknownError", raw)


def submit_and_wait(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, leg: Leg, nonce: int, tip: int) -> Tuple[Optional[str], Optional[Tuple[str, Any]]]:
    call = compose_swap_call(substrate, hot_ss58, leg)
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=cold, tip=tip, nonce=nonce)
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True, wait_for_finalization=False)
    if getattr(receipt, "is_success", False):
        return (getattr(receipt, "extrinsic_hash", None), None)
    # Failure
    err = decode_receipt_error(receipt)
    return (getattr(receipt, "extrinsic_hash", None), err)


###############################################################################
# Main loop
###############################################################################

def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    setup_logging(args.debug)

    # Password (one prompt)
    password = init_password_flow(args)

    # Connect
    substrate = connect(args.ws)

    # Floors (directional): map (origin, dest) -> alpha floor
    alpha_floor: Dict[Tuple[int, int], int] = {}

    # Unit conversions
    RAW_TAO = 1_000_000_000
    min_raw_tao = int(args.min_tao * RAW_TAO)

    # Wallet
    wb = load_wallet(args, password)

    # Pick mempool method once (no logs)
    rpc_method = pick_mempool_method(substrate)

    # Single-inflight policy
    inflight = False
    last_ts = 0.0

    while True:
        try:
            now = time.time()
            if inflight and (now - last_ts) < args.cooldown:
                time.sleep(max(0.0, args.poll))
                continue
            inflight = False

            # Fetch mempool extrinsics silently
            res = substrate.rpc_request(rpc_method, [])
            result = res.get("result", [])
            xts: List[str] = []
            for item in result:
                if isinstance(item, str):
                    xts.append(item)
                elif isinstance(item, dict) and "extrinsic" in item:
                    xts.append(item["extrinsic"])

            picked: Optional[Tuple[str, Any, Tuple[Leg, Leg]]] = None

            # Scan for the first usable victim and build plan
            for xt in xts:
                calls = extract_calls_from_extrinsic(substrate, xt)
                for typ, victim in iter_victims_from_calls(calls, min_raw_tao):
                    if typ == "ADD":
                        floor = alpha_floor.get((ROOT, victim.netuid), args.min_alpha)
                        legs = make_plan_add(victim, floor)
                        if legs:
                            front, back = legs
                            LOG.info("[plan] ADD (netuid=%d, tao=%d) -> legs: front %d->%d qty=%d | back %d->%d qty=%d",
                                     victim.netuid, victim.tao,
                                     front.origin, front.dest, front.qty,
                                     back.origin, back.dest, back.qty)
                            picked = (typ, victim, legs)
                            break
                    elif typ == "REMOVE":
                        floor = alpha_floor.get((victim.netuid, ROOT), args.min_alpha)
                        legs = make_plan_remove(victim, floor, args.ratio)
                        if legs:
                            front, back = legs
                            LOG.info("[plan] REMOVE (netuid=%d, amount=%d alpha) -> legs: front %d->%d qty=%d | back %d->%d qty=%d",
                                     victim.netuid, victim.alpha,
                                     front.origin, front.dest, front.qty,
                                     back.origin, back.dest, back.qty)
                            picked = (typ, victim, legs)
                            break
                if picked:
                    break

            if not picked:
                time.sleep(max(0.0, args.poll))
                continue

            # Execute sandwich (one at a time; wait for front inclusion)
            inflight = True
            last_ts = time.time()
            _, victim, (front, back) = picked

            # Nonce plan: two consecutive nonces; different tips avoid equal priority
            start_nonce = get_account_next_index(substrate, wb.cold.ss58_address)

            # FRONT
            txh, err = submit_and_wait(substrate, wb.cold, wb.hot.ss58_address, front, nonce=start_nonce, tip=1)
            if err is None:
                LOG.info("[front] included tx=%s", txh or "<unknown>")
                # BACK
                txh2, err2 = submit_and_wait(substrate, wb.cold, wb.hot.ss58_address, back, nonce=start_nonce + 1, tip=2)
                if err2 is None:
                    LOG.info("[back ] included tx=%s", txh2 or "<unknown>")
                else:
                    canon, raw = err2
                    LOG.error("[back ] failed: %s", raw if isinstance(raw, str) else json.dumps(raw))
            else:
                canon, raw = err
                LOG.error("[front] failed: %s", raw if isinstance(raw, str) else json.dumps(raw))
                # Learn AmountTooLow -> bump floor for this direction
                if str(canon) == "AmountTooLow":
                    new_floor = max(2 * front.qty, alpha_floor.get((front.origin, front.dest), args.min_alpha) * 2, args.min_alpha)
                    alpha_floor[(front.origin, front.dest)] = new_floor
                    LOG.warning("[learn] set floor for %d->%d to %d alpha (from AmountTooLow)", front.origin, front.dest, new_floor)

            # Cooldown regardless
            time.sleep(max(0.0, args.cooldown))

        except KeyboardInterrupt:
            print()
            LOG.info("Interrupted by user.")
            return
        except Exception as e:
            LOG.error("Unhandled error: %s", str(e))
            LOG.debug(traceback.format_exc())
            time.sleep(max(0.1, args.poll))


if __name__ == "__main__":
    main()
