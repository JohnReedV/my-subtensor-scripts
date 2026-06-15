#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PR #2532 live test against the already-created dev-testnet subnet.

This script is intentionally scoped to the subnet from the previous run:
  - endpoint:  wss://archive.dev.opentensor.ai:8443
  - netuid:    463
  - owner UID: 0
  - target UID: 1

It does not create a subnet and does not register another hotkey. It only:
  1) verifies the supplied keys own netuid 463,
  2) verifies UID 0 is the owner hotkey and UID 1 exists,
  3) waits out WeightsSetRateLimit / LastUpdate,
  4) signs set_weights with the owner hotkey,
  5) asserts the owner UID's Weights row contains the non-owner target UID.

Install:
  python3 -m pip install substrate-interface

Run:
  python3 snownerweights_463.py
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException

try:
    from substrateinterface import KeypairType
except Exception:
    KeypairType = None


WS = "wss://archive.dev.opentensor.ai:8443"
NETUID = 463
OWNER_UID = 0
TARGET_UID = 1

COLD_MNEMONIC = "dolphin notice high diary hazard lounge fly autumn display decline recall record"
HOT_MNEMONIC = "capital devote recipe little merit runway throw omit maximum until bench nothing"

SUBTENSOR = "SubtensorModule"
ADMIN = "AdminUtils"

TYPE_REGISTRY = {
    "types": {
        "TaoBalance": "u64",
        "AlphaBalance": "u64",
        "NetUid": "u16",
        "NetUidStorageIndex": "u16",
        "MechId": "u8",
        "U64F64": "u128",
        "U96F32": "u128",
        "I64F64": "i128",
        "I96F32": "i128",
        "substrate_fixed::types::U64F64": "u128",
        "substrate_fixed::types::U96F32": "u128",
        "substrate_fixed::types::I64F64": "i128",
        "substrate_fixed::types::I96F32": "i128",
        "FixedU128<U64>": "u128",
    }
}


def log(msg: str) -> None:
    print(msg, flush=True)


def val(x: Any) -> Any:
    return getattr(x, "value", x)


def as_int(x: Any) -> int:
    x = val(x)
    if x is None:
        return 0
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        if not s:
            return 0
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s)
    if isinstance(x, dict):
        for k in ("value", "bits", "raw", "index", "id", "Id"):
            if k in x:
                return as_int(x[k])
        if len(x) == 1:
            return as_int(next(iter(x.values())))
        for y in x.values():
            try:
                return as_int(y)
            except Exception:
                pass
        raise ValueError(f"cannot convert dict to int: {x!r}")
    if isinstance(x, (list, tuple)):
        return as_int(x[0]) if x else 0
    return int(x)


def as_bool(x: Any) -> bool:
    x = val(x)
    if isinstance(x, bool):
        return x
    if isinstance(x, str):
        return x.strip().lower() in ("1", "true", "yes", "y")
    return bool(x)


def as_list(x: Any) -> List[Any]:
    x = val(x)
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, tuple):
        return list(x)
    return [x]


def as_ss58(x: Any) -> Optional[str]:
    x = val(x)
    if x is None:
        return None
    if isinstance(x, str):
        s = x.strip()
        if not s or s == "0x" + ("00" * 32):
            return None
        return s
    if isinstance(x, dict):
        for k in ("value", "account", "account_id", "id", "Id", "address"):
            if k in x:
                out = as_ss58(x[k])
                if out:
                    return out
        for y in x.values():
            out = as_ss58(y)
            if out:
                return out
        return None
    if isinstance(x, (list, tuple)):
        for y in x:
            out = as_ss58(y)
            if out:
                return out
        return None
    s = str(x).strip()
    return s or None


def short(addr: str) -> str:
    return f"{addr[:7]}…{addr[-7:]}" if len(addr) > 18 else addr


def simplify_error(x: Any) -> str:
    x = val(x)
    if x is None:
        return ""
    if isinstance(x, (list, tuple)):
        return " | ".join(p for p in (simplify_error(y) for y in x) if p)
    if isinstance(x, dict):
        name = x.get("name")
        docs = x.get("docs")
        if name and docs:
            return f"{name}: {' '.join(str(d) for d in docs)}"
        if name:
            return str(name)
        for k in ("error", "dispatch_error", "dispatchError", "details", "value"):
            if k in x:
                nested = simplify_error(x[k])
                if nested:
                    return nested
        return str(x)
    return str(x).strip()


def retryable(text: str) -> bool:
    text = text.lower()
    return any(
        m in text
        for m in (
            "broken pipe",
            "connection reset",
            "connection aborted",
            "connection closed",
            "websocketconnectionclosed",
            "socket is already closed",
            "websocket is not connected",
            "cannot write to closing transport",
            "closing transport",
            "transport endpoint is not connected",
            "remote host closed",
            "connection lost",
            "eof occurred",
            "timed out",
            "timeout",
            "read timed out",
            'decoder class for "compact<u32>" not found',
            'decoder class for "compact<u64>" not found',
            'decoder class for "compact<u128>" not found',
            "already imported",
            "temporarily banned",
            "priority is too low",
            "transaction is outdated",
            "stale",
            "future",
            "usurped",
        )
    )


def setting_weights_too_fast(text: str) -> bool:
    text = text.lower()
    return "settingweightstoofast" in text or "setting weights too fast" in text


class Chain:
    def __init__(self, ws: str, retries: int = 4, retry_sleep: float = 1.0):
        self.ws = ws
        self.retries = retries
        self.retry_sleep = retry_sleep
        self.substrate: Optional[SubstrateInterface] = None
        self.connect()

    def connect(self) -> None:
        self.substrate = SubstrateInterface(
            url=self.ws,
            auto_reconnect=True,
            type_registry=TYPE_REGISTRY,
        )
        self.substrate.init_runtime()

    def call(self, label: str, fn):
        last: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                assert self.substrate is not None
                return fn(self.substrate)
            except Exception as e:
                last = e
                msg = simplify_error(e)
                if attempt >= self.retries or not retryable(msg):
                    raise
                log(f"⚠️  {label} transient error; reconnecting: {msg}")
                try:
                    self.connect()
                except Exception:
                    pass
                time.sleep(self.retry_sleep * attempt)
        assert last is not None
        raise last

    def query(self, module: str, storage: str, params: Sequence[Any] = ()):
        return self.call(
            f"query {module}.{storage}",
            lambda s: s.query(module, storage, list(params)),
        )

    def compose(self, module: str, function: str, params: Dict[str, Any]):
        return self.call(
            f"compose {module}.{function}",
            lambda s: s.compose_call(
                call_module=module,
                call_function=function,
                call_params=params,
            ),
        )

    def submit(self, signer: Keypair, call: Any, label: str):
        assert self.substrate is not None
        xt = self.call("sign " + label, lambda s: s.create_signed_extrinsic(call=call, keypair=signer))
        try:
            rec = self.substrate.submit_extrinsic(
                xt,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except SubstrateRequestException as e:
            raise RuntimeError(f"{label} submission failed: {simplify_error(e)}") from e
        if not getattr(rec, "is_success", False):
            raise RuntimeError(
                f"{label} failed in block {rec.block_hash}: "
                f"{simplify_error(getattr(rec, 'error_message', ''))}"
            )
        return rec

    def ss58_format(self) -> int:
        try:
            return as_int(self.call("get System.SS58Prefix", lambda s: s.get_constant("System", "SS58Prefix")))
        except Exception:
            return 42

    def decimals(self) -> int:
        assert self.substrate is not None
        d = self.substrate.token_decimals
        if isinstance(d, list) and d and isinstance(d[0], int):
            return d[0]
        if isinstance(d, int):
            return d
        return 9


def keypair_from_mnemonic(mnemonic: str, ss58_format: int) -> Keypair:
    kwargs: Dict[str, Any] = {"ss58_format": ss58_format}
    if KeypairType is not None:
        kwargs["crypto_type"] = KeypairType.SR25519
    try:
        return Keypair.create_from_mnemonic(mnemonic=mnemonic.strip(), **kwargs)
    except TypeError:
        kwargs.pop("crypto_type", None)
        return Keypair.create_from_mnemonic(mnemonic=mnemonic.strip(), **kwargs)
    except Exception:
        try:
            return Keypair.create_from_uri(mnemonic.strip(), ss58_format=ss58_format)
        except TypeError:
            return Keypair.create_from_uri(mnemonic.strip())


def q(c: Chain, module: str, storage: str, params: Sequence[Any] = ()) -> Any:
    return val(c.query(module, storage, params))


def q_int(c: Chain, module: str, storage: str, params: Sequence[Any] = ()) -> int:
    return as_int(q(c, module, storage, params))


def q_bool(c: Chain, module: str, storage: str, params: Sequence[Any] = ()) -> bool:
    return as_bool(q(c, module, storage, params))


def q_ss58(c: Chain, module: str, storage: str, params: Sequence[Any] = ()) -> Optional[str]:
    return as_ss58(q(c, module, storage, params))


def current_block(c: Chain) -> int:
    return q_int(c, "System", "Number")


def account_free(c: Chain, ss58: str) -> int:
    info = q(c, "System", "Account", [ss58])
    return as_int(info.get("data", {}).get("free", 0)) if isinstance(info, dict) else 0


def subnet_owner(c: Chain, netuid: int) -> Optional[str]:
    return q_ss58(c, SUBTENSOR, "SubnetOwner", [netuid])


def subnet_owner_hotkey(c: Chain, netuid: int) -> Optional[str]:
    return q_ss58(c, SUBTENSOR, "SubnetOwnerHotkey", [netuid])


def hotkey_uid(c: Chain, netuid: int, hotkey: str) -> Optional[int]:
    out = q(c, SUBTENSOR, "Uids", [netuid, hotkey])
    return None if out is None else as_int(out)


def key_for_uid(c: Chain, netuid: int, uid: int) -> Optional[str]:
    return q_ss58(c, SUBTENSOR, "Keys", [netuid, uid])


def subnetwork_n(c: Chain, netuid: int) -> int:
    return q_int(c, SUBTENSOR, "SubnetworkN", [netuid])


def min_allowed_weights(c: Chain, netuid: int) -> int:
    return q_int(c, SUBTENSOR, "MinAllowedWeights", [netuid])


def max_weights_limit(c: Chain, netuid: int) -> int:
    return q_int(c, SUBTENSOR, "MaxWeightsLimit", [netuid])


def weights_version_key(c: Chain, netuid: int) -> int:
    return q_int(c, SUBTENSOR, "WeightsVersionKey", [netuid])


def commit_reveal_enabled(c: Chain, netuid: int) -> bool:
    return q_bool(c, SUBTENSOR, "CommitRevealWeightsEnabled", [netuid])


def weights_set_rate_limit(c: Chain, netuid: int) -> int:
    return q_int(c, SUBTENSOR, "WeightsSetRateLimit", [netuid])


def last_update_for_uid(c: Chain, netuid: int, uid: int) -> int:
    updates = as_list(q(c, SUBTENSOR, "LastUpdate", [netuid]))
    return as_int(updates[uid]) if 0 <= uid < len(updates) else 0


def validator_permit_for_uid(c: Chain, netuid: int, uid: int) -> bool:
    permits = as_list(q(c, SUBTENSOR, "ValidatorPermit", [netuid]))
    return as_bool(permits[uid]) if 0 <= uid < len(permits) else False


def stake_threshold(c: Chain) -> int:
    return q_int(c, SUBTENSOR, "StakeThreshold")


def owner_alpha(c: Chain, netuid: int, owner_hotkey: str) -> int:
    try:
        return q_int(c, SUBTENSOR, "TotalHotkeyAlpha", [owner_hotkey, netuid])
    except Exception:
        return 0


def normalize_weight_row(row: Any) -> List[Tuple[int, int]]:
    row = val(row) or []
    out: List[Tuple[int, int]] = []
    for item in row:
        item = val(item)
        if isinstance(item, dict):
            lower = {str(k).lower(): v for k, v in item.items()}
            uid = lower.get("uid") or lower.get("uids") or lower.get("dest") or lower.get("dests") or lower.get("0")
            weight = lower.get("weight") or lower.get("weights") or lower.get("value") or lower.get("1")
            if uid is not None and weight is not None:
                out.append((as_int(uid), as_int(weight)))
                continue
            vals = list(item.values())
            if len(vals) >= 2:
                out.append((as_int(vals[0]), as_int(vals[1])))
                continue
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out.append((as_int(item[0]), as_int(item[1])))
            continue
        raise ValueError(f"cannot decode weight row item: {item!r}")
    return out


def weights_row(c: Chain, netuid: int, uid: int) -> List[Tuple[int, int]]:
    return normalize_weight_row(q(c, SUBTENSOR, "Weights", [netuid, uid]))


def cooldown(c: Chain, netuid: int, uid: int) -> Tuple[int, int, int, int, int]:
    now = current_block(c)
    last = last_update_for_uid(c, netuid, uid)
    limit = weights_set_rate_limit(c, netuid)

    if last <= 0 or limit <= 0:
        return 0, now, last, limit, now

    # Runtime should pass at last + limit; +1 avoids public endpoint head/finality race edges.
    target = last + limit + 1
    return max(0, target - now), now, last, limit, target


def wait_until_block(c: Chain, target: int, poll_seconds: float) -> None:
    while True:
        now = current_block(c)
        if now >= target:
            return
        remaining = target - now
        if remaining <= 3 or remaining % 10 == 0:
            log(f"⏳ Waiting for block >= {target}; current={now}; remaining={remaining}")
        time.sleep(poll_seconds)


def disable_commit_reveal_if_needed(c: Chain, cold: Keypair, netuid: int, no_disable: bool) -> None:
    if not commit_reveal_enabled(c, netuid):
        log("✅ CommitRevealWeightsEnabled is already false.")
        return

    if no_disable:
        raise RuntimeError("CommitRevealWeightsEnabled is true; direct set_weights will fail.")

    log("🔧 CommitRevealWeightsEnabled is true; disabling it with the owner coldkey.")
    candidates = [
        (ADMIN, "sudo_set_commit_reveal_weights_enabled", {"netuid": netuid, "enabled": False}),
        (ADMIN, "sudo_set_commit_reveal_weights_enabled", {"netuid": netuid, "commit_reveal_weights_enabled": False}),
        (SUBTENSOR, "sudo_set_commit_reveal_weights_enabled", {"netuid": netuid, "enabled": False}),
        (SUBTENSOR, "sudo_set_commit_reveal_weights_enabled", {"netuid": netuid, "commit_reveal_weights_enabled": False}),
    ]

    errors: List[str] = []
    for module, function, params in candidates:
        try:
            rec = c.submit(cold, c.compose(module, function, params), f"{module}.{function}")
            log(f"✅ commit-reveal disable finalized in block {rec.block_hash}")
            break
        except Exception as e:
            errors.append(f"{module}.{function} {sorted(params.keys())}: {simplify_error(e)}")
    else:
        raise RuntimeError("Could not disable commit reveal: " + " | ".join(errors))

    for _ in range(20):
        if not commit_reveal_enabled(c, netuid):
            log("✅ CommitRevealWeightsEnabled readback is now false.")
            return
        time.sleep(2)

    raise RuntimeError("commit-reveal disable finalized, but readback stayed true")


def choose_destinations(c: Chain, netuid: int, owner_uid: int, target_uid: int) -> List[int]:
    n = subnetwork_n(c, netuid)

    if target_uid < 0 or target_uid >= n:
        raise AssertionError(f"target UID {target_uid} is outside SubnetworkN={n}")
    if target_uid == owner_uid:
        raise AssertionError("target UID must be non-owner")

    target_hotkey = key_for_uid(c, netuid, target_uid)
    if not target_hotkey:
        raise AssertionError(f"target UID {target_uid} has no Keys entry on netuid={netuid}")

    min_allowed = min_allowed_weights(c, netuid)
    dests = [target_uid]

    # netuid 463 was observed with MinAllowedWeights=1. This fallback keeps the
    # script usable if the hyperparameter changes later.
    if len(dests) < min_allowed:
        for uid in range(n):
            if uid not in dests and key_for_uid(c, netuid, uid):
                dests.append(uid)
            if len(dests) >= min_allowed:
                break

    if len(dests) < min_allowed:
        raise AssertionError(f"need {min_allowed} destinations but only found {dests}")

    if all(uid == owner_uid for uid in dests):
        raise AssertionError("destination set contains only the owner UID")

    return dests


def compose_set_weights(c: Chain, netuid: int, dests: List[int], weights: List[int], version_key: int):
    candidates = [
        {"netuid": netuid, "dests": dests, "weights": weights, "version_key": version_key},
        {"netuid": netuid, "uids": dests, "weights": weights, "version_key": version_key},
    ]

    errors: List[str] = []
    for params in candidates:
        try:
            return c.compose(SUBTENSOR, "set_weights", params)
        except Exception as e:
            errors.append(f"{sorted(params.keys())}: {simplify_error(e)}")

    raise RuntimeError("Could not compose set_weights: " + " | ".join(errors))


def submit_set_weights_with_cooldown(
    c: Chain,
    hot: Keypair,
    netuid: int,
    owner_uid: int,
    dests: List[int],
    weights: List[int],
    version_key: int,
    retries: int,
    poll_seconds: float,
):
    last_error = ""
    for attempt in range(1, retries + 1):
        remaining, now, last, limit, target = cooldown(c, netuid, owner_uid)
        if remaining > 0:
            log(
                "⏱️  Waiting for set_weights cooldown: "
                f"current={now}, last_update={last}, rate_limit={limit}, "
                f"safe_target={target}, remaining≈{remaining} block(s)"
            )
            wait_until_block(c, target, poll_seconds)

        try:
            latest_version_key = weights_version_key(c, netuid)
            if latest_version_key != version_key:
                log(f"ℹ️  WeightsVersionKey changed while waiting: {version_key} -> {latest_version_key}")
                version_key = latest_version_key

            call = compose_set_weights(c, netuid, dests, weights, version_key)
            return c.submit(hot, call, f"SubtensorModule.set_weights(netuid={netuid}, dests={dests})")
        except Exception as e:
            last_error = simplify_error(e)
            if not setting_weights_too_fast(last_error) or attempt >= retries:
                raise
            log(f"⚠️  Still hit SettingWeightsTooFast on attempt {attempt}/{retries}: {last_error}")
            time.sleep(poll_seconds)

    raise RuntimeError(f"set_weights did not pass after cooldown retries: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ws", default=WS)
    parser.add_argument("--netuid", type=int, default=NETUID)
    parser.add_argument("--owner-uid", type=int, default=OWNER_UID)
    parser.add_argument("--target-uid", type=int, default=TARGET_UID)
    parser.add_argument("--cold-mnemonic", default=os.environ.get("PR2532_OWNER_COLD_MNEMONIC", COLD_MNEMONIC))
    parser.add_argument("--hot-mnemonic", default=os.environ.get("PR2532_OWNER_HOT_MNEMONIC", HOT_MNEMONIC))
    parser.add_argument("--no-disable-commit-reveal", action="store_true")
    parser.add_argument("--query-retries", type=int, default=4)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--set-weights-retries", type=int, default=8)
    args = parser.parse_args()

    c = Chain(args.ws, retries=args.query_retries)
    ss58 = c.ss58_format()
    decimals = c.decimals()

    cold = keypair_from_mnemonic(args.cold_mnemonic, ss58)
    hot = keypair_from_mnemonic(args.hot_mnemonic, ss58)

    log("🌐 Connected")
    log(f"   ws          = {args.ws}")
    log(f"   ss58_format = {ss58}")
    log(f"   decimals    = {decimals}")
    log(f"   netuid      = {args.netuid}")
    log(f"   coldkey     = {cold.ss58_address} ({short(cold.ss58_address)})")
    log(f"   hotkey      = {hot.ss58_address} ({short(hot.ss58_address)})")
    log(f"   cold free   = {account_free(c, cold.ss58_address)} planck")
    log(f"   hot free    = {account_free(c, hot.ss58_address)} planck")

    chain_owner = subnet_owner(c, args.netuid)
    chain_owner_hot = subnet_owner_hotkey(c, args.netuid)
    if chain_owner != cold.ss58_address or chain_owner_hot != hot.ss58_address:
        raise AssertionError(
            f"netuid={args.netuid} is not owned by these keys\n"
            f"  chain SubnetOwner       = {chain_owner}\n"
            f"  expected coldkey        = {cold.ss58_address}\n"
            f"  chain SubnetOwnerHotkey = {chain_owner_hot}\n"
            f"  expected hotkey         = {hot.ss58_address}"
        )

    owner_uid = hotkey_uid(c, args.netuid, hot.ss58_address)
    if owner_uid is None:
        raise AssertionError(f"owner hotkey is not registered on netuid={args.netuid}")
    if owner_uid != args.owner_uid:
        raise AssertionError(f"owner UID mismatch: expected {args.owner_uid}, got {owner_uid}")

    owner_key = key_for_uid(c, args.netuid, owner_uid)
    if owner_key != hot.ss58_address:
        raise AssertionError(
            f"Keys[{args.netuid}, {owner_uid}] mismatch\n"
            f"  chain key       = {owner_key}\n"
            f"  expected hotkey = {hot.ss58_address}"
        )

    disable_commit_reveal_if_needed(c, cold, args.netuid, args.no_disable_commit_reveal)

    dests = choose_destinations(c, args.netuid, owner_uid, args.target_uid)
    weights = [1 for _ in dests]
    version_key = weights_version_key(c, args.netuid)
    remaining, now, last, limit, target = cooldown(c, args.netuid, owner_uid)

    log("🔎 Pre-flight state:")
    log(f"   owner_uid                  = {owner_uid}")
    log(f"   subnetwork_n               = {subnetwork_n(c, args.netuid)}")
    log(f"   target_uid                 = {args.target_uid}")
    log(f"   destination_uids           = {dests}")
    log(f"   weights                    = {weights}")
    log(f"   min_allowed_weights        = {min_allowed_weights(c, args.netuid)}")
    log(f"   max_weights_limit          = {max_weights_limit(c, args.netuid)}")
    log(f"   weights_version_key        = {version_key}")
    log(f"   owner_validator_permit     = {validator_permit_for_uid(c, args.netuid, owner_uid)}")
    log(f"   owner_total_alpha          = {owner_alpha(c, args.netuid, hot.ss58_address)}")
    log(f"   global_stake_threshold     = {stake_threshold(c)}")
    log(f"   weights_set_rate_limit     = {limit}")
    log(f"   owner_last_update          = {last}")
    log(f"   current_block              = {now}")
    log(f"   safe_target_block          = {target}")
    log(f"   cooldown_remaining_blocks  = {remaining}")

    rec = submit_set_weights_with_cooldown(
        c=c,
        hot=hot,
        netuid=args.netuid,
        owner_uid=owner_uid,
        dests=dests,
        weights=weights,
        version_key=version_key,
        retries=args.set_weights_retries,
        poll_seconds=args.poll_seconds,
    )
    log(f"✅ owner set_weights finalized in block {rec.block_hash}")

    row = weights_row(c, args.netuid, owner_uid)
    row_by_uid = {uid: weight for uid, weight in row}
    missing = [uid for uid in dests if uid not in row_by_uid]
    non_positive = [(uid, row_by_uid[uid]) for uid in dests if uid in row_by_uid and row_by_uid[uid] <= 0]

    if missing:
        raise AssertionError(
            "stored owner Weights row is missing submitted destination UID(s)\n"
            f"  submitted dests = {dests}\n"
            f"  stored row      = {row}"
        )
    if non_positive:
        raise AssertionError(f"stored row has non-positive weights: {non_positive}; row={row}")
    if list(row_by_uid.keys()) == [owner_uid]:
        raise AssertionError("stored row is only self-weight; did not test owner non-self path")

    log("✅ On-chain Weights row assertion passed.")
    log(f"   stored owner row           = {row}")
    log(f"   owner_validator_permit_now = {validator_permit_for_uid(c, args.netuid, owner_uid)}")
    log("")
    log("🎉 PASS: owner hotkey set non-self weights on existing netuid 463.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as e:
        print(f"\nAssertion failed:\n{e}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as e:
        print(f"\nError:\n{simplify_error(e)}", file=sys.stderr)
        raise SystemExit(1)