#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Live test for subtensor PR #2532 on dev testnet:
  Owner hotkey can set non-self weights even when it is not manually validator-permitted.

Default endpoint:
  wss://archive.dev.opentensor.ai:8443

Default owner keys:
  cold mnemonic: dolphin notice high diary hazard lounge fly autumn display decline recall record
  hot mnemonic:  capital devote recipe little merit runway throw omit maximum until bench nothing

Install:
  python3 -m pip install substrate-interface

Run:
  python3 snownerweights_fixed.py

Useful options:
  python3 snownerweights_fixed.py --netuid 463
  python3 snownerweights_fixed.py --create-fresh
  python3 snownerweights_fixed.py --require-owner-permit-false

The fix versus the earlier script is that this one respects the runtime's
WeightsSetRateLimit / LastUpdate gate. A fresh subnet owner usually has a
non-zero LastUpdate from registration, so direct set_weights is too early until
current_block - LastUpdate >= WeightsSetRateLimit.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException

try:
    from substrateinterface import KeypairType
except Exception:  # older substrate-interface versions
    KeypairType = None


DEFAULT_WS = "wss://archive.dev.opentensor.ai:8443"
DEFAULT_COLD_MNEMONIC = (
    "dolphin notice high diary hazard lounge fly autumn display decline recall record"
)
DEFAULT_HOT_MNEMONIC = (
    "capital devote recipe little merit runway throw omit maximum until bench nothing"
)

PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"
U16_MAX = 65535

CUSTOM_TYPE_REGISTRY = {
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


def log(message: str) -> None:
    print(message, flush=True)


def value_of(value: Any) -> Any:
    return getattr(value, "value", value)


def as_int(value: Any) -> int:
    value = value_of(value)

    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return 0
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    if isinstance(value, dict):
        for key in ("value", "bits", "raw", "index", "Id", "id"):
            if key in value:
                return as_int(value[key])
        if len(value) == 1:
            return as_int(next(iter(value.values())))
        for nested in value.values():
            try:
                return as_int(nested)
            except Exception:
                continue
        raise ValueError(f"Cannot convert dict to int: {value!r}")
    if isinstance(value, (list, tuple)):
        if not value:
            return 0
        return as_int(value[0])
    return int(value)


def as_bool(value: Any) -> bool:
    value = value_of(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y")
    return bool(value)


def as_list(value: Any) -> List[Any]:
    value = value_of(value)
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def as_ss58(value: Any) -> Optional[str]:
    value = value_of(value)
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s or s == "0x" + ("00" * 32):
            return None
        return s
    if isinstance(value, dict):
        for key in ("value", "account", "account_id", "id", "Id", "address"):
            if key in value:
                nested = as_ss58(value[key])
                if nested:
                    return nested
        for nested_value in value.values():
            nested = as_ss58(nested_value)
            if nested:
                return nested
        return None
    if isinstance(value, (list, tuple)):
        for item in value:
            nested = as_ss58(item)
            if nested:
                return nested
        return None
    text = str(value).strip()
    return text or None


def short_ss58(addr: str) -> str:
    return f"{addr[:7]}…{addr[-7:]}" if len(addr) > 18 else addr


def simplify_error(raw: Any) -> str:
    raw = value_of(raw)
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        parts = [simplify_error(x) for x in raw]
        parts = [p for p in parts if p]
        return " | ".join(parts)
    if isinstance(raw, dict):
        name = raw.get("name")
        docs = raw.get("docs")
        if name and docs:
            return f"{name}: {' '.join(str(d) for d in docs)}"
        if name:
            return str(name)
        for key in ("error", "dispatch_error", "dispatchError", "details", "value"):
            if key in raw:
                nested = simplify_error(raw[key])
                if nested:
                    return nested
        return str(raw)
    return str(raw).strip()


def is_retryable_transport_error_text(text: str) -> bool:
    lower = text.lower()
    return any(
        marker in lower
        for marker in (
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
            "connection to remote host was lost",
            "connection lost",
            "eof occurred",
            "timed out",
            "timeout",
            "read timed out",
            "i/o operation on closed file",
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


def is_setting_weights_too_fast(text: str) -> bool:
    lower = text.lower()
    return "settingweightstoofast" in lower or "setting weights too fast" in lower


def is_registration_rate_limit(text: str) -> bool:
    lower = text.lower()
    return any(
        marker in lower
        for marker in (
            "toomanyregistrationsthisblock",
            "toomanyregistrationsthisinterval",
            "ratelimit",
            "rate limit",
            "rate-limit",
            "networktxratelimitexceeded",
        )
    )


def is_admin_window_error(text: str) -> bool:
    lower = text.lower()
    return any(
        marker in lower
        for marker in (
            "adminactionprohibitedduringweightswindow",
            "admin",
            "freeze",
            "window",
            "tempo",
            "temporarily",
        )
    )


def keypair_from_mnemonic(mnemonic: str, ss58_format: int) -> Keypair:
    mnemonic = mnemonic.strip()
    kwargs: Dict[str, Any] = {"ss58_format": ss58_format}
    if KeypairType is not None:
        kwargs["crypto_type"] = KeypairType.SR25519
    try:
        return Keypair.create_from_mnemonic(mnemonic=mnemonic, **kwargs)
    except TypeError:
        kwargs.pop("crypto_type", None)
        return Keypair.create_from_mnemonic(mnemonic=mnemonic, **kwargs)
    except Exception:
        try:
            return Keypair.create_from_uri(mnemonic, ss58_format=ss58_format)
        except TypeError:
            return Keypair.create_from_uri(mnemonic)


def keypair_from_uri(uri: str, ss58_format: int) -> Keypair:
    try:
        return Keypair.create_from_uri(uri, ss58_format=ss58_format)
    except TypeError:
        return Keypair.create_from_uri(uri)


def normalize_weight_row(row_value: Any) -> List[Tuple[int, int]]:
    row_value = value_of(row_value) or []
    out: List[Tuple[int, int]] = []

    for item in row_value:
        item = value_of(item)
        if isinstance(item, dict):
            lower: Dict[str, Any] = {str(k).lower(): v for k, v in item.items()}
            uid_val = (
                lower.get("uid")
                or lower.get("uids")
                or lower.get("dest")
                or lower.get("dests")
                or lower.get("0")
            )
            weight_val = (
                lower.get("weight")
                or lower.get("weights")
                or lower.get("value")
                or lower.get("1")
            )
            if uid_val is not None and weight_val is not None:
                out.append((as_int(uid_val), as_int(weight_val)))
                continue
            vals = list(item.values())
            if len(vals) >= 2:
                out.append((as_int(vals[0]), as_int(vals[1])))
                continue
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out.append((as_int(item[0]), as_int(item[1])))
            continue
        raise ValueError(f"Cannot decode weight-row item: {item!r}")

    return out


@dataclass
class Chain:
    ws: str
    query_retries: int = 4
    retry_sleep: float = 1.0

    def __post_init__(self) -> None:
        self.substrate: Optional[SubstrateInterface] = None
        self.connect()

    def connect(self) -> None:
        self.substrate = SubstrateInterface(
            url=self.ws,
            auto_reconnect=True,
            type_registry=CUSTOM_TYPE_REGISTRY,
        )
        self.substrate.init_runtime()

    def _with_retries(self, label: str, fn: Callable[[SubstrateInterface], Any]) -> Any:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.query_retries + 1):
            try:
                assert self.substrate is not None
                return fn(self.substrate)
            except Exception as exc:
                last_exc = exc
                text = simplify_error(exc)
                if attempt >= self.query_retries or not is_retryable_transport_error_text(text):
                    raise
                log(f"⚠️  {label} transient error; reconnecting: {text}")
                try:
                    self.connect()
                except Exception:
                    pass
                time.sleep(self.retry_sleep * attempt)
        assert last_exc is not None
        raise last_exc

    def query(
        self,
        module: str,
        storage: str,
        params: Optional[Sequence[Any]] = None,
        block_hash: Optional[str] = None,
    ) -> Any:
        return self._with_retries(
            f"query {module}.{storage}",
            lambda s: s.query(module, storage, params or [], block_hash=block_hash),
        )

    def query_map(self, module: str, storage: str, params: Optional[Sequence[Any]] = None) -> List[Any]:
        return self._with_retries(
            f"query_map {module}.{storage}",
            lambda s: list(s.query_map(module, storage, params=params)),
        )

    def compose_call(self, module: str, function: str, params: Dict[str, Any]) -> Any:
        return self._with_retries(
            f"compose {module}.{function}",
            lambda s: s.compose_call(
                call_module=module,
                call_function=function,
                call_params=params,
            ),
        )

    def submit(self, signer: Keypair, call: Any, label: str, allow_failure: bool = False) -> Any:
        assert self.substrate is not None
        xt = self._with_retries(
            f"sign {label}",
            lambda s: s.create_signed_extrinsic(call=call, keypair=signer),
        )
        try:
            receipt = self.substrate.submit_extrinsic(
                xt,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except SubstrateRequestException as exc:
            raise RuntimeError(f"{label} submission failed: {simplify_error(exc)}") from exc

        if not allow_failure and not getattr(receipt, "is_success", False):
            raise RuntimeError(
                f"{label} failed in block {receipt.block_hash}: "
                f"{simplify_error(getattr(receipt, 'error_message', ''))}"
            )
        return receipt

    def get_ss58_format(self) -> int:
        try:
            constant = self._with_retries(
                "get System.SS58Prefix",
                lambda s: s.get_constant("System", "SS58Prefix"),
            )
            return as_int(constant)
        except Exception:
            return 42

    def token_decimals(self) -> int:
        assert self.substrate is not None
        decimals = self.substrate.token_decimals
        if isinstance(decimals, list) and decimals and isinstance(decimals[0], int):
            return decimals[0]
        if isinstance(decimals, int):
            return decimals
        return 9


def q(chain: Chain, module: str, storage: str, params: Optional[Sequence[Any]] = None) -> Any:
    return value_of(chain.query(module, storage, params or []))


def q_int(chain: Chain, module: str, storage: str, params: Optional[Sequence[Any]] = None) -> int:
    return as_int(q(chain, module, storage, params or []))


def q_bool(chain: Chain, module: str, storage: str, params: Optional[Sequence[Any]] = None) -> bool:
    return as_bool(q(chain, module, storage, params or []))


def q_ss58(chain: Chain, module: str, storage: str, params: Optional[Sequence[Any]] = None) -> Optional[str]:
    return as_ss58(q(chain, module, storage, params or []))


def current_block(chain: Chain) -> int:
    return q_int(chain, "System", "Number", [])


def wait_until_block(chain: Chain, target_block: int, poll_seconds: float = 1.0, label: str = "") -> None:
    target_block = int(target_block)
    while True:
        now = current_block(chain)
        if now >= target_block:
            return
        remaining = target_block - now
        if remaining == 1 or remaining % 10 == 0:
            suffix = f" | {label}" if label else ""
            log(f"⏳ Waiting for block >= {target_block}; current={now}; remaining={remaining}{suffix}")
        time.sleep(poll_seconds)


def wait_for_blocks(chain: Chain, blocks: int, poll_seconds: float = 1.0, label: str = "") -> None:
    wait_until_block(chain, current_block(chain) + max(1, int(blocks)), poll_seconds, label)


def account_free(chain: Chain, ss58: str) -> int:
    info = q(chain, "System", "Account", [ss58])
    if isinstance(info, dict):
        return as_int(info.get("data", {}).get("free", 0))
    return 0


def networks_added(chain: Chain) -> List[int]:
    out: List[int] = []
    for key, val in chain.query_map(PALLET_SUBTENSOR, "NetworksAdded"):
        try:
            netuid = as_int(key)
            if netuid != 0 and as_bool(val):
                out.append(netuid)
        except Exception:
            continue
    return sorted(set(out))


def subnet_owner(chain: Chain, netuid: int) -> Optional[str]:
    return q_ss58(chain, PALLET_SUBTENSOR, "SubnetOwner", [netuid])


def subnet_owner_hotkey(chain: Chain, netuid: int) -> Optional[str]:
    return q_ss58(chain, PALLET_SUBTENSOR, "SubnetOwnerHotkey", [netuid])


def hotkey_uid(chain: Chain, netuid: int, hotkey_ss58: str) -> Optional[int]:
    value = q(chain, PALLET_SUBTENSOR, "Uids", [netuid, hotkey_ss58])
    if value is None:
        return None
    return as_int(value)


def subnetwork_n(chain: Chain, netuid: int) -> int:
    return q_int(chain, PALLET_SUBTENSOR, "SubnetworkN", [netuid])


def key_for_uid(chain: Chain, netuid: int, uid: int) -> Optional[str]:
    return q_ss58(chain, PALLET_SUBTENSOR, "Keys", [netuid, uid])


def keys_by_uid(chain: Chain, netuid: int) -> Dict[int, str]:
    n = subnetwork_n(chain, netuid)
    out: Dict[int, str] = {}
    for uid in range(n):
        hotkey = key_for_uid(chain, netuid, uid)
        if hotkey:
            out[uid] = hotkey
    return out


def validator_permit_for_uid(chain: Chain, netuid: int, uid: int) -> bool:
    permits = as_list(q(chain, PALLET_SUBTENSOR, "ValidatorPermit", [netuid]))
    if uid < 0 or uid >= len(permits):
        return False
    return as_bool(permits[uid])


def weights_row(chain: Chain, netuid: int, uid: int) -> List[Tuple[int, int]]:
    row = q(chain, PALLET_SUBTENSOR, "Weights", [netuid, uid])
    return normalize_weight_row(row)


def commit_reveal_enabled(chain: Chain, netuid: int) -> bool:
    return q_bool(chain, PALLET_SUBTENSOR, "CommitRevealWeightsEnabled", [netuid])


def weights_version_key(chain: Chain, netuid: int) -> int:
    return q_int(chain, PALLET_SUBTENSOR, "WeightsVersionKey", [netuid])


def min_allowed_weights(chain: Chain, netuid: int) -> int:
    return q_int(chain, PALLET_SUBTENSOR, "MinAllowedWeights", [netuid])


def max_weight_limit(chain: Chain, netuid: int) -> int:
    return q_int(chain, PALLET_SUBTENSOR, "MaxWeightsLimit", [netuid])


def tempo(chain: Chain, netuid: int) -> int:
    return q_int(chain, PALLET_SUBTENSOR, "Tempo", [netuid])


def stake_threshold(chain: Chain) -> int:
    return q_int(chain, PALLET_SUBTENSOR, "StakeThreshold", [])


def owner_alpha(chain: Chain, netuid: int, hotkey_ss58: str) -> int:
    try:
        return q_int(chain, PALLET_SUBTENSOR, "TotalHotkeyAlpha", [hotkey_ss58, netuid])
    except Exception:
        return 0


def weights_set_rate_limit(chain: Chain, netuid: int) -> int:
    return q_int(chain, PALLET_SUBTENSOR, "WeightsSetRateLimit", [netuid])


def last_update_for_uid(chain: Chain, netuid: int, uid: int) -> int:
    values = as_list(q(chain, PALLET_SUBTENSOR, "LastUpdate", [netuid]))
    if uid < 0 or uid >= len(values):
        return 0
    return as_int(values[uid])


def remaining_weight_rate_limit_blocks(chain: Chain, netuid: int, uid: int) -> Tuple[int, int, int, int]:
    last = last_update_for_uid(chain, netuid, uid)
    limit = weights_set_rate_limit(chain, netuid)
    now = current_block(chain)
    if last <= 0 or limit <= 0:
        return 0, now, last, limit
    target = last + limit
    return max(0, target - now), now, last, limit


def submit_register_network(chain: Chain, cold: Keypair, owner_hot_ss58: str, owner_cold_ss58: str) -> Any:
    candidates = [
        {"hotkey": owner_hot_ss58},
        {"hotkey": owner_hot_ss58, "coldkey": owner_cold_ss58},
        {"hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"owner_hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"owner_hot": owner_hot_ss58, "owner_cold": owner_cold_ss58},
    ]
    errors: List[str] = []
    for params in candidates:
        try:
            call = chain.compose_call(PALLET_SUBTENSOR, "register_network", params)
        except Exception as exc:
            errors.append(f"compose {sorted(params.keys())}: {simplify_error(exc)}")
            continue
        try:
            return chain.submit(cold, call, "SubtensorModule.register_network")
        except Exception as exc:
            raise RuntimeError(
                f"register_network submission failed with parameter shape {sorted(params.keys())}: "
                f"{simplify_error(exc)}"
            ) from exc
    raise RuntimeError("Could not compose register_network: " + " | ".join(errors))


def submit_burned_register(chain: Chain, cold: Keypair, netuid: int, hot_ss58: str) -> Any:
    call = chain.compose_call(
        PALLET_SUBTENSOR,
        "burned_register",
        {"netuid": int(netuid), "hotkey": hot_ss58},
    )
    return chain.submit(cold, call, f"SubtensorModule.burned_register(netuid={netuid})")


def burned_register_with_retry(
    chain: Chain,
    cold: Keypair,
    netuid: int,
    hot_ss58: str,
    max_attempts: int,
    poll_seconds: float,
) -> Any:
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        try:
            return submit_burned_register(chain, cold, netuid, hot_ss58)
        except Exception as exc:
            last_error = simplify_error(exc)
            if attempt >= max_attempts or not is_registration_rate_limit(last_error):
                raise
            log(f"⚠️  burned_register rate-limited; attempt {attempt}/{max_attempts}: {last_error}")
            wait_for_blocks(chain, 2, poll_seconds, "registration rate-limit backoff")
    raise RuntimeError(f"burned_register failed after retries: {last_error}")


def compose_set_weights(
    chain: Chain,
    netuid: int,
    dest_uids: List[int],
    values: List[int],
    version_key: int,
) -> Any:
    candidates = [
        {
            "netuid": int(netuid),
            "dests": [int(uid) for uid in dest_uids],
            "weights": [int(v) for v in values],
            "version_key": int(version_key),
        },
        {
            "netuid": int(netuid),
            "uids": [int(uid) for uid in dest_uids],
            "weights": [int(v) for v in values],
            "version_key": int(version_key),
        },
    ]
    errors: List[str] = []
    for params in candidates:
        try:
            return chain.compose_call(PALLET_SUBTENSOR, "set_weights", params)
        except Exception as exc:
            errors.append(f"{sorted(params.keys())}: {simplify_error(exc)}")
    raise RuntimeError("Could not compose set_weights: " + " | ".join(errors))


def submit_owner_set_weights_once(
    chain: Chain,
    owner_hot: Keypair,
    netuid: int,
    dest_uids: List[int],
    values: List[int],
    version_key: int,
) -> Any:
    call = compose_set_weights(chain, netuid, dest_uids, values, version_key)
    return chain.submit(
        owner_hot,
        call,
        f"SubtensorModule.set_weights(netuid={netuid}, dests={dest_uids})",
    )


def submit_owner_set_weights_after_rate_limit(
    chain: Chain,
    owner_hot: Keypair,
    netuid: int,
    owner_uid: int,
    dest_uids: List[int],
    values: List[int],
    version_key: int,
    max_attempts: int,
    poll_seconds: float,
) -> Any:
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        remaining, now, last, limit = remaining_weight_rate_limit_blocks(chain, netuid, owner_uid)
        if remaining > 0:
            target = last + limit
            log(
                "⏱️  Waiting for set_weights rate limit: "
                f"current={now}, last_update={last}, limit={limit}, target={target}, remaining≈{remaining} block(s)"
            )
            wait_until_block(chain, target, poll_seconds, "set_weights cooldown")

        try:
            return submit_owner_set_weights_once(
                chain=chain,
                owner_hot=owner_hot,
                netuid=netuid,
                dest_uids=dest_uids,
                values=values,
                version_key=version_key,
            )
        except Exception as exc:
            last_error = simplify_error(exc)
            if not is_setting_weights_too_fast(last_error) or attempt >= max_attempts:
                raise
            log(f"⚠️  set_weights still hit SettingWeightsTooFast on attempt {attempt}/{max_attempts}: {last_error}")
            wait_for_blocks(chain, 2, poll_seconds, "post-failure set_weights cooldown")

    raise RuntimeError(f"set_weights did not pass after rate-limit retries: {last_error}")


def submit_set_commit_reveal_enabled(chain: Chain, owner_cold: Keypair, netuid: int, enabled: bool) -> Any:
    candidates = [
        (PALLET_ADMIN, "sudo_set_commit_reveal_weights_enabled", {"netuid": int(netuid), "enabled": bool(enabled)}),
        (PALLET_ADMIN, "sudo_set_commit_reveal_weights_enabled", {"netuid": int(netuid), "commit_reveal_weights_enabled": bool(enabled)}),
        (PALLET_SUBTENSOR, "sudo_set_commit_reveal_weights_enabled", {"netuid": int(netuid), "enabled": bool(enabled)}),
        (PALLET_SUBTENSOR, "sudo_set_commit_reveal_weights_enabled", {"netuid": int(netuid), "commit_reveal_weights_enabled": bool(enabled)}),
    ]
    errors: List[str] = []
    for module, function, params in candidates:
        try:
            call = chain.compose_call(module, function, params)
            return chain.submit(owner_cold, call, f"{module}.{function}(netuid={netuid}, enabled={enabled})")
        except Exception as exc:
            errors.append(f"{module}.{function} {sorted(params.keys())}: {simplify_error(exc)}")
    raise RuntimeError("Unable to submit commit-reveal setter: " + " | ".join(errors))


def find_owned_netuids(chain: Chain, cold: Keypair, hot: Keypair) -> List[int]:
    owned: List[int] = []
    for netuid in networks_added(chain):
        if subnet_owner(chain, netuid) == cold.ss58_address and subnet_owner_hotkey(chain, netuid) == hot.ss58_address:
            owned.append(netuid)
    return sorted(owned)


def choose_existing_owned_netuid(chain: Chain, cold: Keypair, hot: Keypair) -> Optional[int]:
    owned = find_owned_netuids(chain, cold, hot)
    if not owned:
        return None

    scored: List[Tuple[int, int, int, int, int]] = []
    for netuid in owned:
        owner_uid = hotkey_uid(chain, netuid, hot.ss58_address)
        if owner_uid is None:
            scored.append((1, 1, 999_999, -netuid, netuid))
            continue
        keys = keys_by_uid(chain, netuid)
        has_non_owner = any(uid != owner_uid for uid in keys)
        cr_enabled = commit_reveal_enabled(chain, netuid)
        remaining, _, _, _ = remaining_weight_rate_limit_blocks(chain, netuid, owner_uid)
        scored.append((1 if cr_enabled else 0, 0 if has_non_owner else 1, remaining, -netuid, netuid))

    scored.sort()
    return scored[0][-1]


def create_fresh_owner_subnet(chain: Chain, cold: Keypair, hot: Keypair) -> int:
    before = set(networks_added(chain))
    log("🧱 Creating a fresh subnet with the supplied coldkey/hotkey owner pair.")
    rec = submit_register_network(chain, cold, hot.ss58_address, cold.ss58_address)
    log(f"✅ register_network finalized in block {rec.block_hash}")

    for _ in range(60):
        after = set(networks_added(chain))
        created = sorted(after - before)
        for netuid in reversed(created):
            if subnet_owner(chain, netuid) == cold.ss58_address and subnet_owner_hotkey(chain, netuid) == hot.ss58_address:
                log(f"✅ Fresh owner subnet resolved: netuid={netuid}")
                return netuid
        time.sleep(2)

    raise RuntimeError("register_network finalized, but no newly owned subnet was found.")


def resolve_test_netuid(chain: Chain, cold: Keypair, hot: Keypair, args: argparse.Namespace) -> int:
    if args.netuid is not None:
        netuid = int(args.netuid)
        if netuid == 0:
            raise RuntimeError("netuid 0/root cannot be used for this test.")
        owner = subnet_owner(chain, netuid)
        owner_hot = subnet_owner_hotkey(chain, netuid)
        if owner != cold.ss58_address or owner_hot != hot.ss58_address:
            raise RuntimeError(
                f"netuid={netuid} is not owned by the supplied keypair.\n"
                f"  chain SubnetOwner       = {owner}\n"
                f"  expected coldkey        = {cold.ss58_address}\n"
                f"  chain SubnetOwnerHotkey = {owner_hot}\n"
                f"  expected hotkey         = {hot.ss58_address}"
            )
        return netuid

    if not args.create_fresh:
        existing = choose_existing_owned_netuid(chain, cold, hot)
        if existing is not None:
            log(f"♻️  Reusing existing owner subnet netuid={existing}")
            return existing

    return create_fresh_owner_subnet(chain, cold, hot)


def ensure_owner_uid(chain: Chain, netuid: int, cold: Keypair, hot: Keypair, args: argparse.Namespace) -> int:
    owner_uid = hotkey_uid(chain, netuid, hot.ss58_address)
    if owner_uid is not None:
        return owner_uid

    log("ℹ️  SubnetOwnerHotkey has no UID yet; registering owner hotkey on the subnet.")
    burned_register_with_retry(
        chain=chain,
        cold=cold,
        netuid=netuid,
        hot_ss58=hot.ss58_address,
        max_attempts=args.register_retries,
        poll_seconds=args.poll_seconds,
    )
    for _ in range(30):
        owner_uid = hotkey_uid(chain, netuid, hot.ss58_address)
        if owner_uid is not None:
            return owner_uid
        time.sleep(2)
    raise RuntimeError("Owner hotkey did not resolve to a UID after registration.")


def ensure_commit_reveal_disabled(chain: Chain, netuid: int, cold: Keypair, args: argparse.Namespace) -> None:
    if not commit_reveal_enabled(chain, netuid):
        log("✅ CommitRevealWeightsEnabled is already false.")
        return

    if args.skip_disable_commit_reveal:
        raise RuntimeError(
            "CommitRevealWeightsEnabled is true and --skip-disable-commit-reveal was set. "
            "Direct set_weights is rejected while commit-reveal is enabled."
        )

    log("🔧 CommitRevealWeightsEnabled is true; disabling it with the subnet owner coldkey.")
    last_error = ""
    for attempt in range(1, args.admin_retries + 1):
        try:
            rec = submit_set_commit_reveal_enabled(chain, cold, netuid, False)
            log(f"✅ commit-reveal disable extrinsic finalized in block {rec.block_hash}")
        except Exception as exc:
            last_error = simplify_error(exc)
            log(f"⚠️  commit-reveal disable attempt {attempt}/{args.admin_retries} failed: {last_error}")
            if not is_admin_window_error(last_error) and attempt >= 2:
                raise
            wait_for_blocks(chain, args.admin_retry_blocks, args.poll_seconds, "admin-window backoff")
            continue

        for _ in range(20):
            if not commit_reveal_enabled(chain, netuid):
                log("✅ CommitRevealWeightsEnabled readback is now false.")
                return
            time.sleep(2)
        last_error = "extrinsic finalized, but readback still true"

    raise RuntimeError(f"Could not disable CommitRevealWeightsEnabled. Last error: {last_error}")


def ensure_non_owner_uid(
    chain: Chain,
    netuid: int,
    cold: Keypair,
    owner_uid: int,
    ss58_format: int,
    args: argparse.Namespace,
) -> Dict[int, str]:
    keys = keys_by_uid(chain, netuid)
    if any(uid != owner_uid for uid in keys):
        return keys

    if not q_bool(chain, PALLET_SUBTENSOR, "NetworkRegistrationAllowed", [netuid]):
        raise RuntimeError(
            f"netuid={netuid} has only owner UID and NetworkRegistrationAllowed=false; "
            "cannot add a non-owner target UID."
        )

    log("➕ Subnet currently has only the owner UID; registering one non-owner target hotkey.")
    last_error = ""
    for i in range(args.register_retries):
        target_uri = f"//PR2532OwnerWeightTarget//{args.run_id}//{netuid}//{i}"
        target_hot = keypair_from_uri(target_uri, ss58_format)
        if hotkey_uid(chain, netuid, target_hot.ss58_address) is not None:
            keys = keys_by_uid(chain, netuid)
            if any(uid != owner_uid for uid in keys):
                return keys

        try:
            rec = burned_register_with_retry(
                chain=chain,
                cold=cold,
                netuid=netuid,
                hot_ss58=target_hot.ss58_address,
                max_attempts=3,
                poll_seconds=args.poll_seconds,
            )
            log(
                f"✅ burned_register target finalized in block {rec.block_hash} | "
                f"target={short_ss58(target_hot.ss58_address)}"
            )
        except Exception as exc:
            last_error = simplify_error(exc)
            log(f"⚠️  target registration attempt {i + 1}/{args.register_retries} failed: {last_error}")
            wait_for_blocks(chain, args.registration_retry_blocks, args.poll_seconds, "target registration backoff")
            continue

        for _ in range(30):
            keys = keys_by_uid(chain, netuid)
            if any(uid != owner_uid for uid in keys):
                return keys
            time.sleep(2)

    raise RuntimeError(f"Could not create/find non-owner UID. Last registration error: {last_error}")


def assert_owner_can_set_non_self_weights(
    chain: Chain,
    netuid: int,
    owner_hot: Keypair,
    owner_uid: int,
    args: argparse.Namespace,
) -> None:
    keys = keys_by_uid(chain, netuid)
    if owner_uid not in keys:
        raise AssertionError(f"Owner UID {owner_uid} is missing from Keys for netuid={netuid}.")

    non_owner_uids = sorted(uid for uid in keys if uid != owner_uid)
    if not non_owner_uids:
        raise AssertionError("No non-owner UID exists; cannot test non-self weights.")

    # Use exactly one non-owner destination, matching the Rust PR test shape.
    dest_uids = [non_owner_uids[0]]
    values = [1]
    version_key = weights_version_key(chain, netuid)

    remaining, now, last, limit = remaining_weight_rate_limit_blocks(chain, netuid, owner_uid)
    permit_before_wait = validator_permit_for_uid(chain, netuid, owner_uid)
    owner_stake_alpha = owner_alpha(chain, netuid, owner_hot.ss58_address)
    threshold = stake_threshold(chain)

    log("🔎 Pre-flight state before final cooldown wait:")
    log(f"   netuid                     = {netuid}")
    log(f"   owner_uid                  = {owner_uid}")
    log(f"   subnetwork_n               = {subnetwork_n(chain, netuid)}")
    log(f"   tempo                      = {tempo(chain, netuid)}")
    log(f"   min_allowed_weights        = {min_allowed_weights(chain, netuid)}")
    log(f"   max_weight_limit           = {max_weight_limit(chain, netuid)}")
    log(f"   weights_version_key        = {version_key}")
    log(f"   owner_validator_permit     = {permit_before_wait}")
    log(f"   owner_total_alpha          = {owner_stake_alpha}")
    log(f"   global_stake_threshold     = {threshold}")
    log(f"   weights_set_rate_limit     = {limit}")
    log(f"   owner_last_update          = {last}")
    log(f"   current_block              = {now}")
    log(f"   cooldown_remaining_blocks  = {remaining}")
    log(f"   non_self_destination_uids  = {dest_uids}")

    if max_weight_limit(chain, netuid) < U16_MAX:
        raise AssertionError(
            f"MaxWeightsLimit={max_weight_limit(chain, netuid)} is below u16::MAX. "
            "This simple one-weight live test expects the default max limit."
        )

    rec = submit_owner_set_weights_after_rate_limit(
        chain=chain,
        owner_hot=owner_hot,
        netuid=netuid,
        owner_uid=owner_uid,
        dest_uids=dest_uids,
        values=values,
        version_key=version_key,
        max_attempts=args.set_weights_retries,
        poll_seconds=args.poll_seconds,
    )
    log(f"✅ owner set_weights finalized in block {rec.block_hash}")

    permit_at_submit_end = validator_permit_for_uid(chain, netuid, owner_uid)
    if args.require_owner_permit_false and permit_at_submit_end:
        raise AssertionError(
            "Owner validator permit became true before/during set_weights. The owner set_weights call succeeded, "
            "but this run did not isolate the no-manual-permit dispatch bypass."
        )

    row = weights_row(chain, netuid, owner_uid)
    row_uids = [uid for uid, weight in row]
    if row_uids != dest_uids:
        raise AssertionError(
            "Weights row does not match submitted non-self destination UIDs.\n"
            f"  expected = {dest_uids}\n"
            f"  actual   = {row_uids}\n"
            f"  row      = {row}"
        )
    if not row or any(weight <= 0 for _, weight in row):
        raise AssertionError(f"Weights row contains empty/non-positive weights: {row}")
    if len(row) == 1 and row[0][0] == owner_uid:
        raise AssertionError("Weights row is only a self-weight; this did not test the owner non-self path.")

    log("✅ On-chain Weights row assertion passed.")
    log(f"   stored owner row           = {row}")
    log(f"   owner_validator_permit_now = {permit_at_submit_end}")

    if not permit_before_wait:
        log("✅ Owner permit was false before the final cooldown wait, so this live run exercised the intended owner path pre-flight.")
    else:
        log("ℹ️  Owner permit was already true before submission; this still asserts owner set_weights on-chain, but not a false-permit dispatch state.")

    if threshold > 0 and owner_stake_alpha < threshold:
        log("✅ Owner alpha was below StakeThreshold pre-flight, so this also exercised the minimum-stake bypass.")
    elif threshold == 0:
        log("ℹ️  StakeThreshold is 0 on this chain, so the minimum-stake gate is globally open on this run.")
    else:
        log("ℹ️  Owner alpha was at/above StakeThreshold pre-flight, so this run did not isolate the minimum-stake bypass.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Live dev-testnet test for PR #2532 owner hotkey set_weights behavior."
    )
    parser.add_argument("--ws", default=DEFAULT_WS, help=f"WebSocket endpoint. Default: {DEFAULT_WS}")
    parser.add_argument("--netuid", type=int, default=None, help="Use a specific existing owner subnet.")
    parser.add_argument(
        "--create-fresh",
        action="store_true",
        help="Force creation of a fresh subnet instead of reusing an existing owned subnet.",
    )
    parser.add_argument(
        "--cold-mnemonic",
        default=os.environ.get("PR2532_OWNER_COLD_MNEMONIC", DEFAULT_COLD_MNEMONIC),
        help="Owner coldkey mnemonic. Can also use PR2532_OWNER_COLD_MNEMONIC.",
    )
    parser.add_argument(
        "--hot-mnemonic",
        default=os.environ.get("PR2532_OWNER_HOT_MNEMONIC", DEFAULT_HOT_MNEMONIC),
        help="Owner hotkey mnemonic. Can also use PR2532_OWNER_HOT_MNEMONIC.",
    )
    parser.add_argument(
        "--skip-disable-commit-reveal",
        action="store_true",
        help="Do not try to disable CommitRevealWeightsEnabled before direct set_weights.",
    )
    parser.add_argument(
        "--require-owner-permit-false",
        action="store_true",
        help="Fail if the owner validator permit is true by the time set_weights succeeds.",
    )
    parser.add_argument("--query-retries", type=int, default=4)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--admin-retries", type=int, default=12)
    parser.add_argument("--admin-retry-blocks", type=int, default=2)
    parser.add_argument("--register-retries", type=int, default=20)
    parser.add_argument("--registration-retry-blocks", type=int, default=2)
    parser.add_argument("--set-weights-retries", type=int, default=6)
    parser.add_argument(
        "--run-id",
        default=str(int(time.time() * 1000)),
        help="Unique run id used for deterministic target hotkey derivation.",
    )
    args = parser.parse_args()

    chain = Chain(ws=args.ws, query_retries=args.query_retries)
    ss58_format = chain.get_ss58_format()
    decimals = chain.token_decimals()

    cold = keypair_from_mnemonic(args.cold_mnemonic, ss58_format)
    hot = keypair_from_mnemonic(args.hot_mnemonic, ss58_format)

    log("🌐 Connected")
    log(f"   ws          = {args.ws}")
    log(f"   ss58_format = {ss58_format}")
    log(f"   decimals    = {decimals}")
    log(f"   coldkey     = {cold.ss58_address} ({short_ss58(cold.ss58_address)})")
    log(f"   hotkey      = {hot.ss58_address} ({short_ss58(hot.ss58_address)})")
    log(f"   cold free   = {account_free(chain, cold.ss58_address)} planck")
    log(f"   hot free    = {account_free(chain, hot.ss58_address)} planck")

    netuid = resolve_test_netuid(chain, cold, hot, args)

    owner = subnet_owner(chain, netuid)
    owner_hot = subnet_owner_hotkey(chain, netuid)
    if owner != cold.ss58_address or owner_hot != hot.ss58_address:
        raise AssertionError(
            f"Resolved netuid={netuid}, but owner storage does not match supplied keys.\n"
            f"  SubnetOwner       = {owner}\n"
            f"  expected coldkey  = {cold.ss58_address}\n"
            f"  SubnetOwnerHotkey = {owner_hot}\n"
            f"  expected hotkey   = {hot.ss58_address}"
        )

    owner_uid = ensure_owner_uid(chain, netuid, cold, hot, args)
    log(f"✅ Owner UID resolved: netuid={netuid}, owner_uid={owner_uid}")

    ensure_commit_reveal_disabled(chain, netuid, cold, args)

    keys = ensure_non_owner_uid(
        chain=chain,
        netuid=netuid,
        cold=cold,
        owner_uid=owner_uid,
        ss58_format=ss58_format,
        args=args,
    )
    non_owner = sorted(uid for uid in keys if uid != owner_uid)
    log(f"✅ Non-owner UID(s) available: {non_owner}")

    assert_owner_can_set_non_self_weights(
        chain=chain,
        netuid=netuid,
        owner_hot=hot,
        owner_uid=owner_uid,
        args=args,
    )

    log("")
    log("🎉 PASS: subnet owner hotkey set non-self weights successfully on dev testnet.")
    log(f"   netuid    = {netuid}")
    log(f"   owner_uid = {owner_uid}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"\nAssertion failed:\n{exc}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as exc:
        print(f"\nError:\n{simplify_error(exc)}", file=sys.stderr)
        raise SystemExit(1)