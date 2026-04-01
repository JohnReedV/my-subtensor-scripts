#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dissolution indexer for Subtensor subnet removals.

Given a block number where a subnet was dissolved / deregistered, this script:

  1. Connects to a Substrate node with py-substrate-interface.
  2. Finds every Subtensor::NetworkRemoved(netuid) event in the target block.
  3. Pulls *pre-state* at block N-1 and *post-state* at block N.
  4. Reconstructs the destroy_alpha_in_out_stakes() staker TAO distribution:
       - reads SubnetTAO(netuid) before the block,
       - enumerates Alpha / AlphaV2 entries for the subnet,
       - uses TotalHotkeyAlpha and TotalHotkeyShares / TotalHotkeySharesV2
         to turn share entries into actual alpha value when possible,
       - applies the same largest-remainder pro-rata algorithm as the runtime.
  5. Reconstructs owner lock refund *as far as chain-observable data allows*:
       - exact lock amount and refund eligibility from storage,
       - event/balance based inference for the owner's credited refund,
       - effective emission offset inferred as lock - inferred_refund when unambiguous.
  6. Correlates same-extrinsic events and balance deltas so you can see:
       - which coldkeys received TAO,
       - which accounts appear to be LP owners,
       - any residual positive credits not explained by the alpha->TAO unwind.

Important notes:
  - Substrate state queried at block_hash is POST-state for that block. The script uses
    block N-1 for pre-state and block N for post-state.
  - Current runtimes may contain Alpha/TotalHotkeyShares, AlphaV2/TotalHotkeySharesV2,
    or both during migrations. The script prefers V2 and falls back to V1.
  - The runtime computes owner refund as:
        refund = max(0, lock_cost - owner_received_emission_value)
    for legacy subnets (registered before NetworkRegistrationStartBlock), and zero
    otherwise. The lock amount and eligibility are exact from storage. The final owner
    refund amount is inferred from events/balance effects unless it can be isolated
    perfectly from the same-extrinsic flow.

Usage examples:
    python3 dissolution_indexer.py --ws ws://127.0.0.1:9945 --block 123456
    python3 dissolution_indexer.py --ws wss://entrypoint.finney.opentensor.ai:443 --block 7379490 --json-out report.json
    python3 dissolution_indexer.py --ws ws://127.0.0.1:9945 --block 123456 --netuid 11 --pretty
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN, getcontext
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from substrateinterface import SubstrateInterface

# High precision for SafeFloat / fixed-point-ish values that may decode as decimal strings.
getcontext().prec = 80


class ProgressLogger:
    """Minimal stderr logger for long-running indexing stages."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._started_at = time.time()
        self._progress_state: Dict[str, Tuple[int, float]] = {}

    def _emit(self, message: str) -> None:
        if not self.enabled:
            return
        elapsed = time.time() - self._started_at
        print(f"[{elapsed:7.1f}s] {message}", file=sys.stderr, flush=True)

    def info(self, message: str) -> None:
        self._emit(message)

    def progress(
        self,
        key: str,
        current: int,
        total: Optional[int] = None,
        *,
        every: int = 50,
        min_interval_s: float = 10.0,
        label: Optional[str] = None,
    ) -> None:
        if not self.enabled:
            return
        now = time.time()
        prev_current, prev_ts = self._progress_state.get(key, (0, 0.0))
        should_emit = False

        if current <= 1 or current == total:
            should_emit = True
        elif every > 0 and current % every == 0:
            should_emit = True
        elif now - prev_ts >= min_interval_s and current != prev_current:
            should_emit = True

        if not should_emit:
            return

        self._progress_state[key] = (current, now)
        if label is None:
            if total is None:
                label = f"Progress: {current}"
            else:
                label = f"Progress: {current}/{total}"
        self._emit(label)


# ──────────────────────────────────────────────────────────────────────────────
# Basic helpers
# ──────────────────────────────────────────────────────────────────────────────


def _unwrap(value: Any) -> Any:
    return getattr(value, "value", value)


def _jsonable(value: Any) -> Any:
    value = _unwrap(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _to_int(value: Any) -> Optional[int]:
    value = _unwrap(value)
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, Decimal):
        return int(value.to_integral_value(rounding=ROUND_DOWN))
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return int(s, 16)
            except Exception:
                return None
        try:
            return int(s)
        except Exception:
            try:
                return int(Decimal(s).to_integral_value(rounding=ROUND_DOWN))
            except Exception:
                return None
    if isinstance(value, dict):
        # Common wrappers / scalecodec patterns.
        for key in ("value", "bits", "free", "amount", "balance", "inner"):
            if key in value:
                got = _to_int(value[key])
                if got is not None:
                    return got
        if len(value) == 1:
            return _to_int(next(iter(value.values())))
        return None
    return None


def _to_decimal(value: Any) -> Optional[Decimal]:
    value = _unwrap(value)
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool):
        return Decimal(int(value))
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return Decimal(int(s, 16))
            except Exception:
                return None
        try:
            return Decimal(s)
        except Exception:
            return None
    if isinstance(value, dict):
        for key in ("value", "bits", "amount", "balance", "inner"):
            if key in value:
                got = _to_decimal(value[key])
                if got is not None:
                    return got
        if len(value) == 1:
            return _to_decimal(next(iter(value.values())))
        return None
    return None


def _format_units(value: Optional[int], decimals: int) -> Optional[str]:
    if value is None:
        return None
    q = Decimal(value) / (Decimal(10) ** decimals)
    # normalize() is a bit too aggressive; keep plain string.
    return format(q, "f")


def _block_hash(substrate: SubstrateInterface, block_number: int) -> str:
    bh = substrate.get_block_hash(block_number)
    if not bh:
        raise RuntimeError(f"Could not resolve block hash for block {block_number}")
    return bh


def _get_block_number(substrate: SubstrateInterface, block_hash: str) -> int:
    try:
        header = substrate.get_block_header(block_hash=block_hash)
    except Exception:
        return 0
    hdr_val = _unwrap(header)
    if isinstance(hdr_val, dict) and "header" in hdr_val:
        hdr_val = hdr_val["header"]
    if not isinstance(hdr_val, dict):
        return 0
    return _to_int(hdr_val.get("number")) or 0


def connect(url: str, logger: Optional[ProgressLogger] = None) -> SubstrateInterface:
    if logger is not None:
        logger.info(f"Connecting to {url}")
    substrate = SubstrateInterface(url=url)
    substrate.init_runtime()
    if logger is not None:
        chain_name = None
        try:
            chain_name = substrate.chain
        except Exception:
            chain_name = None
        logger.info(f"Runtime ready on {chain_name or 'unknown chain'}")
    return substrate


def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


def list_pallet_names(substrate: SubstrateInterface) -> List[str]:
    md = substrate.get_metadata()
    return [str(p.name) for p in md.pallets]


def resolve_subtensor_pallet(substrate: SubstrateInterface) -> str:
    names = list_pallet_names(substrate)
    for name in names:
        if "subtensor" in name.lower():
            return name
    # Fallbacks seen on various chains/tests.
    for fallback in ("SubtensorModule", "Subtensor"):
        try:
            substrate.get_metadata_storage_function(fallback, "NetworksAdded")
            return fallback
        except Exception:
            pass
    raise RuntimeError("Could not resolve the Subtensor pallet name from metadata")


def resolve_storage_pallet(
    substrate: SubstrateInterface,
    storage_name: str,
    preferred: Optional[str] = None,
) -> Optional[str]:
    names = list_pallet_names(substrate)
    ordered: List[str] = []
    if preferred and preferred in names:
        ordered.append(preferred)
    ordered.extend([n for n in names if n not in ordered])
    for pallet in ordered:
        try:
            meta = substrate.get_metadata_storage_function(pallet, storage_name)
            if meta is not None:
                return pallet
        except Exception:
            continue
    return None


def has_storage(
    substrate: SubstrateInterface,
    storage_name: str,
    preferred: Optional[str] = None,
) -> bool:
    return resolve_storage_pallet(substrate, storage_name, preferred=preferred) is not None


def query_value(
    substrate: SubstrateInterface,
    pallet: Optional[str],
    storage: str,
    params: Optional[List[Any]] = None,
    block_hash: Optional[str] = None,
    default: Any = None,
) -> Any:
    if pallet is None:
        return default
    try:
        return _unwrap(substrate.query(pallet, storage, params or [], block_hash=block_hash))
    except Exception:
        return default


def query_map_entries(
    substrate: SubstrateInterface,
    pallet: Optional[str],
    storage: str,
    params: Optional[List[Any]] = None,
    block_hash: Optional[str] = None,
    page_size: int = 200,
) -> List[Tuple[Any, Any]]:
    if pallet is None:
        return []
    out: List[Tuple[Any, Any]] = []
    try:
        result = substrate.query_map(
            pallet,
            storage,
            params=params or [],
            block_hash=block_hash,
            page_size=page_size,
            ignore_decoding_errors=True,
        )
        for key_obj, value_obj in result:
            out.append((_unwrap(key_obj), _unwrap(value_obj)))
    except Exception:
        return []
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Key / account parsing helpers
# ──────────────────────────────────────────────────────────────────────────────


def _looks_like_ss58(substrate: SubstrateInterface, value: Any) -> bool:
    value = _unwrap(value)
    if not isinstance(value, str):
        return False
    try:
        return bool(substrate.is_valid_ss58_address(value))
    except Exception:
        return False


def _flatten_key(value: Any) -> List[Any]:
    value = _unwrap(value)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        out: List[Any] = []
        for item in value:
            out.extend(_flatten_key(item))
        return out
    if isinstance(value, dict):
        # dict ordering is stable in Python; keep it.
        out: List[Any] = []
        for item in value.values():
            out.extend(_flatten_key(item))
        return out
    return [value]


def _first_account(substrate: SubstrateInterface, values: Sequence[Any]) -> Optional[str]:
    for value in values:
        value = _unwrap(value)
        if _looks_like_ss58(substrate, value):
            return value
        if isinstance(value, str) and value.startswith("0x") and len(value) >= 34:
            # Some registries decode account ids as hex.
            try:
                return substrate.ss58_encode(value)
            except Exception:
                continue
    return None


def _extract_one_account_one_int(substrate: SubstrateInterface, key: Any) -> Tuple[Optional[str], Optional[int]]:
    flat = _flatten_key(key)
    account = _first_account(substrate, flat)
    ints: List[int] = []
    for item in flat:
        parsed = _to_int(item)
        if parsed is not None:
            ints.append(parsed)
    return account, ints[0] if ints else None


def _extract_cold_and_netuid(substrate: SubstrateInterface, key: Any) -> Tuple[Optional[str], Optional[int]]:
    # For Alpha::<T>::iter_prefix((hot,)) the key should decode as (cold, netuid).
    return _extract_one_account_one_int(substrate, key)


def _extract_hot_and_netuid(substrate: SubstrateInterface, key: Any) -> Tuple[Optional[str], Optional[int]]:
    # For TotalHotkeyAlpha::<T>::iter() the key should decode as (hot, netuid).
    return _extract_one_account_one_int(substrate, key)


def _extract_owner_and_posid(substrate: SubstrateInterface, key: Any) -> Tuple[Optional[str], Optional[int]]:
    # For Positions::<T>::iter_prefix((netuid,)) the key should decode as (owner, pos_id).
    return _extract_one_account_one_int(substrate, key)


# ──────────────────────────────────────────────────────────────────────────────
# Event / extrinsic parsing
# ──────────────────────────────────────────────────────────────────────────────


def _normalize_named_args(args_raw: Any) -> Tuple[List[Any], Dict[str, Any]]:
    args_raw = _unwrap(args_raw)
    out_list: List[Any] = []
    out_named: Dict[str, Any] = {}

    if args_raw is None:
        return out_list, out_named

    if isinstance(args_raw, dict):
        for key, value in args_raw.items():
            out_list.append(_jsonable(value))
            out_named[str(key)] = _jsonable(value)
        return out_list, out_named

    if isinstance(args_raw, list):
        for item in args_raw:
            item_u = _unwrap(item)
            if isinstance(item_u, dict) and "name" in item_u and "value" in item_u:
                out_list.append(_jsonable(item_u["value"]))
                out_named[str(item_u["name"])] = _jsonable(item_u["value"])
            else:
                out_list.append(_jsonable(item_u))
        return out_list, out_named

    out_list.append(_jsonable(args_raw))
    return out_list, out_named


def _event_phase_index(record: Dict[str, Any]) -> Optional[int]:
    phase = _unwrap(record.get("phase"))
    if phase is None:
        return None
    if isinstance(phase, dict):
        for key in ("ApplyExtrinsic", "apply_extrinsic"):
            if key in phase:
                return _to_int(phase[key])
        return None
    if isinstance(phase, str):
        if phase.startswith("ApplyExtrinsic(") and phase.endswith(")"):
            try:
                return int(phase[len("ApplyExtrinsic(") : -1])
            except Exception:
                return None
    return None


def normalize_event(record: Any) -> Dict[str, Any]:
    record_u = _unwrap(record)
    if not isinstance(record_u, dict):
        return {
            "phase_idx": None,
            "pallet": None,
            "event": None,
            "attrs": [],
            "attrs_named": {},
            "raw": _jsonable(record_u),
        }

    event = _unwrap(record_u.get("event", record_u))
    if not isinstance(event, dict):
        event = {}

    pallet = (
        event.get("module_id")
        or event.get("module")
        or event.get("section")
        or event.get("pallet")
    )
    variant = event.get("event_id") or event.get("method") or event.get("variant")
    attrs_raw = event.get("attributes") or event.get("data") or event.get("args") or []
    attrs_list, attrs_named = _normalize_named_args(attrs_raw)

    return {
        "phase_idx": _event_phase_index(record_u),
        "pallet": pallet,
        "event": variant,
        "attrs": attrs_list,
        "attrs_named": attrs_named,
        "raw": _jsonable(record_u),
    }


def load_events(substrate: SubstrateInterface, block_hash: str) -> List[Dict[str, Any]]:
    return [normalize_event(ev) for ev in substrate.get_events(block_hash=block_hash)]


def events_for_phase(events: List[Dict[str, Any]], phase_idx: Optional[int]) -> List[Dict[str, Any]]:
    return [ev for ev in events if ev.get("phase_idx") == phase_idx]


def _event_first_int(ev: Dict[str, Any]) -> Optional[int]:
    for value in ev.get("attrs", []):
        parsed = _to_int(value)
        if parsed is not None:
            return parsed
    for value in ev.get("attrs_named", {}).values():
        parsed = _to_int(value)
        if parsed is not None:
            return parsed
    return None


def find_network_removed_events(
    events: List[Dict[str, Any]],
    subtensor_pallet: str,
    netuid_filter: Optional[int] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ev in events:
        if (ev.get("pallet") or "").lower() != subtensor_pallet.lower():
            continue
        if ev.get("event") != "NetworkRemoved":
            continue
        netuid = _event_first_int(ev)
        if netuid_filter is not None and netuid != netuid_filter:
            continue
        item = dict(ev)
        item["netuid"] = netuid
        out.append(item)
    return out


def _extract_call_from_raw(raw: Any) -> Tuple[Optional[str], Optional[str], Any]:
    raw = _unwrap(raw)
    if raw is None or not isinstance(raw, dict):
        return None, None, None
    call = _unwrap(raw.get("call", raw))
    if not isinstance(call, dict):
        return None, None, None
    module = (
        call.get("call_module")
        or call.get("call_module_name")
        or call.get("pallet")
        or call.get("module")
        or call.get("section")
    )
    fn = call.get("call_function") or call.get("function") or call.get("method")
    args = call.get("call_args") or call.get("args") or []
    return module, fn, args


def _extract_extrinsic_signer_ss58(raw: Any) -> Optional[str]:
    raw = _unwrap(raw)
    if not isinstance(raw, dict):
        return None
    for key in ("address", "signer"):
        value = raw.get(key)
        if isinstance(value, str):
            return value
    return None


def load_block_extrinsics(substrate: SubstrateInterface, block_hash: str) -> List[Any]:
    block = substrate.get_block(block_hash=block_hash)
    return block.get("extrinsics") or block.get("extrinsic") or []


# ──────────────────────────────────────────────────────────────────────────────
# Balance / account helpers
# ──────────────────────────────────────────────────────────────────────────────


def account_info(substrate: SubstrateInterface, account: str, block_hash: str) -> Dict[str, int]:
    info = query_value(substrate, "System", "Account", [account], block_hash=block_hash, default={})
    data = info.get("data", info) if isinstance(info, dict) else {}
    return {
        "free": _to_int(data.get("free")) or 0,
        "reserved": _to_int(data.get("reserved")) or 0,
        "misc_frozen": _to_int(data.get("misc_frozen")) or _to_int(data.get("frozen")) or 0,
        "fee_frozen": _to_int(data.get("fee_frozen")) or 0,
    }


def account_delta(substrate: SubstrateInterface, account: str, pre_hash: str, post_hash: str) -> Dict[str, int]:
    pre = account_info(substrate, account, pre_hash)
    post = account_info(substrate, account, post_hash)
    return {
        "free_delta": post["free"] - pre["free"],
        "reserved_delta": post["reserved"] - pre["reserved"],
        "misc_frozen_delta": post["misc_frozen"] - pre["misc_frozen"],
        "fee_frozen_delta": post["fee_frozen"] - pre["fee_frozen"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Alpha / stake reconstruction
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class AlphaBackend:
    alpha_pallet: Optional[str]
    alpha_storage: str
    shares_pallet: Optional[str]
    shares_storage: str
    priority: int  # lower is preferred


@dataclass
class StakerEntry:
    hotkey: str
    coldkey: str
    netuid: int
    backend: str
    raw_share: str
    total_hotkey_alpha: int
    total_hotkey_shares: Optional[str]
    actual_alpha_value: int
    share_tao: int = 0
    remainder: int = 0
    index: int = 0


@dataclass
class DissolutionContext:
    subtensor_pallet: str
    positions_pallet: Optional[str]
    subnet_owner_pallet: Optional[str]
    subnet_owner_hotkey_pallet: Optional[str]
    subnet_locked_pallet: Optional[str]
    subnet_tao_pallet: Optional[str]
    total_stake_pallet: Optional[str]
    network_registered_at_pallet: Optional[str]
    network_registration_start_block_pallet: Optional[str]
    total_hotkey_alpha_pallet: Optional[str]
    subnet_owner_cut_pallet: Optional[str]
    swap_v3_initialized_pallet: Optional[str]



def discover_context(substrate: SubstrateInterface, subtensor_pallet: str) -> DissolutionContext:
    return DissolutionContext(
        subtensor_pallet=subtensor_pallet,
        positions_pallet=resolve_storage_pallet(substrate, "Positions"),
        subnet_owner_pallet=resolve_storage_pallet(substrate, "SubnetOwner", preferred=subtensor_pallet),
        subnet_owner_hotkey_pallet=resolve_storage_pallet(substrate, "SubnetOwnerHotkey", preferred=subtensor_pallet),
        subnet_locked_pallet=resolve_storage_pallet(substrate, "SubnetLocked", preferred=subtensor_pallet),
        subnet_tao_pallet=resolve_storage_pallet(substrate, "SubnetTAO", preferred=subtensor_pallet),
        total_stake_pallet=resolve_storage_pallet(substrate, "TotalStake", preferred=subtensor_pallet),
        network_registered_at_pallet=resolve_storage_pallet(substrate, "NetworkRegisteredAt", preferred=subtensor_pallet),
        network_registration_start_block_pallet=resolve_storage_pallet(
            substrate,
            "NetworkRegistrationStartBlock",
            preferred=subtensor_pallet,
        ),
        total_hotkey_alpha_pallet=resolve_storage_pallet(substrate, "TotalHotkeyAlpha", preferred=subtensor_pallet),
        subnet_owner_cut_pallet=resolve_storage_pallet(substrate, "SubnetOwnerCut", preferred=subtensor_pallet),
        swap_v3_initialized_pallet=resolve_storage_pallet(substrate, "SwapV3Initialized"),
    )


def discover_alpha_backends(substrate: SubstrateInterface, subtensor_pallet: str) -> List[AlphaBackend]:
    candidates = [
        ("AlphaV2", "TotalHotkeySharesV2", 0),
        ("Alpha", "TotalHotkeyShares", 1),
    ]
    out: List[AlphaBackend] = []
    for alpha_storage, shares_storage, priority in candidates:
        alpha_pallet = resolve_storage_pallet(substrate, alpha_storage, preferred=subtensor_pallet)
        shares_pallet = resolve_storage_pallet(substrate, shares_storage, preferred=subtensor_pallet)
        if alpha_pallet is None and shares_pallet is None:
            continue
        out.append(
            AlphaBackend(
                alpha_pallet=alpha_pallet,
                alpha_storage=alpha_storage,
                shares_pallet=shares_pallet,
                shares_storage=shares_storage,
                priority=priority,
            )
        )
    out.sort(key=lambda x: x.priority)
    return out


def _shares_to_actual_alpha(
    total_alpha: int,
    raw_share: Optional[Decimal],
    total_shares: Optional[Decimal],
) -> int:
    if raw_share is None:
        return 0
    if total_shares is not None and total_shares > 0 and total_alpha > 0:
        value = (Decimal(total_alpha) * raw_share / total_shares).to_integral_value(rounding=ROUND_DOWN)
        return int(value)
    return int(raw_share.to_integral_value(rounding=ROUND_DOWN))


def reconstruct_stakers(
    substrate: SubstrateInterface,
    ctx: DissolutionContext,
    alpha_backends: List[AlphaBackend],
    netuid: int,
    pre_hash: str,
    logger: Optional[ProgressLogger] = None,
) -> Tuple[List[StakerEntry], int, int]:
    """
    Returns (entries, total_alpha_value, pot_tao).
    """
    pot_tao = _to_int(
        query_value(substrate, ctx.subnet_tao_pallet, "SubnetTAO", [netuid], block_hash=pre_hash, default=0)
    ) or 0

    total_hotkey_alpha_rows = query_map_entries(
        substrate,
        ctx.total_hotkey_alpha_pallet,
        "TotalHotkeyAlpha",
        block_hash=pre_hash,
    )

    hot_totals: Dict[str, int] = {}
    for key, value in total_hotkey_alpha_rows:
        hotkey, row_netuid = _extract_hot_and_netuid(substrate, key)
        if hotkey is None or row_netuid != netuid:
            continue
        hot_totals[hotkey] = _to_int(value) or 0

    entries: List[StakerEntry] = []
    seen: set[Tuple[str, str, int]] = set()
    idx = 0

    if logger is not None:
        logger.info(f"[netuid {netuid}] Reconstructing stakers from {len(hot_totals)} hotkeys (pot={pot_tao})")

    for hot_idx, (hotkey, total_hotkey_alpha) in enumerate(hot_totals.items(), start=1):
        if logger is not None:
            logger.progress(
                key=f"hotkeys:{netuid}",
                current=hot_idx,
                total=len(hot_totals),
                every=max(1, len(hot_totals) // 20),
                min_interval_s=10.0,
                label=f"[netuid {netuid}] Hotkeys scanned: {hot_idx}/{len(hot_totals)}",
            )
        chosen_total_shares: Optional[Decimal] = None
        chosen_backend_name: Optional[str] = None
        # Prefer v2 shares if present.
        for backend in alpha_backends:
            shares_raw = query_value(
                substrate,
                backend.shares_pallet,
                backend.shares_storage,
                [hotkey, netuid],
                block_hash=pre_hash,
                default=None,
            )
            shares_dec = _to_decimal(shares_raw)
            if shares_dec is not None and shares_dec > 0:
                chosen_total_shares = shares_dec
                chosen_backend_name = backend.alpha_storage
                break

        for backend in alpha_backends:
            # Prefer higher-priority backend entries when duplicates exist.
            rows = query_map_entries(
                substrate,
                backend.alpha_pallet,
                backend.alpha_storage,
                [hotkey],
                block_hash=pre_hash,
            )
            for key, raw_share_value in rows:
                coldkey, row_netuid = _extract_cold_and_netuid(substrate, key)
                if coldkey is None or row_netuid != netuid:
                    continue
                dedupe_key = (hotkey, coldkey, netuid)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                raw_share_dec = _to_decimal(raw_share_value)
                total_shares_for_entry: Optional[Decimal] = None
                if chosen_backend_name == backend.alpha_storage and chosen_total_shares is not None:
                    total_shares_for_entry = chosen_total_shares
                else:
                    # Fallback to backend-local shares if chosen backend differed.
                    shares_raw = query_value(
                        substrate,
                        backend.shares_pallet,
                        backend.shares_storage,
                        [hotkey, netuid],
                        block_hash=pre_hash,
                        default=None,
                    )
                    total_shares_for_entry = _to_decimal(shares_raw)

                actual_alpha = _shares_to_actual_alpha(
                    total_alpha=total_hotkey_alpha,
                    raw_share=raw_share_dec,
                    total_shares=total_shares_for_entry,
                )
                if actual_alpha <= 0:
                    continue

                entries.append(
                    StakerEntry(
                        hotkey=hotkey,
                        coldkey=coldkey,
                        netuid=netuid,
                        backend=backend.alpha_storage,
                        raw_share=str(raw_share_dec) if raw_share_dec is not None else str(_jsonable(raw_share_value)),
                        total_hotkey_alpha=total_hotkey_alpha,
                        total_hotkey_shares=(
                            str(total_shares_for_entry) if total_shares_for_entry is not None else None
                        ),
                        actual_alpha_value=actual_alpha,
                        index=idx,
                    )
                )
                idx += 1

    total_alpha_value = sum(entry.actual_alpha_value for entry in entries)

    if pot_tao > 0 and total_alpha_value > 0 and entries:
        distributed = 0
        for entry in entries:
            prod = pot_tao * entry.actual_alpha_value
            share = prod // total_alpha_value
            rem = prod % total_alpha_value
            entry.share_tao = int(share)
            entry.remainder = int(rem)
            distributed += int(share)

        leftover = pot_tao - distributed
        if leftover > 0:
            entries.sort(key=lambda e: (-e.remainder, e.index))
            give = min(leftover, len(entries))
            for entry in entries[:give]:
                entry.share_tao += 1
            # restore original order for readability
            entries.sort(key=lambda e: e.index)

    return entries, total_alpha_value, pot_tao


# ──────────────────────────────────────────────────────────────────────────────
# LP / position helpers
# ──────────────────────────────────────────────────────────────────────────────


def load_lp_positions(
    substrate: SubstrateInterface,
    positions_pallet: Optional[str],
    netuid: int,
    block_hash: str,
) -> List[Dict[str, Any]]:
    rows = query_map_entries(substrate, positions_pallet, "Positions", [netuid], block_hash=block_hash)
    out: List[Dict[str, Any]] = []
    for key, value in rows:
        owner, pos_id = _extract_owner_and_posid(substrate, key)
        out.append(
            {
                "owner": owner,
                "position_id": pos_id,
                "raw_position": _jsonable(value),
            }
        )
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Main reconciliation
# ──────────────────────────────────────────────────────────────────────────────


def collect_positive_deposits(phase_events: List[Dict[str, Any]], substrate: SubstrateInterface) -> Dict[str, int]:
    deposit_by_account: Dict[str, int] = defaultdict(int)
    endowed_by_account: Dict[str, int] = defaultdict(int)

    for ev in phase_events:
        pallet = (ev.get("pallet") or "").lower()
        name = (ev.get("event") or "").lower()
        # Prefer Balances::Deposit. Endowed is used as a fallback only when Deposit is absent,
        # because some runtimes may emit both for a newly-created account.
        if pallet != "balances" or name not in {"deposit", "endowed"}:
            continue
        account: Optional[str] = None
        amount: Optional[int] = None

        # Named attrs first.
        for _, value in ev.get("attrs_named", {}).items():
            if account is None and _looks_like_ss58(substrate, value):
                account = value
            if amount is None:
                parsed = _to_int(value)
                if parsed is not None:
                    amount = parsed
        if account is None or amount is None:
            # Positional fallback.
            for value in ev.get("attrs", []):
                if account is None and _looks_like_ss58(substrate, value):
                    account = value
                    continue
                if amount is None:
                    parsed = _to_int(value)
                    if parsed is not None:
                        amount = parsed
        if account is None or amount is None or amount <= 0:
            continue

        if name == "deposit":
            deposit_by_account[account] += amount
        elif name == "endowed":
            endowed_by_account[account] += amount

    merged: Dict[str, int] = {}
    accounts = set(deposit_by_account) | set(endowed_by_account)
    for account in accounts:
        merged[account] = deposit_by_account.get(account, 0) or endowed_by_account.get(account, 0)
    return merged


def aggregate_staker_shares(entries: List[StakerEntry]) -> Dict[str, int]:
    out: Dict[str, int] = defaultdict(int)
    for entry in entries:
        out[entry.coldkey] += entry.share_tao
    return dict(out)


def infer_owner_refund(
    owner: Optional[str],
    lock_cost: int,
    is_legacy_refund_eligible: bool,
    credited_by_event: Dict[str, int],
    staker_share_by_coldkey: Dict[str, int],
    lp_owners: set[str],
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "owner": owner,
        "legacy_refund_eligible": is_legacy_refund_eligible,
        "locked_balance_before": lock_cost,
        "inferred_refund": None,
        "inferred_effective_owner_emission_offset": None,
        "refund_tao": None,
        "owner_emission_tao_offset": None,
        "inference_quality": "none",
    }
    if owner is None:
        return result

    owner_credit = credited_by_event.get(owner, 0)
    owner_staker_credit = staker_share_by_coldkey.get(owner, 0)
    residual_after_staker = owner_credit - owner_staker_credit
    result["observed_positive_credit_to_owner"] = owner_credit
    result["owner_staker_distribution_component"] = owner_staker_credit
    result["residual_after_staker_component"] = residual_after_staker

    if not is_legacy_refund_eligible:
        # New subnets get no lock refund by design.
        result["inferred_refund"] = 0
        result["inferred_effective_owner_emission_offset"] = 0
        result["refund_tao"] = 0
        result["owner_emission_tao_offset"] = 0
        result["inference_quality"] = "exact:no-legacy-refund"
        return result

    # If owner is not an LP owner, residual after staker component is a clean refund inference.
    if owner not in lp_owners:
        inferred_refund = max(0, residual_after_staker)
        inferred_offset = max(0, lock_cost - inferred_refund)
        result["inferred_refund"] = inferred_refund
        result["inferred_effective_owner_emission_offset"] = inferred_offset
        result["refund_tao"] = inferred_refund
        result["owner_emission_tao_offset"] = inferred_offset
        result["inference_quality"] = "exact:event-residual"
        return result

    # If the owner is also an LP owner, residual may include LP tao refund.
    # Still provide a lower-bound / upper-bound style inference.
    inferred_lower_bound = max(0, residual_after_staker)
    result["inferred_refund"] = inferred_lower_bound
    result["inferred_effective_owner_emission_offset"] = max(0, lock_cost - inferred_lower_bound)
    result["refund_tao"] = inferred_lower_bound
    result["owner_emission_tao_offset"] = max(0, lock_cost - inferred_lower_bound)
    result["inference_quality"] = "ambiguous:owner-is-lp-owner"
    return result


def reconcile_account_rows(
    substrate: SubstrateInterface,
    pre_hash: str,
    post_hash: str,
    owner: Optional[str],
    staker_entries: List[StakerEntry],
    lp_positions_pre: List[Dict[str, Any]],
    credited_by_event: Dict[str, int],
    logger: Optional[ProgressLogger] = None,
    netuid: Optional[int] = None,
) -> List[Dict[str, Any]]:
    accounts: set[str] = set()
    roles: Dict[str, set[str]] = defaultdict(set)

    if owner:
        accounts.add(owner)
        roles[owner].add("subnet_owner")

    for entry in staker_entries:
        accounts.add(entry.coldkey)
        roles[entry.coldkey].add("staker_coldkey")
        accounts.add(entry.hotkey)
        roles[entry.hotkey].add("staker_hotkey")

    for pos in lp_positions_pre:
        owner_acc = pos.get("owner")
        if isinstance(owner_acc, str):
            accounts.add(owner_acc)
            roles[owner_acc].add("lp_owner")

    for account in credited_by_event.keys():
        accounts.add(account)
        roles[account].add("credited_in_event")

    rows: List[Dict[str, Any]] = []
    sorted_accounts = sorted(accounts)
    if logger is not None:
        prefix = f"[netuid {netuid}] " if netuid is not None else ""
        logger.info(f"{prefix}Reconciling accounts: {len(sorted_accounts)}")

    for idx_account, account in enumerate(sorted_accounts, start=1):
        pre = account_info(substrate, account, pre_hash)
        post = account_info(substrate, account, post_hash)
        delta = {
            "free_delta": post["free"] - pre["free"],
            "reserved_delta": post["reserved"] - pre["reserved"],
            "misc_frozen_delta": post["misc_frozen"] - pre["misc_frozen"],
            "fee_frozen_delta": post["fee_frozen"] - pre["fee_frozen"],
        }
        rows.append(
            {
                "account": account,
                "roles": sorted(roles[account]),
                "credited_by_balance_events": credited_by_event.get(account, 0),
                "pre": pre,
                "post": post,
                "delta": delta,
            }
        )
        if logger is not None:
            prefix = f"[netuid {netuid}] " if netuid is not None else ""
            logger.progress(
                key=f"accounts:{netuid or 'all'}",
                current=idx_account,
                total=len(sorted_accounts),
                every=max(1, len(sorted_accounts) // 20),
                min_interval_s=15.0,
                label=f"{prefix}Accounts reconciled: {idx_account}/{len(sorted_accounts)}",
            )
    return rows


# ──────────────────────────────────────────────────────────────────────────────
# Full dissolution report
# ──────────────────────────────────────────────────────────────────────────────


def build_dissolution_report(
    substrate: SubstrateInterface,
    ctx: DissolutionContext,
    alpha_backends: List[AlphaBackend],
    block_number: int,
    block_hash: str,
    pre_hash: str,
    network_removed_event: Dict[str, Any],
    all_events_in_block: List[Dict[str, Any]],
    extrinsics: List[Any],
    decimals: int,
    logger: Optional[ProgressLogger] = None,
) -> Dict[str, Any]:
    netuid = network_removed_event["netuid"]
    phase_idx = network_removed_event.get("phase_idx")
    phase_events = events_for_phase(all_events_in_block, phase_idx)

    if logger is not None:
        logger.info(f"[netuid {netuid}] Loading pre-state and same-extrinsic events")

    owner = query_value(substrate, ctx.subnet_owner_pallet, "SubnetOwner", [netuid], block_hash=pre_hash)
    owner_hotkey = query_value(
        substrate,
        ctx.subnet_owner_hotkey_pallet,
        "SubnetOwnerHotkey",
        [netuid],
        block_hash=pre_hash,
    )
    lock_cost = _to_int(
        query_value(substrate, ctx.subnet_locked_pallet, "SubnetLocked", [netuid], block_hash=pre_hash, default=0)
    ) or 0
    reg_at = _to_int(
        query_value(
            substrate,
            ctx.network_registered_at_pallet,
            "NetworkRegisteredAt",
            [netuid],
            block_hash=pre_hash,
            default=0,
        )
    ) or 0
    reg_start_block = _to_int(
        query_value(
            substrate,
            ctx.network_registration_start_block_pallet,
            "NetworkRegistrationStartBlock",
            [],
            block_hash=pre_hash,
            default=0,
        )
    ) or 0
    owner_cut = _to_int(
        query_value(substrate, ctx.subnet_owner_cut_pallet, "SubnetOwnerCut", [], block_hash=pre_hash, default=None)
    )
    owner_cut_float = None
    if owner_cut is not None:
        owner_cut_float = str((Decimal(owner_cut) / Decimal(65535)))

    subnet_tao_pre = _to_int(
        query_value(substrate, ctx.subnet_tao_pallet, "SubnetTAO", [netuid], block_hash=pre_hash, default=0)
    ) or 0
    subnet_tao_post = _to_int(
        query_value(substrate, ctx.subnet_tao_pallet, "SubnetTAO", [netuid], block_hash=block_hash, default=0)
    ) or 0
    total_stake_pre = _to_int(
        query_value(substrate, ctx.total_stake_pallet, "TotalStake", [], block_hash=pre_hash, default=0)
    ) or 0
    total_stake_post = _to_int(
        query_value(substrate, ctx.total_stake_pallet, "TotalStake", [], block_hash=block_hash, default=0)
    ) or 0
    swap_v3_initialized_pre = bool(
        query_value(
            substrate,
            ctx.swap_v3_initialized_pallet,
            "SwapV3Initialized",
            [netuid],
            block_hash=pre_hash,
            default=False,
        )
    )

    if logger is not None:
        logger.info(f"[netuid {netuid}] Loading TotalHotkeyAlpha snapshot")

    staker_entries, total_alpha_value, pot_tao = reconstruct_stakers(
        substrate=substrate,
        ctx=ctx,
        alpha_backends=alpha_backends,
        netuid=netuid,
        pre_hash=pre_hash,
        logger=logger,
    )

    if logger is not None:
        logger.info(
            f"[netuid {netuid}] Staker reconstruction complete: {len(staker_entries)} entries, total_alpha={total_alpha_value}, distributed_tao={sum(e.share_tao for e in staker_entries)}"
        )
    staker_share_by_coldkey = aggregate_staker_shares(staker_entries)

    if logger is not None:
        logger.info(f"[netuid {netuid}] Loading LP positions")
    lp_positions_pre = load_lp_positions(substrate, ctx.positions_pallet, netuid, pre_hash)
    if logger is not None:
        logger.info(f"[netuid {netuid}] LP positions loaded: {len(lp_positions_pre)}")
    lp_owners = {
        pos["owner"] for pos in lp_positions_pre if isinstance(pos.get("owner"), str)
    }

    credited_by_event = collect_positive_deposits(phase_events, substrate)

    owner_refund = infer_owner_refund(
        owner=owner if isinstance(owner, str) else None,
        lock_cost=lock_cost,
        is_legacy_refund_eligible=bool(reg_at < reg_start_block),
        credited_by_event=credited_by_event,
        staker_share_by_coldkey=staker_share_by_coldkey,
        lp_owners=lp_owners,
    )
    owner_refund["refund_tao_human"] = _format_units(owner_refund.get("refund_tao"), decimals)
    owner_refund["owner_emission_tao_offset_human"] = _format_units(owner_refund.get("owner_emission_tao_offset"), decimals)

    account_rows = reconcile_account_rows(
        substrate=substrate,
        pre_hash=pre_hash,
        post_hash=block_hash,
        owner=owner if isinstance(owner, str) else None,
        staker_entries=staker_entries,
        lp_positions_pre=lp_positions_pre,
        credited_by_event=credited_by_event,
        logger=logger,
        netuid=netuid,
    )

    extrinsic_info: Dict[str, Any] = {
        "index": phase_idx,
        "signer": None,
        "module": None,
        "function": None,
        "args": None,
        "raw": None,
    }
    if phase_idx is not None and 0 <= phase_idx < len(extrinsics):
        raw_xt = _unwrap(extrinsics[phase_idx])
        module, fn, args_raw = _extract_call_from_raw(raw_xt)
        _args_list, args_named = _normalize_named_args(args_raw)
        extrinsic_info = {
            "index": phase_idx,
            "signer": _extract_extrinsic_signer_ss58(raw_xt),
            "module": module,
            "function": fn,
            "args": args_named if args_named else _jsonable(args_raw),
            "raw": _jsonable(raw_xt),
        }

    explained_credit_by_account: Dict[str, int] = defaultdict(int)
    for account, amount in staker_share_by_coldkey.items():
        explained_credit_by_account[account] += amount
    if owner_refund.get("inferred_refund") is not None and isinstance(owner_refund.get("owner"), str):
        explained_credit_by_account[owner_refund["owner"]] += int(owner_refund["inferred_refund"])

    unexplained_positive_credit_by_account: Dict[str, int] = {}
    for account, amount in credited_by_event.items():
        unexplained = amount - explained_credit_by_account.get(account, 0)
        if unexplained != 0:
            unexplained_positive_credit_by_account[account] = unexplained

    summary = {
        "netuid": netuid,
        "block_number": block_number,
        "block_hash": block_hash,
        "pre_block_hash": pre_hash,
        "phase_extrinsic_index": phase_idx,
        "extrinsic": extrinsic_info,
        "network_removed_event": network_removed_event,
        "pre_state": {
            "owner": owner,
            "owner_hotkey": owner_hotkey,
            "registered_at": reg_at,
            "network_registration_start_block": reg_start_block,
            "legacy_owner_refund_eligible": reg_at < reg_start_block,
            "subnet_owner_cut_raw": owner_cut,
            "subnet_owner_cut_float": owner_cut_float,
            "subnet_locked_before": lock_cost,
            "subnet_tao_before": subnet_tao_pre,
            "subnet_tao_after": subnet_tao_post,
            "total_stake_before": total_stake_pre,
            "total_stake_after": total_stake_post,
            "swap_v3_initialized_before": swap_v3_initialized_pre,
        },
        "owner_refund": owner_refund,
        "staker_distribution": {
            "pot_tao_before": pot_tao,
            "pot_tao_before_human": _format_units(pot_tao, decimals),
            "total_alpha_value_before": total_alpha_value,
            "entries": [
                {
                    "hotkey": e.hotkey,
                    "coldkey": e.coldkey,
                    "backend": e.backend,
                    "raw_share": e.raw_share,
                    "total_hotkey_alpha": e.total_hotkey_alpha,
                    "total_hotkey_shares": e.total_hotkey_shares,
                    "actual_alpha_value": e.actual_alpha_value,
                    "actual_alpha_value_human": _format_units(e.actual_alpha_value, decimals),
                    "tao_received_from_alpha": e.share_tao,
                    "tao_received_from_alpha_human": _format_units(e.share_tao, decimals),
                    "share_tao": e.share_tao,
                    "share_tao_human": _format_units(e.share_tao, decimals),
                    "remainder": e.remainder,
                }
                for e in staker_entries
            ],
            "aggregated_by_coldkey": [
                {
                    "coldkey": cold,
                    "alpha_before": sum(e.actual_alpha_value for e in staker_entries if e.coldkey == cold),
                    "alpha_before_human": _format_units(sum(e.actual_alpha_value for e in staker_entries if e.coldkey == cold), decimals),
                    "tao_received_from_alpha": amount,
                    "tao_received_from_alpha_human": _format_units(amount, decimals),
                    "share_tao": amount,
                    "share_tao_human": _format_units(amount, decimals),
                }
                for cold, amount in sorted(staker_share_by_coldkey.items())
            ],
            "sum_distributed_tao": sum(e.share_tao for e in staker_entries),
            "sum_distributed_tao_human": _format_units(sum(e.share_tao for e in staker_entries), decimals),
        },
        "lp_positions_pre": lp_positions_pre,
        "lp_owner_set": sorted(lp_owners),
        "positive_credits_by_balance_events": {
            account: {
                "amount": amount,
                "amount_human": _format_units(amount, decimals),
            }
            for account, amount in sorted(credited_by_event.items())
        },
        "same_phase_events": phase_events,
        "accounts": account_rows,
        "reconciliation": {
            "explained_credit_by_account": {
                account: {
                    "amount": amount,
                    "amount_human": _format_units(amount, decimals),
                }
                for account, amount in sorted(explained_credit_by_account.items())
                if amount != 0
            },
            "unexplained_positive_credit_by_account": {
                account: {
                    "amount": amount,
                    "amount_human": _format_units(amount, decimals),
                }
                for account, amount in sorted(unexplained_positive_credit_by_account.items())
            },
            "notes": [
                "Positive unexplained credit often corresponds to LP TAO refunds or other same-extrinsic payouts not reconstructed from Alpha->TAO unwind alone.",
                "If the subnet owner is also an LP owner, the owner refund inference may include LP refund residuals unless liquidity events isolate them.",
            ],
        },
    }

    if logger is not None:
        logger.info(
            f"[netuid {netuid}] Done: owner_refund={owner_refund.get('refund_tao', owner_refund.get('inferred_refund'))} quality={owner_refund.get('inference_quality')}"
        )

    return summary


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def build_report(
    substrate: SubstrateInterface,
    block_number: int,
    netuid_filter: Optional[int] = None,
    logger: Optional[ProgressLogger] = None,
) -> Dict[str, Any]:
    if block_number <= 0:
        raise ValueError("--block must be > 0 so a pre-state (block-1) exists")

    if logger is not None:
        logger.info("Resolving metadata and storage layout")

    decimals = token_decimals(substrate)
    subtensor_pallet = resolve_subtensor_pallet(substrate)
    ctx = discover_context(substrate, subtensor_pallet)
    alpha_backends = discover_alpha_backends(substrate, subtensor_pallet)

    if logger is not None:
        logger.info(
            f"Resolved subtensor={subtensor_pallet}, decimals={decimals}, alpha_backends={', '.join(b.alpha_storage for b in alpha_backends) or 'none'}"
        )

    if logger is not None:
        logger.info(f"Loading block {block_number} and pre-state block {block_number - 1}")
    block_hash = _block_hash(substrate, block_number)
    pre_hash = _block_hash(substrate, block_number - 1)

    if logger is not None:
        logger.info("Loading events and extrinsics")
    events = load_events(substrate, block_hash)
    extrinsics = load_block_extrinsics(substrate, block_hash)
    removals = find_network_removed_events(events, subtensor_pallet, netuid_filter=netuid_filter)
    if logger is not None:
        logger.info(
            f"Loaded {len(events)} events, {len(extrinsics)} extrinsics, {len(removals)} NetworkRemoved matches"
        )

    chain_name = None
    try:
        chain_name = substrate.chain
    except Exception:
        chain_name = None

    result: Dict[str, Any] = {
        "chain": chain_name,
        "ws_url": getattr(substrate, "url", None),
        "block_number": block_number,
        "block_hash": block_hash,
        "pre_block_hash": pre_hash,
        "token_decimals": decimals,
        "subtensor_pallet": subtensor_pallet,
        "alpha_backends": [
            {
                "alpha_pallet": backend.alpha_pallet,
                "alpha_storage": backend.alpha_storage,
                "shares_pallet": backend.shares_pallet,
                "shares_storage": backend.shares_storage,
                "priority": backend.priority,
            }
            for backend in alpha_backends
        ],
        "dissolutions": [],
    }

    for idx_removal, removal in enumerate(removals, start=1):
        if logger is not None:
            logger.info(f"Building dissolution report {idx_removal}/{len(removals)} for netuid={removal['netuid']}")
        report = build_dissolution_report(
            substrate=substrate,
            ctx=ctx,
            alpha_backends=alpha_backends,
            block_number=block_number,
            block_hash=block_hash,
            pre_hash=pre_hash,
            network_removed_event=removal,
            all_events_in_block=events,
            extrinsics=extrinsics,
            decimals=decimals,
            logger=logger,
        )
        result["dissolutions"].append(report)

    if not result["dissolutions"]:
        result["warning"] = (
            f"No {subtensor_pallet}::NetworkRemoved events were found in block {block_number}"
            + (f" for netuid={netuid_filter}" if netuid_filter is not None else "")
        )

    return result


def human_print(report: Dict[str, Any]) -> None:
    print(f"Chain: {report.get('chain')}")
    print(f"Block: {report['block_number']}  hash={report['block_hash']}")
    if "warning" in report:
        print(f"WARNING: {report['warning']}")
        return

    for item in report.get("dissolutions", []):
        print("=" * 88)
        print(f"netuid={item['netuid']}  extrinsic_index={item['phase_extrinsic_index']}")
        extrinsic = item.get("extrinsic") or {}
        print(
            f"call={extrinsic.get('module')}::{extrinsic.get('function')} signer={extrinsic.get('signer')}"
        )
        owner_refund = item.get("owner_refund") or {}
        pre = item.get("pre_state") or {}
        print(
            f"owner={pre.get('owner')}  lock_before={pre.get('subnet_locked_before')}  legacy_refund={pre.get('legacy_owner_refund_eligible')}"
        )
        print(
            f"owner_refund={owner_refund.get('refund_tao', owner_refund.get('inferred_refund'))}  quality={owner_refund.get('inference_quality')}  owner_emission_offset={owner_refund.get('owner_emission_tao_offset', owner_refund.get('inferred_effective_owner_emission_offset'))}"
        )
        st = item.get("staker_distribution") or {}
        print(
            f"staker_pot_tao={st.get('pot_tao_before')}  total_alpha_value={st.get('total_alpha_value_before')}  distributed={st.get('sum_distributed_tao')}"
        )
        agg = st.get("aggregated_by_coldkey") or []
        if agg:
            print("staker payouts:")
            for row in agg:
                print(
                    f"  - {row['coldkey']}: alpha_before={row.get('alpha_before')} ({row.get('alpha_before_human')}) -> tao_received={row.get('tao_received_from_alpha', row.get('share_tao'))} ({row.get('tao_received_from_alpha_human', row.get('share_tao_human'))})"
                )
        unexpl = item.get("reconciliation", {}).get("unexplained_positive_credit_by_account", {})
        if unexpl:
            print("unexplained positive credits:")
            for account, row in unexpl.items():
                print(f"  - {account}: {row['amount']} ({row['amount_human']})")


def main() -> None:
    ap = argparse.ArgumentParser(description="Index a subnet dissolution block and reconstruct token flows")
    ap.add_argument("--ws", required=True, help="Substrate websocket endpoint")
    ap.add_argument("--block", required=True, type=int, help="Block number where NetworkRemoved occurred")
    ap.add_argument("--netuid", type=int, default=None, help="Optional netuid filter if block has multiple dissolutions")
    ap.add_argument("--json-out", default=None, help="Optional file to write JSON report to")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.add_argument("--human", action="store_true", help="Also print a short human summary")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress logs on stderr")
    args = ap.parse_args()

    logger = ProgressLogger(enabled=not args.quiet)
    substrate = connect(args.ws, logger=logger)
    report = build_report(substrate, block_number=args.block, netuid_filter=args.netuid, logger=logger)

    if args.human:
        human_print(report)

    if args.pretty or args.json_out:
        text = json.dumps(report, indent=2, sort_keys=False, ensure_ascii=False)
    else:
        text = json.dumps(report, separators=(",", ":"), ensure_ascii=False)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
        logger.info(f"Wrote JSON report to {args.json_out}")
    else:
        sys.stdout.write(text)
        sys.stdout.write("\n")

    logger.info("Done")


if __name__ == "__main__":
    main()
