#!/usr/bin/env python3
"""
Diagnose why `RegisterNetwork` is still rate-limited on Finney testnet by reading:
  - NetworkRateLimit (blocks)
  - LastRateLimitedBlock[RateLimitKey::NetworkLastRegistered] (the global last-registration block)

Your runtime stores the "last lock block" inside the map:
    LastRateLimitedBlock<RateLimitKey<T::AccountId> -> u64>
under the enum key variant:
    RateLimitKey::NetworkLastRegistered

This script:
  1) Connects to wss://test.finney.opentensor.ai:443 (override via OPENTENSOR_WS)
  2) Reads the chain head block/timestamp
  3) Reads NetworkRateLimit
  4) Iterates LastRateLimitedBlock and finds the entry whose key is NetworkLastRegistered
  5) Computes the same predicate as the runtime:
         block.saturating_sub(last_block) >= NetworkRateLimit
     and prints a clear diagnosis (including the "last_block > head" trap)

Requirements:
    pip install substrate-interface
Environment:
    OPENTENSOR_WS (optional) defaults to wss://test.finney.opentensor.ai:443
"""

import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional, Tuple, List

from substrateinterface import SubstrateInterface

# Import SubstrateRequestException if available; fall back otherwise
try:
    from substrateinterface.exceptions import SubstrateRequestException
except Exception:
    class SubstrateRequestException(Exception):
        pass


# ---------- Configuration ----------
OPENTENSOR_WS = os.environ.get("OPENTENSOR_WS", "wss://archive.chain.opentensor.ai")

# Pallet guesses used by Subtensor deployments
POSSIBLE_PALLETS = ["SubtensorModule", "Subtensor"]

# Storage item names (from your pallet snippet)
NETWORK_RATE_LIMIT_NAME = "NetworkRateLimit"
LAST_RATE_LIMITED_BLOCK_NAME = "LastRateLimitedBlock"
NETWORK_LAST_LOCK_COST_NAME = "NetworkLastLockCost"  # optional/diagnostic


# ---------- Helpers ----------
def saturating_sub(a: int, b: int) -> int:
    """Rust-like u64 saturating subtraction for non-negative ints."""
    return a - b if a >= b else 0


def to_int(value: Any) -> Optional[int]:
    """Best-effort convert SCALE value to int."""
    if value is None:
        return None
    v = getattr(value, "value", value)
    try:
        return int(v)
    except Exception:
        if isinstance(v, str) and v.startswith("0x"):
            try:
                return int(v, 16)
            except Exception:
                return None
    return None


def to_simple(obj: Any):
    """Recursively unwrap substrate-interface ScaleType values to plain Python types."""
    if hasattr(obj, "value"):
        return to_simple(getattr(obj, "value"))
    if isinstance(obj, (list, tuple)):
        return type(obj)(to_simple(x) for x in obj)
    if isinstance(obj, dict):
        return {k: to_simple(v) for k, v in obj.items()}
    return obj


def list_storage_items(substrate: SubstrateInterface, pallet: str) -> List[str]:
    """
    List storage item names for a pallet.
    Tries both modern and legacy substrate-interface methods.
    """
    # 1) Try helper (works on many substrate-interface versions)
    try:
        sfuncs = substrate.get_metadata_storage_functions(pallet)
        if sfuncs:
            return list(sfuncs.keys())
    except Exception:
        pass

    # 2) Fallback to raw metadata walk
    items: List[str] = []
    try:
        md = substrate.get_metadata()
        pallets = getattr(md, "pallets", None)
        if not pallets:
            return items
        for p in pallets:
            name = getattr(p, "name", "")
            if name == pallet and getattr(p, "storage", None) is not None:
                storage = p.storage
                for entry in getattr(storage, "items", []):
                    item_name = getattr(entry, "name", None)
                    if item_name:
                        items.append(item_name)
                break
    except Exception:
        pass
    return items


def detect_pallet_for_value(substrate: SubstrateInterface, storage_name: str) -> str:
    """
    Detect which pallet holds a given StorageValue by trying direct queries,
    then falling back to metadata scans among POSSIBLE_PALLETS.
    """
    last_err: Optional[Exception] = None
    for pallet in POSSIBLE_PALLETS:
        try:
            _ = substrate.query(module=pallet, storage_function=storage_name)
            return pallet
        except Exception as e:
            last_err = e
            continue

    # Fallback: metadata scan
    for pallet in POSSIBLE_PALLETS:
        try:
            items = list_storage_items(substrate, pallet)
            if storage_name in items:
                return pallet
        except Exception:
            continue

    raise RuntimeError(
        f"Could not find storage value '{storage_name}' in pallets {POSSIBLE_PALLETS}. "
        f"Last error: {last_err}"
    )


def detect_pallet_for_map(substrate: SubstrateInterface, storage_name: str) -> str:
    """
    Detect which pallet holds a StorageMap by trying query_map.
    This works even if the map is empty (StopIteration means it exists but has no entries).
    """
    last_err: Optional[Exception] = None
    for pallet in POSSIBLE_PALLETS:
        try:
            gen = substrate.query_map(module=pallet, storage_function=storage_name)
            # Force generator creation & optionally one iteration
            it = iter(gen)
            try:
                next(it)  # may raise StopIteration; still success if storage exists
            except StopIteration:
                pass
            return pallet
        except Exception as e:
            last_err = e
            continue

    # Fallback: metadata scan
    for pallet in POSSIBLE_PALLETS:
        try:
            items = list_storage_items(substrate, pallet)
            if storage_name in items:
                return pallet
        except Exception:
            continue

    raise RuntimeError(
        f"Could not find storage map '{storage_name}' in pallets {POSSIBLE_PALLETS}. "
        f"Last error: {last_err}"
    )


def get_block_number(substrate: SubstrateInterface, block_hash: str) -> int:
    """Resolve a block number from a hash with fallbacks."""
    try:
        num = substrate.get_block_number(block_hash)
        if num is not None:
            return int(num)
    except Exception:
        pass
    header = substrate.get_block_header(block_hash)
    number = getattr(header, "number", None)
    if number is None and isinstance(header, dict):
        number = header.get("number") or header.get("result", {}).get("number")
    if isinstance(number, str):
        return int(number, 16) if number.startswith("0x") else int(number)
    return int(number)


def get_block_timestamp_ms(substrate: SubstrateInterface, block_number: int) -> Optional[int]:
    """Return Timestamp.Now (ms) at a given block number."""
    try:
        block_hash = substrate.get_block_hash(block_number)
        if not block_hash:
            return None
        ts = substrate.query(module="Timestamp", storage_function="Now", block_hash=block_hash)
        return to_int(ts)
    except Exception:
        return None


def estimate_block_time_sec(substrate: SubstrateInterface, head_number: int, lookback: int = 200) -> Optional[float]:
    """Estimate average seconds per block using Timestamp.Now over a lookback window."""
    if head_number <= 1:
        return None
    start_num = max(1, head_number - lookback)
    t_head = get_block_timestamp_ms(substrate, head_number)
    t_start = get_block_timestamp_ms(substrate, start_num)
    if t_head is None or t_start is None or t_head <= t_start:
        return None
    delta_ms = t_head - t_start
    blocks = head_number - start_num
    return (delta_ms / 1000.0) / blocks if blocks > 0 else None


def is_network_last_registered_key(simple_key: Any) -> bool:
    """
    Heuristically detect the enum variant name from the simplified key.
    We accept several shapes that substrate-interface may return.
    """
    # Direct string
    if isinstance(simple_key, str):
        return "NetworkLastRegistered" in simple_key

    # Dict with a single key like {"NetworkLastRegistered": None}
    if isinstance(simple_key, dict):
        if "NetworkLastRegistered" in simple_key:
            return True
        # Older representations could be {"__enum__": "RateLimitKey::NetworkLastRegistered"}
        enum_tag = simple_key.get("__enum__")
        if isinstance(enum_tag, str) and "NetworkLastRegistered" in enum_tag:
            return True
        # Some versions wrap: {"name": "NetworkLastRegistered", ...}
        name = simple_key.get("name")
        if isinstance(name, str) and name == "NetworkLastRegistered":
            return True
        # Or {"variant": {"name": "NetworkLastRegistered", ...}}
        variant = simple_key.get("variant")
        if isinstance(variant, dict) and variant.get("name") == "NetworkLastRegistered":
            return True

    # List/Tuple representations like ["NetworkLastRegistered", None]
    if isinstance(simple_key, (list, tuple)) and simple_key:
        if isinstance(simple_key[0], str) and "NetworkLastRegistered" in simple_key[0]:
            return True

    return False


def pretty_variant_name(simple_key: Any) -> str:
    """Return a readable variant name for logging."""
    if isinstance(simple_key, str):
        return simple_key
    if isinstance(simple_key, dict):
        if "NetworkLastRegistered" in simple_key:
            return "NetworkLastRegistered"
        if "__enum__" in simple_key:
            return str(simple_key["__enum__"])
        if "name" in simple_key:
            return str(simple_key["name"])
        if "variant" in simple_key and isinstance(simple_key["variant"], dict):
            return str(simple_key["variant"].get("name", "UnknownVariant"))
    if isinstance(simple_key, (list, tuple)) and simple_key:
        if isinstance(simple_key[0], str):
            return simple_key[0]
    return str(simple_key)


# ---------- Main diagnostic ----------
def main():
    print(f"Connecting to {OPENTENSOR_WS} ...")
    substrate = SubstrateInterface(url=OPENTENSOR_WS)

    # Head info
    head_hash = substrate.get_chain_head()
    head_num = get_block_number(substrate, head_hash)
    head_ts_ms = get_block_timestamp_ms(substrate, head_num)
    head_ts = datetime.fromtimestamp((head_ts_ms or 0) / 1000, tz=timezone.utc) if head_ts_ms else None

    # Locate storages
    pallet_for_rate_limit = detect_pallet_for_value(substrate, NETWORK_RATE_LIMIT_NAME)
    pallet_for_map = detect_pallet_for_map(substrate, LAST_RATE_LIMITED_BLOCK_NAME)

    # Optional: last lock cost storage (may or may not be present)
    try:
        pallet_for_last_cost = detect_pallet_for_value(substrate, NETWORK_LAST_LOCK_COST_NAME)
    except Exception:
        pallet_for_last_cost = None

    # Read NetworkRateLimit
    rate_limit_raw = substrate.query(module=pallet_for_rate_limit, storage_function=NETWORK_RATE_LIMIT_NAME)
    rate_limit = to_int(rate_limit_raw)

    # Read NetworkLastLockCost (optional)
    last_cost = None
    if pallet_for_last_cost:
        try:
            last_cost_raw = substrate.query(module=pallet_for_last_cost, storage_function=NETWORK_LAST_LOCK_COST_NAME)
            last_cost = to_int(last_cost_raw)
        except Exception:
            pass

    # Iterate LastRateLimitedBlock to find NetworkLastRegistered entry
    network_last_registered_block: Optional[int] = None
    all_seen_variants: List[str] = []

    gen = substrate.query_map(module=pallet_for_map, storage_function=LAST_RATE_LIMITED_BLOCK_NAME)
    for key_obj, val_obj in gen:
        simple_key = to_simple(key_obj)
        variant_name = pretty_variant_name(simple_key)
        all_seen_variants.append(variant_name)
        if is_network_last_registered_key(simple_key):
            network_last_registered_block = to_int(val_obj)
            # There should be exactly one; break on first match
            break

    # Output
    print("\n=== Chain ===")
    print(f"Head:        #{head_num} ({head_hash})")
    if head_ts:
        print(f"Head time:   {head_ts.isoformat()}")

    print("\n=== Storage (pallets detected) ===")
    print(f"{pallet_for_rate_limit}.{NETWORK_RATE_LIMIT_NAME}: {rate_limit}  (blocks)")
    print(f"{pallet_for_map}.{LAST_RATE_LIMITED_BLOCK_NAME}[RateLimitKey::NetworkLastRegistered]: {network_last_registered_block}")
    if last_cost is not None:
        print(f"{pallet_for_last_cost}.{NETWORK_LAST_LOCK_COST_NAME}: {last_cost}  (raw balance units)")

    # Extra info: list what variants we saw (helps confirm decoding)
    if all_seen_variants:
        preview = ", ".join(sorted(set(all_seen_variants))[:12])
        print(f"\nSeen LastRateLimitedBlock keys (sample): {preview}")

    # Compute predicate: block.saturating_sub(last_block) >= rate_limit
    print("\n=== Computation (as in runtime) ===")
    if network_last_registered_block is None or rate_limit is None:
        print("Missing required values to compute predicate. "
              "Verify that the map contains the NetworkLastRegistered entry and that NetworkRateLimit is readable.")
        sys.exit(2)

    delta = saturating_sub(head_num, network_last_registered_block)
    blocks_remaining = max(0, rate_limit - delta)
    print(f"block (head):        {head_num}")
    print(f"last_block (global): {network_last_registered_block}")
    print(f"saturating_sub:      {delta}")
    print(f"rate_limit:          {rate_limit}")
    print(f"blocks_remaining:    {blocks_remaining}")

    # Estimate ETA from recent block time
    avg_sec = estimate_block_time_sec(substrate, head_num, lookback=200)
    if avg_sec is not None and blocks_remaining > 0:
        eta_sec = blocks_remaining * avg_sec
        # Pretty format
        if eta_sec < 60:
            eta_str = f"{eta_sec:.1f}s"
        elif eta_sec < 3600:
            eta_str = f"{eta_sec/60:.1f}m"
        elif eta_sec < 172800:
            eta_str = f"{eta_sec/3600:.1f}h"
        else:
            eta_str = f"{eta_sec/86400:.2f}d"
        print(f"~time remaining:     {eta_str}  (avg {avg_sec:.2f}s/block)")

    # Diagnosis
    print("\n=== Diagnosis ===")
    if network_last_registered_block > head_num:
        print("The stored last registration block is AHEAD of the current head. "
              "Due to saturating_sub, delta stays 0 until the head surpasses that block, "
              "causing persistent RateLimitExceeded regardless of wall time.")
        print(f"Head must reach >={network_last_registered_block + rate_limit} to clear the window.")
    else:
        if delta >= rate_limit:
            print("Delta >= rate_limit. According to on-chain values, the rate-limit window HAS passed. "
                  "If you still receive RateLimitExceeded, you may be submitting to a node with different state, "
                  "a different runtime/constant, or a mismatched pre-dispatch path.")
        else:
            print("Delta < rate_limit. The global window has NOT passed yet; remaining blocks above explain the error.")


if __name__ == "__main__":
    try:
        main()
    except SubstrateRequestException as e:
        print(f"Substrate request error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
