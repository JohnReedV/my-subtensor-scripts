#!/usr/bin/env python3
"""
Query the historical state of `SubnetLocked` at the first block on/after
February 1, 2025 (00:00:00 UTC) from the Opentensor archive node.

Storage type:
    #[pallet::storage] // --- MAP ( netuid ) --> total_subnet_locked
    pub type SubnetLocked<T: Config> =
        StorageMap<_, Identity, NetUid, TaoCurrency, ValueQuery, DefaultZeroTao<T>>;

Requirements:
    pip install substrate-interface
"""

import os
import sys
from datetime import datetime, timezone
from typing import Optional, Tuple, Any, Iterable

from substrateinterface import SubstrateInterface
# FIX: SubstrateRequestException must be imported from substrateinterface.exceptions
try:
    from substrateinterface.exceptions import SubstrateRequestException
except Exception:  # Fallback if the class isn't present in the installed version
    class SubstrateRequestException(Exception):
        pass


ARCHIVE_WS = os.environ.get("OPENTENSOR_ARCHIVE_WS", "wss://archive.chain.opentensor.ai")
TARGET_DATETIME_UTC = datetime(2025, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
STORAGE_NAME = "SubnetLocked"
# Try common pallet names
POSSIBLE_PALLETS = ["SubtensorModule", "Subtensor"]


def get_block_number(substrate: SubstrateInterface, block_hash: str) -> int:
    """Return block number from a block hash."""
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
    """Return the Timestamp.Now (ms) at a given block number."""
    try:
        block_hash = substrate.get_block_hash(block_number)
        if not block_hash:
            return None
        ts = substrate.query(module="Timestamp", storage_function="Now", block_hash=block_hash)
        return int(ts.value) if ts is not None else None
    except Exception:
        return None


def find_block_on_or_after(substrate: SubstrateInterface, target_dt: datetime) -> Tuple[int, str, int]:
    """
    Binary search for the earliest block whose on-chain Timestamp.Now >= target_dt.
    Returns (block_number, block_hash, timestamp_ms).
    """
    assert target_dt.tzinfo is not None, "target_dt must be timezone-aware (UTC)"
    target_ms = int(target_dt.timestamp() * 1000)

    head_hash = substrate.get_chain_head()
    head_number = get_block_number(substrate, head_hash)
    head_ts = get_block_timestamp_ms(substrate, head_number)
    if head_ts is None:
        raise RuntimeError("Could not read timestamp at chain head.")

    if target_ms > head_ts:
        raise ValueError(
            f"Target {target_dt.isoformat()} is after chain head time "
            f"{datetime.fromtimestamp(head_ts/1000, tz=timezone.utc).isoformat()}."
        )

    low = 1
    low_ts = get_block_timestamp_ms(substrate, low)
    while low_ts is None and low < head_number:
        low += 1
        low_ts = get_block_timestamp_ms(substrate, low)
    if low_ts is None:
        raise RuntimeError("Could not find any block with a readable timestamp.")

    if target_ms <= low_ts:
        block_hash = substrate.get_block_hash(low)
        return low, block_hash, low_ts

    high = head_number
    while low < high:
        mid = (low + high) // 2
        ts_mid = get_block_timestamp_ms(substrate, mid)
        if ts_mid is None:
            low = mid + 1
            continue
        if ts_mid < target_ms:
            low = mid + 1
        else:
            high = mid

    found_num = low
    found_hash = substrate.get_block_hash(found_num)
    found_ts = get_block_timestamp_ms(substrate, found_num)
    if not found_hash or found_ts is None:
        raise RuntimeError("Failed to resolve block hash or timestamp after search.")
    return found_num, found_hash, found_ts


def detect_pallet_for_storage(substrate: SubstrateInterface, storage_name: str) -> str:
    """
    Detect which pallet contains the given storage item by attempting a simple map query
    (reading key 0, which safely returns the default if absent).
    """
    last_err: Optional[Exception] = None
    for pallet in POSSIBLE_PALLETS:
        try:
            _ = substrate.query(module=pallet, storage_function=storage_name, params=[0])
            return pallet
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(
        f"Could not find storage '{storage_name}' in pallets {POSSIBLE_PALLETS}. "
        f"Last error: {last_err}"
    )


def to_simple(obj: Any):
    """Recursively unwrap substrate-interface ScaleType values to plain Python types."""
    if hasattr(obj, "value"):
        return to_simple(getattr(obj, "value"))
    if isinstance(obj, (list, tuple)):
        return type(obj)(to_simple(x) for x in obj)
    if isinstance(obj, dict):
        return {k: to_simple(v) for k, v in obj.items()}
    return obj


def get_token_decimals(substrate: SubstrateInterface) -> int:
    """Fetch tokenDecimals from chain properties, default to 9 if unavailable."""
    try:
        props = substrate.get_chain_properties() or {}
        dec = props.get("tokenDecimals") or props.get("token_decimals")
        if isinstance(dec, list) and dec:
            return int(dec[0])
        if isinstance(dec, int):
            return dec
    except Exception:
        pass
    return 9  # TAO uses 9 decimals (rao)


def human_amount(value: int, decimals: int) -> float:
    try:
        return value / (10 ** decimals)
    except Exception:
        return float(value)


def query_subnet_locked_at_block(
    substrate: SubstrateInterface,
    pallet: str,
    block_hash: str
) -> Iterable[Tuple[int, int]]:
    """Iterate over (netuid, locked_raw) pairs for SubnetLocked at a historical block."""
    results = substrate.query_map(
        module=pallet,
        storage_function=STORAGE_NAME,
        block_hash=block_hash
    )
    for key_tuple, value_obj in results:
        key_decoded = to_simple(key_tuple)
        if isinstance(key_decoded, (list, tuple)):
            netuid = int(key_decoded[0])
        else:
            netuid = int(key_decoded)
        locked_raw = int(to_simple(value_obj))
        yield netuid, locked_raw


def main():
    print(f"Connecting to {ARCHIVE_WS} ...")
    substrate = SubstrateInterface(url=ARCHIVE_WS)

    print(f"Searching for the first block on/after {TARGET_DATETIME_UTC.isoformat()} ...")
    try:
        block_number, block_hash, block_ts_ms = find_block_on_or_after(substrate, TARGET_DATETIME_UTC)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    block_ts_utc = datetime.fromtimestamp(block_ts_ms / 1000, tz=timezone.utc)
    print(f"Using block #{block_number} ({block_hash}) with timestamp {block_ts_utc.isoformat()}")

    pallet = detect_pallet_for_storage(substrate, STORAGE_NAME)
    print(f"Detected pallet for '{STORAGE_NAME}': {pallet}")

    decimals = get_token_decimals(substrate)
    entries = list(query_subnet_locked_at_block(substrate, pallet, block_hash))

    if not entries:
        print("No entries found for SubnetLocked at that block.")
        return

    entries.sort(key=lambda x: x[0])  # sort by netuid

    zero_count = 0
    total_count = 0
    total_locked_raw = 0

    print("\n--- SubnetLocked (historical) ---")
    for netuid, locked_raw in entries:
        total_count += 1
        total_locked_raw += locked_raw
        if locked_raw == 0:
            zero_count += 1
        locked_hr = human_amount(locked_raw, decimals)
        print(f"netuid={netuid:>4}  locked_raw={locked_raw:<24}  locked≈{locked_hr} (10^{decimals} decimals)")

    pct_zero = (zero_count / total_count) * 100 if total_count else 0.0
    total_locked_hr = human_amount(total_locked_raw, decimals)

    print("\n--- Summary ---")
    print(f"Block: #{block_number} ({block_hash}) @ {block_ts_utc.isoformat()}")
    print(f"Entries: {total_count} | Zero-value entries: {zero_count} ({pct_zero:.2f}%)")
    print(f"Total locked (raw): {total_locked_raw}")
    print(f"Total locked (human): {total_locked_hr} (assuming {decimals} decimals)")


if __name__ == "__main__":
    try:
        main()
    except SubstrateRequestException as e:
        print(f"Substrate request error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
