#!/usr/bin/env python3
"""
List all (hot, cold) wallets that have Alpha shares on a specific netuid
for a Subtensor chain.

Storage (from runtime):
    Alpha<T: Config> : StorageNMap<
        (AccountId hot, AccountId cold, NetUid subnet),
        U64F64
    >

What this script does:
  1) Connects to the node specified by OPENTENSOR_WS (or default).
  2) Detects which pallet contains `Alpha` (SubtensorModule or Subtensor).
  3) Iterates the entire Alpha NMap and filters entries with the target netuid.
  4) Prints each hot/cold pair and the share value.
     - Tries to decode U64F64 (128-bit fixed point: 64.64) to decimal.
     - Also shows the raw underlying integer/hex for transparency.

Environment:
    OPENTENSOR_WS  (optional) default: wss://archive.chain.opentensor.ai
    ALPHA_NETUID   (optional) default: 100
    SS58_FORMAT    (optional) override detected ss58 address format (int)

Usage:
    python list_alpha_by_netuid.py
"""

import os
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple
from decimal import Decimal, getcontext

# High precision for U64F64 conversion
getcontext().prec = 50

# --- substrate-interface imports
try:
    from substrateinterface import SubstrateInterface
    from substrateinterface.exceptions import SubstrateRequestException
    try:
        # Newer substrate-interface
        from substrateinterface.utils.ss58 import ss58_encode as _ss58_encode, ss58_decode as _ss58_decode
    except Exception:
        # Older versions
        from substrateinterface.utils.ss58 import ss58_encode as _ss58_encode
        _ss58_decode = None
except Exception as e:
    print("This script requires `substrate-interface`. Install with:\n"
          "    pip install substrate-interface\n", file=sys.stderr)
    raise

# ---------- Configuration ----------
OPENTENSOR_WS = os.environ.get("OPENTENSOR_WS", "wss://archive.chain.opentensor.ai")
TARGET_NETUID = int(os.environ.get("ALPHA_NETUID", "100"))

# Pallet guesses used by Subtensor deployments
POSSIBLE_PALLETS = ["SubtensorModule", "Subtensor"]

# Storage item names
ALPHA_STORAGE_NAME = "Alpha"


# ---------- Helpers (unwrapping & formatting) ----------
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
    """List storage item names for a pallet (works on many substrate-interface versions)."""
    try:
        sfuncs = substrate.get_metadata_storage_functions(pallet)
        if sfuncs:
            return list(sfuncs.keys())
    except Exception:
        pass

    # Fallback to raw metadata walk
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


def detect_pallet_for_map(substrate: SubstrateInterface, storage_name: str) -> str:
    """
    Detect which pallet holds a StorageMap/StorageNMap by trying query_map.
    This works even if the map is empty (StopIteration means it exists but has no entries).
    """
    last_err: Optional[Exception] = None
    for pallet in POSSIBLE_PALLETS:
        try:
            gen = substrate.query_map(module=pallet, storage_function=storage_name)
            it = iter(gen)
            try:
                next(it)
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


def is_hex_str(s: str) -> bool:
    return isinstance(s, str) and s.startswith("0x") and len(s) >= 4


def _to_bytes(x: Any) -> Optional[bytes]:
    """Best-effort convert to bytes from ScaleType/str(hex)/bytes/int-ish."""
    v = to_simple(x)
    if v is None:
        return None
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        if is_hex_str(v):
            try:
                return bytes.fromhex(v[2:])
            except Exception:
                return None
        # Might already be an SS58 address; we don't convert SS58->bytes here unless decode is available
        return None
    return None


def ensure_ss58(address_like: Any, ss58_format: int) -> str:
    """
    Convert an AccountId-like value to SS58 string if possible; otherwise return a readable fallback.
    """
    # Common wrapping shape for AccountId: {"Id": "0x..."} after to_simple, handle that
    v = to_simple(address_like)
    if isinstance(v, dict) and "Id" in v:
        v = v["Id"]

    # If it's already a plausible SS58 string, return as-is
    if isinstance(v, str) and not is_hex_str(v) and len(v) >= 40:
        return v

    b = _to_bytes(v)
    if b is not None and len(b) == 32:
        try:
            return _ss58_encode(b, ss58_format=ss58_format)
        except Exception:
            return "0x" + b.hex()

    # Last resort: readable form of whatever we got
    if isinstance(v, str):
        return v
    try:
        return str(v)
    except Exception:
        return repr(v)


def to_u128(value: Any) -> Optional[int]:
    """
    Extract an integer from various SCALE representations (incl. hex string/dicts).
    Useful as the underlying bits for U64F64.
    """
    v = to_simple(value)
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and is_hex_str(v):
        try:
            return int(v, 16)
        except Exception:
            return None
    if isinstance(v, dict):
        # Sometimes custom types expose {"bits": "0x..."} or {"value": "..."}
        for k in ("bits", "value", "inner"):
            if k in v and isinstance(v[k], str) and is_hex_str(v[k]):
                try:
                    return int(v[k], 16)
                except Exception:
                    pass
        # Or nested numeric
        for k in ("bits", "value", "inner", "raw"):
            if k in v and isinstance(v[k], int):
                return int(v[k])
    return None


def u64f64_to_decimal_str(value: Any) -> Tuple[Optional[str], Optional[int]]:
    """
    Convert a U64F64 SCALE value into a decimal string and return (decimal_str, raw_int).
    If decoding fails, returns (None, raw_int_or_None).
    """
    raw = to_u128(value)
    if raw is None:
        return None, None
    try:
        dec = Decimal(raw) / Decimal(1 << 64)
        # Trim to a reasonable display without losing too much precision
        return f"{dec.normalize()}", raw
    except Exception:
        return None, raw


def parse_alpha_key(key_obj: Any, substrate: SubstrateInterface) -> Optional[Tuple[str, str, Optional[int]]]:
    """
    Extract (hot_ss58, cold_ss58, netuid_int) from the map key representation returned by substrate-interface.
    We handle a variety of shapes after `to_simple`.
    """
    s = to_simple(key_obj)

    # Common case: tuple/list of three
    if isinstance(s, (list, tuple)) and len(s) == 3:
        hot_ss58 = ensure_ss58(s[0], substrate.ss58_format)
        cold_ss58 = ensure_ss58(s[1], substrate.ss58_format)
        # netuid might be int or wrapped
        netuid = None
        try:
            if isinstance(s[2], int):
                netuid = int(s[2])
            elif isinstance(s[2], str) and s[2].isdigit():
                netuid = int(s[2])
            elif isinstance(s[2], str) and is_hex_str(s[2]):
                netuid = int(s[2], 16)
            elif isinstance(s[2], dict):
                # Try common sub-shapes
                if "value" in s[2]:
                    netuid = int(s[2]["value"])
                elif "__enum__" in s[2]:
                    # unlikely for plain integer
                    netuid = None
            else:
                # last resort
                netuid = int(str(s[2]))
        except Exception:
            netuid = None
        return hot_ss58, cold_ss58, netuid

    # Sometimes keys show up as dict with indexes "0","1","2"
    if isinstance(s, dict) and all(k in s for k in ("0", "1", "2")):
        hot_ss58 = ensure_ss58(s["0"], substrate.ss58_format)
        cold_ss58 = ensure_ss58(s["1"], substrate.ss58_format)
        netuid = None
        try:
            v = s["2"]
            if isinstance(v, int):
                netuid = v
            elif isinstance(v, str) and v.isdigit():
                netuid = int(v)
            elif isinstance(v, str) and is_hex_str(v):
                netuid = int(v, 16)
        except Exception:
            netuid = None
        return hot_ss58, cold_ss58, netuid

    return None


# ---------- Main ----------
def main():
    print(f"Connecting to {OPENTENSOR_WS} ...", file=sys.stderr)
    substrate = SubstrateInterface(url=OPENTENSOR_WS)

    # Determine SS58 format (allow override)
    ss58_format = substrate.ss58_format
    if "SS58_FORMAT" in os.environ:
        try:
            ss58_format = int(os.environ["SS58_FORMAT"])
        except Exception:
            pass

    pallet_for_alpha = detect_pallet_for_map(substrate, ALPHA_STORAGE_NAME)

    print(f"Detected pallet: {pallet_for_alpha}.{ALPHA_STORAGE_NAME}", file=sys.stderr)
    print(f"Target netuid:  {TARGET_NETUID}", file=sys.stderr)
    print("\n# hot,cold,netuid,alpha(U64F64),alpha_raw_u128")
    count = 0
    total_scanned = 0

    # NOTE: SubstrateInterface currently doesn't support partial key iteration across NMap
    # reliably, so we iterate all and filter by netuid.
    gen = substrate.query_map(module=pallet_for_alpha, storage_function=ALPHA_STORAGE_NAME)
    for key_obj, val_obj in gen:
        total_scanned += 1
        parsed = parse_alpha_key(key_obj, substrate)
        if not parsed:
            continue
        hot_ss58, cold_ss58, netuid = parsed
        if netuid != TARGET_NETUID:
            continue

        alpha_str, raw_int = u64f64_to_decimal_str(val_obj)
        # Print even if alpha_str couldn't be decoded; raw is shown when available
        if alpha_str is None and raw_int is None:
            # Last resort: show a minimal string form
            alpha_display = str(to_simple(val_obj))
            raw_display = ""
        else:
            alpha_display = alpha_str if alpha_str is not None else ""
            raw_display = str(raw_int) if raw_int is not None else ""

        print(f"{hot_ss58},{cold_ss58},{netuid},{alpha_display},{raw_display}")
        count += 1

    print(f"\nScanned {total_scanned} Alpha entries; matched netuid {TARGET_NETUID}: {count}.", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except SubstrateRequestException as e:
        print(f"Substrate request error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
