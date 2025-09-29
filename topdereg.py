#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Top pruning-eligible subnets + upcoming immunity exits for Subtensor.

Fixes:
- Ensure we "see" all recent netuids: iterate maps AND probe 0..probe_max for NetworkRegisteredAt/NetworksAdded.
- Proper I96F32 decode from RAW storage for SubnetMovingPrice.
- Log the moving price for each subnet as it is fetched.
- Format zero prices without scientific notation.

Usage:
    pip install substrate-interface
    python topdereg.py
    python topdereg.py --url wss://archive.chain.opentensor.ai --at-block 6464000 --limit 15 --probe-max 4096 --names
"""

from __future__ import annotations
import argparse
from dataclasses import dataclass
from decimal import Decimal, getcontext
from typing import Optional, List, Dict, Tuple, Iterable

from substrateinterface import SubstrateInterface

# High precision for fixed-point division
getcontext().prec = 50

ROOT_NETUID = 0

# ======== Utilities ========

def to_int(v) -> int:
    if v is None:
        return 0
    try:
        return int(v)
    except Exception:
        try:
            return int(getattr(v, "value"))
        except Exception:
            if isinstance(v, dict) and "value" in v:
                return int(v["value"])
            raise

def decode_i96f32_from_raw(raw_val) -> Optional[Decimal]:
    """
    Decode I96F32 from raw SCALE storage bytes:
      - signed 128-bit integer, little-endian two's complement
      - 32 fractional bits
      value = int128 / 2**32
    """
    if raw_val is None:
        return None

    if hasattr(raw_val, "to_hex"):
        hex_str = raw_val.to_hex()
    elif isinstance(raw_val, bytes):
        hex_str = "0x" + raw_val.hex()
    elif isinstance(raw_val, str):
        hex_str = raw_val
    else:
        return None

    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    if not hex_str:
        return None

    data = bytes.fromhex(hex_str)
    if len(data) < 16:
        data = data.ljust(16, b"\x00")
    elif len(data) > 16:
        data = data[:16]

    int128 = int.from_bytes(data, "little", signed=True)
    return Decimal(int128) / Decimal(1 << 32)

def fmt_dec_fixed(d: Decimal, places: int = 12) -> str:
    """Return a fixed-point string with exactly `places` decimals (no scientific notation)."""
    q = Decimal(10) ** -places
    try:
        val = d.quantize(q)
    except Exception:
        val = d
    # Use 'f' format to avoid "0E-12"
    try:
        return format(val, f".{places}f")
    except Exception:
        return str(val)

def decode_netuid(key) -> int:
    try:
        return int(getattr(key, "value"))
    except Exception:
        try:
            return int(key)
        except Exception:
            return int(str(key))

def decode_bytes_to_str(val) -> Optional[str]:
    v = getattr(val, "value", val)
    try:
        if isinstance(v, (bytes, bytearray)):
            s = v.decode("utf-8", errors="ignore")
            return s or None
        if isinstance(v, list) and all(isinstance(x, int) for x in v):
            s = bytes(v).decode("utf-8", errors="ignore")
            return s or None
        if isinstance(v, str):
            return v or None
    except Exception:
        pass
    return None

# ======== Data model ========

@dataclass
class Subnet:
    netuid: int
    price: Decimal
    registered_at: int
    release_block: int
    immune_now: bool
    added: bool
    blocks_remaining: int

# ======== Chain access ========

def get_block_context(substrate: SubstrateInterface, at_block: Optional[int]) -> Tuple[str, int]:
    if at_block is not None:
        block_hash = substrate.get_block_hash(at_block)
        if block_hash is None:
            raise RuntimeError(f"Could not find block hash for block {at_block}")
        return block_hash, at_block
    head_hash = substrate.get_chain_head()
    if head_hash is None:
        raise RuntimeError("Could not get chain head hash.")
    return head_hash, substrate.get_block_number(head_hash)

def get_network_immunity_period(substrate: SubstrateInterface, block_hash: str) -> int:
    # Storage value: SubtensorModule::NetworkImmunityPeriod (u64)
    try:
        res = substrate.query("SubtensorModule", "NetworkImmunityPeriod", block_hash=block_hash)
        v = to_int(res.value)
        if v:
            return v
    except Exception:
        pass
    # Optional constant fallback
    try:
        const = substrate.get_constant("SubtensorModule", "NetworkImmunityPeriod")
        v = to_int(getattr(const, "value", const))
        if v:
            return v
    except Exception:
        pass
    return 0

def print_price_log(netuid: int, source: str, raw_hex: Optional[str], decoded: Optional[Decimal], final_price: Decimal, added: Optional[bool], immune_now: Optional[bool], reg_at: Optional[int], release_block: Optional[int], enabled: bool):
    if not enabled:
        return
    raw_info = (raw_hex[:18] + "...") if (raw_hex and raw_hex.startswith("0x")) else str(raw_hex)
    print(
        f"[price] netuid={netuid:>4} source={source:<8} raw={raw_info:<20} "
        f"decoded={fmt_dec_fixed(decoded or Decimal(0), 12):>16} final={fmt_dec_fixed(final_price,12):>16} "
        f"added={'?' if added is None else ('Y' if added else 'N')} immune={'?' if immune_now is None else ('Y' if immune_now else 'N')} "
        f"reg_at={reg_at if reg_at is not None else '?'} release={release_block if release_block is not None else '?'}"
    )

def fetch_price(substrate: SubstrateInterface, netuid: int, block_hash: str, *, log_prices: bool, added: Optional[bool], immune_now: Optional[bool], reg_at: Optional[int], release_block: Optional[int]) -> Decimal:
    """
    Decode SubnetMovingPrice (I96F32) from raw storage; fallback to decoded query or 0.
    Logs each fetch.
    """
    # 1) RAW decode
    try:
        storage_key = substrate.create_storage_key("SubtensorModule", "SubnetMovingPrice", [netuid])
        raw = substrate.get_storage_by_key(storage_key, block_hash=block_hash)
        raw_hex = None
        if hasattr(raw, "to_hex"):
            raw_hex = raw.to_hex()
        elif isinstance(raw, (bytes, bytearray)):
            raw_hex = "0x" + bytes(raw).hex()
        elif isinstance(raw, str):
            raw_hex = raw

        dec = decode_i96f32_from_raw(raw)
        if dec is not None:
            price = dec.copy_abs()
            print_price_log(netuid, "raw", raw_hex, dec, price, added, immune_now, reg_at, release_block, log_prices)
            return price
        else:
            print_price_log(netuid, "raw-none", raw_hex, None, Decimal(0), added, immune_now, reg_at, release_block, log_prices)
    except Exception:
        print_price_log(netuid, "raw-error", None, None, Decimal(0), added, immune_now, reg_at, release_block, log_prices)

    # 2) Decoded query fallback
    try:
        res = substrate.query("SubtensorModule", "SubnetMovingPrice", [netuid], block_hash=block_hash)
        v = getattr(res, "value", res)
        if isinstance(v, (int, float)):
            price = Decimal(v)
            print_price_log(netuid, "decoded", None, price, price, added, immune_now, reg_at, release_block, log_prices)
            return price
        if isinstance(v, str):
            try:
                price = Decimal(v)
                print_price_log(netuid, "decoded", None, price, price, added, immune_now, reg_at, release_block, log_prices)
                return price
            except Exception:
                pass
        if isinstance(v, dict) and "value" in v:
            try:
                price = Decimal(str(v["value"]))
                print_price_log(netuid, "decoded", None, price, price, added, immune_now, reg_at, release_block, log_prices)
                return price
            except Exception:
                pass
    except Exception:
        pass

    # 3) Final fallback
    price = Decimal(0)
    print_price_log(netuid, "fallback", None, None, price, added, immune_now, reg_at, release_block, log_prices)
    return price

def build_added_map(substrate: SubstrateInterface, block_hash: str, page_size: int = 1000) -> Dict[int, bool]:
    """Load NetworksAdded into a dict[netuid] = bool."""
    added_map: Dict[int, bool] = {}
    it = substrate.query_map(
        module="SubtensorModule",
        storage_function="NetworksAdded",
        block_hash=block_hash,
        page_size=page_size,
    )
    for key, val in it:
        netuid = decode_netuid(key)
        added_map[netuid] = bool(to_int(getattr(val, "value", val)))
    return added_map

def build_registration_map(substrate: SubstrateInterface, block_hash: str, page_size: int = 1000) -> Dict[int, int]:
    """Load NetworkRegisteredAt into a dict[netuid] = registered_at."""
    reg_map: Dict[int, int] = {}
    it = substrate.query_map(
        module="SubtensorModule",
        storage_function="NetworkRegisteredAt",
        block_hash=block_hash,
        page_size=page_size,
    )
    for key, val in it:
        netuid = decode_netuid(key)
        reg_map[netuid] = to_int(getattr(val, "value", val))
    return reg_map

def probe_fill_maps(substrate: SubstrateInterface, block_hash: str, reg_map: Dict[int, int], added_map: Dict[int, bool], probe_max: int):
    """
    Fallback scan to ensure we include recent netuids.
    For each netuid in 0..probe_max:
      - If missing from reg_map, query NetworkRegisteredAt[netuid].
      - If missing from added_map, query NetworksAdded[netuid].
    """
    for netuid in range(0, probe_max + 1):
        if netuid not in reg_map:
            try:
                v = substrate.query("SubtensorModule", "NetworkRegisteredAt", [netuid], block_hash=block_hash)
                reg_map[netuid] = to_int(getattr(v, "value", v))
            except Exception:
                pass
        if netuid not in added_map:
            try:
                v = substrate.query("SubtensorModule", "NetworksAdded", [netuid], block_hash=block_hash)
                added_map[netuid] = bool(to_int(getattr(v, "value", v)))
            except Exception:
                pass

def load_all_subnets(substrate: SubstrateInterface, block_hash: str, current_block: int, *, probe_max: int, log_prices: bool) -> List[Subnet]:
    imm = get_network_immunity_period(substrate, block_hash)

    # First pass: from maps (paginated)
    reg_map = build_registration_map(substrate, block_hash, page_size=1000)
    added_map = build_added_map(substrate, block_hash, page_size=1000)

    # Fallback probe to guarantee coverage of recent netuids
    probe_fill_maps(substrate, block_hash, reg_map, added_map, probe_max=probe_max)

    subnets: List[Subnet] = []
    for netuid, reg_at in reg_map.items():
        if netuid == ROOT_NETUID or reg_at == 0:
            continue

        release_block = reg_at + imm
        immune_now = current_block < release_block
        blocks_remaining = max(0, release_block - current_block)
        added = bool(added_map.get(netuid, False))

        # Fetch price with logging
        price = fetch_price(
            substrate, netuid, block_hash,
            log_prices=log_prices,
            added=added, immune_now=immune_now,
            reg_at=reg_at, release_block=release_block
        )

        subnets.append(
            Subnet(
                netuid=netuid,
                price=price,
                registered_at=reg_at,
                release_block=release_block,
                immune_now=immune_now,
                added=added,
                blocks_remaining=blocks_remaining,
            )
        )
    return subnets

# ======== Ranking ========

def rank_key(s: Subnet):
    # Lowest price first; tie-break by earliest registration, then netuid
    return (s.price, s.registered_at, s.netuid)

def compute_rank_at_block(all_subnets: List[Subnet], target: Subnet, block_number: int) -> Tuple[int, int]:
    """
    Rank of 'target' among subnets that will be out of immunity by 'block_number'.
    Uses current moving prices as a proxy for future ordering.
    Returns (rank_1_based, eligible_count).
    """
    eligible = [s for s in all_subnets if s.release_block <= block_number]
    eligible.sort(key=rank_key)
    for idx, s in enumerate(eligible, start=1):
        if s.netuid == target.netuid:
            return idx, len(eligible)
    return -1, len(eligible)

# ======== Output ========

def print_table(rows: List[Dict[str, str]], header: List[str]) -> None:
    widths = [len(h) for h in header]
    for row in rows:
        for i, h in enumerate(header):
            widths[i] = max(widths[i], len(str(row.get(h, ""))))
    line = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print(line)
    print("| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(header)) + " |")
    print(line)
    for row in rows:
        print("| " + " | ".join(str(row.get(h, "")).ljust(widths[i]) for i, h in enumerate(header)) + " |")
    print(line)

# ======== Main ========

def main():
    ap = argparse.ArgumentParser(description="List pruning-eligible subnets and upcoming immunity exits.")
    ap.add_argument("--url", default="wss://archive.chain.opentensor.ai", help="WebSocket endpoint")
    ap.add_argument("--at-block", type=int, default=None, help="Evaluate at this block instead of the head")
    ap.add_argument("--limit", type=int, default=10, help="How many top eligible subnets to show")
    ap.add_argument("--probe-max", type=int, default=2048, help="Probe 0..N for missing netuids (robust coverage)")
    ap.add_argument("--names", action="store_true", help="Also fetch and display SubnetName (extra RPC calls)")
    ap.add_argument("--no-log-prices", action="store_true", help="Disable per-subnet price logging")
    args = ap.parse_args()

    log_prices = not args.no_log_prices

    substrate = SubstrateInterface(url=args.url)
    block_hash, current_block = get_block_context(substrate, args.at_block)

    all_subnets = load_all_subnets(substrate, block_hash, current_block, probe_max=args.probe_max, log_prices=log_prices)
    if not all_subnets:
        print("No subnets found.")
        return

    # ---- Summary counts ----
    total = len(all_subnets)
    added_count = sum(1 for s in all_subnets if s.added)
    immune_count = sum(1 for s in all_subnets if s.immune_now)
    max_uid = max(s.netuid for s in all_subnets) if all_subnets else -1
    print(f"\n[summary] block={current_block} total_subnets={total} added={added_count} immune_now={immune_count} max_netuid_seen={max_uid}")

    # ---- 1) Top-N pruning-eligible now (added && not immune) ----
    eligible_now = [s for s in all_subnets if (s.added and not s.immune_now)]
    eligible_now.sort(key=rank_key)
    top_n = eligible_now[: args.limit]

    # Optional names
    name_cache: Dict[int, Optional[str]] = {}
    def get_name(netuid: int) -> str:
        if not args.names:
            return ""
        if netuid in name_cache:
            return name_cache[netuid] or ""
        try:
            nv = substrate.query("SubtensorModule", "SubnetName", [netuid], block_hash=block_hash)
            name = decode_bytes_to_str(nv)
        except Exception:
            name = None
        name_cache[netuid] = name
        return name or ""

    rows_eligible = []
    for idx, s in enumerate(top_n, start=1):
        rows_eligible.append(
            {
                "Rank": str(idx),
                "NetUID": str(s.netuid),
                "Name": get_name(s.netuid),
                "Price (moving)": fmt_dec_fixed(s.price, 12),
                "RegisteredAt": str(s.registered_at),
                "ImmuneUntil": str(s.release_block),
            }
        )

    print(f"\n=== Top {len(rows_eligible)} pruning-eligible subnets at block {current_block} (added & out of immunity) ===")
    print_table(
        rows_eligible,
        header=["Rank", "NetUID", "Name", "Price (moving)", "RegisteredAt", "ImmuneUntil"],
    )

    # ---- 2) Next 3 coming out of immunity (network-wide; added or not) ----
    immune_now_list = [s for s in all_subnets if s.immune_now]
    immune_now_list.sort(key=lambda s: (s.release_block, s.registered_at, s.netuid))
    coming = immune_now_list[:3]

    if coming:
        rows_coming = []
        print(f"\n=== Next {len(coming)} subnets exiting immunity network-wide (as of block {current_block}) ===")
        for s in coming:
            rank_at_release, eligible_count = compute_rank_at_block(all_subnets, s, s.release_block)
            rows_coming.append(
                {
                    "NetUID": str(s.netuid),
                    "Name": get_name(s.netuid),
                    "Added?": "Yes" if s.added else "No",
                    "Price (moving)": fmt_dec_fixed(s.price, 12),
                    "ExitsAt": str(s.release_block),
                    "BlocksUntil": str(s.blocks_remaining),
                    "Rank@Exit": f"{rank_at_release}/{eligible_count}" if rank_at_release > 0 else "-",
                }
            )
        print_table(
            rows_coming,
            header=["NetUID", "Name", "Added?", "Price (moving)", "ExitsAt", "BlocksUntil", "Rank@Exit"],
        )
    else:
        print("\n=== No subnets are currently in immunity network-wide ===")

    print(
        "\nNotes:\n"
        "- Eligibility list mirrors pruning logic: only subnets with NetworksAdded == true and past immunity.\n"
        "- The 'Next exiting immunity' section scans ALL registered subnets (added or not), via maps + direct probing up to --probe-max.\n"
        "- Rank@Exit uses current SubnetMovingPrice as a proxy for future rank.\n"
        "- Prices are decoded from I96F32 (signed 128-bit, 32 fractional bits) via raw storage when available."
    )

if __name__ == "__main__":
    main()
