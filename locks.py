#!/usr/bin/env python3
"""
Query the historical state of `NetworkLastLockCost` at each subnet's
registration block + 1 for netuids 65..128 from the Opentensor archive node.

Storage types:

    #[pallet::storage]
    /// --- MAP ( netuid ) --> block_created
    pub type NetworkRegisteredAt<T: Config> =
        StorageMap<_, Identity, NetUid, u64, ValueQuery, DefaultNetworkRegisteredAt<T>>;

    #[pallet::storage]
    /// ITEM( last_network_lock_cost )
    pub type NetworkLastLockCost<T> =
        StorageValue<_, TaoCurrency, ValueQuery, DefaultNetworkMinLockCost<T>>;

Output:
    Prints, for each netuid 65..128, the block it registered at, the query
    block (registration + 1), and the NetworkLastLockCost at that historical block
    in raw units and human units (assuming chain tokenDecimals).

Requirements:
    pip install substrate-interface
Environment:
    OPENTENSOR_ARCHIVE_WS (optional): websocket endpoint for archive node.
        Default: wss://archive.chain.opentensor.ai
"""

import os
import re
import sys
from typing import Dict, Tuple, Optional, Any, List

from substrateinterface import SubstrateInterface
# Some versions of substrate-interface raise SubstrateRequestException for RPC errors
try:
    from substrateinterface.exceptions import SubstrateRequestException
except Exception:  # pragma: no cover
    class SubstrateRequestException(Exception):
        pass


ARCHIVE_WS = os.environ.get("OPENTENSOR_ARCHIVE_WS", "wss://archive.chain.opentensor.ai")
STORAGE_VALUE_NAME = "NetworkLastLockCost"
POSSIBLE_PALLETS = ["SubtensorModule", "Subtensor"]  # try common pallet names


# ---- Paste of the user's NetworkRegisteredAt data (netuid -> block_created) ----
RAW_REGISTERED_AT = r"""
[
  [
    [
      1
    ]
    1,497,824
  ]
  [
    [
      2
    ]
    2,734,060
  ]
  [
    [
      3
    ]
    4,165,565
  ]
  [
    [
      4
    ]
    1,411,451
  ]
  [
    [
      5
    ]
    2,491,604
  ]
  [
    [
      6
    ]
    3,219,949
  ]
  [
    [
      7
    ]
    2,627,691
  ]
  [
    [
      8
    ]
    1,477,264
  ]
  [
    [
      9
    ]
    1,489,797
  ]
  [
    [
      10
    ]
    2,869,647
  ]
  [
    [
      11
    ]
    2,918,568
  ]
  [
    [
      12
    ]
    2,256,433
  ]
  [
    [
      13
    ]
    1,907,637
  ]
  [
    [
      14
    ]
    4,848,444
  ]
  [
    [
      15
    ]
    3,684,902
  ]
  [
    [
      16
    ]
    2,765,446
  ]
  [
    [
      17
    ]
    2,840,556
  ]
  [
    [
      18
    ]
    1,604,679
  ]
  [
    [
      19
    ]
    1,956,072
  ]
  [
    [
      20
    ]
    1,970,929
  ]
  [
    [
      21
    ]
    3,156,578
  ]
  [
    [
      22
    ]
    2,009,702
  ]
  [
    [
      23
    ]
    2,063,528
  ]
  [
    [
      24
    ]
    2,538,424
  ]
  [
    [
      25
    ]
    2,998,801
  ]
  [
    [
      26
    ]
    4,893,280
  ]
  [
    [
      27
    ]
    1,727,132
  ]
  [
    [
      28
    ]
    4,878,363
  ]
  [
    [
      29
    ]
    3,379,782
  ]
  [
    [
      30
    ]
    3,250,216
  ]
  [
    [
      31
    ]
    2,719,593
  ]
  [
    [
      32
    ]
    2,515,294
  ]
  [
    [
      33
    ]
    2,943,950
  ]
  [
    [
      34
    ]
    3,493,948
  ]
  [
    [
      35
    ]
    3,037,158
  ]
  [
    [
      36
    ]
    4,871,163
  ]
  [
    [
      37
    ]
    3,212,175
  ]
  [
    [
      38
    ]
    3,756,684
  ]
  [
    [
      39
    ]
    3,280,104
  ]
  [
    [
      40
    ]
    3,372,582
  ]
  [
    [
      41
    ]
    3,394,182
  ]
  [
    [
      42
    ]
    3,613,591
  ]
  [
    [
      43
    ]
    3,408,582
  ]
  [
    [
      44
    ]
    3,550,319
  ]
  [
    [
      45
    ]
    3,633,154
  ]
  [
    [
      46
    ]
    3,919,107
  ]
  [
    [
      47
    ]
    4,236,387
  ]
  [
    [
      48
    ]
    3,856,677
  ]
  [
    [
      49
    ]
    4,107,524
  ]
  [
    [
      50
    ]
    4,763,204
  ]
  [
    [
      51
    ]
    3,966,206
  ]
  [
    [
      52
    ]
    3,989,825
  ]
  [
    [
      53
    ]
    4,203,869
  ]
  [
    [
      54
    ]
    4,742,549
  ]
  [
    [
      55
    ]
    4,703,386
  ]
  [
    [
      56
    ]
    4,312,927
  ]
  [
    [
      57
    ]
    4,343,091
  ]
  [
    [
      58
    ]
    4,367,003
  ]
  [
    [
      59
    ]
    4,401,833
  ]
  [
    [
      60
    ]
    4,796,992
  ]
  [
    [
      61
    ]
    4,457,976
  ]
  [
    [
      62
    ]
    4,474,225
  ]
  [
    [
      63
    ]
    4,885,578
  ]
  [
    [
      64
    ]
    4,531,295
  ]
  [
    [
      65
    ]
    4,950,813
  ]
  [
    [
      66
    ]
    4,958,013
  ]
  [
    [
      67
    ]
    4,965,213
  ]
  [
    [
      68
    ]
    4,972,413
  ]
  [
    [
      69
    ]
    4,979,613
  ]
  [
    [
      70
    ]
    5,008,428
  ]
  [
    [
      71
    ]
    5,048,438
  ]
  [
    [
      72
    ]
    5,064,327
  ]
  [
    [
      73
    ]
    5,160,047
  ]
  [
    [
      74
    ]
    5,086,205
  ]
  [
    [
      75
    ]
    5,102,795
  ]
  [
    [
      76
    ]
    5,114,649
  ]
  [
    [
      77
    ]
    5,128,460
  ]
  [
    [
      78
    ]
    5,143,608
  ]
  [
    [
      79
    ]
    5,173,967
  ]
  [
    [
      80
    ]
    5,188,340
  ]
  [
    [
      81
    ]
    5,203,057
  ]
  [
    [
      82
    ]
    5,216,791
  ]
  [
    [
      83
    ]
    5,231,190
  ]
  [
    [
      84
    ]
    5,248,864
  ]
  [
    [
      85
    ]
    5,258,781
  ]
  [
    [
      86
    ]
    5,275,445
  ]
  [
    [
      87
    ]
    5,292,605
  ]
  [
    [
      88
    ]
    5,299,805
  ]
  [
    [
      89
    ]
    5,313,364
  ]
  [
    [
      90
    ]
    5,328,705
  ]
  [
    [
      91
    ]
    5,342,193
  ]
  [
    [
      92
    ]
    5,356,404
  ]
  [
    [
      93
    ]
    5,370,681
  ]
  [
    [
      94
    ]
    5,386,070
  ]
  [
    [
      95
    ]
    5,403,674
  ]
  [
    [
      96
    ]
    5,410,917
  ]
  [
    [
      97
    ]
    5,432,489
  ]
  [
    [
      98
    ]
    5,445,992
  ]
  [
    [
      99
    ]
    5,453,192
  ]
  [
    [
      100
    ]
    5,460,392
  ]
  [
    [
      101
    ]
    5,481,350
  ]
  [
    [
      102
    ]
    5,499,703
  ]
  [
    [
      103
    ]
    5,515,448
  ]
  [
    [
      104
    ]
    5,528,520
  ]
  [
    [
      105
    ]
    5,545,447
  ]
  [
    [
      106
    ]
    5,558,480
  ]
  [
    [
      107
    ]
    5,565,706
  ]
  [
    [
      108
    ]
    5,586,824
  ]
  [
    [
      109
    ]
    5,598,862
  ]
  [
    [
      110
    ]
    5,606,062
  ]
  [
    [
      111
    ]
    5,615,562
  ]
  [
    [
      112
    ]
    5,633,022
  ]
  [
    [
      113
    ]
    5,651,055
  ]
  [
    [
      114
    ]
    5,671,631
  ]
  [
    [
      115
    ]
    5,683,635
  ]
  [
    [
      116
    ]
    5,699,219
  ]
  [
    [
      117
    ]
    5,710,859
  ]
  [
    [
      118
    ]
    5,724,794
  ]
  [
    [
      119
    ]
    5,740,660
  ]
  [
    [
      120
    ]
    5,749,344
  ]
  [
    [
      121
    ]
    5,766,528
  ]
  [
    [
      122
    ]
    5,778,578
  ]
  [
    [
      123
    ]
    5,794,330
  ]
  [
    [
      124
    ]
    5,813,454
  ]
  [
    [
      125
    ]
    5,834,408
  ]
  [
    [
      126
    ]
    5,841,630
  ]
  [
    [
      127
    ]
    5,848,837
  ]
  [
    [
      128
    ]
    5,856,038
  ]
]
""".strip()
# ----------------------------------------------------------------------------


def to_simple(obj: Any):
    """Recursively unwrap substrate-interface ScaleType values to plain Python types."""
    if hasattr(obj, "value"):
        return to_simple(getattr(obj, "value"))
    if isinstance(obj, (list, tuple)):
        return type(obj)(to_simple(x) for x in obj)
    if isinstance(obj, dict):
        return {k: to_simple(v) for k, v in obj.items()}
    return obj


def parse_registered_at(raw: str) -> Dict[int, int]:
    """
    The pasted data is NOT valid JSON (contains thousands separators and unusual nesting).
    Parse pairs of the form:
        [
          [
            <netuid>
          ]
          <block with commas>
        ]
    Returns dict: netuid -> block_created (int)
    """
    # Regex matches: "[ [ <netuid> ] <block-with-commas> ]" across whitespace/newlines
    pattern = re.compile(r"\[\s*\[\s*(\d+)\s*\]\s*([\d,]+)\s*\]", re.MULTILINE)
    out: Dict[int, int] = {}
    for m in pattern.finditer(raw):
        netuid = int(m.group(1))
        block_str = m.group(2).replace(",", "")
        block = int(block_str)
        out[netuid] = block
    if not out:
        raise ValueError("Failed to parse any (netuid, block) pairs from RAW_REGISTERED_AT.")
    return out


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


def detect_pallet_for_value(substrate: SubstrateInterface, storage_value_name: str) -> str:
    """
    Detect which pallet contains the given StorageValue by attempting a simple query at the head.
    """
    head = substrate.get_chain_head()
    last_err: Optional[Exception] = None
    for pallet in POSSIBLE_PALLETS:
        try:
            _ = substrate.query(module=pallet, storage_function=storage_value_name, block_hash=head)
            return pallet
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(
        f"Could not find StorageValue '{storage_value_name}' in pallets {POSSIBLE_PALLETS}. "
        f"Last error: {last_err}"
    )


def query_lock_cost_at_block(
    substrate: SubstrateInterface,
    pallet: str,
    block_number: int
) -> Tuple[Optional[str], Optional[int]]:
    """
    Return (block_hash, lock_cost_raw) for NetworkLastLockCost at given block_number.
    If query fails, returns (block_hash or None, None).
    """
    try:
        block_hash = substrate.get_block_hash(block_number)
        if not block_hash:
            return None, None
        val = substrate.query(module=pallet, storage_function=STORAGE_VALUE_NAME, block_hash=block_hash)
        raw = int(to_simple(val)) if val is not None else 0
        return block_hash, raw
    except Exception:
        # If metadata changed and the item didn't exist yet, this can fail on older blocks.
        try:
            block_hash = substrate.get_block_hash(block_number)
        except Exception:
            block_hash = None
        return block_hash, None


def main():
    # Parse registration data
    reg_map = parse_registered_at(RAW_REGISTERED_AT)
    # Focus on netuid 65..128 only
    target_netuids = [n for n in sorted(reg_map.keys()) if 65 <= n <= 128]
    if not target_netuids:
        print("No target netuids (65..128) found in the provided data.", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to {ARCHIVE_WS} ...")
    substrate = SubstrateInterface(url=ARCHIVE_WS)
    decimals = get_token_decimals(substrate)

    # Detect which pallet holds the StorageValue
    pallet = detect_pallet_for_value(substrate, STORAGE_VALUE_NAME)
    print(f"Detected pallet for '{STORAGE_VALUE_NAME}': {pallet}")

    # Query each netuid at (registration_block + 1)
    rows: List[Tuple[int, int, int, Optional[str], Optional[int]]] = []
    #            netuid, reg_block, query_block, block_hash, lock_cost_raw

    for netuid in target_netuids:
        reg_block = reg_map[netuid]
        query_block = reg_block + 1
        block_hash, lock_raw = query_lock_cost_at_block(substrate, pallet, query_block)
        rows.append((netuid, reg_block, query_block, block_hash, lock_raw))

    # Print results
    print("\n--- NetworkLastLockCost at registration+1 (netuids 65..128) ---")
    hdr = f"{'netuid':>6}  {'reg_block':>10}  {'query_block':>11}  {'block_hash':<66}  {'lock_cost_raw':>18}  {'lock_cost_human':>18}"
    print(hdr)
    print("-" * len(hdr))

    missing = 0
    total = 0
    sum_raw = 0

    for netuid, reg_block, query_block, block_hash, lock_raw in rows:
        if lock_raw is None:
            missing += 1
            lock_hr_str = "N/A"
            lock_raw_str = "N/A"
        else:
            total += 1
            sum_raw += lock_raw
            lock_hr_str = f"{human_amount(lock_raw, decimals):.9f}"
            lock_raw_str = str(lock_raw)

        bh = block_hash or ""
        print(
            f"{netuid:6d}  {reg_block:10d}  {query_block:11d}  {bh:<66}  {lock_raw_str:>18}  {lock_hr_str:>18}"
        )

    print("\n--- Summary ---")
    print(f"Pallet: {pallet} | StorageValue: {STORAGE_VALUE_NAME}")
    print(f"Token decimals: {decimals}")
    print(f"Entries succeeded: {total} | Failed/unsupported: {missing}")
    if total:
        print(f"Total (raw): {sum_raw}")
        print(f"Average (human): {human_amount(sum_raw, decimals) / total:.9f}")


if __name__ == "__main__":
    try:
        main()
    except SubstrateRequestException as e:
        print(f"Substrate request error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
