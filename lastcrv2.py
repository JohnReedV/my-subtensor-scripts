#!/usr/bin/env python3
"""
Print EVERY WeightCommit entry for all netuids.

Storage layout (SubtensorModule::WeightCommits):
    DoubleMap (netuid, account_id) → VecDeque[
        (hash, commit_block, first_reveal_block, last_reveal_block)
    ]
"""

import argparse
from substrateinterface import SubstrateInterface


# ---------- helpers ---------------------------------------------------------


def as_int(scale_obj) -> int:
    """Safely convert a SCALE numeric object (U8/U16/U32/U64/...) to Python int."""
    return int(scale_obj.value) if hasattr(scale_obj, "value") else int(scale_obj)


def as_hex(scale_obj) -> str:
    """Return 0x-prefixed hex string from a hash-like SCALE object."""
    if hasattr(scale_obj, "value"):
        return scale_obj.value  # substrate-interface already returns str for H256
    return str(scale_obj)


def as_account(scale_obj) -> str:
    """Convert an AccountId SCALE object to a printable SS58 string (or hex)."""
    if hasattr(scale_obj, "value"):
        return scale_obj.value
    return str(scale_obj)


# ---------- cli -------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Print every WeightCommit for every netuid / account."
    )
    p.add_argument(
        "--url",
        default="wss://entrypoint-finney.opentensor.ai",
        help="WebSocket endpoint of the Substrate node",
    )
    p.add_argument(
        "--module",
        default="SubtensorModule",
        help="Runtime module containing WeightCommits",
    )
    p.add_argument(
        "--storage",
        default="WeightCommits",
        help="Storage function name",
    )
    return p.parse_args()


# ---------- main ------------------------------------------------------------


def main() -> None:
    args = parse_args()
    substrate = SubstrateInterface(url=args.url)

    entries_found = 0

    for (netuid_scale, account_scale), deque_obj in substrate.query_map(
        module=args.module, storage_function=args.storage
    ):
        commits = deque_obj.value  # VecDeque → list[tuple]
        if not commits:
            continue

        netuid = as_int(netuid_scale)
        account = as_account(account_scale)

        for commit in commits:
            h_scale, cb_scale, frb_scale, lrb_scale = commit
            print(
                f"netuid {netuid:>3} | account {account} | "
                f"hash {as_hex(h_scale)} | commit_block {as_int(cb_scale)} | "
                f"first_reveal_block {as_int(frb_scale)} | last_reveal_block {as_int(lrb_scale)}"
            )
            entries_found += 1

    if entries_found == 0:
        print("No WeightCommits found.")


if __name__ == "__main__":
    main()
