#!/usr/bin/env python3
"""
Find the subnet (netuid) that has the *largest* commit‑reveal window
(`RevealPeriodEpochs`) and print the pair (netuid, epochs).

Usage
-----
    python3 max_reveal_period_epochs.py [wss_endpoint]

    • If you omit the endpoint it defaults to  
      ``wss://archive.chain.opentensor.ai``.

Dependencies
------------
    pip install substrate-interface
"""

import sys
from substrateinterface import SubstrateInterface


STORAGE_ITEM = "RevealPeriodEpochs"
PALLET_CANDIDATES = ("SubtensorModule", "Subtensor")  # old → new


def main() -> None:
    # ────────────────────────────────────────────────────────────────
    # 1) Connect to the node
    # ────────────────────────────────────────────────────────────────
    url = sys.argv[1] if len(sys.argv) > 1 else "wss://archive.chain.opentensor.ai"
    substrate = SubstrateInterface(url=url)

    # ────────────────────────────────────────────────────────────────
    # 2) Iterate over the map and track the maximum
    # ────────────────────────────────────────────────────────────────
    max_netuid, max_epochs = None, -1

    for pallet in PALLET_CANDIDATES:
        try:
            # query_map → iterator yielding (key, value) pairs
            for key_scale, val_scale in substrate.query_map(
                pallet, STORAGE_ITEM, page_size=256
            ):
                netuid = int(key_scale.value)
                epochs = int(val_scale.value)
                if epochs > max_epochs:
                    max_netuid, max_epochs = netuid, epochs

            # If we found at least one entry, no need to try the next pallet name
            if max_netuid is not None:
                break

        except ValueError:  # pallet/storage item not found under this name
            continue

    # ────────────────────────────────────────────────────────────────
    # 3) Output
    # ────────────────────────────────────────────────────────────────
    if max_netuid is None:
        print(f"The storage map {STORAGE_ITEM} is empty or not found.")
    else:
        print(f"Highest reveal_period_epochs = {max_epochs}  (netuid {max_netuid})")


if __name__ == "__main__":
    main()
