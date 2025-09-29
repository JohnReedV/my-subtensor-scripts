#!/usr/bin/env python3
"""
Find the block number of the last time a CRV3WeightsRevealed event was emitted
and print the block number.

Usage
-----
    python3 last_crv3_weights_revealed.py [wss_endpoint]

    • If you omit the endpoint it defaults to  
      ``wss://archive.chain.opentensor.ai``.

Dependencies
------------
    pip install substrate-interface
"""

import sys
from substrateinterface import SubstrateInterface


PALLET_CANDIDATES = ("SubtensorModule", "Subtensor")  # old → new
EVENT_NAME = "CRV3WeightsRevealed"


def main() -> None:
    # ────────────────────────────────────────────────────────────────
    # 1) Connect to the node
    # ────────────────────────────────────────────────────────────────
    url = sys.argv[1] if len(sys.argv) > 1 else "wss://archive.chain.opentensor.ai"
    substrate = SubstrateInterface(url=url)

    # ────────────────────────────────────────────────────────────────
    # 2) Get the latest block number
    # ────────────────────────────────────────────────────────────────
    latest_hash = substrate.get_chain_finalised_head()
    latest_block = substrate.get_block(block_hash=latest_hash)
    current_block_number = latest_block['header']['number']

    # ────────────────────────────────────────────────────────────────
    # 3) Search backwards for the event
    # ────────────────────────────────────────────────────────────────
    found_block = None

    for block_number in range(current_block_number, -1, -1):
        block_hash = substrate.get_block_hash(block_number)
        events = substrate.get_events(block_hash)

        for evt in events:
            if evt.event is not None and evt.event.module.name in PALLET_CANDIDATES and evt.event.name == EVENT_NAME:
                found_block = block_number
                break

        if found_block is not None:
            break

    # ────────────────────────────────────────────────────────────────
    # 4) Output
    # ────────────────────────────────────────────────────────────────
    if found_block is None:
        print(f"The event {EVENT_NAME} was not found in any block.")
    else:
        print(found_block)


if __name__ == "__main__":
    main()