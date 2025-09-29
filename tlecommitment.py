#!/usr/bin/env python3

import time
from bittensor import logging, Wallet, Subtensor, timelock

logging.set_info()  # or set_debug()

def main():
    subtensor = Subtensor("wss://test.finney.opentensor.ai:443")
    wallet = Wallet(
        name="tester",
        hotkey="tester_hot"
    )

    netuid = 325

    data = "Rest easy sire, let me try something new..."

    blocks_until_reveal = 3

    result, msg = subtensor.set_reveal_commitment(
        wallet=wallet,
        netuid=netuid,
        data=data,
        blocks_until_reveal=blocks_until_reveal,
    )
    logging.info(f"set_reveal_commitment() extrinsic: {result}, msg: {msg}")

    if not result:
        logging.error("❌ Failed to submit timelocked commitment.")
        return

    block_time_seconds = 12.0
    total_wait = int(block_time_seconds * blocks_until_reveal)

    logging.info(
        f"Timelocked commitment submitted. Waiting ~{blocks_until_reveal} blocks "
        f"({total_wait} seconds) for automatic reveal..."
    )
    time.sleep(total_wait)

    revealed_for_this_hotkey = subtensor.get_revealed_commitment(
        netuid=netuid,
        hotkey_ss58_address=wallet.hotkey.ss58_address
    )

    subtensor.set_reveal_commitment()

    


    if revealed_for_this_hotkey:
        logging.info(f"✅ Revealed data for this hotkey: {revealed_for_this_hotkey}")
    else:
        logging.warning(
            "No revealed data found yet. Either the chain hasn't processed it, "
            "or blocks_until_reveal hasn't fully elapsed."
        )


if __name__ == "__main__":
    main()
