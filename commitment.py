#!/usr/bin/env python3

import hashlib
from bittensor import Subtensor, Wallet, logging

logging.set_debug()

def main():
    sub = Subtensor("ws://127.0.0.1:9945")
    wallet = Wallet(name="mock", hotkey="mock_hot")

    message = "Hello Bittensor World! Lets see how many bytes I can shove in here! Shouldn't be more than 128..... Let us see the truth."
    hashed_bytes = hashlib.blake2b(message.encode("utf-8"), digest_size=32).digest()
    hashed_hex_str = "0x" + hashed_bytes.hex()

    receipt = sub.set_commitment(
        wallet=wallet,
        netuid=325,
        data=message,
    )

    logging.info(f"set_commitment included in block: {receipt.block_hash}")

if __name__ == "__main__":
    main()
