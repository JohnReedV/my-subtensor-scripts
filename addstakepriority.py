#!/usr/bin/env python3
import time
import hashlib
from bittensor import Subtensor, logging, Wallet
from scalecodec.utils.ss58 import ss58_decode

logging.set_info()

def extrinsic_scale_hash(scale_bytes: bytes) -> str:
    """Compute the Substrate-style blake2_256 hash of the raw scale-encoded extrinsic bytes."""
    return "0x" + hashlib.blake2b(scale_bytes, digest_size=32).hexdigest()

def main():
    # ----------------------------------------------------
    # 1) Connect to the node
    # ----------------------------------------------------
    sub = Subtensor("ws://127.0.0.1:9945")

    # ----------------------------------------------------
    # 2) Use your existing wallet (with a hotkey that can pay fees)
    # ----------------------------------------------------
    wallet = Wallet(name='tester', hotkey='tester_hot')

    logging.info(f"Coldkey: {wallet.coldkey.ss58_address}")
    logging.info(f"Hotkey:  {wallet.hotkey.ss58_address}")

    # ----------------------------------------------------
    # 3) Compose the add_stake extrinsic
    # ----------------------------------------------------
    add_stake_call = sub.substrate.compose_call(
        call_module="SubtensorModule",
        call_function="add_stake",
        call_params={
            "hotkey": wallet.hotkey.ss58_address,
            "netuid": 2,
            "amount_staked": 123_456_789  # Example stake amount
        }
    )

    extrinsic = sub.substrate.create_signed_extrinsic(
        call=add_stake_call,
        keypair=wallet.hotkey  # The account that pays fees
    )

    # ----------------------------------------------------
    # 4) Submit extrinsic WITHOUT waiting for inclusion
    # ----------------------------------------------------
    receipt = sub.substrate.submit_extrinsic(
        extrinsic,
        wait_for_inclusion=False,
        wait_for_finalization=False
    )
    submitted_hash = receipt.extrinsic_hash
    logging.info(f"Submitted extrinsic hash: {submitted_hash}")

    # ----------------------------------------------------
    # 5) Fetch the *current* pending extrinsics
    # ----------------------------------------------------
    pending_extrinsics = sub.substrate.get()


    # NOTE: Each item in 'pending_extrinsics' is a raw SCALE-encoded extrinsic (in hex).
    #       We can decode them to compare against our extrinsic hash and inspect fields.
    logging.info(f"Number of pending extrinsics: {len(pending_extrinsics)}")

    found_extrinsic_data = None
    for scale_hex in pending_extrinsics:
        # Convert hex -> raw bytes
        scale_bytes = bytes.fromhex(scale_hex.replace("0x", ""))

        # Check if it matches the extrinsic hash we just submitted
        decoded_hash = extrinsic_scale_hash(scale_bytes)

        if decoded_hash.lower() == submitted_hash.lower():
            found_extrinsic_data = scale_bytes
            logging.info(f"Found matching extrinsic in pending pool: {decoded_hash}")
            break

    if not found_extrinsic_data:
        logging.warning("Could not find our extrinsic in pending_extrinsics() – it may have been included already.")
        return

    # ----------------------------------------------------
    # 6) Decode the matching extrinsic to inspect fields
    # ----------------------------------------------------
    # We'll use the substrate interface's Extrinsic scale type to decode it.
    extrinsic_decoder = sub.substrate.create_scale_object("Extrinsic")
    extrinsic_decoder.decode_scale(found_extrinsic_data)

    # The "value" is a dict-like structure with extrinsic fields:
    #   {
    #       'address': '5...some SS58 or raw pubkey...',
    #       'signature': { ... },
    #       'era': { ... },
    #       'nonce': 123,
    #       'call_function': 'add_stake',
    #       'call_module': 'SubtensorModule',
    #       'call_args': [
    #           { 'name': 'hotkey', 'value': '5FTz...' },
    #           { 'name': 'netuid', 'value': 2 },
    #           { 'name': 'amount_staked', 'value': 123456789 },
    #       ],
    #       ...
    #   }
    decoded_extrinsic = extrinsic_decoder.value

    logging.info("Decoded extrinsic fields:")
    for k, v in decoded_extrinsic.items():
        logging.info(f"  {k}: {v}")

    # ----------------------------------------------------
    # 7) Priority?
    # ----------------------------------------------------
    # The standard pending extrinsic info does NOT include the node’s “priority”
    # in the extrinsic itself (that’s an internal transaction-pool value).
    # If your node includes it, it'd have to be in the returned structure, 
    # but typically it's not. Usually, you won't see 'priority' here.
    #
    # You may see something like:
    # {
    #   'address': '5FTzyxF...',
    #   'signature': {...},
    #   'nonce': 1,
    #   'era': 0,
    #   'call_function': 'add_stake',
    #   'call_module': 'SubtensorModule',
    #   'call_args': [...]
    # }
    #
    # There's normally NO 'priority' key in pending_extrinsics. 
    # The node doesn't embed that into the extrinsic data.

    # If your chain DOES happen to embed it somewhere (unlikely), 
    # you'd parse it out now. Otherwise, it's just not there.

if __name__ == "__main__":
    main()
