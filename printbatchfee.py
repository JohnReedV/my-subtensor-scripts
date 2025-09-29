#!/usr/bin/env python3
import time
from bittensor import Subtensor, logging, Wallet

logging.set_info()

def main():
    # Connect to your node.
    sub = Subtensor("wss://test.finney.opentensor.ai:443")
    
    # Create the "tester" wallet with hotkey "tester_hot".
    # (The wallet’s coldkey holds the funds and will be used for signing.)
    wallet = Wallet(name='tester', hotkey='tester_hot')
    
    # Use the wallet's hotkey address for the call parameter.
    hotkey_address = wallet.hotkey.ss58_address

    # Compose three identical add_stake calls.
    add_stake_calls = []
    for _ in range(2):
        call = sub.substrate.compose_call(
            call_module="SubtensorModule",  # Update this if your module name differs
            call_function="add_stake",
            call_params={
                "hotkey": hotkey_address,
                "netuid": 325,
                "amount_staked": 2000000
            }
        )
        add_stake_calls.append(call)

    # Compose a batch call using the Utility pallet.
    batch_call = sub.substrate.compose_call(
        call_module="Utility",
        call_function="batch",
        call_params={"calls": add_stake_calls}
    )

    # Get and log only the estimated fee (partial_fee) using the coldkey for fee calculation.
    fee_info = sub.substrate.get_payment_info(call=batch_call, keypair=wallet.coldkey)
    estimated_fee = fee_info.get("partial_fee")
    logging.info(f"Estimated fee: {estimated_fee}")

    # Create a signed extrinsic using the batch call, signing with the coldkey.
    extrinsic = sub.substrate.create_signed_extrinsic(
        call=batch_call,
        keypair=wallet.coldkey
    )

    # Submit the extrinsic and wait for inclusion and finalization.
    receipt = sub.substrate.submit_extrinsic(
        extrinsic,
        wait_for_inclusion=True,
        wait_for_finalization=True
    )
    
    logging.info(f"Extrinsic included in block: {receipt.block_hash}")
    
    # Log only the finalized fee if available.
    final_fee = getattr(receipt, "extrinsic_fee", None)
    if final_fee is not None:
        logging.info(f"Final fee: {final_fee}")
    else:
        logging.info("Final fee info not available in receipt.")

if __name__ == "__main__":
    main()
