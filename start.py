#!/usr/bin/env python3

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

def main():
    # 1. Connect to your node:
    # Replace 'ws://127.0.0.1:9944' with the actual WebSocket endpoint
    substrate = SubstrateInterface(
        url="ws://127.0.0.1:9945",
    )

    # 2. Construct the keypair from a known seed phrase or an existing key file
    # Replace '//Alice' with your actual seed (or more secure method)
    tester_hot_keypair = Keypair.create_from_mnemonic("mango slogan ball flame blur you crystal water quick gather struggle exhaust")
    
    # 3. Compose the call to your runtime extrinsic
    #    Adjust the module name (e.g. 'ModuleName'), extrinsic name ('start_call'),
    #    and parameters to match your actual pallet.
    netuid = 3  # example value
    call = substrate.compose_call(
        call_module='SubtensorModule',      # e.g. the pallet name in your runtime
        call_function='start_call',    # the extrinsic you want to call
        call_params={
            'netuid': netuid
        }
    )

    # 4. Create the extrinsic for signing
    extrinsic = substrate.create_signed_extrinsic(
        call=call,
        keypair=tester_hot_keypair
    )

    # 5. Submit the extrinsic
    try:
        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
        if receipt.is_success:
            print(f"Extrinsic '{receipt.extrinsic_hash}' sent and included in block '{receipt.block_hash}'")
        else:
            print(f"Extrinsic '{receipt.extrinsic_hash}' failed: {receipt.error_message}")
    except SubstrateRequestException as e:
        print(f"Failed to send extrinsic: {e}")

if __name__ == "__main__":
    main()
