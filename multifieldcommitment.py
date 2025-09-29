#!/usr/bin/env python3

from substrateinterface import SubstrateInterface, Keypair

def main():
    # 1. Connect to Substrate-based chain
    substrate = SubstrateInterface(
        url="wss://test.finney.opentensor.ai:443",
    )

    # 2. Create or load your keypair (this example uses Alice's dev account)
    keypair = Keypair.create_from_uri('//Alice')

    # 3. Prepare your multiple data fields.
    #    - "Raw2": "0x1111" means 2 bytes, 0x11 0x11.
    #    - "Raw2": "0x2222" is 2 bytes, 0x22 0x22.
    #    - "Raw2": "0x3333" is 2 bytes, 0x33 0x33.
    multi_data_fields = [
        { "Raw2": "0x1111" },
        { "Raw2": "0x2222" },
        { "Raw2": "0x3333" },
    ]

    # 4. Compose the call to your `Commitments::set_commitment` function
    call = substrate.compose_call(
        call_module='Commitments',           # Adjust to your actual pallet name
        call_function='set_commitment',      # Must match your Rust #[pallet::call_index(_)]
        call_params={
            'netuid': 325,
            'info': {
                'fields': multi_data_fields
            }
        }
    )

    # 5. Create a signed extrinsic
    extrinsic = substrate.create_signed_extrinsic(
        call=call,
        keypair=keypair
    )

    # 6. Submit extrinsic and wait for inclusion
    receipt = substrate.submit_extrinsic(
        extrinsic,
        wait_for_inclusion=True
    )

    print(f"set_commitment included in block: {receipt.block_hash}")

if __name__ == "__main__":
    main()
