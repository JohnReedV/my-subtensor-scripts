#!/usr/bin/env python3

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

def main():
    substrate = SubstrateInterface(
        url="ws://127.0.0.1:9945",
    )

    keypair = Keypair.create_from_uri('//Alice')

    multi_data_fields = [
        {"Raw2": "0x1111"},
         {"Raw2": "0x2222"},
         {"Raw2": "0x3333"},
    ]

    call = substrate.compose_call(
        call_module='Commitments',
        call_function='set_commitment',
        call_params={
            'netuid': 2,
            'info': {
                'fields': [multi_data_fields]
            }
        }
    )

    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

    try:
        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
        print(f"Extrinsic included in block: {receipt.block_hash}")
    except SubstrateRequestException as e:
        print(f"Failed to submit extrinsic: {e}")

if __name__ == "__main__":
    main()
