#!/usr/bin/env python3

from substrateinterface import SubstrateInterface, Keypair, ExtrinsicReceipt

def main():
    # 1) Connect to your Substrate-based node (adjust URL, SS58, etc. as needed).
    substrate = SubstrateInterface(
        url="ws://127.0.0.1:9945",
    )

    # 2) Derive a keypair to act as the COLDKEY from the dev mnemonic `//Alice`.
    #    This key signs the extrinsic (thus recognized as the origin).
    coldkey = Keypair.create_from_uri("//Alice")

    # 3) Derive or load a separate HOTKEY. For example, using dev mnemonic `//Bob`.
    #    (If you want coldkey == hotkey, you could reuse `//Alice`, but typically they're different.)
    hotkey = Keypair.create_from_uri("//Bob")

    # 4) Compose the call to the 'burned_register' function in your pallet (e.g., 'SubtensorModule').
    call = substrate.compose_call(
        call_module = 'SubtensorModule',  # Adjust to match your runtime pallet name
        call_function = 'burned_register',
        call_params = {
            'netuid':  2,
            # The hotkey must be passed as an SS58 address (T::AccountId).
            'hotkey':  coldkey.ss58_address
        }
    )

    # 5) Create a signed extrinsic with the COLDKEY (//Alice).
    extrinsic = substrate.create_signed_extrinsic(
        call = call,
        keypair = coldkey
    )

    # 6) Submit the extrinsic and wait for inclusion.
    receipt = substrate.submit_extrinsic(
        extrinsic,
        wait_for_inclusion=True
    )

    # 7) Check the result.
    if isinstance(receipt, ExtrinsicReceipt):
        print(f"Extrinsic '{receipt.extrinsic_hash}' included in block '{receipt.block_hash}'")
        if receipt.is_success:
            print("burned_register extrinsic succeeded.")
        else:
            print(f"burned_register extrinsic failed: {receipt.error_message}")
    else:
        print("No ExtrinsicReceipt returned. Check node logs or your connection.")

if __name__ == "__main__":
    main()
