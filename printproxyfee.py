#!/usr/bin/env python3
import time
from bittensor import Subtensor, logging, Wallet

logging.set_info()

def main():
    # --------------------------------------------
    # 0. Connect and create the wallet
    # --------------------------------------------
    sub = Subtensor("wss://test.finney.opentensor.ai:443")

    # We'll assume the wallet has:
    #   - `coldkey` = the "real" account (holds funds)
    #   - `hotkey`  = the proxy
    wallet = Wallet(name='tester', hotkey='tester_hot')

    coldkey = wallet.coldkey      # The "real" account
    hotkey = wallet.hotkey        # The "proxy" account

    cold_ss58 = coldkey.ss58_address
    hot_ss58  = hotkey.ss58_address

    # --------------------------------------------
    # 1. Compose the `add_proxy` call
    #    This sets "hotkey" as a proxy of "coldkey"
    #    with proxy_type = Staking, delay=0 (no delay).
    # --------------------------------------------
    add_proxy_call = sub.substrate.compose_call(
        call_module="Proxy",
        call_function="add_proxy",
        call_params={
            "delegate": hot_ss58,               # The proxy
            "proxy_type": "Staking",            # Must allow add_stake
            "delay": 0
        }
    )

    # --------------------------------------------
    # 2. Estimate fee for `add_proxy` (coldkey pays)
    # --------------------------------------------
    fee_info = sub.substrate.get_payment_info(
        call=add_proxy_call,
        keypair=coldkey
    )
    estimated_fee = fee_info.get("partial_fee", None)
    logging.info(f"[ADD_PROXY] Estimated fee: {estimated_fee}")

    # --------------------------------------------
    # 3. Submit the `add_proxy` extrinsic,
    #    signed by the coldkey
    # --------------------------------------------
    add_proxy_extrinsic = sub.substrate.create_signed_extrinsic(
        call=add_proxy_call,
        keypair=coldkey
    )
    add_proxy_receipt = sub.substrate.submit_extrinsic(
        add_proxy_extrinsic,
        wait_for_inclusion=True,
        wait_for_finalization=True
    )
    logging.info(f"[ADD_PROXY] Extrinsic included in block: {add_proxy_receipt.block_hash}")

    final_fee = getattr(add_proxy_receipt, "extrinsic_fee", None)
    if final_fee is not None:
        logging.info(f"[ADD_PROXY] Final fee: {final_fee}")
    else:
        logging.info("[ADD_PROXY] Final fee info not available.")

    # NOTE:
    #   After this transaction, `hotkey` is now recognized on-chain
    #   as a proxy for `coldkey` with `Staking` permissions.
    #
    #   If you have ALREADY added this proxy in the past, you can skip
    #   steps 1-3 (the add_proxy) next time.

    # --------------------------------------------
    # 4. Compose the actual `add_stake` call
    #    (the call we want the proxy to make)
    # --------------------------------------------
    add_stake_call = sub.substrate.compose_call(
        call_module="SubtensorModule",  # Adjust if your module name is different
        call_function="add_stake",
        call_params={
            "hotkey": hot_ss58,
            "netuid": 325,
            "amount_staked": 123_456_789  # Example stake
        }
    )

    # --------------------------------------------
    # 5. Wrap that call in a `proxy(...)` extrinsic
    #    so the hotkey can dispatch on behalf of the coldkey
    # --------------------------------------------
    proxy_call = sub.substrate.compose_call(
        call_module="Proxy",
        call_function="proxy",
        call_params={
            "real": cold_ss58,       # The real account on whose behalf we dispatch
            "force_proxy_type": "Staking",
            "call": add_stake_call.value
        }
    )

    # --------------------------------------------
    # 6. Estimate fee for the proxy call
    #    (the hotkey will pay the fee)
    # --------------------------------------------
    proxy_fee_info = sub.substrate.get_payment_info(
        call=proxy_call,
        keypair=hotkey
    )
    proxy_estimated_fee = proxy_fee_info.get("partial_fee", None)
    logging.info(f"[PROXY] Estimated fee: {proxy_estimated_fee}")

    # --------------------------------------------
    # 7. Create a signed extrinsic (hotkey signs)
    # --------------------------------------------
    proxy_extrinsic = sub.substrate.create_signed_extrinsic(
        call=proxy_call,
        keypair=hotkey  # The proxy pays
    )

    # --------------------------------------------
    # 8. Submit the extrinsic and wait for finalization
    # --------------------------------------------
    proxy_receipt = sub.substrate.submit_extrinsic(
        proxy_extrinsic,
        wait_for_inclusion=True,
        wait_for_finalization=True
    )
    logging.info(f"[PROXY] Extrinsic included in block: {proxy_receipt.block_hash}")

    proxy_final_fee = getattr(proxy_receipt, "extrinsic_fee", None)
    if proxy_final_fee is not None:
        logging.info(f"[PROXY] Final fee: {proxy_final_fee}")
    else:
        logging.info("[PROXY] Final fee info not available.")


if __name__ == "__main__":
    main()
