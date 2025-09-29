#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Call `SubtensorModule.root_dissolve_network` for netuid=5,
signing with your local Bittensor **miner** wallet's *coldkey*.

By default the script:
  • Connects to the node at $LOCALNET_SH_PATH, otherwise ws://127.0.0.1:9935
  • Uses wallet name "miner" and hotkey "default" (hotkey is not used for signing here)
  • Wraps the call with Sudo (requires your coldkey to be the sudo key)

Usage:
  python3 root_dissolve_net5.py
  python3 root_dissolve_net5.py --endpoint ws://127.0.0.1:9945
  python3 root_dissolve_net5.py --wallet miner --hotkey default --netuid 5
  python3 root_dissolve_net5.py --direct   # send call without Sudo wrapper

Notes:
  • If your coldkey file is encrypted, you'll be prompted for the password.
  • On chains using `sudo_unchecked_weight`, the script auto-falls back to it.
"""

import os
import sys
import argparse
from getpass import getpass

from substrateinterface import SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException

# Bittensor wallet loader (legacy SDK API)
# Docs: https://docs.learnbittensor.org/legacy-python-api/html/autoapi/bittensor/wallet/
import bittensor as bt


def connect(endpoint: str) -> SubstrateInterface:
    return SubstrateInterface(url=endpoint)


def compose_call(substrate: SubstrateInterface, module: str, function: str, params: dict):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def wrap_with_sudo(substrate: SubstrateInterface, inner_call):
    """
    Try `Sudo.sudo_unchecked_weight` first (some chains), otherwise `Sudo.sudo`.
    """
    try:
        return compose_call(
            substrate,
            "Sudo",
            "sudo_unchecked_weight",
            {"call": inner_call, "weight": 0}
        )
    except Exception:
        return compose_call(substrate, "Sudo", "sudo", {"call": inner_call})


def submit(substrate: SubstrateInterface, signer_kp, call):
    xt = substrate.create_signed_extrinsic(call=call, keypair=signer_kp)
    try:
        receipt = substrate.submit_extrinsic(
            xt, wait_for_inclusion=True, wait_for_finalization=True
        )
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e

    if not receipt.is_success:
        raise RuntimeError(
            f"Extrinsic failed in block {receipt.block_hash}: {receipt.error_message}"
        )
    return receipt


def load_coldkey(wallet_name: str, hotkey_name: str):
    """
    Load the miner wallet's *coldkey* (signer).
    If encrypted, prompt for password.
    """
    w = bt.wallet(name=wallet_name, hotkey=hotkey_name)

    # First try without a password (works for unencrypted keys or unlocked session).
    try:
        return w.get_coldkey()
    except Exception:
        # Prompt only if needed.
        pwd = getpass(f"Enter password for wallet '{wallet_name}' coldkey (press Enter for none): ")
        return w.get_coldkey(password=pwd if pwd else None)


def main():
    parser = argparse.ArgumentParser(description="root_dissolve network (netuid) using local Bittensor 'miner' wallet.")
    parser.add_argument("--endpoint", default=os.environ.get("LOCALNET_SH_PATH", "ws://127.0.0.1:9935"),
                        help="WebSocket endpoint, defaults to $LOCALNET_SH_PATH or ws://127.0.0.1:9935")
    parser.add_argument("--wallet", default="miner", help="Bittensor wallet name (default: miner)")
    parser.add_argument("--hotkey", default="default", help="Bittensor hotkey name (default: default)")
    parser.add_argument("--netuid", type=int, default=5, help="Target netuid to dissolve (default: 5)")
    parser.add_argument("--direct", action="store_true",
                        help="Send call directly without Sudo (use only if your chain exposes it without Root)")

    args = parser.parse_args()

    # 1) Connect
    substrate = connect(args.endpoint)
    print(f"[i] Connected to {args.endpoint}")

    # 2) Load signer (miner wallet coldkey)
    coldkey = load_coldkey(args.wallet, args.hotkey)
    print(f"[i] Using wallet '{args.wallet}' coldkey: {coldkey.ss58_address}")

    # 3) Compose inner call
    inner = compose_call(
        substrate,
        "SubtensorModule",
        "root_dissolve_network",
        {"netuid": int(args.netuid)},
    )

    # 4) Optionally wrap with Sudo
    call = inner if args.direct else wrap_with_sudo(substrate, inner)

    # 5) Submit
    print(f"[→] Submitting call: {'Sudo.sudo(...)' if not args.direct else 'SubtensorModule.root_dissolve_network'} (netuid={args.netuid})")
    receipt = submit(substrate, coldkey, call)

    print("\n✅ Success")
    print(f"  • Extrinsic hash: {receipt.extrinsic_hash}")
    print(f"  • Block hash    : {receipt.block_hash}")
    print(f"  • Event count   : {len(receipt.triggered_events)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
