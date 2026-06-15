#!/usr/bin/env python3

from substrateinterface import SubstrateInterface

ENDPOINT = "wss://archive.chain.opentensor.ai:443"
NETUID = 26
REG_BLOCK = 8_123_781
CHECK_BLOCK = REG_BLOCK + 1

# From Taostats account page.
CURRENT_OWNER_ALPHA = 235_236.7531
CURRENT_OWNER_TAO_VALUE = 2_502.1385

RAO = 1_000_000_000


def as_int(x):
    v = x.value
    if isinstance(v, int):
        return v
    if isinstance(v, dict):
        for k in ("value", "bits", "inner"):
            if k in v:
                return int(v[k])
    return int(v)


def tao(x):
    return as_int(x) / RAO


def query_any(substrate, block_hash, storage_name, params=None):
    params = params or []

    # Most likely correct module name first.
    for module in ("SubtensorModule", "Subtensor"):
        try:
            return substrate.query(
                module=module,
                storage_function=storage_name,
                params=params,
                block_hash=block_hash,
            )
        except Exception:
            pass

    raise RuntimeError(f"Could not query storage item: {storage_name}")


def pool_price(substrate, block_hash, netuid):
    subnet_tao = tao(query_any(substrate, block_hash, "SubnetTAO", [netuid]))
    alpha_in = tao(query_any(substrate, block_hash, "SubnetAlphaIn", [netuid]))

    if alpha_in == 0:
        raise RuntimeError("SubnetAlphaIn is zero; cannot compute price")

    return subnet_tao / alpha_in, subnet_tao, alpha_in


def main():
    substrate = SubstrateInterface(url=ENDPOINT)

    check_hash = substrate.get_block_hash(CHECK_BLOCK)
    latest_hash = substrate.get_chain_head()

    locked = tao(query_any(substrate, check_hash, "SubnetLocked", [NETUID]))
    min_lock = tao(query_any(substrate, check_hash, "NetworkMinLockCost"))
    alpha_out = tao(query_any(substrate, check_hash, "SubnetAlphaOut", [NETUID]))

    historical_price, historical_tao, historical_alpha_in = pool_price(
        substrate, check_hash, NETUID
    )
    current_price, current_tao, current_alpha_in = pool_price(
        substrate, latest_hash, NETUID
    )

    current_wallet_price = CURRENT_OWNER_TAO_VALUE / CURRENT_OWNER_ALPHA
    owner_mint_basis = locked - min_lock
    price_from_mint = owner_mint_basis / alpha_out if alpha_out else 0

    print(f"netuid: {NETUID}")
    print(f"registration block: {REG_BLOCK}")
    print(f"checked block: {CHECK_BLOCK}")
    print()
    print("=== block-after-registration state ===")
    print(f"SubnetLocked: {locked:.9f} TAO")
    print(f"NetworkMinLockCost: {min_lock:.9f} TAO")
    print(f"owner mint basis, locked - min_lock: {owner_mint_basis:.9f} TAO")
    print(f"SubnetTAO: {historical_tao:.9f} TAO")
    print(f"SubnetAlphaIn: {historical_alpha_in:.9f} alpha")
    print(f"SubnetAlphaOut: {alpha_out:.9f} alpha")
    print(f"historical pool price: {historical_price:.12f} TAO/alpha")
    print(f"price from owner mint basis / AlphaOut: {price_from_mint:.12f} TAO/alpha")
    print()
    print("=== current state ===")
    print(f"current SubnetTAO: {current_tao:.9f} TAO")
    print(f"current SubnetAlphaIn: {current_alpha_in:.9f} alpha")
    print(f"current pool price: {current_price:.12f} TAO/alpha")
    print(f"current wallet-implied price: {current_wallet_price:.12f} TAO/alpha")
    print()
    print("=== comparison ===")
    print(f"pool price multiple: {current_price / historical_price:.6f}x")
    print(f"wallet implied / historical multiple: {current_wallet_price / historical_price:.6f}x")
    print(f"owner alpha current value at pool price: {CURRENT_OWNER_ALPHA * current_price:.9f} TAO")
    print(f"owner alpha value at historical price: {CURRENT_OWNER_ALPHA * historical_price:.9f} TAO")


if __name__ == "__main__":
    main()