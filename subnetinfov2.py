#!/usr/bin/env python3
"""
Fetch and print SubnetHyperparamsV2 (incl. yuma3_enabled) for a given netuid.

Dependencies
------------
    pip install substrate-interface scalecodec
"""

from pprint import pprint

from substrateinterface import SubstrateInterface
from scalecodec import ScaleBytes

# ---------------------------------------------------------------------------
#  Register SCALE layout for SubnetHyperparamsV2
# ---------------------------------------------------------------------------
CUSTOM_TYPES = {
    "types": {
        "I32F32": "i64",
        "SubnetHyperparamsV2": {
            "type": "struct",
            "type_mapping": [
                ["rho",                         "Compact<u16>"],
                ["kappa",                       "Compact<u16>"],
                ["immunity_period",             "Compact<u16>"],
                ["min_allowed_weights",         "Compact<u16>"],
                ["max_weights_limit",           "Compact<u16>"],
                ["tempo",                       "Compact<u16>"],
                ["min_difficulty",              "Compact<u64>"],
                ["max_difficulty",              "Compact<u64>"],
                ["weights_version",             "Compact<u64>"],
                ["weights_rate_limit",          "Compact<u64>"],
                ["adjustment_interval",         "Compact<u16>"],
                ["activity_cutoff",             "Compact<u16>"],
                ["registration_allowed",        "bool"],
                ["target_regs_per_interval",    "Compact<u16>"],
                ["min_burn",                    "Compact<u64>"],
                ["max_burn",                    "Compact<u64>"],
                ["bonds_moving_avg",            "Compact<u64>"],
                ["max_regs_per_block",          "Compact<u16>"],
                ["serving_rate_limit",          "Compact<u64>"],
                ["max_validators",              "Compact<u16>"],
                ["adjustment_alpha",            "Compact<u64>"],
                ["difficulty",                  "Compact<u64>"],
                ["commit_reveal_period",        "Compact<u64>"],
                ["commit_reveal_weights_enabled","bool"],
                ["alpha_high",                  "Compact<u16>"],
                ["alpha_low",                   "Compact<u16>"],
                ["liquid_alpha_enabled",        "bool"],
                ["alpha_sigmoid_steepness",     "I32F32"],
                ["yuma_version",                "Compact<u16>"],
                ["subnet_is_active",            "bool"],
                ["transfers_enabled",           "bool"],
                ["bonds_reset_enabled",         "bool"],
                ["user_liquidity_enabled",      "bool"],
            ]
        }
    }
}


def main() -> None:
    # ---------------------------------------------------------------------
    # 1) Connect to the node.
    # ---------------------------------------------------------------------
    substrate = SubstrateInterface(url="ws://127.0.0.1:9945")
    substrate.runtime_config.update_type_registry(CUSTOM_TYPES)

    # ---------------------------------------------------------------------
    # 2) Call the dedicated RPC.
    # ---------------------------------------------------------------------
    netuid = 1                                             # adjust as needed
    rpc_method = "subnetInfo_getSubnetHyperparamsV2"
    response = substrate.rpc_request(rpc_method, [netuid, None])
    raw_result = response["result"]                       # Vec<u8> as list

    # ---------------------------------------------------------------------
    # 3) Convert to bytes → ScaleBytes.
    # ---------------------------------------------------------------------
    if isinstance(raw_result, list):
        scale_data = ScaleBytes(bytes(raw_result))
    elif isinstance(raw_result, str):
        scale_data = ScaleBytes(raw_result)
    else:
        raise TypeError(f"Unexpected return type: {type(raw_result)}")

    # ---------------------------------------------------------------------
    # 4) Decode Option<SubnetHyperparamsV2>.
    # ---------------------------------------------------------------------
    option_obj = substrate.runtime_config.create_scale_object(
        "Option<SubnetHyperparamsV2>", data=scale_data
    )
    option_obj.decode()

    if option_obj.value is None:
        print(f"Subnet {netuid} does not exist or returned None.")
    else:
        pprint(option_obj.value)


if __name__ == "__main__":
    main()
