from substrateinterface import SubstrateInterface

substrate = SubstrateInterface(
    url = "wss://archive.chain.opentensor.ai"
)

netuid = 1
target_block_number = 3000000
target_block_hash = substrate.get_block_hash(target_block_number)

result = substrate.query(
    module='SubtensorModule',
    storage_function='Emission',
    params=[netuid],
    block_hash=target_block_hash
)

print(result.value)
