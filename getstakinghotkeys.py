from substrateinterface import SubstrateInterface

def main():
    substrate = SubstrateInterface(url="wss://entrypoint-finney.opentensor.ai")

    zero_count = 0
    total_count = 0

    map_results = substrate.query_map(
        module='SubtensorModule',
        storage_function='StakingHotkeys',
    )

    for key_tuple, alpha_object in map_results:
        print(alpha_object)
        
        if not alpha_object:
            zero_count += 1
        total_count += 1

    if total_count == 0:
        print("No entries found.")
    else:
        percentage_zero = (zero_count / total_count) * 100
        print(f"{percentage_zero:.2f}% of entries have a zero value.")

if __name__ == "__main__":
    main()
