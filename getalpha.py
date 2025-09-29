from substrateinterface import SubstrateInterface

def main():
    substrate = SubstrateInterface(url="wss://archive.chain.opentensor.ai")
    
    zero_count = 0
    total_count = 0

    map_results = substrate.query_map(
        module='Commitments', 
        storage_function='RevealedCommitments',
    )

    for key_tuple, alpha_object in map_results:
        alpha_value = alpha_object.value
        print(alpha_value)
        print(key_tuple)
        
        if alpha_value == 0:
            zero_count += 1
        total_count += 1

    if total_count == 0:
        print("No entries found.")
    else:
        percentage_zero = (zero_count / total_count) * 100
        print(f"total: {total_count} zero count: {zero_count}")
        print(f"{percentage_zero:.2f}% of entries have a zero value.")

if __name__ == "__main__":
    main()
