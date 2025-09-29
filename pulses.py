from substrateinterface import SubstrateInterface
import sys
import time

WS_URL = "wss://archive.chain.opentensor.ai"
MODULE = "Drand"
STORAGE_FN = "Pulses"
PAGE_SIZE = 1000
PROGRESS_EVERY = 10

def main():
    substrate = SubstrateInterface(url=WS_URL)

    lowest_round = None
    lowest_val = None
    start_key = None
    pages = 0
    scanned = 0
    t0 = time.time()

    while True:
        result = substrate.query_map(
            module=MODULE,
            storage_function=STORAGE_FN,
            page_size=PAGE_SIZE,
            start_key=start_key
        )

        page_count = 0
        for key_obj, val_obj in result:
            # key_obj.value should be the round (u64). Handle a few shapes defensively.
            key_val = getattr(key_obj, "value", key_obj)

            if isinstance(key_val, int):
                round_num = key_val
            elif isinstance(key_val, (list, tuple)):
                ints = [v for v in key_val if isinstance(v, int)]
                if not ints:
                    continue
                round_num = ints[0]
            elif isinstance(key_val, dict):
                ints = [v for v in key_val.values() if isinstance(v, int)]
                if not ints:
                    continue
                round_num = ints[0]
            else:
                continue

            if lowest_round is None or round_num < lowest_round:
                lowest_round = round_num
                lowest_val = getattr(val_obj, "value", val_obj)

            page_count += 1

        scanned += page_count
        pages += 1

        if pages % PROGRESS_EVERY == 0:
            elapsed = time.time() - t0
            print(
                f"[progress] pages={pages} scanned={scanned} current_lowest_round={lowest_round} elapsed={elapsed:.1f}s",
                file=sys.stderr
            )

        # pagination
        if not getattr(result, "has_next_page", False):
            break
        start_key = getattr(result, "last_key", None)
        if start_key is None:
            break

    if lowest_round is None:
        print("No entries found.")
        return

    # As requested: output just the lowest round number
    print(lowest_round)
    # If you want the pulse too, uncomment:
    print(lowest_val)

if __name__ == "__main__":
    main()
