import requests
import time

from bittensor import Subtensor, logging, Wallet

DRAND_API_BASE_URL_Q = "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

logging.set_info()


def get_drand_info(uri):
    """Fetch Drand network information."""
    url = f"{uri}/info"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def get_current_round(info):
    """Calculate the current round based on genesis_time and period."""
    current_time = int(time.time())
    genesis_time = info["genesis_time"]
    period = info["period"]
    return (current_time - genesis_time) // period + 1


def main():
    sub = Subtensor("local")

    uids = [0]
    weights = [0.1]

    wallet_name = 'miner'
    hotkey_name = 'miner_hot'
    wallet = Wallet(name=wallet_name, hotkey=hotkey_name)

    block = sub.get_current_block()
    result, message = sub.set_weights(
        wallet=wallet,
        netuid=4,
        uids=uids,
        weights=weights,
        wait_for_inclusion=True,
        wait_for_finalization=True,
    )
    logging.info(f">>> block [blue]{block + 1}[/blue], message: [magenta]{message}[/magenta]")

    reveal_round = int(message.split(":")[-1])
    # Fetch Drand network info
    for uri in [DRAND_API_BASE_URL_Q]:
        print(f"Fetching info from {uri}...")
        info = get_drand_info(uri)
        print("Info:", info)

        while True:
            time.sleep(info["period"])
            current_round = get_current_round(info)
            logging.console.info(f"Current round: [yellow]{current_round}[/yellow]")
            if current_round == reveal_round:
                logging.console.warning(f">>> it's time to target round: [blue]{reveal_round}[/blue]")
                break


if __name__ == "__main__":
    main()