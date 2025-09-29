import requests
import time
import binascii
from substrateinterface import SubstrateInterface, Keypair

NODE_URL = "wss://entrypoint-finney.opentensor.ai"
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
DRAND_ENDPOINTS = [
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
    "https://drand.cloudflare.com",
    "https://api.drand.secureweb3.com:6875",
]
HTTP_FETCH_TIMEOUT = 10000
MAX_PULSES_TO_FETCH = 50

def fetch_drand_by_round(round_num):
    relative_path = f"/{CHAIN_HASH}/public/{round_num}"
    return fetch_from_any_endpoint(relative_path)

def fetch_drand_latest():
    relative_path = f"/{CHAIN_HASH}/public/latest"
    return fetch_from_any_endpoint(relative_path)

def fetch_from_any_endpoint(relative_path):
    deadline = time.time() + (HTTP_FETCH_TIMEOUT / 1000.0)
    for endpoint in DRAND_ENDPOINTS:
        uri = endpoint + relative_path
        try:
            response = requests.get(uri, timeout=HTTP_FETCH_TIMEOUT/1000.0)
            if response.status_code == 200:
                return response.json()
        except requests.exceptions.RequestException:
            pass
        if time.time() > deadline:
            break
    raise Exception("No valid response from any Drand endpoint")

def try_into_pulse(drand_resp):
    round_num = drand_resp["round"]
    randomness = binascii.unhexlify(drand_resp["randomness"])
    signature = binascii.unhexlify(drand_resp["signature"])
    if len(randomness) != 32:
        raise Exception("Randomness is not 32 bytes")

    return {
        "round": round_num,
        "randomness": randomness,
        "signature": signature
    }

def encode_compact_u32(value: int) -> bytes:
    if value < 64:
        return ((value << 2) & 0xFF).to_bytes(1, 'little')
    elif value < 16384:
        val = (value << 2) | 0x01
        return val.to_bytes(2, 'little')
    elif value < 1073741824:
        val = (value << 2) | 0x02
        return val.to_bytes(4, 'little')
    else:
        val = (value << 2) | 0x03
        return val.to_bytes(5, 'little')

def encode_pulse(pulse):
    encoded = pulse["round"].to_bytes(8, 'little')
    encoded += encode_compact_u32(len(pulse["randomness"]))
    encoded += pulse["randomness"]
    encoded += encode_compact_u32(len(pulse["signature"]))
    encoded += pulse["signature"]
    return encoded

def encode_pulses_payload(pulses_payload):
    encoded = pulses_payload["block_number"].to_bytes(4, 'little')

    pulses_list = pulses_payload["pulses"]
    encoded += encode_compact_u32(len(pulses_list))
    for p in pulses_list:
        encoded += p["round"].to_bytes(8, 'little')  # u64
        encoded += encode_compact_u32(len(p["randomness"]))
        encoded += p["randomness"]
        encoded += encode_compact_u32(len(p["signature"]))
        encoded += p["signature"]

    # Encode public as MultiSigner::Sr25519
    encoded += b'\x01'
    encoded += pulses_payload["public"]

    return encoded

substrate = SubstrateInterface(url=NODE_URL)
keypair = Keypair.create_from_uri("//Bob")

def submit_new_pulses(current_block):
    next_unsigned_at = substrate.query(
        module='Drand',
        storage_function='NextUnsignedAt'
    ).value or 0

    if current_block < next_unsigned_at:
        return

    last_stored_round = substrate.query(
        module='Drand',
        storage_function='LastStoredRound'
    ).value or 0

    latest_resp = fetch_drand_latest()
    latest_pulse = try_into_pulse(latest_resp)
    current_round = latest_pulse["round"]

    if last_stored_round == 0:
        last_stored_round = current_round - 1

    if current_round <= last_stored_round:
        print("No new rounds to fetch.")
        return

    rounds_to_fetch = min(current_round - last_stored_round, MAX_PULSES_TO_FETCH)
    pulses = []
    for r in range(last_stored_round + 1, last_stored_round + 1 + rounds_to_fetch):
        p = try_into_pulse(fetch_drand_by_round(r))
        pulses.append(p)

    if not pulses:
        print("No new pulses to submit.")
        return

    public_bytes = keypair.public_key
    encoded_payload = encode_pulses_payload({
        "block_number": current_block,
        "pulses": pulses,
        "public": public_bytes
    })
    signature_bytes = keypair.sign(encoded_payload)

    pulses_for_call = []
    for p in pulses:
        pulses_for_call.append({
            "round": p["round"],
            "randomness": "0x" + p["randomness"].hex(),
            "signature": "0x" + p["signature"].hex()
        })

    pulses_payload_for_call = {
        "block_number": current_block,
        "pulses": pulses_for_call,
        "public": {
            "Sr25519": "0x" + public_bytes.hex()
        }
    }

    signature_for_call = {
        "Sr25519": "0x" + signature_bytes.hex()
    }

    call = substrate.compose_call(
        call_module='Drand',
        call_function='write_pulse',
        call_params={
            "pulses_payload": pulses_payload_for_call,
            "signature": signature_for_call
        }
    )

    extrinsic = substrate.create_unsigned_extrinsic(call=call)
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

    if receipt.is_success:
        print(f"Successfully submitted pulses from round {last_stored_round + 1} up to {last_stored_round + rounds_to_fetch}")
    else:
        print(f"Failed to submit: {receipt.error_message}")

def block_subscription_handler(obj, update_nr, subscription_id):
    current_block = obj['header']['number']
    submit_new_pulses(current_block)

substrate.subscribe_block_headers(subscription_handler=block_subscription_handler)