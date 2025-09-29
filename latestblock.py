

import bittensor as bt
sub = bt.SubtensorApi()
latest_block = sub.block
print(f"Latest Bittensor block number: {latest_block}")



# import asyncio
# import json
# import hashlib
# import websockets

# NODE_URL = "wss://archive.chain.opentensor.ai"

# async def clear_mempool():
#     async with websockets.connect(NODE_URL) as ws:
#         await ws.send(json.dumps({
#             "id": 1,
#             "jsonrpc": "2.0",
#             "method": "author_pendingExtrinsics",
#             "params": []
#         }))
#         resp = json.loads(await ws.recv())
#         pending = resp.get("result", [])
        
#         for ext_hex in pending:
#             raw = bytes.fromhex(ext_hex[2:])
#             h = hashlib.blake2b(raw, digest_size=32).digest()
#             ext_hash = "0x" + h.hex()
            
#             await ws.send(json.dumps({
#                 "id": 2,
#                 "jsonrpc": "2.0",
#                 "method": "author_removeExtrinsic",
#                 "params": [[ext_hash]]
#             }))
#             await ws.recv()
#             print(f"Removed {ext_hash}")
        
#         print("Mempool cleared.")

# if __name__ == "__main__":
#     asyncio.run(clear_mempool())