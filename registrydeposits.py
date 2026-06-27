#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dump old Registry-related Balances.Holds at a historical Subtensor block and
print the block where each existing Registry deposit was made.

Default:
  endpoint: wss://archive.chain.opentensor.ai
  block:    8486592

Important:
- Substrate historical state at a block hash is post-state for that block.
- If block 8486592 is the migration block and the Registry holds were removed
  in that block, use --block 8486591 to inspect pre-migration state.

Install:
  python3 -m pip install substrate-interface

Run:
  python3 registry_holds_with_deposit_blocks.py

Or:
  python3 registry_holds_with_deposit_blocks.py \
    --ws wss://archive.chain.opentensor.ai \
    --block 8486592 \
    --workers 4 \
    --out registry_holds_with_deposit_blocks_8486592.json
"""

import argparse
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import SubstrateInterface


DEFAULT_WS = "wss://archive.chain.opentensor.ai"
DEFAULT_BLOCK = 8_486_592
DEFAULT_OUT = "registry_holds_with_deposit_blocks_8486592.json"

BALANCES_PALLET = "Balances"
HOLDS_STORAGE = "Holds"

# Bittensor / Subtensor uses 9 decimals for TAO planck-style base units.
DEFAULT_DECIMALS = 9


# ─────────────────────────────────────────────
# Connection / RPC helpers
# ─────────────────────────────────────────────

def connect(ws: str) -> SubstrateInterface:
    return SubstrateInterface(
        url=ws,
        ss58_format=42,
    )


def rpc(substrate: SubstrateInterface, method: str, params: list) -> Any:
    res = substrate.rpc_request(method, params)

    if isinstance(res, dict) and "error" in res:
        raise RuntimeError(f"{method} failed: {res['error']}")

    if isinstance(res, dict) and "result" in res:
        return res["result"]

    return res


def get_block_hash(substrate: SubstrateInterface, block_number: int) -> str:
    block_hash = rpc(substrate, "chain_getBlockHash", [block_number])
    if not block_hash:
        raise RuntimeError(f"No block hash returned for block #{block_number}")
    return block_hash


def get_storage_hash(
    substrate: SubstrateInterface,
    storage_key: str,
    block_hash: str,
) -> Optional[str]:
    """
    Fast existence precheck.

    state_getStorageHash returns null when the raw storage key does not exist.
    This lets us avoid SCALE decoding for blocks where Balances.Holds(account)
    is definitely absent.
    """
    return rpc(substrate, "state_getStorageHash", [storage_key, block_hash])


def token_decimals(substrate: SubstrateInterface) -> int:
    try:
        d = substrate.token_decimals
        if isinstance(d, list) and d and isinstance(d[0], int):
            return d[0]
        if isinstance(d, int):
            return d
    except Exception:
        pass
    return DEFAULT_DECIMALS


# ─────────────────────────────────────────────
# JSON / hold decoding helpers
# ─────────────────────────────────────────────

def as_value(x: Any) -> Any:
    return x.value if hasattr(x, "value") else x


def json_safe(x: Any) -> Any:
    """
    Convert substrate-interface / scalecodec objects into JSON-safe values.
    """
    x = as_value(x)

    if isinstance(x, dict):
        return {str(k): json_safe(v) for k, v in x.items()}

    if isinstance(x, (list, tuple)):
        return [json_safe(v) for v in x]

    if isinstance(x, bytes):
        return "0x" + x.hex()

    try:
        json.dumps(x)
        return x
    except TypeError:
        return str(x)


def normalize_holds(holds_obj: Any) -> List[Any]:
    holds = json_safe(holds_obj)

    if holds is None:
        return []

    if isinstance(holds, list):
        return holds

    # Defensive fallback for odd decoder shapes.
    return [holds]


def hold_reason(hold: Any) -> Any:
    h = json_safe(hold)

    if isinstance(h, dict):
        if "id" in h:
            return h["id"]
        if "reason" in h:
            return h["reason"]

    return h


def reason_text(hold: Any) -> str:
    return json.dumps(hold_reason(hold), sort_keys=True).lower()


def is_registry_hold(hold: Any) -> bool:
    """
    Old Registry identity holds usually decode like:
      {"id": {"Registry": "RegistryIdentity"}, "amount": ...}

    Be tolerant because runtime metadata / substrate-interface versions can
    represent enum variants slightly differently.
    """
    return "registry" in reason_text(hold)


def hold_amount(hold: Any) -> int:
    h = json_safe(hold)

    if not isinstance(h, dict):
        return 0

    amount = h.get("amount", 0)

    if isinstance(amount, int):
        return amount

    if isinstance(amount, str):
        cleaned = amount.replace(",", "").strip()
        # In case it ever comes back with units, keep only the first token.
        cleaned = cleaned.split()[0]
        try:
            return int(cleaned)
        except Exception:
            return 0

    try:
        return int(amount)
    except Exception:
        return 0


def tao(amount_planck: int, decimals: int) -> float:
    return amount_planck / (10 ** decimals)


def same_registry_deposit(candidate_hold: Any, target_hold: Any) -> bool:
    """
    Match a specific existing Registry deposit.

    For Registry identity deposits there should normally be only one Registry
    hold per account. Matching by Registry reason + amount is more robust than
    matching the entire Balances.Holds vector, because the account may have
    other holds that were added later.
    """
    return (
        is_registry_hold(candidate_hold)
        and hold_amount(candidate_hold) == hold_amount(target_hold)
    )


# ─────────────────────────────────────────────
# Storage helpers
# ─────────────────────────────────────────────

def balances_holds_storage_key(substrate: SubstrateInterface, account_ss58: str) -> str:
    """
    Compute the raw storage key for Balances.Holds(account).

    We print this because it is the key being binary-searched, equivalent in
    spirit to passing a storage key into which-block.
    """
    return substrate.create_storage_key(
        BALANCES_PALLET,
        HOLDS_STORAGE,
        [account_ss58],
    ).to_hex()


def query_holds_at_block(
    substrate: SubstrateInterface,
    account_ss58: str,
    block_hash: str,
) -> List[Any]:
    q = substrate.query(
        BALANCES_PALLET,
        HOLDS_STORAGE,
        [account_ss58],
        block_hash=block_hash,
    )
    return normalize_holds(q)


def registry_deposit_exists_at_block(
    substrate: SubstrateInterface,
    account_ss58: str,
    target_hold: Any,
    storage_key: str,
    block_hash: str,
    use_storage_hash_precheck: bool = True,
) -> bool:
    if use_storage_hash_precheck:
        try:
            raw_hash = get_storage_hash(substrate, storage_key, block_hash)
            if raw_hash is None:
                return False
        except Exception:
            # If the node does not support state_getStorageHash, fall back to
            # decoded query. Most Substrate archive nodes support it.
            pass

    holds = query_holds_at_block(substrate, account_ss58, block_hash)

    for h in holds:
        if same_registry_deposit(h, target_hold):
            return True

    return False


# ─────────────────────────────────────────────
# Fast binary search, which-block style
# ─────────────────────────────────────────────

class SharedBlockHashCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._cache: Dict[int, str] = {}

    def get(self, substrate: SubstrateInterface, block_number: int) -> str:
        with self._lock:
            cached = self._cache.get(block_number)
            if cached is not None:
                return cached

        block_hash = get_block_hash(substrate, block_number)

        with self._lock:
            self._cache[block_number] = block_hash

        return block_hash


@dataclass
class DepositTask:
    index: int
    account: str
    target_hold: Any
    amount_planck: int
    storage_key: str


@dataclass
class DepositResult:
    index: int
    account: str
    amount_planck: int
    storage_key: str
    target_hold: Any
    first_seen_block: Optional[int]
    first_seen_block_hash: Optional[str]
    error: Optional[str]


_thread_local = threading.local()


def worker_substrate(ws: str) -> SubstrateInterface:
    """
    One SubstrateInterface connection per worker thread.
    substrate-interface connections are stateful, so avoid sharing one object
    across threads.
    """
    if not hasattr(_thread_local, "substrate"):
        _thread_local.substrate = connect(ws)
    return _thread_local.substrate


def find_first_deposit_block(
    substrate: SubstrateInterface,
    block_hash_cache: SharedBlockHashCache,
    account_ss58: str,
    target_hold: Any,
    storage_key: str,
    start_block: int,
    end_block: int,
    use_storage_hash_precheck: bool,
) -> Tuple[Optional[int], Optional[str]]:
    """
    Binary search for the first block where this Registry hold exists.

    Assumption, same as which-block:
      For the specific deposit being searched, the predicate is false before
      the deposit is made, then true from the deposit block through end_block.

    If a deposit was cleared and later recreated with the same amount, any pure
    binary search over the final state predicate can be misleading; that case
    needs event/extrinsic scanning.
    """
    end_hash = block_hash_cache.get(substrate, end_block)

    exists_at_end = registry_deposit_exists_at_block(
        substrate=substrate,
        account_ss58=account_ss58,
        target_hold=target_hold,
        storage_key=storage_key,
        block_hash=end_hash,
        use_storage_hash_precheck=use_storage_hash_precheck,
    )

    if not exists_at_end:
        return None, None

    lo = start_block
    hi = end_block
    answer = end_block

    while lo <= hi:
        mid = (lo + hi) // 2
        mid_hash = block_hash_cache.get(substrate, mid)

        exists = registry_deposit_exists_at_block(
            substrate=substrate,
            account_ss58=account_ss58,
            target_hold=target_hold,
            storage_key=storage_key,
            block_hash=mid_hash,
            use_storage_hash_precheck=use_storage_hash_precheck,
        )

        if exists:
            answer = mid
            hi = mid - 1
        else:
            lo = mid + 1

    answer_hash = block_hash_cache.get(substrate, answer)
    return answer, answer_hash


def process_deposit_task(
    ws: str,
    block_hash_cache: SharedBlockHashCache,
    task: DepositTask,
    start_block: int,
    end_block: int,
    use_storage_hash_precheck: bool,
) -> DepositResult:
    substrate = worker_substrate(ws)

    try:
        first_block, first_hash = find_first_deposit_block(
            substrate=substrate,
            block_hash_cache=block_hash_cache,
            account_ss58=task.account,
            target_hold=task.target_hold,
            storage_key=task.storage_key,
            start_block=start_block,
            end_block=end_block,
            use_storage_hash_precheck=use_storage_hash_precheck,
        )

        return DepositResult(
            index=task.index,
            account=task.account,
            amount_planck=task.amount_planck,
            storage_key=task.storage_key,
            target_hold=task.target_hold,
            first_seen_block=first_block,
            first_seen_block_hash=first_hash,
            error=None,
        )

    except Exception as e:
        return DepositResult(
            index=task.index,
            account=task.account,
            amount_planck=task.amount_planck,
            storage_key=task.storage_key,
            target_hold=task.target_hold,
            first_seen_block=None,
            first_seen_block_hash=None,
            error=str(e),
        )


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ws", default=DEFAULT_WS, help="Archive WebSocket endpoint")
    ap.add_argument("--block", type=int, default=DEFAULT_BLOCK, help="Historical block number")
    ap.add_argument("--start-block", type=int, default=0, help="Binary-search lower bound")
    ap.add_argument("--workers", type=int, default=4, help="Parallel binary-search workers")
    ap.add_argument("--out", default=DEFAULT_OUT, help="Output JSON file")
    ap.add_argument(
        "--print-all-holds",
        action="store_true",
        help="Also include non-Registry holds in the output JSON",
    )
    ap.add_argument(
        "--no-storage-hash-precheck",
        action="store_true",
        help="Disable state_getStorageHash precheck and always decode Balances.Holds",
    )
    args = ap.parse_args()

    if args.start_block < 0:
        raise ValueError("--start-block must be >= 0")

    if args.start_block > args.block:
        raise ValueError("--start-block cannot be greater than --block")

    workers = max(1, int(args.workers))
    use_storage_hash_precheck = not args.no_storage_hash_precheck

    print(f"[i] Connecting: {args.ws}")
    substrate = connect(args.ws)
    decimals = token_decimals(substrate)

    target_block_hash = get_block_hash(substrate, args.block)
    print(f"[i] target block #{args.block} hash = {target_block_hash}")
    print(f"[i] token decimals = {decimals}")

    print("[i] Initializing historical runtime metadata at target block...")
    substrate.init_runtime(block_hash=target_block_hash)

    registry_tasks: List[DepositTask] = []
    all_holds_entries: List[Dict[str, Any]] = []

    total_accounts_with_holds = 0
    total_registry_accounts = 0
    total_registry_holds = 0
    total_registry_amount = 0

    print("[i] Iterating Balances.Holds at target historical state...")

    result = substrate.query_map(
        module=BALANCES_PALLET,
        storage_function=HOLDS_STORAGE,
        params=[],
        block_hash=target_block_hash,
        page_size=100,
    )

    for account_key, holds_obj in result:
        total_accounts_with_holds += 1

        account_value = as_value(account_key)
        account = account_value if isinstance(account_value, str) else str(account_value)

        holds_list = normalize_holds(holds_obj)
        registry_holds = [h for h in holds_list if is_registry_hold(h)]

        if args.print_all_holds:
            all_holds_entries.append(
                {
                    "account": account,
                    "holds": holds_list,
                }
            )

        if not registry_holds:
            continue

        total_registry_accounts += 1

        storage_key = balances_holds_storage_key(substrate, account)

        for h in registry_holds:
            amount = hold_amount(h)
            total_registry_holds += 1
            total_registry_amount += amount

            registry_tasks.append(
                DepositTask(
                    index=len(registry_tasks),
                    account=account,
                    target_hold=json_safe(h),
                    amount_planck=amount,
                    storage_key=storage_key,
                )
            )

    print("[i] Target-state summary:")
    print(
        json.dumps(
            {
                "accounts_with_any_holds": total_accounts_with_holds,
                "accounts_with_registry_holds": total_registry_accounts,
                "registry_hold_count": total_registry_holds,
                "registry_total_amount_planck": total_registry_amount,
                "registry_total_amount_tao": tao(total_registry_amount, decimals),
            },
            indent=2,
            sort_keys=True,
        )
    )

    if not registry_tasks:
        out = {
            "endpoint": args.ws,
            "block_number": args.block,
            "block_hash": target_block_hash,
            "query": "Balances.Holds",
            "filter": "hold reason contains Registry",
            "summary": {
                "accounts_with_any_holds": total_accounts_with_holds,
                "accounts_with_registry_holds": 0,
                "registry_hold_count": 0,
                "registry_total_amount_planck": 0,
                "registry_total_amount_tao": 0,
            },
            "registry_entries": [],
        }

        if args.print_all_holds:
            out["all_holds_entries"] = all_holds_entries

        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, sort_keys=True)

        print(
            "\n[!] No Registry holds found at this block's post-state. "
            "If this is the migration block, try --block 8486591."
        )
        print(f"[✓] Wrote: {args.out}")
        return 0

    print(
        f"[i] Finding first-seen block for {len(registry_tasks)} Registry deposit(s) "
        f"using binary search over blocks {args.start_block}..{args.block} "
        f"with {workers} worker(s)..."
    )

    block_hash_cache = SharedBlockHashCache()
    block_hash_cache.get(substrate, args.block)

    results: List[DepositResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_task = {
            executor.submit(
                process_deposit_task,
                args.ws,
                block_hash_cache,
                task,
                args.start_block,
                args.block,
                use_storage_hash_precheck,
            ): task
            for task in registry_tasks
        }

        completed = 0

        for fut in as_completed(future_to_task):
            completed += 1
            res = fut.result()
            results.append(res)

            amount_tao = tao(res.amount_planck, decimals)

            if res.error:
                print(
                    f"[{completed}/{len(registry_tasks)}] "
                    f"ERROR account={res.account} "
                    f"amount_planck={res.amount_planck} "
                    f"amount_tao={amount_tao:.9f} "
                    f"error={res.error}"
                )
            else:
                print(
                    f"[{completed}/{len(registry_tasks)}] "
                    f"account={res.account} "
                    f"amount_planck={res.amount_planck} "
                    f"amount_tao={amount_tao:.9f} "
                    f"deposit_made_block={res.first_seen_block} "
                    f"storage_key={res.storage_key}"
                )

    results.sort(key=lambda r: r.index)

    registry_entries: List[Dict[str, Any]] = []

    for res in results:
        registry_entries.append(
            {
                "account": res.account,
                "amount_planck": res.amount_planck,
                "amount_tao": tao(res.amount_planck, decimals),
                "deposit_made_block": res.first_seen_block,
                "deposit_made_block_hash": res.first_seen_block_hash,
                "balances_holds_storage_key": res.storage_key,
                "registry_hold": json_safe(res.target_hold),
                "error": res.error,
            }
        )

    error_count = sum(1 for r in results if r.error)

    out = {
        "endpoint": args.ws,
        "block_number": args.block,
        "block_hash": target_block_hash,
        "binary_search_start_block": args.start_block,
        "query": "Balances.Holds",
        "filter": "hold reason contains Registry",
        "method": (
            "which-block-style binary search over archive state; predicate is "
            "specific Registry hold exists in Balances.Holds(account)"
        ),
        "summary": {
            "accounts_with_any_holds": total_accounts_with_holds,
            "accounts_with_registry_holds": total_registry_accounts,
            "registry_hold_count": total_registry_holds,
            "registry_total_amount_planck": total_registry_amount,
            "registry_total_amount_tao": tao(total_registry_amount, decimals),
            "deposit_block_lookup_errors": error_count,
        },
        "registry_entries": registry_entries,
    }

    if args.print_all_holds:
        out["all_holds_entries"] = all_holds_entries

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)

    print("\n[✓] Done")
    print(json.dumps(out["summary"], indent=2, sort_keys=True))
    print(f"[✓] Wrote: {args.out}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as e:
        print(f"\n[✗] Error: {e}", file=sys.stderr)
        raise SystemExit(1)