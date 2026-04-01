#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic burned_register pricing test for continuous per-block exponential decay,
run stage-by-stage across multiple subnets, including automatic creation of
missing requested subnets, a limit-price registration scenario, and a same-block
multi-registration scenario.

This version fixes:
1) Broken websocket sessions are explicitly reconnected before retrying.
2) Critical state reads are strict + retrying, so transient decode/query
   failures do not silently become zeros.
3) Default worker policy:
      - if --workers is explicitly passed, honor it
      - else if multiple netuids were explicitly passed with --netuids,
        default to fan out across those networks
      - otherwise default to serial execution (workers=1)
4) Only bootstrap is auto-retried as a whole stage. Stateful stages are not
   replayed automatically.
5) The script no longer depends on BurnLastHalvingBlock because the runtime
   update logic no longer uses it.
6) All extrinsics now go through a resilient submit path that:
      - retries metadata/signing reads safely
      - reconnects and re-submits the same signed extrinsic after transport loss
      - recovers receipts from recent finalized blocks when the websocket drops

Thread-safety note
------------------
py-polkadot-sdk / substrate-interface can misbehave under concurrent metadata
decoding. To keep the script stable, this script:

  • eagerly initializes runtime metadata once per SubstrateInterface connection
  • routes all substrate-interface calls through one global lock
  • treats Compact<u32> decoder failures and broken pipes as retryable
  • explicitly reconnects broken websocket sessions before retrying

Runtime behavior mirrored by this script
----------------------------------------
At on_initialize(current_block):

  1) if BurnHalfLife > 0 and current_block > 1:
       burn *= factor_q32
     where factor_q32 is the largest Q32 value such that:
       factor_q32 ^ BurnHalfLife <= 0.5

  2) RegistrationsThisBlock = 0

At each successful non-root registration in block N:

  1) the current burn is charged
  2) RegistrationsThisBlock += 1
  3) burn *= BurnIncreaseMult immediately in the registration path

Scenarios per network
---------------------
Optional) Default-parameter stress scenario:
   - runs only if --with-default-stress is passed
   - does NOT modify BurnHalfLife or BurnIncreaseMult
   - performs many sequential burned_register calls
   - verifies dynamic burn behavior block by block
   - verifies immediate post-registration bump in the registration block
   - finishes with a fixed no-registration decay sample
   - uses a soft burn cap + graceful funding fallback so runs stay stable

1) Default-parameter limit-price scenario:
   - first submits register_limit with limit_price=0 and asserts failure
   - then submits register_limit with a permissive limit and asserts success
   - verifies immediate post-registration bump in the registration block

2) Default-parameter same-block multi-registration scenario:
   - first submits 10 burned_register calls in one Utility batch on the same subnet
   - then submits another same-block registration burst from 10 distinct coldkeys
     using a sudo-wrapped Utility batch of sudo_as(burned_register(...)) calls
   - asserts the final burn reflects all same-block bumps in both phases
   - asserts RegistrationsThisBlock and SubnetworkN reflect all successful registrations
   - asserts the different-account phase charges the exact expected price sequence
     for every registration in that same block
   - verifies the following block only decays from the post-batch burn

3) BurnHalfLife=4, BurnIncreaseMult=2
4) BurnHalfLife=8, BurnIncreaseMult=3
"""

import sys
import time
import ast
import re
import argparse
import traceback
from dataclasses import dataclass, replace
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Sequence, Tuple, Callable

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────
DEFAULT_WS = "ws://127.0.0.1:9945"

TEST_CONFIGS: List[Tuple[int, int]] = [
    (4, 2),
    (8, 3),
]

STRESS_TARGET_TOTAL_REGS = 20
NEXT_REG_BALANCE_SAFETY_MULT = 4
NEXT_REG_BALANCE_BUFFER_TAO = 25.0
MIN_FUNDS_TAO_REG_COLD = 500.0

# Keep optional stress runs from blowing up payer balances.
STRESS_SOFT_MAX_BURN_TAO = 500.0
MIN_ONE_REG_BUFFER_TAO = 1.0
DEFAULT_STRESS_POST_DECAY_STEPS = 60
SAME_BLOCK_MULTI_REG_COUNT = 10

REGISTER_NETWORK_MIN_OWNER_COLD_TAO = 5000.0
REGISTER_NETWORK_MIN_OWNER_HOT_TAO = 5.0

PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"

U64_MAX = (1 << 64) - 1
ONE_Q32 = 1 << 32
HALF_Q32 = 1 << 31

# Only bootstrap is safe to auto-retry. Stateful stages should not replay.
STAGE_RETRY_ATTEMPTS = 3

# Fine-grained retrying for query/compose operations.
QUERY_RETRY_ATTEMPTS = 4
QUERY_RETRY_BACKOFF_SEC = 0.20

# Resilient extrinsic submission / recovery.
SUBMIT_RETRY_ATTEMPTS = 6
SUBMIT_RETRY_BACKOFF_SEC = 0.35
RECOVERY_SEARCH_FINALIZED_DEPTH = 128
RECOVERY_SEARCH_PASSES = 8
RECOVERY_SEARCH_SLEEP_SEC = 0.35

ALICE_LOCK = Lock()
PRINT_LOCK = Lock()

# Global lock for all substrate-interface access.
SUBSTRATE_IO_LOCK = Lock()


# ─────────────────────────────────────────────────────────────
# Context
# ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class NetworkContext:
    ws: str
    netuid: int
    decimals: int
    run_nonce: int
    payer_uri: str


@dataclass
class RecoveredReceipt:
    block_hash: str
    is_success: bool = True
    error_message: str = ""
    recovered: bool = True
    submitted_extrinsic_hex: str = ""


# ─────────────────────────────────────────────────────────────
# Logging helpers
# ─────────────────────────────────────────────────────────────
def safe_print(msg: str):
    with PRINT_LOCK:
        print(msg, flush=True)


def make_logger(netuid: int):
    def _log(msg: str):
        lines = str(msg).splitlines() or [""]
        with PRINT_LOCK:
            for line in lines:
                print(f"[net {netuid}] {line}", flush=True)
    return _log


def short_ss58(ss58: str) -> str:
    return f"{ss58[:6]}…{ss58[-6:]}" if len(ss58) > 16 else ss58


def scenario_banner(log, title: str, subtitle: Optional[str] = None):
    line = "━" * 92
    log(line)
    log(title)
    if subtitle:
        log(subtitle)
    log(line)


def simplify_error_message(raw: Any) -> str:
    if raw is None:
        return ""

    if isinstance(raw, (list, tuple)):
        parts = [simplify_error_message(item) for item in raw]
        parts = [p for p in parts if p]
        if parts:
            return " | ".join(parts)
        return ""

    if isinstance(raw, dict):
        name = raw.get("name")
        docs = raw.get("docs")
        if name and docs:
            return f"{name} — {' '.join(str(d) for d in docs)}"
        if name:
            return str(name)

        for key in ("error", "dispatch_error", "dispatchError", "details", "value"):
            if key in raw:
                nested = simplify_error_message(raw[key])
                if nested:
                    return nested
        return str(raw)

    text = str(raw).strip()
    if not text:
        return ""
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, (dict, list, tuple)):
            return simplify_error_message(parsed)
    except Exception:
        pass
    return text


def is_retryable_transport_error(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = [
        "broken pipe",
        "connection reset",
        "connection aborted",
        "connection closed",
        "websocketconnectionclosed",
        "socket is already closed",
        "websocket is not connected",
        "cannot write to closing transport",
        "closing transport",
        "transport endpoint is not connected",
        "remote host closed",
        "connection to remote host was lost",
        "connection lost",
        "eof occurred",
        "timed out",
        "timeout",
        "read timed out",
        "i/o operation on closed file",
        'decoder class for "compact<u32>" not found',
        'decoder class for "compact<u64>" not found',
        'decoder class for "compact<u128>" not found',
    ]
    return any(marker in text for marker in markers)


def is_submission_pending_error(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = [
        "already imported",
        "already in block",
        "temporarily banned",
        "priority is too low",
        "transaction is outdated",
        "stale",
        "future",
        "usurped",
    ]
    return any(marker in text for marker in markers)


def format_state(
    label: str,
    block: int,
    burn: int,
    regs: int,
    decimals: int,
    subnetwork_n: Optional[int] = None,
    icon: str = "🔹",
) -> str:
    parts = [
        f"{icon} {label:<10}",
        f"blk {block:<5}",
        f"burn {fmt_tao(burn, decimals):>15}",
        f"regs {regs}",
    ]
    if subnetwork_n is not None:
        parts.append(f"n {subnetwork_n}")
    return " │ ".join(parts)


def should_log_progress(idx: int, total: int) -> bool:
    if idx <= 3 or idx == total:
        return True
    if total >= 10 and idx % 5 == 0:
        return True
    return False


def should_log_decay_step(step: int, total_steps: int) -> bool:
    key_steps = {
        1,
        total_steps,
        max(1, total_steps // 4),
        max(1, total_steps // 2),
        max(1, (3 * total_steps) // 4),
    }
    return step in key_steps


def receipt_was_recovered(rec: Any) -> bool:
    return getattr(rec, "recovered", False) is True


# ─────────────────────────────────────────────────────────────
# Substrate helpers
# ─────────────────────────────────────────────────────────────
def _reconnect_substrate(substrate: SubstrateInterface):
    """
    Reconnect the websocket on an existing SubstrateInterface instance.

    First try reconnecting on the existing instance. If that fails, rebuild a
    fresh SubstrateInterface and swap its internals into the existing object.
    """
    last_exc: Optional[Exception] = None
    url = getattr(substrate, "url", None)

    for attempt in range(1, QUERY_RETRY_ATTEMPTS + 1):
        try:
            with SUBSTRATE_IO_LOCK:
                try:
                    substrate.close()
                except Exception:
                    pass

                try:
                    # Preferred path on an existing object.
                    substrate.connect_websocket()
                    substrate.init_runtime()
                    return
                except Exception:
                    if not url:
                        raise

                    # Fallback: rebuild the entire object.
                    fresh = SubstrateInterface(url=url, auto_reconnect=True)
                    fresh.init_runtime()

                    substrate.__dict__.clear()
                    substrate.__dict__.update(fresh.__dict__)
                    return
        except Exception as e:
            last_exc = e
            if attempt >= QUERY_RETRY_ATTEMPTS or not is_retryable_transport_error(e):
                raise
            time.sleep(QUERY_RETRY_BACKOFF_SEC * attempt)

    assert last_exc is not None
    raise last_exc


def _substrate_call_with_retries(
    substrate: SubstrateInterface,
    fn: Callable[[], Any],
    attempts: int = QUERY_RETRY_ATTEMPTS,
):
    last_exc: Optional[Exception] = None

    for attempt in range(1, attempts + 1):
        try:
            with SUBSTRATE_IO_LOCK:
                return fn()
        except Exception as e:
            last_exc = e
            if attempt >= attempts or not is_retryable_transport_error(e):
                raise

            try:
                _reconnect_substrate(substrate)
            except Exception:
                pass

            time.sleep(QUERY_RETRY_BACKOFF_SEC * attempt)

    assert last_exc is not None
    raise last_exc


def connect(ws: str) -> SubstrateInterface:
    last_exc: Optional[Exception] = None

    for attempt in range(1, QUERY_RETRY_ATTEMPTS + 1):
        try:
            with SUBSTRATE_IO_LOCK:
                substrate = SubstrateInterface(url=ws, auto_reconnect=True)
                substrate.init_runtime()
                return substrate
        except Exception as e:
            last_exc = e
            if attempt >= QUERY_RETRY_ATTEMPTS or not is_retryable_transport_error(e):
                raise
            time.sleep(QUERY_RETRY_BACKOFF_SEC * attempt)

    assert last_exc is not None
    raise last_exc


def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


def to_planck(tao: float, decimals: int) -> int:
    return int(round(tao * (10 ** decimals)))


def from_planck(p: int, decimals: int) -> float:
    return p / float(10 ** decimals)


def fmt_tao(p: int, decimals: int) -> str:
    return f"{from_planck(p, decimals):.9f} TAO"


def as_int(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    if isinstance(v, dict):
        for k in ("value", "bits", "index", "raw"):
            if k in v:
                return as_int(v[k])
        if v:
            return as_int(next(iter(v.values())))
        return 0
    if hasattr(v, "value"):
        return as_int(v.value)
    return int(v)


def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return _substrate_call_with_retries(
        substrate,
        lambda: substrate.compose_call(call_module=module, call_function=function, call_params=params),
    )


def safe_query(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
):
    return _substrate_call_with_retries(
        substrate,
        lambda: substrate.query(module, storage, params or [], block_hash=block_hash),
    )


def safe_query_map(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    max_results: Optional[int] = None,
):
    return _substrate_call_with_retries(
        substrate,
        lambda: list(substrate.query_map(module, storage, params=params, max_results=max_results)),
    )


def get_chain_head_hash(substrate: SubstrateInterface) -> str:
    return _substrate_call_with_retries(substrate, lambda: substrate.get_chain_head())


def safe_rpc_request(substrate: SubstrateInterface, method: str, params: Sequence[Any]):
    return _substrate_call_with_retries(substrate, lambda: substrate.rpc_request(method, list(params)))


def rpc_result_or_raise(response: Any, method: str):
    if isinstance(response, dict):
        if response.get("error") is not None:
            raise RuntimeError(f"RPC {method} failed: {response['error']}")
        if "result" in response:
            return response["result"]
    return response


def get_finalized_head_hash(substrate: SubstrateInterface) -> str:
    try:
        result = rpc_result_or_raise(
            safe_rpc_request(substrate, "chain_getFinalizedHead", []),
            "chain_getFinalizedHead",
        )
        if result:
            return str(result)
    except Exception:
        pass
    return get_chain_head_hash(substrate)


def get_block_hash_at_number(substrate: SubstrateInterface, block_number: int) -> str:
    result = rpc_result_or_raise(
        safe_rpc_request(substrate, "chain_getBlockHash", [int(block_number)]),
        "chain_getBlockHash",
    )
    if not result:
        raise RuntimeError(f"chain_getBlockHash returned no result for block {block_number}")
    return str(result)


def get_block_extrinsics(substrate: SubstrateInterface, block_hash: str) -> List[str]:
    result = rpc_result_or_raise(
        safe_rpc_request(substrate, "chain_getBlock", [block_hash]),
        "chain_getBlock",
    )
    if not isinstance(result, dict):
        return []
    block = result.get("block")
    if not isinstance(block, dict):
        return []
    return [str(ext).lower() for ext in (block.get("extrinsics") or [])]


def extrinsic_hex(xt: Any) -> str:
    if xt is None:
        return ""

    if isinstance(xt, (bytes, bytearray)):
        return "0x" + bytes(xt).hex()

    data = getattr(xt, "data", None)
    if data is not None and data is not xt:
        hx = extrinsic_hex(data)
        if hx:
            return hx

    value = getattr(xt, "value", None)
    if value is not None and value is not xt:
        hx = extrinsic_hex(value)
        if hx:
            return hx

    text = str(xt).strip()
    if text.startswith(("0x", "0X")):
        return text.lower()
    return ""


def event_extrinsic_index(event_record: Any) -> Optional[int]:
    rec = getattr(event_record, "value", event_record)
    if not isinstance(rec, dict):
        return None

    if rec.get("extrinsic_idx") is not None:
        try:
            return as_int(rec["extrinsic_idx"])
        except Exception:
            pass

    phase = getattr(rec.get("phase"), "value", rec.get("phase"))
    if isinstance(phase, dict):
        for key, value in phase.items():
            if "apply" in str(key).lower() and "extrinsic" in str(key).lower():
                try:
                    return as_int(value)
                except Exception:
                    pass

    if isinstance(phase, str):
        m = re.search(r"apply[^0-9]*([0-9]+)", phase, flags=re.IGNORECASE)
        if m:
            return int(m.group(1))

    return None


def event_identity(event_record: Any) -> Tuple[str, str, Any]:
    rec = getattr(event_record, "value", event_record)
    if not isinstance(rec, dict):
        return "", "", None

    event = getattr(rec.get("event"), "value", rec.get("event"))
    if not isinstance(event, dict):
        return "", "", None

    module = (
        event.get("module_id")
        or event.get("module")
        or event.get("section")
        or event.get("pallet")
        or ""
    )
    if isinstance(module, dict):
        module = module.get("name") or module.get("module_id") or next(iter(module.values()), "")

    name = (
        event.get("event_id")
        or event.get("event")
        or event.get("method")
        or event.get("name")
        or ""
    )
    if isinstance(name, dict):
        name = name.get("name") or name.get("event_id") or next(iter(name.values()), "")

    attrs = event.get("attributes")
    if attrs is None:
        for key in ("params", "args", "details", "value"):
            if key in event:
                attrs = event[key]
                break

    return str(module), str(name), attrs


def _extract_named_or_positional_balance(attrs: Any, target_names: Sequence[str]) -> Optional[int]:
    target_names_lower = {str(name).lower() for name in target_names}

    def _walk(value: Any) -> Optional[int]:
        value = getattr(value, "value", value)

        if value is None:
            return None

        if isinstance(value, dict):
            lowered = {str(k).lower(): v for k, v in value.items()}
            for key in target_names_lower:
                if key in lowered:
                    try:
                        return as_int(lowered[key])
                    except Exception:
                        pass

            name = lowered.get("name") or lowered.get("field") or lowered.get("id")
            if name is not None and str(name).lower() in target_names_lower and "value" in lowered:
                try:
                    return as_int(lowered["value"])
                except Exception:
                    pass

            for nested in value.values():
                found = _walk(nested)
                if found is not None:
                    return found
            return None

        if isinstance(value, (list, tuple)):
            if len(value) >= 2:
                try:
                    return as_int(getattr(value[1], "value", value[1]))
                except Exception:
                    pass
            for item in value:
                found = _walk(item)
                if found is not None:
                    return found
            return None

        return None

    return _walk(attrs)


def receipt_extrinsic_index(substrate: SubstrateInterface, rec: Any) -> Optional[int]:
    direct_idx = getattr(rec, "extrinsic_idx", None)
    if direct_idx is not None:
        try:
            return as_int(direct_idx)
        except Exception:
            pass

    block_hash = getattr(rec, "block_hash", None)
    submitted_xt_hex = getattr(rec, "submitted_extrinsic_hex", "") or ""
    if not block_hash or not submitted_xt_hex:
        return None

    try:
        extrinsics = get_block_extrinsics(substrate, block_hash)
        return extrinsics.index(submitted_xt_hex)
    except Exception:
        return None


def transaction_fee_paid_for_receipt(substrate: SubstrateInterface, rec: Any) -> Optional[int]:
    block_hash = getattr(rec, "block_hash", None)
    extrinsic_idx = receipt_extrinsic_index(substrate, rec)
    if not block_hash or extrinsic_idx is None:
        return None

    events_res = safe_query(substrate, "System", "Events", [], block_hash=block_hash)
    events = getattr(events_res, "value", events_res) or []

    for event_record in events:
        idx = event_extrinsic_index(event_record)
        if idx != extrinsic_idx:
            continue

        module, name, attrs = event_identity(event_record)
        if module.lower().replace("_", "") != "transactionpayment":
            continue
        if name.lower() != "transactionfeepaid":
            continue

        fee = _extract_named_or_positional_balance(
            attrs,
            target_names=("actual_fee", "actualfee", "fee", "amount", "paid", "actual_fee_paid"),
        )
        if fee is not None:
            return fee

    return None


def extrinsic_outcome_from_events(
    substrate: SubstrateInterface,
    block_hash: str,
    extrinsic_idx: int,
) -> Tuple[bool, str]:
    events_res = safe_query(substrate, "System", "Events", [], block_hash=block_hash)
    events = getattr(events_res, "value", events_res) or []

    saw_matching_phase = False

    for event_record in events:
        idx = event_extrinsic_index(event_record)
        if idx != extrinsic_idx:
            continue

        saw_matching_phase = True
        module, name, attrs = event_identity(event_record)
        if module.lower() == "system" and name.lower() == "extrinsicsuccess":
            return True, ""
        if module.lower() == "system" and name.lower() == "extrinsicfailed":
            return False, simplify_error_message(attrs) or "ExtrinsicFailed"

    if saw_matching_phase:
        return True, ""

    return True, "recovered from chain without an explicit System.ExtrinsicSuccess/Failed event"


def recover_prebuilt_extrinsic_receipt(
    substrate: SubstrateInterface,
    xt: Any,
    search_depth: int = RECOVERY_SEARCH_FINALIZED_DEPTH,
    passes: int = RECOVERY_SEARCH_PASSES,
) -> Optional[RecoveredReceipt]:
    xt_hex = extrinsic_hex(xt)
    if not xt_hex:
        return None

    seen_block_hashes: set[str] = set()

    for poll_idx in range(1, passes + 1):
        try:
            head_hash = get_finalized_head_hash(substrate)
            head_number = block_number_at(substrate, head_hash)
        except Exception:
            if poll_idx >= passes:
                return None
            time.sleep(RECOVERY_SEARCH_SLEEP_SEC * poll_idx)
            continue

        min_block = max(0, head_number - max(1, int(search_depth)) + 1)

        for block_number in range(head_number, min_block - 1, -1):
            try:
                block_hash = get_block_hash_at_number(substrate, block_number)
            except Exception:
                continue

            if not block_hash or block_hash in seen_block_hashes:
                continue
            seen_block_hashes.add(block_hash)

            try:
                extrinsics = get_block_extrinsics(substrate, block_hash)
            except Exception:
                continue

            try:
                extrinsic_idx = extrinsics.index(xt_hex)
            except ValueError:
                continue

            is_success, error_message = extrinsic_outcome_from_events(substrate, block_hash, extrinsic_idx)
            return RecoveredReceipt(
                block_hash=block_hash,
                is_success=is_success,
                error_message=error_message,
                recovered=True,
                submitted_extrinsic_hex=xt_hex,
            )

        if poll_idx < passes:
            time.sleep(RECOVERY_SEARCH_SLEEP_SEC * poll_idx)

    return None


def create_signed_extrinsic_safe(substrate: SubstrateInterface, signer: Keypair, call):
    return _substrate_call_with_retries(
        substrate,
        lambda: substrate.create_signed_extrinsic(call=call, keypair=signer),
        attempts=SUBMIT_RETRY_ATTEMPTS,
    )


def submit_prebuilt_extrinsic(
    substrate: SubstrateInterface,
    xt,
    allow_failed: bool,
):
    last_exc: Optional[Exception] = None
    submitted_xt_hex = extrinsic_hex(xt)

    for attempt in range(1, SUBMIT_RETRY_ATTEMPTS + 1):
        try:
            with SUBSTRATE_IO_LOCK:
                rec = substrate.submit_extrinsic(
                    xt,
                    wait_for_inclusion=True,
                    wait_for_finalization=True,
                )
            if submitted_xt_hex:
                try:
                    setattr(rec, "submitted_extrinsic_hex", submitted_xt_hex)
                except Exception:
                    pass
            if not allow_failed and not rec.is_success:
                raise RuntimeError(f"Extrinsic failed in block {rec.block_hash}: {rec.error_message}")
            return rec

        except SubstrateRequestException as e:
            last_exc = e

            recovered = recover_prebuilt_extrinsic_receipt(substrate, xt)
            if recovered is not None:
                if not allow_failed and not recovered.is_success:
                    raise RuntimeError(
                        f"Extrinsic failed in block {recovered.block_hash}: "
                        f"{recovered.error_message or 'unknown error'}"
                    )
                return recovered

            if attempt >= SUBMIT_RETRY_ATTEMPTS:
                raise RuntimeError(f"Extrinsic submission failed: {e}") from e

            if is_retryable_transport_error(e):
                try:
                    _reconnect_substrate(substrate)
                except Exception:
                    pass
                time.sleep(SUBMIT_RETRY_BACKOFF_SEC * attempt)
                continue

            if is_submission_pending_error(e):
                time.sleep(SUBMIT_RETRY_BACKOFF_SEC * attempt)
                continue

            raise RuntimeError(f"Extrinsic submission failed: {e}") from e

        except Exception as e:
            last_exc = e

            if is_retryable_transport_error(e) or is_submission_pending_error(e):
                recovered = recover_prebuilt_extrinsic_receipt(substrate, xt)
                if recovered is not None:
                    if not allow_failed and not recovered.is_success:
                        raise RuntimeError(
                            f"Extrinsic failed in block {recovered.block_hash}: "
                            f"{recovered.error_message or 'unknown error'}"
                        )
                    return recovered

                if attempt >= SUBMIT_RETRY_ATTEMPTS:
                    raise

                if is_retryable_transport_error(e):
                    try:
                        _reconnect_substrate(substrate)
                    except Exception:
                        pass

                time.sleep(SUBMIT_RETRY_BACKOFF_SEC * attempt)
                continue

            raise

    assert last_exc is not None
    raise last_exc


def submit(substrate: SubstrateInterface, signer: Keypair, call, sudo: bool = False):
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})

    xt = create_signed_extrinsic_safe(substrate, signer, call)
    return submit_prebuilt_extrinsic(substrate, xt, allow_failed=False)


def submit_allow_failure(substrate: SubstrateInterface, signer: Keypair, call, sudo: bool = False):
    if sudo:
        call = compose_call(substrate, "Sudo", "sudo", {"call": call})

    xt = create_signed_extrinsic_safe(substrate, signer, call)
    return submit_prebuilt_extrinsic(substrate, xt, allow_failed=True)


def q_int(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
    default: int = 0,
) -> int:
    try:
        res = safe_query(substrate, module, storage, params or [], block_hash=block_hash)
        if res is None or res.value is None:
            return default
        return as_int(res.value)
    except Exception:
        return default


def q_int_strict(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
) -> int:
    res = safe_query(substrate, module, storage, params or [], block_hash=block_hash)
    if res is None:
        raise RuntimeError(f"Query returned None for {module}.{storage} params={params} block_hash={block_hash}")
    if res.value is None:
        raise RuntimeError(f"Query value was None for {module}.{storage} params={params} block_hash={block_hash}")
    return as_int(res.value)


def account_free_at(substrate: SubstrateInterface, ss58: str, block_hash: Optional[str] = None) -> int:
    info = safe_query(substrate, "System", "Account", [ss58], block_hash=block_hash).value
    return int(info["data"]["free"])


def account_free(substrate: SubstrateInterface, ss58: str) -> int:
    return account_free_at(substrate, ss58)


def transfer_keep_alive(substrate: SubstrateInterface, signer: Keypair, dest_ss58: str, amount_planck: int):
    call = compose_call(substrate, "Balances", "transfer_keep_alive", {"dest": dest_ss58, "value": int(amount_planck)})
    submit(substrate, signer, call, sudo=False)


def ensure_min_balance(substrate: SubstrateInterface, funder: Keypair, who: Keypair, min_tao: float, decimals: int):
    tgt = to_planck(min_tao, decimals)
    cur = account_free(substrate, who.ss58_address)
    if cur < tgt:
        with ALICE_LOCK:
            cur2 = account_free(substrate, who.ss58_address)
            if cur2 < tgt:
                transfer_keep_alive(substrate, funder, who.ss58_address, tgt - cur2)


def try_prepare_next_registration_balance(
    substrate: SubstrateInterface,
    funder: Keypair,
    who: Keypair,
    reference_burn_planck: int,
    decimals: int,
    safety_mult: int = NEXT_REG_BALANCE_SAFETY_MULT,
    buffer_tao: float = NEXT_REG_BALANCE_BUFFER_TAO,
    min_one_reg_buffer_tao: float = MIN_ONE_REG_BUFFER_TAO,
) -> Tuple[bool, int, str]:
    target = int(reference_burn_planck) * int(max(1, safety_mult)) + to_planck(buffer_tao, decimals)
    min_required = int(reference_burn_planck) + to_planck(min_one_reg_buffer_tao, decimals)

    cur = account_free(substrate, who.ss58_address)
    if cur >= target:
        return True, cur, ""

    msg = ""
    try:
        with ALICE_LOCK:
            cur2 = account_free(substrate, who.ss58_address)
            if cur2 < target:
                transfer_keep_alive(substrate, funder, who.ss58_address, target - cur2)
    except Exception as e:
        msg = simplify_error_message(str(e))

    cur_after = account_free(substrate, who.ss58_address)
    if cur_after >= min_required:
        return True, cur_after, msg

    if not msg:
        msg = (
            f"insufficient payer funding after top-up attempt "
            f"(have {fmt_tao(cur_after, decimals)}, need at least {fmt_tao(min_required, decimals)})"
        )
    return False, cur_after, msg


def ensure_balance_for_next_registration(
    substrate: SubstrateInterface,
    funder: Keypair,
    who: Keypair,
    reference_burn_planck: int,
    decimals: int,
    safety_mult: int = NEXT_REG_BALANCE_SAFETY_MULT,
    buffer_tao: float = NEXT_REG_BALANCE_BUFFER_TAO,
):
    ok, cur_after, msg = try_prepare_next_registration_balance(
        substrate=substrate,
        funder=funder,
        who=who,
        reference_burn_planck=reference_burn_planck,
        decimals=decimals,
        safety_mult=safety_mult,
        buffer_tao=buffer_tao,
    )
    if not ok:
        raise RuntimeError(msg or f"could not prepare payer balance; current={fmt_tao(cur_after, decimals)}")


def produce_one_block(substrate: SubstrateInterface, signer: Keypair, tag: str):
    call = compose_call(substrate, "System", "remark", {"remark": bytes(tag, "utf-8")})
    return submit(substrate, signer, call, sudo=False)


def produce_n_blocks(substrate: SubstrateInterface, signer: Keypair, n: int, tag_prefix: str):
    receipts = []
    for i in range(n):
        receipts.append(produce_one_block(substrate, signer, f"{tag_prefix}-{i}"))
        time.sleep(0.05)
    return receipts


def block_number_at(substrate: SubstrateInterface, block_hash: str) -> int:
    return q_int_strict(substrate, "System", "Number", [], block_hash=block_hash)


def open_network(ctx: NetworkContext):
    substrate = connect(ctx.ws)
    sudo = Keypair.create_from_uri("//Alice")
    reg_cold = Keypair.create_from_uri(ctx.payer_uri)
    log = make_logger(ctx.netuid)
    return substrate, sudo, reg_cold, log


# ─────────────────────────────────────────────────────────────
# Chain queries
# ─────────────────────────────────────────────────────────────
def burn_at_strict(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    candidates = ["Burn", "NeuronBurn", "RegistrationBurn", "SubnetBurn", "BurnCost"]
    last_exc: Optional[Exception] = None

    for storage in candidates:
        try:
            return q_int_strict(substrate, PALLET_SUBTENSOR, storage, [netuid], block_hash)
        except Exception as e:
            last_exc = e

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"Could not read burn for netuid={netuid} at block_hash={block_hash}")


def min_burn_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    v = q_int(substrate, PALLET_SUBTENSOR, "MinBurn", [netuid], block_hash)
    if v != 0:
        return v
    return q_int(substrate, PALLET_SUBTENSOR, "MinBurn", [], block_hash)


def max_burn_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    v = q_int(substrate, PALLET_SUBTENSOR, "MaxBurn", [netuid], block_hash)
    if v != 0:
        return v
    return q_int(substrate, PALLET_SUBTENSOR, "MaxBurn", [], block_hash)


def burn_half_life_at_strict(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    return q_int_strict(substrate, PALLET_SUBTENSOR, "BurnHalfLife", [netuid], block_hash)


def burn_increase_mult_at_strict(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    return q_int_strict(substrate, PALLET_SUBTENSOR, "BurnIncreaseMult", [netuid], block_hash)


def regs_this_block_at_strict(substrate: SubstrateInterface, netuid: int, block_hash: str) -> int:
    return q_int_strict(substrate, PALLET_SUBTENSOR, "RegistrationsThisBlock", [netuid], block_hash)


def subnetwork_n_at_strict(substrate: SubstrateInterface, netuid: int, block_hash: Optional[str] = None) -> int:
    return q_int_strict(substrate, PALLET_SUBTENSOR, "SubnetworkN", [netuid], block_hash)


def max_allowed_uids_at_strict(substrate: SubstrateInterface, netuid: int, block_hash: Optional[str] = None) -> int:
    return q_int_strict(substrate, PALLET_SUBTENSOR, "MaxAllowedUids", [netuid], block_hash)


def hotkey_uid_at(
    substrate: SubstrateInterface,
    netuid: int,
    hot_ss58: str,
    block_hash: Optional[str] = None,
) -> Optional[int]:
    res = safe_query(substrate, PALLET_SUBTENSOR, "Uids", [netuid, hot_ss58], block_hash=block_hash)
    if res is None or res.value is None:
        return None
    return as_int(res.value)


def hotkey_registered_on_network_at(
    substrate: SubstrateInterface,
    netuid: int,
    hot_ss58: str,
    block_hash: Optional[str] = None,
) -> bool:
    return hotkey_uid_at(substrate, netuid, hot_ss58, block_hash) is not None


def registration_allowed_at(substrate: SubstrateInterface, netuid: int, block_hash: str) -> bool:
    try:
        res = safe_query(substrate, PALLET_SUBTENSOR, "NetworkRegistrationAllowed", [netuid], block_hash=block_hash)
        return bool(res.value)
    except Exception:
        return True


def networks_added(substrate: SubstrateInterface) -> List[int]:
    nets: List[int] = []
    try:
        for key, val in safe_query_map(substrate, PALLET_SUBTENSOR, "NetworksAdded"):
            if bool(val.value):
                kv = getattr(key, "value", key)
                try:
                    if isinstance(kv, int):
                        nets.append(int(kv))
                    elif isinstance(kv, dict) and kv:
                        nets.append(int(next(iter(kv.values()))))
                    else:
                        nets.append(int(str(kv)))
                except Exception:
                    pass
    except Exception:
        pass
    return sorted(set(nets))


def read_net_state(substrate: SubstrateInterface, netuid: int, block_hash: str) -> Dict[str, int]:
    block = block_number_at(substrate, block_hash)
    return {
        "hash": block_hash,
        "block": block,
        "burn": burn_at_strict(substrate, netuid, block_hash),
        "regs": regs_this_block_at_strict(substrate, netuid, block_hash),
        "n": subnetwork_n_at_strict(substrate, netuid, block_hash),
    }


# ─────────────────────────────────────────────────────────────
# Admin setters
# ─────────────────────────────────────────────────────────────
def sudo_set_network_rate_limit(substrate: SubstrateInterface, sudo: Keypair, rate_limit: int):
    with ALICE_LOCK:
        for pallet in (PALLET_ADMIN, PALLET_SUBTENSOR):
            try:
                call = compose_call(substrate, pallet, "sudo_set_network_rate_limit", {"rate_limit": int(rate_limit)})
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception:
                continue


def sudo_set_registration_allowed(substrate: SubstrateInterface, sudo: Keypair, netuid: int, allowed: bool):
    candidates = [
        (PALLET_ADMIN, "sudo_set_network_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_ADMIN, "sudo_set_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_SUBTENSOR, "sudo_set_network_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
        (PALLET_SUBTENSOR, "sudo_set_registration_allowed", {"netuid": netuid, "registration_allowed": bool(allowed)}),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn, params in candidates:
            try:
                call = compose_call(substrate, pallet, fn, params)
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    if last is not None:
        raise last


def sudo_set_burn_half_life(substrate: SubstrateInterface, sudo: Keypair, netuid: int, burn_half_life: int):
    candidates = [
        (PALLET_ADMIN, "sudo_set_burn_half_life"),
        (PALLET_SUBTENSOR, "sudo_set_burn_half_life"),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn in candidates:
            try:
                call = compose_call(substrate, pallet, fn, {"netuid": int(netuid), "burn_half_life": int(burn_half_life)})
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    raise RuntimeError(f"Failed to set BurnHalfLife via any known pallet: {last}")


def sudo_set_burn_increase_mult(substrate: SubstrateInterface, sudo: Keypair, netuid: int, burn_increase_mult: int):
    candidates = [
        (PALLET_ADMIN, "sudo_set_burn_increase_mult"),
        (PALLET_SUBTENSOR, "sudo_set_burn_increase_mult"),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn in candidates:
            try:
                call = compose_call(substrate, pallet, fn, {"netuid": int(netuid), "burn_increase_mult": int(burn_increase_mult)})
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    raise RuntimeError(f"Failed to set BurnIncreaseMult via any known pallet: {last}")


def sudo_set_subnet_limit(substrate: SubstrateInterface, sudo: Keypair, max_subnets: int):
    candidates = [
        (PALLET_ADMIN, "sudo_set_subnet_limit", {"max_subnets": int(max_subnets)}),
        (PALLET_SUBTENSOR, "sudo_set_subnet_limit", {"max_subnets": int(max_subnets)}),
    ]
    last = None
    with ALICE_LOCK:
        for pallet, fn, params in candidates:
            try:
                call = compose_call(substrate, pallet, fn, params)
                submit(substrate, sudo, call, sudo=True)
                return
            except Exception as e:
                last = e
    raise RuntimeError(f"Failed to set subnet limit via any known pallet: {last}")


# ─────────────────────────────────────────────────────────────
# Registration extrinsics
# ─────────────────────────────────────────────────────────────
def _recover_registration_receipt_if_already_applied(
    substrate: SubstrateInterface,
    netuid: int,
    hot_ss58: str,
) -> Optional[RecoveredReceipt]:
    """
    After a retryable transport failure, check whether the registration likely
    already landed on-chain. If yes, return a synthetic receipt anchored at the
    current head.

    This is conservative and only used as a fallback for flaky transports.
    """
    try:
        for _ in range(3):
            head_hash = get_chain_head_hash(substrate)
            if head_hash and hotkey_registered_on_network_at(substrate, netuid, hot_ss58, head_hash):
                return RecoveredReceipt(block_hash=head_hash)
            time.sleep(0.20)
    except Exception:
        pass
    return None


def burned_register(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int):
    call = compose_call(substrate, PALLET_SUBTENSOR, "burned_register", {"netuid": int(netuid), "hotkey": hot_ss58})
    return submit(substrate, cold, call, sudo=False)


def burned_register_with_retry(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    last = None
    for i in range(1, max_attempts + 1):
        try:
            return burned_register(substrate, cold, hot_ss58, netuid)
        except Exception as e:
            last = e
            s = str(e).lower()

            if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                produce_n_blocks(substrate, cold, backoff_blocks, "reg-backoff")
                continue

            raise

    if last is not None:
        raise last
    raise RuntimeError("burned_register_with_retry failed unexpectedly")


def register_limit(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str, netuid: int, limit_price: int):
    call = compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "register_limit",
        {
            "netuid": int(netuid),
            "hotkey": hot_ss58,
            "limit_price": int(limit_price),
        },
    )
    return submit(substrate, cold, call, sudo=False)


def register_limit_allow_failure(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    limit_price: int,
):
    call = compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "register_limit",
        {
            "netuid": int(netuid),
            "hotkey": hot_ss58,
            "limit_price": int(limit_price),
        },
    )
    return submit_allow_failure(substrate, cold, call, sudo=False)


def register_limit_allow_failure_with_retry(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    limit_price: int,
    max_attempts: int = 4,
):
    # Transport retries/recovery happen inside submit_allow_failure().
    _ = max_attempts
    return register_limit_allow_failure(substrate, cold, hot_ss58, netuid, limit_price)


def register_limit_with_retry(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    limit_price: int,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    last = None
    for i in range(1, max_attempts + 1):
        try:
            return register_limit(substrate, cold, hot_ss58, netuid, limit_price)
        except Exception as e:
            last = e
            s = str(e).lower()

            if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                produce_n_blocks(substrate, cold, backoff_blocks, "reg-limit-backoff")
                continue

            raise

    if last is not None:
        raise last
    raise RuntimeError("register_limit_with_retry failed unexpectedly")


def submit_batched_calls_with_retry(
    substrate: SubstrateInterface,
    signer: Keypair,
    calls: List[Any],
    max_attempts: int = 6,
    backoff_blocks: int = 1,
    sudo: bool = False,
):
    candidates = [
        ("Utility", "batch_all", {"calls": calls}),
        ("Utility", "batch", {"calls": calls}),
    ]

    last = None
    for i in range(1, max_attempts + 1):
        for pallet, fn, params in candidates:
            try:
                call = compose_call(substrate, pallet, fn, params)
                return submit(substrate, signer, call, sudo=sudo)
            except Exception as e:
                last = e
                s = str(e).lower()

                if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                    produce_n_blocks(substrate, signer, backoff_blocks, "batch-backoff")
                    break

        else:
            continue

        if last is not None:
            s = str(last).lower()
            if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                continue
            raise last

    if last is not None:
        raise last
    raise RuntimeError("submit_batched_calls_with_retry failed unexpectedly")


def batch_burned_registers_with_retry(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58_list: List[str],
    netuid: int,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    calls = [
        compose_call(
            substrate,
            PALLET_SUBTENSOR,
            "burned_register",
            {"netuid": int(netuid), "hotkey": hot_ss58},
        )
        for hot_ss58 in hot_ss58_list
    ]
    return submit_batched_calls_with_retry(
        substrate=substrate,
        signer=cold,
        calls=calls,
        max_attempts=max_attempts,
        backoff_blocks=backoff_blocks,
    )


def batch_sudo_as_burned_registers_with_retry(
    substrate: SubstrateInterface,
    sudo: Keypair,
    cold_hot_pairs: List[Tuple[str, str]],
    netuid: int,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    calls = []
    for cold_ss58, hot_ss58 in cold_hot_pairs:
        inner_call = compose_call(
            substrate,
            PALLET_SUBTENSOR,
            "burned_register",
            {"netuid": int(netuid), "hotkey": hot_ss58},
        )
        calls.append(
            compose_call(
                substrate,
                "Sudo",
                "sudo_as",
                {"who": cold_ss58, "call": inner_call},
            )
        )

    return submit_batched_calls_with_retry(
        substrate=substrate,
        signer=sudo,
        calls=calls,
        max_attempts=max_attempts,
        backoff_blocks=backoff_blocks,
        sudo=True,
    )


def register_network(
    substrate: SubstrateInterface,
    signer: Keypair,
    owner_hot_ss58: str,
    owner_cold_ss58: str,
):
    candidates = [
        {"owner_hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"hotkey": owner_hot_ss58, "coldkey": owner_cold_ss58},
        {"owner_hot": owner_hot_ss58, "owner_cold": owner_cold_ss58},
    ]
    last = None
    for params in candidates:
        try:
            call = compose_call(substrate, PALLET_SUBTENSOR, "register_network", params)
            return submit(substrate, signer, call, sudo=False)
        except Exception as e:
            last = e
    raise RuntimeError(f"register_network failed with all candidates: {last}")


def register_network_with_retry(
    substrate: SubstrateInterface,
    signer: Keypair,
    owner_hot_ss58: str,
    owner_cold_ss58: str,
    max_attempts: int = 6,
    backoff_blocks: int = 1,
):
    last = None
    for i in range(1, max_attempts + 1):
        try:
            return register_network(substrate, signer, owner_hot_ss58, owner_cold_ss58)
        except Exception as e:
            last = e
            s = str(e).lower()

            if ("ratelimit" in s or "rate limit" in s or "custom error: 6" in s) and i < max_attempts:
                produce_n_blocks(substrate, signer, backoff_blocks, "register-network-backoff")
                continue

            raise

    if last is not None:
        raise last
    raise RuntimeError("register_network_with_retry failed unexpectedly")


def allocate_scratch_subnet_for_stage(
    substrate: SubstrateInterface,
    sudo: Keypair,
    decimals: int,
    seed_tag: str,
    log: Callable[[str], None],
) -> int:
    before = set(networks_added(substrate))

    try:
        desired_limit = max((max(before) if before else 0) + 8, len(before) + 8)
        sudo_set_subnet_limit(substrate, sudo, desired_limit)
    except Exception as e:
        log(f"ℹ️  Scratch subnet allocation could not raise subnet limit automatically: {simplify_error_message(str(e))}")

    owner_cold = Keypair.create_from_uri(f"//Alice//DynBurnScratchCold//{seed_tag}")
    owner_hot = Keypair.create_from_uri(f"//Alice//DynBurnScratchHot//{seed_tag}")

    ensure_min_balance(substrate, sudo, owner_cold, REGISTER_NETWORK_MIN_OWNER_COLD_TAO, decimals)
    ensure_min_balance(substrate, sudo, owner_hot, REGISTER_NETWORK_MIN_OWNER_HOT_TAO, decimals)

    register_network_with_retry(
        substrate=substrate,
        signer=owner_cold,
        owner_hot_ss58=owner_hot.ss58_address,
        owner_cold_ss58=owner_cold.ss58_address,
    )

    after = set(networks_added(substrate))
    created = sorted(n for n in after if n not in before and n != 0)
    if not created:
        raise RuntimeError(f"Scratch subnet allocation did not create a visible subnet for seed={seed_tag}")

    scratch_netuid = created[-1]

    probe_rec = produce_one_block(substrate, owner_cold, f"scratch-probe-{seed_tag}-{scratch_netuid}")
    if not registration_allowed_at(substrate, scratch_netuid, probe_rec.block_hash):
        sudo_set_registration_allowed(substrate, sudo, scratch_netuid, True)
        produce_one_block(substrate, owner_cold, f"scratch-enable-{seed_tag}-{scratch_netuid}")

    log(f"🧪 Using scratch subnet {scratch_netuid} for this burn-config stage.")
    return scratch_netuid


# ─────────────────────────────────────────────────────────────
# Exact integer math helpers mirroring the runtime
# ─────────────────────────────────────────────────────────────
def sat_add_u64(a: int, b: int) -> int:
    a = max(0, int(a))
    b = max(0, int(b))
    s = a + b
    return U64_MAX if s > U64_MAX else s


def sat_mul_u64(a: int, b: int) -> int:
    a = max(0, int(a))
    b = max(0, int(b))
    p = a * b
    return U64_MAX if p > U64_MAX else p


def sat_pow_u64(base: int, exp: int) -> int:
    result = 1
    factor = max(0, int(base))
    power = max(0, int(exp))
    while power > 0:
        if (power & 1) == 1:
            result = sat_mul_u64(result, factor)
        power >>= 1
        if power > 0:
            factor = sat_mul_u64(factor, factor)
    return result


def mul_by_q32(value: int, factor_q32: int) -> int:
    value = max(0, int(value))
    factor_q32 = max(0, int(factor_q32))
    product = value * factor_q32
    shifted = product >> 32
    return U64_MAX if shifted > U64_MAX else shifted


def pow_q32(base_q32: int, exp: int) -> int:
    result = ONE_Q32
    factor = max(0, int(base_q32))
    power = max(0, int(exp))
    while power > 0:
        if (power & 1) == 1:
            result = mul_by_q32(result, factor)
        power >>= 1
        if power > 0:
            factor = mul_by_q32(factor, factor)
    return result


def decay_factor_q32(half_life: int) -> int:
    half_life = max(0, int(half_life))
    if half_life == 0:
        return ONE_Q32
    lo = 0
    hi = ONE_Q32
    while (lo + 1) < hi:
        mid = lo + ((hi - lo) // 2)
        mid_pow = pow_q32(mid, half_life)
        if mid_pow > HALF_Q32:
            hi = mid
        else:
            lo = mid
    return lo


# ─────────────────────────────────────────────────────────────
# Exact simulation of the corrected runtime (decay on initialize, bump on successful registration)
# ─────────────────────────────────────────────────────────────
def simulate_one_on_initialize_step(
    burn_before: int,
    entering_block: int,
    burn_half_life: int,
) -> int:
    burn = max(0, int(burn_before))
    current_block = max(0, int(entering_block))

    if burn_half_life > 0 and current_block > 1:
        factor_q32 = decay_factor_q32(burn_half_life)
        burn = mul_by_q32(burn, factor_q32)
        if burn == 0:
            burn = 1

    return burn


def build_same_block_charge_sequence(
    entry_burn: int,
    burn_increase_mult: int,
    reg_count: int,
) -> Tuple[List[int], int]:
    burn = max(0, int(entry_burn))
    mult = max(1, int(burn_increase_mult))
    count = max(0, int(reg_count))

    charges: List[int] = []
    for _ in range(count):
        charges.append(burn)
        burn = sat_mul_u64(burn, mult)
        if burn == 0:
            burn = 1

    return charges, burn


def simulate_registration_bumps_for_block(
    burn_before: int,
    burn_increase_mult: int,
    regs_this_block: int,
) -> int:
    burn = max(0, int(burn_before))

    if regs_this_block > 0:
        mult = max(1, int(burn_increase_mult))
        bump = sat_pow_u64(mult, int(regs_this_block))
        burn = sat_mul_u64(burn, bump)
        if burn == 0:
            burn = 1

    return burn


def simulate_from_block_state(
    start_burn: int,
    start_block: int,
    end_block: int,
    burn_half_life: int,
    burn_increase_mult: int,
    regs_this_block_map: Dict[int, int],
) -> int:
    burn = int(start_burn)
    if end_block <= start_block:
        return burn

    for block_number in range(start_block + 1, end_block + 1):
        burn = simulate_one_on_initialize_step(
            burn_before=burn,
            entering_block=block_number,
            burn_half_life=burn_half_life,
        )
        regs_this_block = int(regs_this_block_map.get(block_number, 0))
        burn = simulate_registration_bumps_for_block(
            burn_before=burn,
            burn_increase_mult=burn_increase_mult,
            regs_this_block=regs_this_block,
        )
    return burn


# ─────────────────────────────────────────────────────────────
# Assertion helpers
# ─────────────────────────────────────────────────────────────
def assert_state(
    phase: str,
    actual_burn: int,
    expected_burn: int,
    decimals: int,
):
    if actual_burn != expected_burn:
        raise AssertionError(
            f"[assert] {phase}\n"
            f"  actual burn   = {actual_burn} ({fmt_tao(actual_burn, decimals)})\n"
            f"  expected burn = {expected_burn} ({fmt_tao(expected_burn, decimals)})\n"
        )


def assert_sampled_transition(
    prev_state: Dict[str, int],
    cur_state: Dict[str, int],
    burn_half_life: int,
    burn_increase_mult: int,
    regs_map: Dict[int, int],
    decimals: int,
    phase: str,
    require_n_stable: bool = True,
):
    exp_burn = simulate_from_block_state(
        start_burn=prev_state["burn"],
        start_block=prev_state["block"],
        end_block=cur_state["block"],
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map=regs_map,
    )

    assert_state(
        phase=phase,
        actual_burn=cur_state["burn"],
        expected_burn=exp_burn,
        decimals=decimals,
    )

    if require_n_stable and cur_state["n"] != prev_state["n"]:
        raise AssertionError(
            f"[assert] unexpected SubnetworkN change during no-registration decay phase\n"
            f"  prev_n = {prev_state['n']}\n"
            f"  cur_n  = {cur_state['n']}\n"
            f"  prev_block = {prev_state['block']}\n"
            f"  cur_block  = {cur_state['block']}\n"
        )


def sample_decay_for_n_blocks(
    substrate: SubstrateInterface,
    block_signer: Keypair,
    netuid: int,
    decimals: int,
    start_state: Dict[str, int],
    burn_half_life: int,
    burn_increase_mult: int,
    num_steps: int,
    tag_prefix: str,
    print_prefix: str,
    log,
) -> Dict[str, int]:
    prev_state = dict(start_state)
    regs_map: Dict[int, int] = {start_state["block"]: start_state["regs"]}

    for step in range(1, num_steps + 1):
        rec = produce_one_block(substrate, block_signer, f"{tag_prefix}-{step}")
        cur_state = read_net_state(substrate, netuid, rec.block_hash)

        assert_sampled_transition(
            prev_state=prev_state,
            cur_state=cur_state,
            burn_half_life=burn_half_life,
            burn_increase_mult=burn_increase_mult,
            regs_map=regs_map,
            decimals=decimals,
            phase=f"{print_prefix} sampled decay step #{step}",
            require_n_stable=True,
        )

        regs_map[cur_state["block"]] = cur_state["regs"]

        if should_log_decay_step(step, num_steps):
            log(
                format_state(
                    f"{print_prefix}{step:03d}",
                    cur_state["block"],
                    cur_state["burn"],
                    cur_state["regs"],
                    decimals,
                    cur_state["n"],
                    icon="📉",
                )
            )

        prev_state = cur_state

    elapsed_blocks = max(0, prev_state["block"] - start_state["block"])
    actual_ratio = (
        float(prev_state["burn"]) / float(start_state["burn"])
        if start_state["burn"] > 0 else 0.0
    )
    expected_ratio = (decay_factor_q32(burn_half_life) / float(ONE_Q32)) ** elapsed_blocks

    log(
        f"📊 Decay check passed over {num_steps} sampled step(s) "
        f"| actual ratio ≈ {actual_ratio:.12f} | expected ≈ {expected_ratio:.12f} "
        f"| elapsed blocks = {elapsed_blocks}"
    )

    return prev_state


# ─────────────────────────────────────────────────────────────
# Scenario: default-parameter stress
# ─────────────────────────────────────────────────────────────
def run_many_registrations_default_params(ctx: NetworkContext):
    substrate, sudo, reg_cold, log = open_network(ctx)

    sync_rec = produce_one_block(substrate, reg_cold, f"stress-sync-{ctx.run_nonce}")
    sync_hash = sync_rec.block_hash
    sync_state = read_net_state(substrate, ctx.netuid, sync_hash)

    default_hl = burn_half_life_at_strict(substrate, ctx.netuid, sync_hash)
    default_mult = burn_increase_mult_at_strict(substrate, ctx.netuid, sync_hash)
    default_burn = sync_state["burn"]
    default_regs = sync_state["regs"]
    default_n = sync_state["n"]
    max_allowed = max_allowed_uids_at_strict(substrate, ctx.netuid, sync_hash)

    if default_hl <= 0:
        raise AssertionError("Default BurnHalfLife must be > 0 for the default stress scenario.")
    if default_burn <= 0:
        raise AssertionError("Default burn must be > 0 for the default stress scenario.")

    factor_q32 = decay_factor_q32(default_hl)
    factor_float = factor_q32 / float(ONE_Q32)
    burn_soft_cap = to_planck(STRESS_SOFT_MAX_BURN_TAO, ctx.decimals)

    scenario_banner(
        log,
        f"🚀 Default stress scenario | BurnHalfLife={default_hl} | BurnIncreaseMult={default_mult}",
        f"decay factor ≈ {factor_float:.12f} | "
        f"target regs = {STRESS_TARGET_TOTAL_REGS} | max allowed uids = {max_allowed} | "
        f"soft burn cap = {STRESS_SOFT_MAX_BURN_TAO:.3f} TAO",
    )
    log(format_state("base", sync_state["block"], default_burn, default_regs, ctx.decimals, default_n, icon="🧪"))

    prep_state = sync_state
    n_prep = prep_state["n"]
    capacity_budget = max(0, max_allowed - n_prep)
    if capacity_budget == 0:
        raise AssertionError(
            f"[assert] no available uid slots on netuid {ctx.netuid} for default stress scenario\n"
            f"  max_allowed = {max_allowed}\n"
            f"  current_n   = {n_prep}\n"
        )
    total_regs = max(1, min(STRESS_TARGET_TOTAL_REGS, capacity_budget))

    log(format_state("prep", prep_state["block"], prep_state["burn"], prep_state["regs"], ctx.decimals, n_prep, icon="🧭"))
    log(f"📦 Burst plan | registrations = {total_regs} | capacity budget = {capacity_budget}")

    prev_block = prep_state["block"]
    prev_burn = prep_state["burn"]
    regs_map: Dict[int, int] = {prep_state["block"]: prep_state["regs"]}
    stress_hotkeys: List[str] = []
    safety_mult = max(NEXT_REG_BALANCE_SAFETY_MULT, default_mult * 2)
    stop_reason: Optional[str] = None

    for i in range(total_regs):
        if prev_burn >= burn_soft_cap:
            stop_reason = (
                f"soft burn cap reached before registration {i+1}: "
                f"{fmt_tao(prev_burn, ctx.decimals)} >= {STRESS_SOFT_MAX_BURN_TAO:.3f} TAO"
            )
            break

        ready, cur_after, fund_msg = try_prepare_next_registration_balance(
            substrate=substrate,
            funder=sudo,
            who=reg_cold,
            reference_burn_planck=prev_burn,
            decimals=ctx.decimals,
            safety_mult=safety_mult,
            buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
        )
        if not ready:
            stop_reason = (
                f"payer funding exhausted before registration {i+1}: "
                f"payer balance = {fmt_tao(cur_after, ctx.decimals)}"
            )
            if fund_msg:
                stop_reason += f" | {fund_msg}"
            break

        hot = Keypair.create_from_uri(f"//Alice//DynBurnStress//{ctx.netuid}//{ctx.run_nonce}//{i}")
        stress_hotkeys.append(hot.ss58_address)

        reg_rec = burned_register_with_retry(substrate, reg_cold, hot.ss58_address, ctx.netuid)
        reg_state = read_net_state(substrate, ctx.netuid, reg_rec.block_hash)

        burn_reg = reg_state["burn"]
        regs_reg = reg_state["regs"]
        n_reg = reg_state["n"]
        reg_block = reg_state["block"]

        if not receipt_was_recovered(reg_rec):
            exp_regs_map = dict(regs_map)
            exp_regs_map[reg_block] = regs_reg
            exp_burn_reg = simulate_from_block_state(
                start_burn=prev_burn,
                start_block=prev_block,
                end_block=reg_block,
                burn_half_life=default_hl,
                burn_increase_mult=default_mult,
                regs_this_block_map=exp_regs_map,
            )
            assert_state(
                phase=f"default stress registration #{i+1} should match immediate-bump runtime logic",
                actual_burn=burn_reg,
                expected_burn=exp_burn_reg,
                decimals=ctx.decimals,
            )
        else:
            log(
                f"⚠️  Registration #{i+1} recovered after transport failure; "
                f"skipping exact burn assertion at block {reg_block}."
            )

        if regs_reg < 1 and not receipt_was_recovered(reg_rec):
            raise AssertionError(
                f"[assert] expected at least one registration in block {reg_block}, "
                f"but RegistrationsThisBlock={regs_reg}"
            )

        expected_n = n_prep + i + 1
        if n_reg != expected_n:
            raise AssertionError(
                f"[assert] unexpected SubnetworkN during default stress registration #{i+1}\n"
                f"  actual   = {n_reg}\n"
                f"  expected = {expected_n}\n"
            )

        if not hotkey_registered_on_network_at(substrate, ctx.netuid, hot.ss58_address, reg_rec.block_hash):
            raise AssertionError(
                "[assert] newly registered hotkey is not present on the subnet in its registration block\n"
                f"  hotkey = {hot.ss58_address}\n"
                f"  block  = {reg_block}\n"
            )

        if should_log_progress(i + 1, total_regs):
            log(
                format_state(
                    f"reg {i+1:02d}/{total_regs}",
                    reg_block,
                    burn_reg,
                    regs_reg,
                    ctx.decimals,
                    n_reg,
                    icon="📝",
                )
            )

        regs_map[reg_block] = regs_reg
        prev_block = reg_block
        prev_burn = burn_reg

    completed_regs = len(stress_hotkeys)

    if completed_regs == 0:
        raise AssertionError(
            f"[assert] default stress scenario on net {ctx.netuid} completed zero registrations. "
            f"Stop reason: {stop_reason or 'unknown'}"
        )

    if stop_reason:
        log(f"🛑 Burst stopped early after {completed_regs}/{total_regs} registrations | {stop_reason}")
    elif completed_regs < total_regs:
        log(f"ℹ️  Burst stopped after {completed_regs}/{total_regs} registrations.")
    else:
        log(f"✅ Burst reached planned target of {completed_regs} registrations.")

    post_rec = produce_one_block(substrate, reg_cold, f"stress-post-{ctx.run_nonce}")
    post_state = read_net_state(substrate, ctx.netuid, post_rec.block_hash)

    exp_burn_post = simulate_from_block_state(
        start_burn=prev_burn,
        start_block=prev_block,
        end_block=post_state["block"],
        burn_half_life=default_hl,
        burn_increase_mult=default_mult,
        regs_this_block_map=regs_map,
    )

    assert_state(
        phase="default stress post-registration decay block should match runtime logic",
        actual_burn=post_state["burn"],
        expected_burn=exp_burn_post,
        decimals=ctx.decimals,
    )

    log(format_state("post-decay", post_state["block"], post_state["burn"], post_state["regs"], ctx.decimals, post_state["n"], icon="📉"))

    expected_post_n = n_prep + completed_regs
    if post_state["n"] != expected_post_n:
        raise AssertionError(
            "[assert] expected SubnetworkN to remain at the total after the default stress burst\n"
            f"  actual   = {post_state['n']}\n"
            f"  expected = {expected_post_n}\n"
        )

    latest_hotkey = stress_hotkeys[-1]
    if not hotkey_registered_on_network_at(substrate, ctx.netuid, latest_hotkey, post_state["hash"]):
        raise AssertionError(
            "[assert] the most recently registered hotkey should still be present "
            "immediately after the default stress scenario post block"
        )

    log(f"✅ Burst complete | registrations = {completed_regs} | final subnetwork_n = {post_state['n']}")

    decay_steps = max(1, min(default_hl, DEFAULT_STRESS_POST_DECAY_STEPS))
    log(f"🧭 Sampling {decay_steps} no-registration decay step(s) after the burst.")
    sample_decay_for_n_blocks(
        substrate=substrate,
        block_signer=reg_cold,
        netuid=ctx.netuid,
        decimals=ctx.decimals,
        start_state=post_state,
        burn_half_life=default_hl,
        burn_increase_mult=default_mult,
        num_steps=decay_steps,
        tag_prefix=f"stress-decay-{ctx.run_nonce}",
        print_prefix="sd",
        log=log,
    )

    log("✅ Default stress scenario passed.")


# ─────────────────────────────────────────────────────────────
# Scenario: default-parameter limit-price
# ─────────────────────────────────────────────────────────────
def run_register_limit_scenario(ctx: NetworkContext):
    substrate, sudo, reg_cold, log = open_network(ctx)

    sync_rec = produce_one_block(substrate, reg_cold, f"limit-sync-{ctx.run_nonce}")
    sync_state = read_net_state(substrate, ctx.netuid, sync_rec.block_hash)

    half_life = burn_half_life_at_strict(substrate, ctx.netuid, sync_rec.block_hash)
    increase_mult = burn_increase_mult_at_strict(substrate, ctx.netuid, sync_rec.block_hash)
    factor_q32 = decay_factor_q32(half_life)
    factor_float = factor_q32 / float(ONE_Q32)

    scenario_banner(
        log,
        f"🛡️  Limit-price scenario | BurnHalfLife={half_life} | BurnIncreaseMult={increase_mult}",
        f"decay factor ≈ {factor_float:.12f}",
    )
    log(format_state("sync", sync_state["block"], sync_state["burn"], sync_state["regs"], ctx.decimals, sync_state["n"], icon="🔎"))

    if half_life <= 0:
        raise AssertionError("BurnHalfLife must be > 0 for the limit-price scenario.")
    if sync_state["burn"] <= 0:
        raise AssertionError("Burn must be > 0 for the limit-price scenario.")

    fail_limit = 0
    ensure_balance_for_next_registration(
        substrate=substrate,
        funder=sudo,
        who=reg_cold,
        reference_burn_planck=sync_state["burn"],
        decimals=ctx.decimals,
        safety_mult=max(NEXT_REG_BALANCE_SAFETY_MULT, increase_mult * 2),
        buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
    )

    fail_hot = Keypair.create_from_uri(f"//Alice//DynBurnLimitFail//{ctx.netuid}//{ctx.run_nonce}")
    fail_rec = register_limit_allow_failure_with_retry(
        substrate=substrate,
        cold=reg_cold,
        hot_ss58=fail_hot.ss58_address,
        netuid=ctx.netuid,
        limit_price=fail_limit,
    )
    fail_state = read_net_state(substrate, ctx.netuid, fail_rec.block_hash)

    if fail_rec.is_success:
        raise AssertionError(
            "[assert] register_limit(limit_price=0) unexpectedly succeeded while burn was positive"
        )

    exp_burn_fail = simulate_from_block_state(
        start_burn=sync_state["burn"],
        start_block=sync_state["block"],
        end_block=fail_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={},
    )

    assert_state(
        phase="limit scenario failure block should match decay-only runtime logic",
        actual_burn=fail_state["burn"],
        expected_burn=exp_burn_fail,
        decimals=ctx.decimals,
    )

    if fail_state["burn"] <= fail_limit:
        raise AssertionError(
            f"[assert] failure block burn should be strictly above the failing limit price\n"
            f"  burn       = {fail_state['burn']}\n"
            f"  limit      = {fail_limit}\n"
        )

    if fail_state["regs"] != 0:
        raise AssertionError(
            f"[assert] failed limit-order registration should not increment RegistrationsThisBlock\n"
            f"  actual regs_this_block = {fail_state['regs']}\n"
        )

    if fail_state["n"] != sync_state["n"]:
        raise AssertionError(
            f"[assert] failed limit-order registration should not change SubnetworkN\n"
            f"  before = {sync_state['n']}\n"
            f"  after  = {fail_state['n']}\n"
        )

    if hotkey_registered_on_network_at(substrate, ctx.netuid, fail_hot.ss58_address, fail_state["hash"]):
        raise AssertionError(
            "[assert] failing limit-order hotkey should not be registered on the subnet"
        )

    err_msg = simplify_error_message(getattr(fail_rec, "error_message", "") or "")
    log(format_state("reject", fail_state["block"], fail_state["burn"], fail_state["regs"], ctx.decimals, fail_state["n"], icon="🛑"))
    if err_msg:
        log(f"🧾 Rejected exactly as expected: {err_msg}")

    success_limit = fail_state["burn"]

    ensure_balance_for_next_registration(
        substrate=substrate,
        funder=sudo,
        who=reg_cold,
        reference_burn_planck=success_limit,
        decimals=ctx.decimals,
        safety_mult=max(NEXT_REG_BALANCE_SAFETY_MULT, increase_mult * 2),
        buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
    )

    ok_hot = Keypair.create_from_uri(f"//Alice//DynBurnLimitOk//{ctx.netuid}//{ctx.run_nonce}")
    ok_rec = register_limit_with_retry(
        substrate=substrate,
        cold=reg_cold,
        hot_ss58=ok_hot.ss58_address,
        netuid=ctx.netuid,
        limit_price=success_limit,
    )
    ok_state = read_net_state(substrate, ctx.netuid, ok_rec.block_hash)

    if not receipt_was_recovered(ok_rec):
        exp_burn_ok = simulate_from_block_state(
            start_burn=fail_state["burn"],
            start_block=fail_state["block"],
            end_block=ok_state["block"],
            burn_half_life=half_life,
            burn_increase_mult=increase_mult,
            regs_this_block_map={ok_state["block"]: ok_state["regs"]},
        )
        assert_state(
            phase="successful limit-order registration block should match runtime logic",
            actual_burn=ok_state["burn"],
            expected_burn=exp_burn_ok,
            decimals=ctx.decimals,
        )
    else:
        log(
            f"⚠️  Successful limit-order registration recovered after transport failure; "
            f"skipping exact burn assertion at block {ok_state['block']}."
        )

    burn_charged_for_ok = simulate_from_block_state(
        start_burn=fail_state["burn"],
        start_block=fail_state["block"],
        end_block=ok_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={},
    )

    if burn_charged_for_ok > success_limit:
        raise AssertionError(
            "[assert] successful limit-order registration should charge at or below the submitted limit\n"
            f"  charged burn = {burn_charged_for_ok}\n"
            f"  limit price  = {success_limit}\n"
            f"  final burn   = {ok_state['burn']}\n"
        )

    if ok_state["regs"] < 1 and not receipt_was_recovered(ok_rec):
        raise AssertionError(
            f"[assert] successful limit-order registration should increment RegistrationsThisBlock\n"
            f"  actual regs_this_block = {ok_state['regs']}\n"
        )

    if ok_state["n"] != fail_state["n"] + 1:
        raise AssertionError(
            "[assert] successful limit-order registration should increase SubnetworkN by exactly 1\n"
            f"  before = {fail_state['n']}\n"
            f"  after  = {ok_state['n']}\n"
        )

    if not hotkey_registered_on_network_at(substrate, ctx.netuid, ok_hot.ss58_address, ok_state["hash"]):
        raise AssertionError(
            "[assert] successful limit-order hotkey should be registered on the subnet"
        )

    log(format_state("accept", ok_state["block"], ok_state["burn"], ok_state["regs"], ctx.decimals, ok_state["n"], icon="✅"))
    log(f"💡 Accepted with limit_price = {success_limit} ({fmt_tao(success_limit, ctx.decimals)})")

    post_rec = produce_one_block(substrate, reg_cold, f"limit-post-{ctx.run_nonce}")
    post_state = read_net_state(substrate, ctx.netuid, post_rec.block_hash)

    exp_burn_post = simulate_from_block_state(
        start_burn=ok_state["burn"],
        start_block=ok_state["block"],
        end_block=post_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={},
    )

    assert_state(
        phase="limit scenario post-registration decay block should match runtime logic",
        actual_burn=post_state["burn"],
        expected_burn=exp_burn_post,
        decimals=ctx.decimals,
    )

    if post_state["n"] != ok_state["n"]:
        raise AssertionError(
            "[assert] post-registration decay block should not change SubnetworkN after successful limit-order registration\n"
            f"  before = {ok_state['n']}\n"
            f"  after  = {post_state['n']}\n"
        )

    log(format_state("decay", post_state["block"], post_state["burn"], post_state["regs"], ctx.decimals, post_state["n"], icon="📉"))
    log("✅ Limit-price scenario passed.")

# ─────────────────────────────────────────────────────────────
# Scenario: same-block multi-registration
# ─────────────────────────────────────────────────────────────
def run_same_block_multi_registration_scenario(ctx: NetworkContext):
    substrate, sudo, reg_cold, log = open_network(ctx)

    sync_rec = produce_one_block(substrate, reg_cold, f"same-block-sync-{ctx.run_nonce}")
    sync_state = read_net_state(substrate, ctx.netuid, sync_rec.block_hash)

    half_life = burn_half_life_at_strict(substrate, ctx.netuid, sync_rec.block_hash)
    increase_mult = burn_increase_mult_at_strict(substrate, ctx.netuid, sync_rec.block_hash)
    factor_q32 = decay_factor_q32(half_life)
    factor_float = factor_q32 / float(ONE_Q32)

    scenario_banner(
        log,
        f"🧩 Same-block multi-registration | BurnHalfLife={half_life} | BurnIncreaseMult={increase_mult}",
        f"decay factor ≈ {factor_float:.12f} | batched registrations in one block = {SAME_BLOCK_MULTI_REG_COUNT}",
    )
    log(format_state("sync", sync_state["block"], sync_state["burn"], sync_state["regs"], ctx.decimals, sync_state["n"], icon="🔎"))

    if half_life <= 0:
        raise AssertionError("BurnHalfLife must be > 0 for the same-block multi-registration scenario.")
    if sync_state["burn"] <= 0:
        raise AssertionError("Burn must be > 0 for the same-block multi-registration scenario.")

    batch_count = SAME_BLOCK_MULTI_REG_COUNT

    # Phase A: one coldkey submits a large Utility batch on a single subnet.
    funding_reference_burn = sat_mul_u64(
        sync_state["burn"],
        sat_pow_u64(max(1, increase_mult), batch_count),
    )
    ensure_balance_for_next_registration(
        substrate=substrate,
        funder=sudo,
        who=reg_cold,
        reference_burn_planck=funding_reference_burn,
        decimals=ctx.decimals,
        safety_mult=max(NEXT_REG_BALANCE_SAFETY_MULT, batch_count * max(2, increase_mult * 2)),
        buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
    )

    # Funding may submit Balances extrinsics in one or more blocks, so re-sync the
    # subnet state after funding and measure the same-cold batch entirely from that
    # post-funding reference point.
    same_cold_sync_rec = produce_one_block(substrate, reg_cold, f"same-block-batch-sync-{ctx.run_nonce}")
    same_cold_sync_state = read_net_state(substrate, ctx.netuid, same_cold_sync_rec.block_hash)

    hotkeys = [
        Keypair.create_from_uri(f"//Alice//DynBurnSameBlock//{ctx.netuid}//{ctx.run_nonce}//{i}").ss58_address
        for i in range(batch_count)
    ]
    same_cold_before_balance = account_free_at(substrate, reg_cold.ss58_address, same_cold_sync_state["hash"])

    batch_rec = batch_burned_registers_with_retry(
        substrate=substrate,
        cold=reg_cold,
        hot_ss58_list=hotkeys,
        netuid=ctx.netuid,
    )
    batch_state = read_net_state(substrate, ctx.netuid, batch_rec.block_hash)

    entry_burn_batch = simulate_from_block_state(
        start_burn=same_cold_sync_state["burn"],
        start_block=same_cold_sync_state["block"],
        end_block=batch_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={},
    )
    expected_batch_charges, expected_batch_final_burn = build_same_block_charge_sequence(
        entry_burn=entry_burn_batch,
        burn_increase_mult=increase_mult,
        reg_count=batch_count,
    )

    log(format_state("batch", batch_state["block"], batch_state["burn"], batch_state["regs"], ctx.decimals, batch_state["n"], icon="🧱"))
    log(
        f"🧮 Same-cold batch expected charge path: first={fmt_tao(expected_batch_charges[0], ctx.decimals)}, "
        f"last={fmt_tao(expected_batch_charges[-1], ctx.decimals)}, final burn={fmt_tao(expected_batch_final_burn, ctx.decimals)}"
    )

    if not receipt_was_recovered(batch_rec):
        assert_state(
            phase="same-cold same-block batch should match exact runtime logic",
            actual_burn=batch_state["burn"],
            expected_burn=expected_batch_final_burn,
            decimals=ctx.decimals,
        )
    else:
        log(
            f"⚠️  Same-cold batch recovered after transport failure; "
            f"skipping exact burn assertion at block {batch_state['block']}."
        )

    if batch_state["regs"] != batch_count and not receipt_was_recovered(batch_rec):
        raise AssertionError(
            "[assert] same-cold same-block batch should increment RegistrationsThisBlock by exactly the batch size\n"
            f"  actual regs_this_block = {batch_state['regs']}\n"
            f"  batch size             = {batch_count}\n"
        )

    if batch_state["n"] != same_cold_sync_state["n"] + batch_count:
        raise AssertionError(
            "[assert] same-cold same-block batch should increase SubnetworkN by exactly the batch size\n"
            f"  before     = {same_cold_sync_state['n']}\n"
            f"  after      = {batch_state['n']}\n"
            f"  batch size = {batch_count}\n"
        )

    if not receipt_was_recovered(batch_rec):
        same_cold_after_balance = account_free_at(substrate, reg_cold.ss58_address, batch_state["hash"])
        actual_same_cold_delta = same_cold_before_balance - same_cold_after_balance
        expected_same_cold_burn_delta = sum(expected_batch_charges)

        outer_batch_fee = transaction_fee_paid_for_receipt(substrate, batch_rec)
        fee_source = "TransactionPayment.TransactionFeePaid"
        if outer_batch_fee is None:
            # Fallback: the same-cold payer is the outer `utility.batch` sender, so any
            # residual above the exact burn-path sum is the batch submission fee.
            outer_batch_fee = max(0, actual_same_cold_delta - expected_same_cold_burn_delta)
            fee_source = "residual fallback"

        expected_same_cold_delta = expected_same_cold_burn_delta + outer_batch_fee
        log(
            f"💸 Same-cold outer batch fee: {fmt_tao(outer_batch_fee, ctx.decimals)} "
            f"({outer_batch_fee} planck, source={fee_source})"
        )

        if actual_same_cold_delta != expected_same_cold_delta:
            raise AssertionError(
                "[assert] same-cold same-block batch should charge the exact sum of the expected same-block price path plus the outer utility.batch fee\n"
                f"  actual delta         = {actual_same_cold_delta} ({fmt_tao(actual_same_cold_delta, ctx.decimals)})\n"
                f"  expected burn delta  = {expected_same_cold_burn_delta} ({fmt_tao(expected_same_cold_burn_delta, ctx.decimals)})\n"
                f"  outer batch fee      = {outer_batch_fee} ({fmt_tao(outer_batch_fee, ctx.decimals)})\n"
                f"  expected total delta = {expected_same_cold_delta} ({fmt_tao(expected_same_cold_delta, ctx.decimals)})\n"
            )

    seen_uids = set()
    for hot_ss58 in hotkeys:
        uid = hotkey_uid_at(substrate, ctx.netuid, hot_ss58, batch_state["hash"])
        if uid is None:
            raise AssertionError(
                "[assert] same-cold same-block batch hotkey should be registered on the subnet\n"
                f"  hotkey = {hot_ss58}\n"
            )
        seen_uids.add(int(uid))

    if len(seen_uids) != batch_count:
        raise AssertionError(
            "[assert] same-cold same-block batch hotkeys should map to distinct UIDs\n"
            f"  unique_uids = {sorted(seen_uids)}\n"
            f"  batch size  = {batch_count}\n"
        )

    batch_post_rec = produce_one_block(substrate, reg_cold, f"same-block-post-{ctx.run_nonce}")
    batch_post_state = read_net_state(substrate, ctx.netuid, batch_post_rec.block_hash)

    exp_burn_batch_post = simulate_from_block_state(
        start_burn=batch_state["burn"],
        start_block=batch_state["block"],
        end_block=batch_post_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={},
    )

    assert_state(
        phase="same-cold same-block post block should match decay-only runtime logic",
        actual_burn=batch_post_state["burn"],
        expected_burn=exp_burn_batch_post,
        decimals=ctx.decimals,
    )

    if batch_post_state["n"] != batch_state["n"]:
        raise AssertionError(
            "[assert] post-batch decay block should not change SubnetworkN after same-cold same-block batch\n"
            f"  before = {batch_state['n']}\n"
            f"  after  = {batch_post_state['n']}\n"
        )

    for hot_ss58 in hotkeys:
        if not hotkey_registered_on_network_at(substrate, ctx.netuid, hot_ss58, batch_post_state["hash"]):
            raise AssertionError(
                "[assert] same-cold same-block batch hotkey should remain registered after the post block\n"
                f"  hotkey = {hot_ss58}\n"
            )

    log(format_state("decay-a", batch_post_state["block"], batch_post_state["burn"], batch_post_state["regs"], ctx.decimals, batch_post_state["n"], icon="📉"))

    # Cool the subnet back down before the distinct-cold phase so that the
    # funding required for the exact per-registration assertions remains practical.
    cooldown_target_burn = max(sync_state["burn"], min_burn_at(substrate, ctx.netuid, batch_post_state["hash"]))
    cooldown_state = batch_post_state
    cooldown_blocks = 0
    if cooldown_state["burn"] > cooldown_target_burn:
        sudo_set_burn_half_life(substrate, sudo, ctx.netuid, 1)
        while cooldown_state["burn"] > cooldown_target_burn and cooldown_blocks < 64:
            cooldown_rec = produce_one_block(substrate, reg_cold, f"same-block-cooldown-{ctx.run_nonce}-{cooldown_blocks}")
            cooldown_state = read_net_state(substrate, ctx.netuid, cooldown_rec.block_hash)
            cooldown_blocks += 1

        sudo_set_burn_half_life(substrate, sudo, ctx.netuid, half_life)

        if cooldown_state["burn"] > cooldown_target_burn:
            raise AssertionError(
                "[assert] cooldown before distinct-cold same-block batch should reduce burn to a practical level\n"
                f"  target burn <= {fmt_tao(cooldown_target_burn, ctx.decimals)}\n"
                f"  actual burn   = {fmt_tao(cooldown_state['burn'], ctx.decimals)}\n"
                f"  cooldown blocks attempted = {cooldown_blocks}\n"
            )

        log(
            f"🧊 Cooldown before distinct-cold batch: {cooldown_blocks} block(s) | "
            f"target <= {fmt_tao(cooldown_target_burn, ctx.decimals)} | "
            f"current = {fmt_tao(cooldown_state['burn'], ctx.decimals)}"
        )
    else:
        log(
            f"🧊 Cooldown before distinct-cold batch not needed | "
            f"current = {fmt_tao(cooldown_state['burn'], ctx.decimals)}"
        )

    # Phase B: a second same-block burst, but each registration is charged to a distinct coldkey.
    diff_accounts: List[Tuple[Keypair, str]] = []
    for i in range(batch_count):
        cold = Keypair.create_from_uri(f"//Alice//DynBurnSameBlockDistinctCold//{ctx.netuid}//{ctx.run_nonce}//{i}")
        hot_ss58 = Keypair.create_from_uri(f"//Alice//DynBurnSameBlockDistinctHot//{ctx.netuid}//{ctx.run_nonce}//{i}").ss58_address
        diff_accounts.append((cold, hot_ss58))

    distinct_prep_rec = produce_one_block(substrate, reg_cold, f"same-block-distinct-prep-{ctx.run_nonce}")
    distinct_prep_state = read_net_state(substrate, ctx.netuid, distinct_prep_rec.block_hash)

    max_expected_distinct_charge = sat_mul_u64(
        distinct_prep_state["burn"],
        sat_pow_u64(max(1, increase_mult), max(0, batch_count - 1)),
    )
    for cold, _ in diff_accounts:
        ensure_balance_for_next_registration(
            substrate=substrate,
            funder=sudo,
            who=cold,
            reference_burn_planck=max_expected_distinct_charge,
            decimals=ctx.decimals,
            safety_mult=1,
            buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
        )

    distinct_sync_rec = produce_one_block(substrate, reg_cold, f"same-block-distinct-sync-{ctx.run_nonce}")
    distinct_sync_state = read_net_state(substrate, ctx.netuid, distinct_sync_rec.block_hash)
    distinct_before_balances = {
        cold.ss58_address: account_free_at(substrate, cold.ss58_address, distinct_sync_state["hash"])
        for cold, _ in diff_accounts
    }

    cold_hot_pairs = [(cold.ss58_address, hot_ss58) for cold, hot_ss58 in diff_accounts]
    distinct_rec = batch_sudo_as_burned_registers_with_retry(
        substrate=substrate,
        sudo=sudo,
        cold_hot_pairs=cold_hot_pairs,
        netuid=ctx.netuid,
    )
    distinct_state = read_net_state(substrate, ctx.netuid, distinct_rec.block_hash)

    distinct_entry_burn = simulate_from_block_state(
        start_burn=distinct_sync_state["burn"],
        start_block=distinct_sync_state["block"],
        end_block=distinct_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={},
    )
    expected_distinct_charges, expected_distinct_final_burn = build_same_block_charge_sequence(
        entry_burn=distinct_entry_burn,
        burn_increase_mult=increase_mult,
        reg_count=batch_count,
    )

    log(format_state("batch-b", distinct_state["block"], distinct_state["burn"], distinct_state["regs"], ctx.decimals, distinct_state["n"], icon="👥"))
    log(
        f"🧮 Distinct-cold batch expected charge path: first={fmt_tao(expected_distinct_charges[0], ctx.decimals)}, "
        f"last={fmt_tao(expected_distinct_charges[-1], ctx.decimals)}, final burn={fmt_tao(expected_distinct_final_burn, ctx.decimals)}"
    )

    if not receipt_was_recovered(distinct_rec):
        assert_state(
            phase="distinct-cold same-block batch should match exact runtime logic",
            actual_burn=distinct_state["burn"],
            expected_burn=expected_distinct_final_burn,
            decimals=ctx.decimals,
        )
    else:
        log(
            f"⚠️  Distinct-cold batch recovered after transport failure; "
            f"skipping exact burn assertion at block {distinct_state['block']}."
        )

    if distinct_state["regs"] != batch_count and not receipt_was_recovered(distinct_rec):
        raise AssertionError(
            "[assert] distinct-cold same-block batch should increment RegistrationsThisBlock by exactly the batch size\n"
            f"  actual regs_this_block = {distinct_state['regs']}\n"
            f"  batch size             = {batch_count}\n"
        )

    if distinct_state["n"] != distinct_sync_state["n"] + batch_count:
        raise AssertionError(
            "[assert] distinct-cold same-block batch should increase SubnetworkN by exactly the batch size\n"
            f"  before     = {distinct_sync_state['n']}\n"
            f"  after      = {distinct_state['n']}\n"
            f"  batch size = {batch_count}\n"
        )

    distinct_seen_uids = set()
    for idx, (cold, hot_ss58) in enumerate(diff_accounts):
        uid = hotkey_uid_at(substrate, ctx.netuid, hot_ss58, distinct_state["hash"])
        if uid is None:
            raise AssertionError(
                "[assert] distinct-cold same-block batch hotkey should be registered on the subnet\n"
                f"  hotkey = {hot_ss58}\n"
            )
        distinct_seen_uids.add(int(uid))

        before_free = distinct_before_balances[cold.ss58_address]
        after_free = account_free_at(substrate, cold.ss58_address, distinct_state["hash"])
        actual_delta = before_free - after_free
        expected_delta = expected_distinct_charges[idx]
        if actual_delta != expected_delta:
            raise AssertionError(
                "[assert] same-block price should increase by the exact expected amount for each distinct-cold registration\n"
                f"  registration idx = {idx}\n"
                f"  coldkey          = {cold.ss58_address}\n"
                f"  actual delta     = {actual_delta} ({fmt_tao(actual_delta, ctx.decimals)})\n"
                f"  expected delta   = {expected_delta} ({fmt_tao(expected_delta, ctx.decimals)})\n"
            )

    if len(distinct_seen_uids) != batch_count:
        raise AssertionError(
            "[assert] distinct-cold same-block batch hotkeys should map to distinct UIDs\n"
            f"  unique_uids = {sorted(distinct_seen_uids)}\n"
            f"  batch size  = {batch_count}\n"
        )

    distinct_post_rec = produce_one_block(substrate, reg_cold, f"same-block-distinct-post-{ctx.run_nonce}")
    distinct_post_state = read_net_state(substrate, ctx.netuid, distinct_post_rec.block_hash)

    exp_burn_distinct_post = simulate_from_block_state(
        start_burn=distinct_state["burn"],
        start_block=distinct_state["block"],
        end_block=distinct_post_state["block"],
        burn_half_life=half_life,
        burn_increase_mult=increase_mult,
        regs_this_block_map={},
    )

    assert_state(
        phase="distinct-cold same-block post block should match decay-only runtime logic",
        actual_burn=distinct_post_state["burn"],
        expected_burn=exp_burn_distinct_post,
        decimals=ctx.decimals,
    )

    if distinct_post_state["n"] != distinct_state["n"]:
        raise AssertionError(
            "[assert] post-batch decay block should not change SubnetworkN after distinct-cold same-block batch\n"
            f"  before = {distinct_state['n']}\n"
            f"  after  = {distinct_post_state['n']}\n"
        )

    for _, hot_ss58 in diff_accounts:
        if not hotkey_registered_on_network_at(substrate, ctx.netuid, hot_ss58, distinct_post_state["hash"]):
            raise AssertionError(
                "[assert] distinct-cold same-block batch hotkey should remain registered after the post block\n"
                f"  hotkey = {hot_ss58}\n"
            )

    log(format_state("decay-b", distinct_post_state["block"], distinct_post_state["burn"], distinct_post_state["regs"], ctx.decimals, distinct_post_state["n"], icon="📉"))
    log("✅ Same-block multi-registration scenario passed.")


# ─────────────────────────────────────────────────────────────
# Scenario: explicit burn config
# ─────────────────────────────────────────────────────────────
def run_one_config(ctx: NetworkContext, burn_half_life: int, burn_increase_mult: int, hotkey_tag: str):
    substrate, sudo, reg_cold, log = open_network(ctx)
    active_netuid = ctx.netuid

    def configure_and_sync(netuid: int, sync_suffix: str) -> Tuple[Dict[str, int], int, int, int, int]:
        sudo_set_burn_half_life(substrate, sudo, netuid, burn_half_life)
        sudo_set_burn_increase_mult(substrate, sudo, netuid, burn_increase_mult)

        sync_rec = produce_one_block(substrate, reg_cold, f"sync-{hotkey_tag}-{ctx.run_nonce}-{sync_suffix}")
        sync_hash = sync_rec.block_hash
        sync_state_local = read_net_state(substrate, netuid, sync_hash)
        min_burn_local = min_burn_at(substrate, netuid, sync_hash)
        max_burn_local = max_burn_at(substrate, netuid, sync_hash)
        hl_onchain_local = burn_half_life_at_strict(substrate, netuid, sync_hash)
        mult_onchain_local = burn_increase_mult_at_strict(substrate, netuid, sync_hash)
        return sync_state_local, min_burn_local, max_burn_local, hl_onchain_local, mult_onchain_local

    sync_state, min_burn, max_burn, hl_onchain, mult_onchain = configure_and_sync(active_netuid, "primary")

    # After earlier scenarios, burn can decay into dust. That makes burned_register
    # hit a reserve-floor corner unrelated to the burn update logic we want to test.
    # In that case, run this explicit burn-config scenario on a fresh scratch subnet.
    if min_burn > 0 and sync_state["burn"] < min_burn:
        log(
            f"⚠️  Current burn on subnet {active_netuid} is below MinBurn "
            f"({fmt_tao(sync_state['burn'], ctx.decimals)} < {fmt_tao(min_burn, ctx.decimals)}); "
            f"switching this burn-config stage to a fresh scratch subnet."
        )
        active_netuid = allocate_scratch_subnet_for_stage(
            substrate=substrate,
            sudo=sudo,
            decimals=ctx.decimals,
            seed_tag=f"cfg-{hotkey_tag}-{ctx.netuid}-{ctx.run_nonce}",
            log=log,
        )
        sync_state, min_burn, max_burn, hl_onchain, mult_onchain = configure_and_sync(active_netuid, "scratch")

    factor_q32 = decay_factor_q32(burn_half_life)
    factor_float = factor_q32 / float(ONE_Q32)

    scenario_banner(
        log,
        f"⚙️  Burn config | BurnHalfLife={burn_half_life} | BurnIncreaseMult={burn_increase_mult}",
        f"subnet = {active_netuid} | decay factor ≈ {factor_float:.12f} | "
        f"min burn = {fmt_tao(min_burn, ctx.decimals) if min_burn else 'n/a'} | "
        f"max burn = {fmt_tao(max_burn, ctx.decimals) if max_burn else 'n/a'}",
    )
    log(format_state("sync", sync_state["block"], sync_state["burn"], sync_state["regs"], ctx.decimals, sync_state["n"], icon="🔎"))

    if sync_state["burn"] <= 0:
        raise AssertionError("Burn is 0 at sync block; cannot test dynamic pricing.")

    if hl_onchain not in (0, burn_half_life):
        raise AssertionError(f"BurnHalfLife mismatch: expected {burn_half_life}, on-chain {hl_onchain}")
    if mult_onchain not in (0, burn_increase_mult):
        raise AssertionError(f"BurnIncreaseMult mismatch: expected {burn_increase_mult}, on-chain {mult_onchain}")

    ensure_balance_for_next_registration(
        substrate=substrate,
        funder=sudo,
        who=reg_cold,
        reference_burn_planck=sync_state["burn"],
        decimals=ctx.decimals,
        safety_mult=max(NEXT_REG_BALANCE_SAFETY_MULT, burn_increase_mult * 2),
        buffer_tao=NEXT_REG_BALANCE_BUFFER_TAO,
    )

    hot = Keypair.create_from_uri(f"//Alice//DynBurnHot{hotkey_tag}//Net{active_netuid}//Run{ctx.run_nonce}")
    reg_rec = burned_register_with_retry(substrate, reg_cold, hot.ss58_address, active_netuid)
    reg_state = read_net_state(substrate, active_netuid, reg_rec.block_hash)

    log(format_state("register", reg_state["block"], reg_state["burn"], reg_state["regs"], ctx.decimals, reg_state["n"], icon="📝"))

    if not receipt_was_recovered(reg_rec):
        exp_burn_reg = simulate_from_block_state(
            start_burn=sync_state["burn"],
            start_block=sync_state["block"],
            end_block=reg_state["block"],
            burn_half_life=burn_half_life,
            burn_increase_mult=burn_increase_mult,
            regs_this_block_map={reg_state["block"]: reg_state["regs"]},
        )

        assert_state(
            phase="burn at registration block should match exact immediate-bump runtime logic",
            actual_burn=reg_state["burn"],
            expected_burn=exp_burn_reg,
            decimals=ctx.decimals,
        )
    else:
        log(
            f"⚠️  Registration recovered after transport failure; "
            f"skipping exact burn assertion at block {reg_state['block']}."
        )

    if reg_state["regs"] < 1 and not receipt_was_recovered(reg_rec):
        raise AssertionError(
            f"[assert] expected at least one registration in block {reg_state['block']}, "
            f"but RegistrationsThisBlock={reg_state['regs']}"
        )

    after_rec = produce_one_block(substrate, reg_cold, f"after-{hotkey_tag}-{ctx.run_nonce}")
    after_state = read_net_state(substrate, active_netuid, after_rec.block_hash)

    log(format_state("post-decay", after_state["block"], after_state["burn"], after_state["regs"], ctx.decimals, after_state["n"], icon="📉"))

    exp_burn_after = simulate_from_block_state(
        start_burn=reg_state["burn"],
        start_block=reg_state["block"],
        end_block=after_state["block"],
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        regs_this_block_map={},
    )

    assert_state(
        phase="burn after registration should follow no-registration decay after the immediate bump",
        actual_burn=after_state["burn"],
        expected_burn=exp_burn_after,
        decimals=ctx.decimals,
    )

    sample_decay_for_n_blocks(
        substrate=substrate,
        block_signer=reg_cold,
        netuid=active_netuid,
        decimals=ctx.decimals,
        start_state=after_state,
        burn_half_life=burn_half_life,
        burn_increase_mult=burn_increase_mult,
        num_steps=burn_half_life,
        tag_prefix=f"decay-{hotkey_tag}-{ctx.run_nonce}",
        print_prefix="dc",
        log=log,
    )

    log(f"✅ Burn config passed for half_life={burn_half_life}, mult={burn_increase_mult}.")


# ─────────────────────────────────────────────────────────────
# Bootstrap / creation
# ─────────────────────────────────────────────────────────────
def bootstrap_network(ctx: NetworkContext):
    substrate, sudo, reg_cold, log = open_network(ctx)

    ensure_min_balance(substrate, sudo, reg_cold, MIN_FUNDS_TAO_REG_COLD, ctx.decimals)

    probe_rec = produce_one_block(substrate, reg_cold, f"probe-registration-allowed-{ctx.netuid}")
    probe_hash = probe_rec.block_hash
    if not registration_allowed_at(substrate, ctx.netuid, probe_hash):
        log("⚠️  Registration disabled; enabling via sudo.")
        sudo_set_registration_allowed(substrate, sudo, ctx.netuid, True)
        produce_one_block(substrate, reg_cold, f"probe-after-enable-{ctx.netuid}")

    log(f"🔌 Connected to {ctx.ws} | decimals={ctx.decimals} | payer={short_ss58(reg_cold.ss58_address)}")


def ensure_requested_netuids_exist(ws: str, requested_netuids: List[int], decimals: int):
    requested = sorted(set(n for n in requested_netuids if n != 0))
    if not requested:
        return

    substrate = connect(ws)
    sudo = Keypair.create_from_uri("//Alice")

    try:
        sudo_set_network_rate_limit(substrate, sudo, 0)
    except Exception:
        pass

    existing = {n for n in networks_added(substrate) if n != 0}
    missing = [n for n in requested if n not in existing]
    if not missing:
        safe_print(f"🧩 Requested subnets already exist: {requested}")
        return

    safe_print(f"🧩 Missing requested subnets detected: {missing}")
    try:
        desired_limit = max(max(requested) + 4, len(existing) + len(missing) + 4)
        sudo_set_subnet_limit(substrate, sudo, desired_limit)
        safe_print(f"📈 Raised subnet limit to at least {desired_limit} (best effort).")
    except Exception as e:
        safe_print(f"ℹ️ Could not adjust subnet limit automatically: {e}")

    attempts = 0
    max_attempts = max(requested) + len(requested) + 10

    while True:
        existing = {n for n in networks_added(substrate) if n != 0}
        missing = [n for n in requested if n not in existing]
        if not missing:
            safe_print(f"✅ Requested subnets now exist: {requested}")
            return

        if attempts >= max_attempts:
            raise RuntimeError(
                f"Unable to create requested netuids after {attempts} attempt(s). "
                f"existing={sorted(existing)} missing={missing}"
            )

        target = missing[0]
        owner_cold = Keypair.create_from_uri(f"//Alice//SubnetOwnerCold//Net{target}")
        owner_hot = Keypair.create_from_uri(f"//Alice//SubnetOwnerHot//Net{target}")

        ensure_min_balance(substrate, sudo, owner_cold, REGISTER_NETWORK_MIN_OWNER_COLD_TAO, decimals)
        ensure_min_balance(substrate, sudo, owner_hot, REGISTER_NETWORK_MIN_OWNER_HOT_TAO, decimals)

        before = {n for n in networks_added(substrate) if n != 0}
        register_network_with_retry(
            substrate=substrate,
            signer=owner_cold,
            owner_hot_ss58=owner_hot.ss58_address,
            owner_cold_ss58=owner_cold.ss58_address,
        )
        after = {n for n in networks_added(substrate) if n != 0}
        created = sorted(after - before)

        attempts += 1
        if not created:
            raise RuntimeError(
                f"register_network did not create a visible subnet while targeting missing={missing}"
            )

        safe_print(
            f"🧱 Created subnet(s) {created} "
            f"using owner {short_ss58(owner_cold.ss58_address)} "
            f"while targeting missing {missing}"
        )


# ─────────────────────────────────────────────────────────────
# Stage runner
# ─────────────────────────────────────────────────────────────
def run_stage_across_networks(
    stage_title: str,
    contexts: List[NetworkContext],
    workers: int,
    stage_fn: Callable[[NetworkContext], Any],
    retryable_stage: bool = False,
):
    netuids = [ctx.netuid for ctx in contexts]
    safe_print(f"\n🚦 Stage: {stage_title} | nets={netuids} | workers={workers}")

    failures: List[Tuple[int, str, str]] = []

    def _run_once(ctx: NetworkContext):
        return stage_fn(ctx)

    def _run_with_retries(ctx: NetworkContext):
        if not retryable_stage:
            return _run_once(ctx)

        netlog = make_logger(ctx.netuid)
        last_exc: Optional[Exception] = None

        for attempt in range(STAGE_RETRY_ATTEMPTS):
            attempt_ctx = ctx if attempt == 0 else replace(
                ctx,
                run_nonce=ctx.run_nonce + attempt * 10_000_000,
            )

            if attempt > 0:
                netlog(
                    f"🔁 Retrying stage '{stage_title}' "
                    f"(attempt {attempt + 1}/{STAGE_RETRY_ATTEMPTS})"
                )

            try:
                return _run_once(attempt_ctx)
            except Exception as e:
                last_exc = e
                if attempt + 1 < STAGE_RETRY_ATTEMPTS and is_retryable_transport_error(e):
                    netlog(f"⚠️  Transient issue detected: {simplify_error_message(e)}")
                    time.sleep(0.75 * (attempt + 1))
                    continue
                raise

        assert last_exc is not None
        raise last_exc

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(_run_with_retries, ctx): ctx.netuid for ctx in contexts}

        for fut in as_completed(future_map):
            netuid = future_map[fut]
            try:
                fut.result()
            except Exception as e:
                tb = traceback.format_exc()
                safe_print(f"❌ Stage '{stage_title}' failed on net {netuid}: {e}")
                safe_print(tb)
                failures.append((netuid, str(e), tb))

    if failures:
        raise RuntimeError(
            f"Stage '{stage_title}' failed on {len(failures)} network(s): "
            + ", ".join(str(netuid) for netuid, _, _ in failures)
        )

    safe_print(f"✅ Stage complete: {stage_title}")


# ─────────────────────────────────────────────────────────────
# Network selection
# ─────────────────────────────────────────────────────────────
def parse_netuids_arg(value: Optional[str]) -> List[int]:
    if not value:
        return []
    out: List[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out


def resolve_existing_netuids(substrate: SubstrateInterface, limit_networks: Optional[int]) -> List[int]:
    nets = [n for n in networks_added(substrate) if n != 0]
    nets = sorted(set(nets))
    if limit_networks is not None:
        nets = nets[: max(0, int(limit_networks))]
    if not nets:
        raise RuntimeError("Could not resolve any non-root netuids to test.")
    return nets


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ws", default=DEFAULT_WS, help=f"WS endpoint (default: {DEFAULT_WS})")
    parser.add_argument("--netuid", type=int, default=None, help="Single netuid to test")
    parser.add_argument("--netuids", default=None, help="Comma-separated list of netuids to test concurrently")
    parser.add_argument("--limit-networks", type=int, default=None, help="Cap the number of auto-discovered non-root networks")
    parser.add_argument("--workers", type=int, default=None, help="Number of concurrent worker threads")
    parser.add_argument("--with-default-stress", action="store_true", help="Run the heavy default-parameter stress scenario before the other tests")
    args = parser.parse_args()

    base = connect(args.ws)
    decimals = token_decimals(base)
    sudo = Keypair.create_from_uri("//Alice")

    try:
        sudo_set_network_rate_limit(base, sudo, 0)
    except Exception:
        pass

    if args.netuid is not None and args.netuids:
        raise RuntimeError("Use either --netuid or --netuids, not both.")

    explicit_request = (args.netuid is not None) or (args.netuids is not None)

    if args.netuid is not None:
        requested_netuids = [int(args.netuid)]
    elif args.netuids is not None:
        requested_netuids = parse_netuids_arg(args.netuids)
    else:
        requested_netuids = []

    if explicit_request:
        ensure_requested_netuids_exist(args.ws, requested_netuids, decimals)
        netuids = sorted(set(n for n in requested_netuids if n != 0))
    else:
        netuids = resolve_existing_netuids(base, args.limit_networks)

    # Default worker policy:
    # - explicit --workers => honor it
    # - explicit multi-netuid request => fan out across those netuids by default
    # - otherwise => serial by default
    if args.workers is not None:
        workers = max(1, int(args.workers))
        worker_msg = f"ℹ️  Using explicit workers={workers}."
    else:
        if args.netuids is not None and len(netuids) > 1:
            workers = max(1, min(4, len(netuids)))
            worker_msg = (
                f"ℹ️  Defaulting to workers={workers} because multiple netuids were explicitly requested. "
                f"Pass --workers 1 for serial execution."
            )
        else:
            workers = 1
            worker_msg = "ℹ️  Defaulting to workers=1. Pass --workers N to enable concurrent stage execution."

    contexts = [
        NetworkContext(
            ws=args.ws,
            netuid=netuid,
            decimals=decimals,
            run_nonce=int(time.time() * 1000) + (netuid * 1_000_000),
            payer_uri=f"//Alice//DynBurnCold//Net{netuid}",
        )
        for netuid in netuids
    ]

    safe_print(f"🌐 Connected to {args.ws} | decimals={decimals}")
    safe_print(
        f"🧪 Testing netuids={netuids} | workers={workers} | "
        f"default_stress={'on' if args.with_default_stress else 'off'}"
    )
    safe_print(worker_msg)
    if len(netuids) == 1:
        safe_print("ℹ️  Only one non-root subnet selected. Use --netuids a,b,c to fan out across multiple subnets explicitly.")

    run_stage_across_networks(
        stage_title="bootstrap",
        contexts=contexts,
        workers=workers,
        stage_fn=bootstrap_network,
        retryable_stage=True,
    )

    if args.with_default_stress:
        run_stage_across_networks(
            stage_title="default stress",
            contexts=contexts,
            workers=workers,
            stage_fn=run_many_registrations_default_params,
            retryable_stage=False,
        )
    else:
        safe_print("⏭️  Skipping default stress stage (enable with --with-default-stress).")

    run_stage_across_networks(
        stage_title="limit-price scenario",
        contexts=contexts,
        workers=workers,
        stage_fn=run_register_limit_scenario,
        retryable_stage=False,
    )

    run_stage_across_networks(
        stage_title="same-block multi-registration scenario",
        contexts=contexts,
        workers=workers,
        stage_fn=run_same_block_multi_registration_scenario,
        retryable_stage=False,
    )

    for idx, (hl, mult) in enumerate(TEST_CONFIGS, start=1):
        hotkey_tag = f"C{idx}H{hl}M{mult}"
        run_stage_across_networks(
            stage_title=f"burn config hl={hl}, mult={mult}",
            contexts=contexts,
            workers=workers,
            stage_fn=lambda ctx, _hl=hl, _mult=mult, _tag=hotkey_tag: run_one_config(ctx, _hl, _mult, _tag),
            retryable_stage=False,
        )

    safe_print("\n🎉 All dynamic burn pricing assertions passed across all requested networks.\n")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as ae:
        print(f"\nAssertion failed:\n{ae}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"\nError:\n{e}", file=sys.stderr)
        sys.exit(1)