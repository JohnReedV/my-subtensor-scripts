#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mainnet-state local-clone integration test for SubnetEmissionEnabled.

This script is meant to run against a local node started from:

    node-subtensor build-patched-spec --chain finney ...

It does NOT mutate live mainnet. It mutates the local clone only.

What this verifies:
  1) The local node has mainnet-cloned emission storage.
  2) The PR runtime contains AdminUtils.sudo_set_subnet_emission_enabled.
  3) A real existing mainnet-state subnet can be toggled off through the owner path.
     The script uses Sudo.sudo_as(real_subnet_owner, AdminUtils.sudo_set_subnet_emission_enabled(...))
     so the inner call receives a signed owner origin, without needing the real owner key.
  4) Disabled target subnet gets zero:
        SubnetTaoInEmission
        SubnetAlphaInEmission
        SubnetExcessTao
  5) Disabled target subnet preserves alpha_out when it had alpha_out before.
  6) Aggregate TAO-side pool emission is preserved:
        sum(SubnetTaoInEmission + SubnetExcessTao) before disable
        ~= same sum after disable
  7) If the target had nonzero baseline pool emission, other subnets receive more
     TAO-side emission after the target is disabled.
  8) The original target toggle state is restored at the end.

Default behavior:
  - Auto-selects the enabled non-root subnet with the largest current pool-side
    TAO emission from mainnet-cloned state.
  - Pass --netuid N to force a specific subnet.
"""

from __future__ import annotations

import argparse
import ast
import signal
import sys
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException


DEFAULT_WS = "ws://127.0.0.1:9945"

PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"
PALLET_SUDO = "Sudo"
PALLET_SYSTEM = "System"
PALLET_UTILITY = "Utility"

ROOT_NETUID = 0

QUERY_RETRIES = 4
QUERY_BACKOFF_SEC = 0.20
SUBMIT_RETRIES = 4
SUBMIT_BACKOFF_SEC = 0.30

DEFAULT_WAIT_BLOCKS = 2
DEFAULT_MAP_QUERY_TIMEOUT_SEC = 45.0
DEFAULT_STORAGE_WAIT_SEC = 20.0
DEFAULT_RELATIVE_TOLERANCE_PCT = 2.0
DEFAULT_ABSOLUTE_TOLERANCE_TAO = 0.01

CUSTOM_TYPE_REGISTRY = {
    "types": {
        "U64F64": "u128",
        "substrate_fixed::types::U64F64": "u128",
        "FixedU128<U64>": "u128",
    }
}


class TestFailure(AssertionError):
    pass


class ScriptTimeout(RuntimeError):
    pass


class Snapshot:
    def __init__(
        self,
        label: str,
        block_hash: str,
        block_number: int,
        target_netuid: int,
        target_row: Dict[str, Any],
        aggregate_tao_in: int,
        aggregate_excess_tao: int,
    ):
        self.label = label
        self.block_hash = block_hash
        self.block_number = int(block_number)
        self.target_netuid = int(target_netuid)
        self.target_row = target_row
        self.aggregate_tao_in = int(aggregate_tao_in)
        self.aggregate_excess_tao = int(aggregate_excess_tao)

    @property
    def total_pool_tao(self) -> int:
        return self.aggregate_tao_in + self.aggregate_excess_tao

    @property
    def target_pool_tao(self) -> int:
        return int(self.target_row["tao_in"]) + int(self.target_row["excess_tao"])

    @property
    def other_pool_tao(self) -> int:
        return self.total_pool_tao - self.target_pool_tao


def log(msg: str) -> None:
    print(msg, flush=True)


def banner(title: str) -> None:
    line = "━" * 92
    log(f"\n{line}\n{title}\n{line}")


def simplify_error_message(raw: Any) -> str:
    if raw is None:
        return ""

    if isinstance(raw, (list, tuple)):
        return " | ".join(
            part for part in (simplify_error_message(item) for item in raw) if part
        )

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
    return any(
        marker in text
        for marker in (
            "broken pipe",
            "connection reset",
            "connection aborted",
            "connection closed",
            "websocketconnectionclosed",
            "websocket is not connected",
            "socket is already closed",
            "cannot write to closing transport",
            "closing transport",
            "remote host closed",
            "connection lost",
            "timed out",
            "timeout",
            "read timed out",
            'decoder class for "compact<u32>" not found',
            'decoder class for "compact<u64>" not found',
            'decoder class for "compact<u128>" not found',
        )
    )


def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise TestFailure(msg)


def assert_eq(actual: Any, expected: Any, msg: str) -> None:
    if actual != expected:
        raise TestFailure(f"{msg}\n  actual   = {actual}\n  expected = {expected}")


def assert_close(actual: int, expected: int, tolerance: int, msg: str) -> None:
    actual_i = int(actual)
    expected_i = int(expected)
    tolerance_i = int(tolerance)
    diff = abs(actual_i - expected_i)

    if diff > tolerance_i:
        raise TestFailure(
            f"{msg}\n"
            f"  actual    = {actual_i}\n"
            f"  expected  = {expected_i}\n"
            f"  diff      = {diff}\n"
            f"  tolerance = {tolerance_i}"
        )


@contextmanager
def unix_timeout(seconds: float, label: str):
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handler(_signum, _frame):
        raise ScriptTimeout(f"{label} timed out after {seconds:.1f}s")

    old_handler = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, _handler)
        signal.setitimer(signal.ITIMER_REAL, float(seconds))
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def short_ss58(ss58: str) -> str:
    return f"{ss58[:7]}…{ss58[-6:]}" if len(ss58) > 18 else ss58


def connect(ws: str) -> SubstrateInterface:
    last: Optional[Exception] = None

    for attempt in range(1, QUERY_RETRIES + 1):
        try:
            substrate = SubstrateInterface(
                url=ws,
                auto_reconnect=True,
                type_registry=CUSTOM_TYPE_REGISTRY,
            )
            substrate.init_runtime()
            return substrate
        except Exception as exc:
            last = exc
            if attempt >= QUERY_RETRIES or not is_retryable_transport_error(exc):
                raise
            time.sleep(QUERY_BACKOFF_SEC * attempt)

    assert last is not None
    raise last


def reconnect(substrate: SubstrateInterface) -> None:
    try:
        substrate.close()
    except Exception:
        pass
    substrate.connect_websocket()
    substrate.init_runtime()


def with_retries(
    substrate: SubstrateInterface,
    fn: Callable[[], Any],
    attempts: int = QUERY_RETRIES,
) -> Any:
    last: Optional[Exception] = None

    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:
            last = exc
            if attempt >= attempts or not is_retryable_transport_error(exc):
                raise

            try:
                reconnect(substrate)
            except Exception:
                pass

            time.sleep(QUERY_BACKOFF_SEC * attempt)

    assert last is not None
    raise last


def token_decimals(substrate: SubstrateInterface) -> int:
    decimals = substrate.token_decimals
    if isinstance(decimals, list) and decimals and isinstance(decimals[0], int):
        return decimals[0]
    if isinstance(decimals, int):
        return decimals
    return 9


def to_planck(tao: float, decimals: int) -> int:
    return int(round(float(tao) * (10**decimals)))


def fmt_planck(planck: int, decimals: int) -> str:
    return f"{int(planck) / float(10**decimals):.9f} TAO"


def as_int(value: Any) -> int:
    value = getattr(value, "value", value)

    if value is None:
        return 0

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        s = value.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)

    if isinstance(value, dict):
        for key in ("value", "bits", "index", "raw", "netuid", "NetUid"):
            if key in value:
                return as_int(value[key])
        if value:
            return as_int(next(iter(value.values())))
        return 0

    if isinstance(value, (list, tuple)) and value:
        return as_int(value[0])

    return int(value)


def as_bool(value: Any) -> bool:
    value = getattr(value, "value", value)

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")

    return bool(as_int(value))


def as_ss58(value: Any) -> Optional[str]:
    value = getattr(value, "value", value)

    if value is None:
        return None

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.startswith("0x0000000000000000000000000000000000000000000000000000000000000000"):
            return None
        return s

    if isinstance(value, dict):
        for key in ("value", "account", "account_id", "id", "Id", "address"):
            if key in value:
                nested = as_ss58(value[key])
                if nested:
                    return nested

        for nested in value.values():
            nested_ss58 = as_ss58(nested)
            if nested_ss58:
                return nested_ss58

    if isinstance(value, (list, tuple)):
        for item in value:
            nested_ss58 = as_ss58(item)
            if nested_ss58:
                return nested_ss58

    text = str(value).strip()
    return text or None


def map_key_to_netuid(key: Any) -> int:
    key_value = getattr(key, "value", key)

    if isinstance(key_value, int):
        return int(key_value)

    if isinstance(key_value, str):
        return as_int(key_value)

    if isinstance(key_value, dict):
        for candidate in ("netuid", "NetUid", "value", "id", "Id", "key"):
            if candidate in key_value:
                return as_int(key_value[candidate])
        if len(key_value) == 1:
            return as_int(next(iter(key_value.values())))
        return as_int(key_value)

    if isinstance(key_value, (list, tuple)):
        if not key_value:
            return 0
        return as_int(key_value[0])

    return as_int(key_value)


def query(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
) -> Any:
    return with_retries(
        substrate,
        lambda: substrate.query(module, storage, params or [], block_hash=block_hash),
    )


def query_value(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
) -> Any:
    result = query(substrate, module, storage, params, block_hash)
    return getattr(result, "value", result)


def q_int(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
    default: Optional[int] = None,
) -> int:
    try:
        value = query_value(substrate, module, storage, params, block_hash)
    except Exception:
        if default is not None:
            return default
        raise

    if value is None:
        if default is not None:
            return default
        raise RuntimeError(f"{module}.{storage}{params or []} returned None")

    return as_int(value)


def q_bool(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
    default: Optional[bool] = None,
) -> bool:
    try:
        value = query_value(substrate, module, storage, params, block_hash)
    except Exception:
        if default is not None:
            return default
        raise

    if value is None:
        if default is not None:
            return default
        raise RuntimeError(f"{module}.{storage}{params or []} returned None")

    return as_bool(value)


def q_ss58(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
    required: bool = False,
) -> Optional[str]:
    try:
        value = query_value(substrate, module, storage, params, block_hash)
    except Exception:
        if required:
            raise
        return None

    ss58 = as_ss58(value)
    if required and not ss58:
        raise RuntimeError(f"{module}.{storage}{params or []} returned no address")
    return ss58


def query_map_values(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    timeout_sec: float,
) -> Dict[int, int]:
    log(f"Reading map {module}.{storage} ...")

    with unix_timeout(timeout_sec, f"{module}.{storage} query_map"):
        entries = with_retries(
            substrate,
            lambda: list(substrate.query_map(module, storage)),
            attempts=1,
        )

    out: Dict[int, int] = {}
    for key, value in entries:
        try:
            netuid = map_key_to_netuid(key)
            amount = as_int(getattr(value, "value", value))
            out[int(netuid)] = int(amount)
        except Exception as exc:
            log(f"Skipping unparseable {storage} entry: key={key!r} value={value!r} error={exc}")

    log(f"Read {len(out)} entries from {module}.{storage}")
    return out


def compose_call(
    substrate: SubstrateInterface,
    module: str,
    function: str,
    params: Dict[str, Any],
) -> Any:
    return with_retries(
        substrate,
        lambda: substrate.compose_call(
            call_module=module,
            call_function=function,
            call_params=params,
        ),
    )


def compose_first(
    substrate: SubstrateInterface,
    candidates: Sequence[Tuple[str, str, Dict[str, Any]]],
) -> Tuple[Any, str]:
    errors: List[str] = []

    for module, function, params in candidates:
        try:
            return compose_call(substrate, module, function, params), f"{module}.{function}"
        except Exception as exc:
            errors.append(f"{module}.{function}({params}): {simplify_error_message(exc)}")

    raise RuntimeError("could not compose any candidate call:\n  - " + "\n  - ".join(errors))


def create_signed(substrate: SubstrateInterface, signer: Keypair, call: Any) -> Any:
    return with_retries(
        substrate,
        lambda: substrate.create_signed_extrinsic(call=call, keypair=signer),
        attempts=SUBMIT_RETRIES,
    )


def submit(
    substrate: SubstrateInterface,
    signer: Keypair,
    call: Any,
    allow_failed: bool = False,
) -> Any:
    xt = create_signed(substrate, signer, call)
    last: Optional[Exception] = None

    for attempt in range(1, SUBMIT_RETRIES + 1):
        try:
            rec = with_retries(
                substrate,
                lambda: substrate.submit_extrinsic(
                    xt,
                    wait_for_inclusion=True,
                    wait_for_finalization=False,
                ),
                attempts=1,
            )

            if not allow_failed and not rec.is_success:
                raise RuntimeError(f"Extrinsic failed in block {rec.block_hash}: {rec.error_message}")

            return rec

        except SubstrateRequestException as exc:
            last = exc
            if attempt >= SUBMIT_RETRIES or not is_retryable_transport_error(exc):
                raise RuntimeError(f"Extrinsic submission failed: {simplify_error_message(exc)}") from exc
            try:
                reconnect(substrate)
            except Exception:
                pass
            time.sleep(SUBMIT_BACKOFF_SEC * attempt)

        except Exception as exc:
            last = exc
            if attempt >= SUBMIT_RETRIES or not is_retryable_transport_error(exc):
                raise
            try:
                reconnect(substrate)
            except Exception:
                pass
            time.sleep(SUBMIT_BACKOFF_SEC * attempt)

    assert last is not None
    raise last


def sudo_call(substrate: SubstrateInterface, inner: Any) -> Any:
    return compose_call(substrate, PALLET_SUDO, "sudo", {"call": inner})


def sudo_as_call(substrate: SubstrateInterface, who: str, inner: Any) -> Any:
    return compose_call(substrate, PALLET_SUDO, "sudo_as", {"who": who, "call": inner})


def submit_sudo(substrate: SubstrateInterface, sudo: Keypair, inner: Any, allow_failed: bool = False) -> Any:
    return submit(substrate, sudo, sudo_call(substrate, inner), allow_failed=allow_failed)


def head_hash(substrate: SubstrateInterface) -> str:
    return with_retries(substrate, lambda: substrate.get_chain_head())


def block_number_at(substrate: SubstrateInterface, block_hash: str) -> int:
    return q_int(substrate, PALLET_SYSTEM, "Number", [], block_hash=block_hash)


def current_block(substrate: SubstrateInterface) -> int:
    return block_number_at(substrate, head_hash(substrate))


def produce_one_block(substrate: SubstrateInterface, signer: Keypair, tag: str) -> Any:
    call = compose_call(substrate, PALLET_SYSTEM, "remark", {"remark": bytes(tag, "utf-8")})
    return submit(substrate, signer, call)


def produce_blocks(substrate: SubstrateInterface, signer: Keypair, count: int, tag: str) -> None:
    for idx in range(max(1, int(count))):
        rec = produce_one_block(substrate, signer, f"{tag}-{idx}-{int(time.time() * 1000)}")
        log(f"Produced block {block_number_at(substrate, rec.block_hash)} for {tag}")
        time.sleep(0.03)


def best_effort_sudo(
    substrate: SubstrateInterface,
    sudo: Keypair,
    candidates: Sequence[Tuple[str, str, Dict[str, Any]]],
) -> bool:
    for module, function, params in candidates:
        try:
            inner = compose_call(substrate, module, function, params)
            rec = submit_sudo(substrate, sudo, inner, allow_failed=True)
            if rec.is_success:
                log(f"Best-effort sudo applied: {module}.{function}({params})")
                return True
            log(f"Best-effort sudo failed: {module}.{function}: {rec.error_message}")
        except Exception as exc:
            log(f"Best-effort sudo skipped {module}.{function}: {simplify_error_message(exc)}")

    return False


def disable_local_limits(substrate: SubstrateInterface, sudo: Keypair) -> None:
    best_effort_sudo(
        substrate,
        sudo,
        [
            (PALLET_ADMIN, "sudo_set_network_rate_limit", {"rate_limit": 0}),
            (PALLET_SUBTENSOR, "sudo_set_network_rate_limit", {"rate_limit": 0}),
        ],
    )

    best_effort_sudo(
        substrate,
        sudo,
        [
            (PALLET_ADMIN, "sudo_set_owner_hparam_rate_limit", {"epochs": 0}),
            (PALLET_ADMIN, "sudo_set_owner_hparam_rate_limit", {"owner_hparam_rate_limit": 0}),
            (PALLET_SUBTENSOR, "sudo_set_owner_hparam_rate_limit", {"epochs": 0}),
            (PALLET_SUBTENSOR, "sudo_set_owner_hparam_rate_limit", {"owner_hparam_rate_limit": 0}),
        ],
    )

    best_effort_sudo(
        substrate,
        sudo,
        [
            (PALLET_ADMIN, "sudo_set_admin_freeze_window", {"window": 0}),
            (PALLET_ADMIN, "sudo_set_admin_freeze_window", {"freeze_window": 0}),
            (PALLET_ADMIN, "sudo_set_admin_freeze_window", {"admin_freeze_window": 0}),
        ],
    )


def subnet_emission_enabled(substrate: SubstrateInterface, netuid: int) -> bool:
    return q_bool(substrate, PALLET_SUBTENSOR, "SubnetEmissionEnabled", [int(netuid)], default=True)


def subnet_owner(substrate: SubstrateInterface, netuid: int) -> Optional[str]:
    return q_ss58(substrate, PALLET_SUBTENSOR, "SubnetOwner", [int(netuid)], required=False)


def read_row(substrate: SubstrateInterface, netuid: int) -> Dict[str, Any]:
    return {
        "netuid": int(netuid),
        "owner": subnet_owner(substrate, netuid),
        "enabled": subnet_emission_enabled(substrate, netuid),
        "tao_in": q_int(substrate, PALLET_SUBTENSOR, "SubnetTaoInEmission", [int(netuid)], default=0),
        "alpha_in": q_int(substrate, PALLET_SUBTENSOR, "SubnetAlphaInEmission", [int(netuid)], default=0),
        "excess_tao": q_int(substrate, PALLET_SUBTENSOR, "SubnetExcessTao", [int(netuid)], default=0),
        "alpha_out": q_int(substrate, PALLET_SUBTENSOR, "SubnetAlphaOutEmission", [int(netuid)], default=0),
    }


def read_all_emission_maps(substrate: SubstrateInterface, timeout_sec: float) -> Dict[str, Dict[int, int]]:
    return {
        "tao_in": query_map_values(substrate, PALLET_SUBTENSOR, "SubnetTaoInEmission", timeout_sec),
        "excess_tao": query_map_values(substrate, PALLET_SUBTENSOR, "SubnetExcessTao", timeout_sec),
        "alpha_in": query_map_values(substrate, PALLET_SUBTENSOR, "SubnetAlphaInEmission", timeout_sec),
        "alpha_out": query_map_values(substrate, PALLET_SUBTENSOR, "SubnetAlphaOutEmission", timeout_sec),
    }


def aggregate_pool_tao(maps: Dict[str, Dict[int, int]]) -> int:
    return sum(maps["tao_in"].values()) + sum(maps["excess_tao"].values())


def candidate_pool(maps: Dict[str, Dict[int, int]], netuid: int) -> int:
    return int(maps["tao_in"].get(netuid, 0)) + int(maps["excess_tao"].get(netuid, 0))


def select_target_netuid(substrate: SubstrateInterface, maps: Dict[str, Dict[int, int]]) -> int:
    candidates: List[Tuple[int, int]] = []

    for netuid in sorted(set(maps["tao_in"]) | set(maps["excess_tao"]) | set(maps["alpha_out"])):
        if netuid == ROOT_NETUID:
            continue

        pool = candidate_pool(maps, netuid)
        alpha_out = int(maps["alpha_out"].get(netuid, 0))

        if pool <= 0:
            continue
        if alpha_out <= 0:
            continue
        if not subnet_emission_enabled(substrate, netuid):
            continue
        if not subnet_owner(substrate, netuid):
            continue

        candidates.append((pool, netuid))

    assert_true(
        bool(candidates),
        "No enabled non-root subnet with positive pool emission, alpha_out, and owner was found in cloned mainnet state.",
    )

    candidates.sort(reverse=True)
    pool, netuid = candidates[0]
    log(f"Auto-selected netuid {netuid} with baseline pool_tao={pool}")
    return netuid


def take_snapshot(
    substrate: SubstrateInterface,
    label: str,
    target_netuid: int,
    map_query_timeout_sec: float,
) -> Snapshot:
    log(f"Taking snapshot: {label}")

    h = head_hash(substrate)
    b = block_number_at(substrate, h)
    maps = read_all_emission_maps(substrate, map_query_timeout_sec)
    row = read_row(substrate, target_netuid)

    # Keep the aggregate from the maps so aggregate and candidate selection use the same data shape.
    aggregate_tao_in = sum(maps["tao_in"].values())
    aggregate_excess_tao = sum(maps["excess_tao"].values())

    return Snapshot(
        label=label,
        block_hash=h,
        block_number=b,
        target_netuid=target_netuid,
        target_row=row,
        aggregate_tao_in=aggregate_tao_in,
        aggregate_excess_tao=aggregate_excess_tao,
    )


def print_snapshot(snapshot: Snapshot, decimals: int) -> None:
    row = snapshot.target_row

    log(
        f"\nSnapshot {snapshot.label} | block={snapshot.block_number}\n"
        f"  aggregate_tao_in      = {snapshot.aggregate_tao_in} ({fmt_planck(snapshot.aggregate_tao_in, decimals)})\n"
        f"  aggregate_excess_tao  = {snapshot.aggregate_excess_tao} ({fmt_planck(snapshot.aggregate_excess_tao, decimals)})\n"
        f"  aggregate_pool_tao    = {snapshot.total_pool_tao} ({fmt_planck(snapshot.total_pool_tao, decimals)})\n"
        f"  target_netuid         = {snapshot.target_netuid}\n"
        f"  target_owner          = {row['owner']}\n"
        f"  target_enabled        = {row['enabled']}\n"
        f"  target_tao_in         = {row['tao_in']} ({fmt_planck(row['tao_in'], decimals)})\n"
        f"  target_excess_tao     = {row['excess_tao']} ({fmt_planck(row['excess_tao'], decimals)})\n"
        f"  target_pool_tao       = {snapshot.target_pool_tao} ({fmt_planck(snapshot.target_pool_tao, decimals)})\n"
        f"  target_alpha_in       = {row['alpha_in']}\n"
        f"  target_alpha_out      = {row['alpha_out']}"
    )


def compose_set_subnet_emission_enabled(substrate: SubstrateInterface, netuid: int, enabled: bool) -> Any:
    return compose_call(
        substrate,
        PALLET_ADMIN,
        "sudo_set_subnet_emission_enabled",
        {"netuid": int(netuid), "enabled": bool(enabled)},
    )


def set_subnet_emission_enabled_as_owner(
    substrate: SubstrateInterface,
    sudo: Keypair,
    owner_ss58: str,
    netuid: int,
    enabled: bool,
) -> None:
    inner = compose_set_subnet_emission_enabled(substrate, netuid, enabled)
    call = sudo_as_call(substrate, owner_ss58, inner)

    rec = submit(substrate, sudo, call, allow_failed=False)
    log(
        f"Sudo.sudo_as({short_ss58(owner_ss58)}, AdminUtils.sudo_set_subnet_emission_enabled("
        f"netuid={netuid}, enabled={enabled})) included in block {block_number_at(substrate, rec.block_hash)}"
    )

    actual = subnet_emission_enabled(substrate, netuid)
    assert_eq(actual, enabled, f"SubnetEmissionEnabled storage mismatch after setting netuid {netuid}")


def absolute_and_relative_tolerance(expected: int, decimals: int, relative_pct: float, absolute_tao: float) -> int:
    rel = int(abs(int(expected)) * max(0.0, float(relative_pct)) / 100.0)
    abs_planck = to_planck(max(0.0, float(absolute_tao)), decimals)
    return max(10, rel, abs_planck)


def assert_total_pool_preserved(
    before: Snapshot,
    after: Snapshot,
    decimals: int,
    relative_pct: float,
    absolute_tao: float,
    label: str,
) -> None:
    tolerance = absolute_and_relative_tolerance(
        before.total_pool_tao,
        decimals,
        relative_pct,
        absolute_tao,
    )

    assert_close(
        actual=after.total_pool_tao,
        expected=before.total_pool_tao,
        tolerance=tolerance,
        msg=(
            f"{label}: aggregate TAO-side pool emission must be preserved\n"
            f"  before={fmt_planck(before.total_pool_tao, decimals)} "
            f"after={fmt_planck(after.total_pool_tao, decimals)}"
        ),
    )


def assert_disabled_target(before: Snapshot, after: Snapshot) -> None:
    netuid = before.target_netuid
    before_row = before.target_row
    after_row = after.target_row

    assert_eq(after_row["enabled"], False, f"netuid {netuid} should be disabled")
    assert_eq(after_row["tao_in"], 0, f"disabled netuid {netuid} must have zero SubnetTaoInEmission")
    assert_eq(after_row["alpha_in"], 0, f"disabled netuid {netuid} must have zero SubnetAlphaInEmission")
    assert_eq(after_row["excess_tao"], 0, f"disabled netuid {netuid} must have zero SubnetExcessTao")
    assert_eq(after.target_pool_tao, 0, f"disabled netuid {netuid} must have zero TAO-side pool emission")

    if int(before_row["alpha_out"]) > 0:
        assert_true(
            int(after_row["alpha_out"]) > 0,
            f"disabled netuid {netuid} should still keep alpha_out path non-zero",
        )

    if before.target_pool_tao > 0:
        assert_true(
            after.other_pool_tao > before.other_pool_tao,
            (
                f"other subnets did not receive redistributed TAO-side emission after disabling {netuid}\n"
                f"  before_other_pool={before.other_pool_tao}\n"
                f"  after_other_pool={after.other_pool_tao}\n"
                f"  disabled_baseline_pool={before.target_pool_tao}"
            ),
        )


def assert_enabled_target_restored(restored: Snapshot, baseline: Snapshot) -> None:
    netuid = baseline.target_netuid
    row = restored.target_row

    assert_eq(row["enabled"], True, f"netuid {netuid} should be re-enabled")

    if baseline.target_pool_tao > 0:
        assert_true(restored.target_pool_tao > 0, f"re-enabled netuid {netuid} should have positive TAO-side pool emission")

    if int(baseline.target_row["alpha_in"]) > 0:
        assert_true(int(row["alpha_in"]) > 0, f"re-enabled netuid {netuid} should have positive alpha_in")

    if int(baseline.target_row["alpha_out"]) > 0:
        assert_true(int(row["alpha_out"]) > 0, f"re-enabled netuid {netuid} should have positive alpha_out")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mainnet-state local-clone test for AdminUtils.sudo_set_subnet_emission_enabled"
    )
    parser.add_argument("--ws", default=DEFAULT_WS)
    parser.add_argument("--netuid", type=int, default=None, help="Optional target netuid. If omitted, the script auto-selects a positive-emission subnet.")
    parser.add_argument("--wait-blocks", type=int, default=DEFAULT_WAIT_BLOCKS)
    parser.add_argument("--map-query-timeout-sec", type=float, default=DEFAULT_MAP_QUERY_TIMEOUT_SEC)
    parser.add_argument("--relative-tolerance-pct", type=float, default=DEFAULT_RELATIVE_TOLERANCE_PCT)
    parser.add_argument("--absolute-tolerance-tao", type=float, default=DEFAULT_ABSOLUTE_TOLERANCE_TAO)
    args = parser.parse_args()

    banner("SubnetEmissionEnabled mainnet-state local-clone test")
    log(f"endpoint: {args.ws}")

    substrate = connect(args.ws)
    decimals = token_decimals(substrate)
    sudo = Keypair.create_from_uri("//Alice")

    log(f"connected | decimals={decimals} | sudo={sudo.ss58_address}")
    log(f"current block: {current_block(substrate)}")

    banner("Preparing local clone controls")
    disable_local_limits(substrate, sudo)
    produce_blocks(substrate, sudo, 1, "post-local-control-setup")

    initial_maps = read_all_emission_maps(substrate, args.map_query_timeout_sec)
    target_netuid = int(args.netuid) if args.netuid is not None else select_target_netuid(substrate, initial_maps)

    target_owner = subnet_owner(substrate, target_netuid)
    assert_true(target_owner is not None, f"target netuid {target_netuid} has no readable SubnetOwner")

    original_enabled = subnet_emission_enabled(substrate, target_netuid)
    log(f"target netuid: {target_netuid}")
    log(f"target owner:  {target_owner}")
    log(f"original SubnetEmissionEnabled[{target_netuid}] = {original_enabled}")

    try:
        if not original_enabled:
            banner("Enabling target first to build enabled baseline")
            set_subnet_emission_enabled_as_owner(
                substrate,
                sudo,
                target_owner,
                target_netuid,
                True,
            )
            produce_blocks(substrate, sudo, args.wait_blocks, "after-initial-enable")

        banner("Reading enabled baseline")
        baseline = take_snapshot(
            substrate,
            "baseline-enabled",
            target_netuid,
            map_query_timeout_sec=args.map_query_timeout_sec,
        )
        print_snapshot(baseline, decimals)

        assert_true(
            baseline.total_pool_tao > 0,
            "aggregate baseline pool emission is zero; the mainnet clone has no TAO-side emission to test",
        )
        assert_true(
            baseline.target_pool_tao > 0,
            (
                f"target netuid {target_netuid} has zero baseline pool emission. "
                "Pass --netuid for a different subnet or omit --netuid to auto-select."
            ),
        )

        banner(f"Disabling pool-side emission on netuid {target_netuid}")
        set_subnet_emission_enabled_as_owner(
            substrate,
            sudo,
            target_owner,
            target_netuid,
            False,
        )
        produce_blocks(substrate, sudo, args.wait_blocks, "after-disable")

        disabled = take_snapshot(
            substrate,
            "disabled-target",
            target_netuid,
            map_query_timeout_sec=args.map_query_timeout_sec,
        )
        print_snapshot(disabled, decimals)

        assert_disabled_target(baseline, disabled)
        assert_total_pool_preserved(
            before=baseline,
            after=disabled,
            decimals=decimals,
            relative_pct=args.relative_tolerance_pct,
            absolute_tao=args.absolute_tolerance_tao,
            label=f"after disabling netuid {target_netuid}",
        )

        banner(f"Re-enabling pool-side emission on netuid {target_netuid}")
        set_subnet_emission_enabled_as_owner(
            substrate,
            sudo,
            target_owner,
            target_netuid,
            True,
        )
        produce_blocks(substrate, sudo, args.wait_blocks, "after-reenable")

        restored = take_snapshot(
            substrate,
            "restored-enabled",
            target_netuid,
            map_query_timeout_sec=args.map_query_timeout_sec,
        )
        print_snapshot(restored, decimals)

        assert_enabled_target_restored(restored, baseline)
        assert_total_pool_preserved(
            before=baseline,
            after=restored,
            decimals=decimals,
            relative_pct=args.relative_tolerance_pct,
            absolute_tao=args.absolute_tolerance_tao,
            label=f"after re-enabling netuid {target_netuid}",
        )

        banner("All mainnet-state SubnetEmissionEnabled assertions passed")

    finally:
        current_enabled = subnet_emission_enabled(substrate, target_netuid)
        if current_enabled != original_enabled:
            banner(f"Restoring original SubnetEmissionEnabled[{target_netuid}]={original_enabled}")
            try:
                set_subnet_emission_enabled_as_owner(
                    substrate,
                    sudo,
                    target_owner,
                    target_netuid,
                    original_enabled,
                )
                produce_blocks(substrate, sudo, args.wait_blocks, "restore-original")
            except Exception as exc:
                log(
                    "WARNING: failed to restore original state on local clone. "
                    f"SubnetEmissionEnabled[{target_netuid}] may still be {current_enabled}. "
                    f"Error: {simplify_error_message(exc)}"
                )

        try:
            final_enabled = subnet_emission_enabled(substrate, target_netuid)
            log(f"final SubnetEmissionEnabled[{target_netuid}] = {final_enabled}")
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except TestFailure as exc:
        print(f"\nAssertion failed:\n{exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"\nError:\n{simplify_error_message(exc) or exc}", file=sys.stderr)
        sys.exit(1)