#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fast local-chain integration test for SubnetEmissionEnabled.

This script verifies the feature without hardcoding a fixed 0.5 TAO block
emission. It derives the expected TAO-side pool emission from the all-enabled
baseline snapshot, then asserts every later toggle phase preserves that same
total.

What it verifies:
1) Creates or uses three non-root subnets.
2) Starts all selected subnets.
3) Creates positive TAO flow using burned_register + add_stake.
4) Toggles subnet pool-side emission through AdminUtils.sudo_set_subnet_emission_enabled.
5) Asserts actual emission storage after every toggle:
      - SubnetEmissionEnabled
      - SubnetTaoInEmission
      - SubnetAlphaInEmission
      - SubnetExcessTao
      - SubnetAlphaOutEmission
6) Asserts disabled subnets receive zero TAO-side emission.
7) Asserts total TAO-side emission across all emission-eligible subnets remains
   equal to the all-enabled baseline after disabling one or more subnets.

Run:
    python3 test_subnet_emission_toggle.py

Useful options:
    python3 test_subnet_emission_toggle.py --netuids 1,2,3
    python3 test_subnet_emission_toggle.py --force-scratch
    python3 test_subnet_emission_toggle.py --expected-block-emission-tao 1.0

If --expected-block-emission-tao is omitted, the script derives the expected
value from the first all-enabled positive-emission baseline snapshot.
"""

from __future__ import annotations

import argparse
import ast
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException


DEFAULT_WS = "ws://127.0.0.1:9945"

PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"
PALLET_SUDO = "Sudo"
PALLET_SYSTEM = "System"
PALLET_BALANCES = "Balances"
PALLET_UTILITY = "Utility"

ROOT_NETUID = 0
MIN_TEST_SUBNETS = 3

QUERY_RETRIES = 4
QUERY_BACKOFF_SEC = 0.20
SUBMIT_RETRIES = 4
SUBMIT_BACKOFF_SEC = 0.30
START_RETRIES = 8
FLOW_SETUP_ATTEMPTS = 5

DEFAULT_OWNER_COLD_FUNDS_TAO = 100_000.0
DEFAULT_OWNER_HOT_FUNDS_TAO = 10.0
DEFAULT_STAKE_TAO = 2_000.0
DEFAULT_RELATIVE_TOLERANCE_PCT = 10.0
DEFAULT_BLOCK_EMISSION_TOLERANCE_PLANCK = 10_000

CUSTOM_TYPE_REGISTRY = {
    "types": {
        "U64F64": "u128",
        "substrate_fixed::types::U64F64": "u128",
        "FixedU128<U64>": "u128",
    }
}


@dataclass(frozen=True)
class ManagedSubnet:
    netuid: int
    owner_ss58: str
    owner_hot_ss58: Optional[str] = None
    created_by_script: bool = False


@dataclass(frozen=True)
class EmissionRow:
    netuid: int
    enabled: bool
    tao_in: int
    alpha_in: int
    excess_tao: int
    alpha_out: int

    @property
    def pool_tao(self) -> int:
        return int(self.tao_in) + int(self.excess_tao)


@dataclass(frozen=True)
class Snapshot:
    label: str
    block_hash: str
    block_number: int
    rows: Dict[int, EmissionRow]

    @property
    def total_pool_tao(self) -> int:
        return sum(row.pool_tao for row in self.rows.values())

    def selected_pool_tao(self, netuids: Iterable[int]) -> int:
        return sum(self.rows[n].pool_tao for n in netuids if n in self.rows)


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
            'decoder class for "compact<u32>" not found',
            'decoder class for "compact<u64>" not found',
            'decoder class for "compact<u128>" not found',
        )
    )


def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def assert_eq(actual: Any, expected: Any, msg: str) -> None:
    if actual != expected:
        raise AssertionError(f"{msg}\n  actual   = {actual}\n  expected = {expected}")


def assert_close(actual: int, expected: int, tolerance: int, msg: str) -> None:
    actual_i = int(actual)
    expected_i = int(expected)
    tolerance_i = int(tolerance)

    if abs(actual_i - expected_i) > tolerance_i:
        raise AssertionError(
            f"{msg}\n"
            f"  actual    = {actual_i}\n"
            f"  expected  = {expected_i}\n"
            f"  diff      = {abs(actual_i - expected_i)}\n"
            f"  tolerance = {tolerance_i}"
        )


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
    return int(round(float(tao) * (10 ** decimals)))


def fmt_planck(planck: int, decimals: int) -> str:
    return f"{int(planck) / float(10 ** decimals):.9f} TAO"


def short_ss58(ss58: str) -> str:
    return f"{ss58[:7]}…{ss58[-6:]}" if len(ss58) > 18 else ss58


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
        for key in ("value", "bits", "index", "raw"):
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

        for nested_value in value.values():
            nested = as_ss58(nested_value)
            if nested:
                return nested

    if isinstance(value, (list, tuple)):
        for item in value:
            nested = as_ss58(item)
            if nested:
                return nested

    text = str(value).strip()
    return text or None


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
    try:
        result = query(substrate, module, storage, params, block_hash)
        return getattr(result, "value", result)
    except Exception:
        return None


def q_int(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
    default: int = 0,
) -> int:
    value = query_value(substrate, module, storage, params, block_hash)
    if value is None:
        return default
    return as_int(value)


def q_bool(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
    default: bool = False,
) -> bool:
    value = query_value(substrate, module, storage, params, block_hash)
    if value is None:
        return default
    return as_bool(value)


def q_ss58(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
    block_hash: Optional[str] = None,
) -> Optional[str]:
    return as_ss58(query_value(substrate, module, storage, params, block_hash))


def query_map(
    substrate: SubstrateInterface,
    module: str,
    storage: str,
    params: Optional[Sequence[Any]] = None,
) -> List[Tuple[Any, Any]]:
    return with_retries(substrate, lambda: list(substrate.query_map(module, storage, params=params)))


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
                    wait_for_finalization=True,
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


def submit_sudo(
    substrate: SubstrateInterface,
    sudo: Keypair,
    inner: Any,
    allow_failed: bool = False,
) -> Any:
    return submit(substrate, sudo, sudo_call(substrate, inner), allow_failed=allow_failed)


def submit_batch_all(
    substrate: SubstrateInterface,
    signer: Keypair,
    calls: Sequence[Any],
    allow_failed: bool = False,
) -> Any:
    assert_true(len(calls) > 0, "cannot submit empty batch")
    batch = compose_call(substrate, PALLET_UTILITY, "batch_all", {"calls": list(calls)})
    return submit(substrate, signer, batch, allow_failed=allow_failed)


def block_number_at(substrate: SubstrateInterface, block_hash: str) -> int:
    return q_int(substrate, PALLET_SYSTEM, "Number", [], block_hash=block_hash)


def produce_one_block(substrate: SubstrateInterface, signer: Keypair, tag: str) -> Any:
    call = compose_call(substrate, PALLET_SYSTEM, "remark", {"remark": bytes(tag, "utf-8")})
    return submit(substrate, signer, call)


def produce_blocks(substrate: SubstrateInterface, signer: Keypair, count: int, tag: str) -> Any:
    last = None
    for i in range(max(1, int(count))):
        last = produce_one_block(substrate, signer, f"{tag}-{i}-{int(time.time() * 1000)}")
        time.sleep(0.02)
    return last


def account_free(substrate: SubstrateInterface, ss58: str) -> int:
    value = query(substrate, PALLET_SYSTEM, "Account", [ss58]).value
    return int(value["data"]["free"])


def transfer_call(substrate: SubstrateInterface, dest: str, amount: int) -> Any:
    return compose_call(
        substrate,
        PALLET_BALANCES,
        "transfer_keep_alive",
        {"dest": dest, "value": int(amount)},
    )


def ensure_min_balance(
    substrate: SubstrateInterface,
    funder: Keypair,
    who_ss58: str,
    min_tao: float,
    decimals: int,
) -> None:
    target = to_planck(min_tao, decimals)
    current = account_free(substrate, who_ss58)

    if current >= target:
        return

    delta = target - current
    log(f"Funding {short_ss58(who_ss58)} with {fmt_planck(delta, decimals)}")
    submit(substrate, funder, transfer_call(substrate, who_ss58, delta))


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


def disable_common_limits(substrate: SubstrateInterface, sudo: Keypair) -> None:
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

    best_effort_sudo(
        substrate,
        sudo,
        [
            (PALLET_ADMIN, "sudo_set_start_call_delay", {"start_call_delay": 0}),
            (PALLET_ADMIN, "sudo_set_start_call_delay", {"delay": 0}),
            (PALLET_ADMIN, "sudo_set_start_call_delay", {"blocks": 0}),
        ],
    )


def networks_added(substrate: SubstrateInterface) -> List[int]:
    nets: List[int] = []

    for key, val in query_map(substrate, PALLET_SUBTENSOR, "NetworksAdded"):
        try:
            if not as_bool(getattr(val, "value", val)):
                continue

            kv = getattr(key, "value", key)

            if isinstance(kv, int):
                nets.append(int(kv))
            elif isinstance(kv, dict) and kv:
                nets.append(as_int(next(iter(kv.values()))))
            else:
                nets.append(as_int(kv))
        except Exception:
            continue

    return sorted(set(nets))


def subnet_exists(substrate: SubstrateInterface, netuid: int) -> bool:
    return q_bool(substrate, PALLET_SUBTENSOR, "NetworksAdded", [int(netuid)], default=False)


def subnet_owner(substrate: SubstrateInterface, netuid: int) -> Optional[str]:
    return q_ss58(substrate, PALLET_SUBTENSOR, "SubnetOwner", [int(netuid)])


def subnet_owner_hotkey(substrate: SubstrateInterface, netuid: int) -> Optional[str]:
    return q_ss58(substrate, PALLET_SUBTENSOR, "SubnetOwnerHotkey", [int(netuid)])


def first_emission_block(substrate: SubstrateInterface, netuid: int) -> Optional[int]:
    value = query_value(substrate, PALLET_SUBTENSOR, "FirstEmissionBlockNumber", [int(netuid)])
    if value is None:
        return None
    try:
        return as_int(value)
    except Exception:
        return None


def subtoken_enabled(substrate: SubstrateInterface, netuid: int) -> bool:
    return q_bool(substrate, PALLET_SUBTENSOR, "SubtokenEnabled", [int(netuid)], default=False)


def subnet_emission_enabled(substrate: SubstrateInterface, netuid: int) -> bool:
    return q_bool(substrate, PALLET_SUBTENSOR, "SubnetEmissionEnabled", [int(netuid)], default=True)


def emission_eligible_netuids(substrate: SubstrateInterface) -> List[int]:
    out: List[int] = []

    for netuid in networks_added(substrate):
        if netuid == ROOT_NETUID:
            continue
        if first_emission_block(substrate, netuid) is None:
            continue
        if not subtoken_enabled(substrate, netuid):
            continue
        out.append(netuid)

    return sorted(set(out))


def compose_register_network(
    substrate: SubstrateInterface,
    owner_hot_ss58: str,
    owner_cold_ss58: str,
) -> Any:
    call, _ = compose_first(
        substrate,
        [
            (PALLET_SUBTENSOR, "register_network", {"hotkey": owner_hot_ss58}),
            (
                PALLET_SUBTENSOR,
                "register_network",
                {"hotkey": owner_hot_ss58, "coldkey": owner_cold_ss58},
            ),
            (
                PALLET_SUBTENSOR,
                "register_network",
                {"hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
            ),
            (
                PALLET_SUBTENSOR,
                "register_network",
                {"owner_hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
            ),
            (
                PALLET_SUBTENSOR,
                "register_network",
                {"owner_hot": owner_hot_ss58, "owner_cold": owner_cold_ss58},
            ),
        ],
    )
    return call


def create_scratch_subnets_batch(
    substrate: SubstrateInterface,
    sudo: Keypair,
    count: int,
    decimals: int,
) -> List[ManagedSubnet]:
    before = set(networks_added(substrate))
    desired_limit = max((max(before) if before else 0) + count + 8, len(before) + count + 8)

    best_effort_sudo(
        substrate,
        sudo,
        [
            (PALLET_ADMIN, "sudo_set_subnet_limit", {"max_subnets": desired_limit}),
            (PALLET_SUBTENSOR, "sudo_set_subnet_limit", {"max_subnets": desired_limit}),
        ],
    )

    generated: List[Tuple[Keypair, Keypair]] = []
    calls: List[Any] = []
    tag = int(time.time() * 1000)

    for idx in range(count):
        owner_cold = Keypair.create_from_uri(f"//Alice//SubnetEmissionToggle//OwnerCold//{tag}//{idx}")
        owner_hot = Keypair.create_from_uri(f"//Alice//SubnetEmissionToggle//OwnerHot//{tag}//{idx}")
        generated.append((owner_cold, owner_hot))

        calls.append(
            transfer_call(
                substrate,
                owner_cold.ss58_address,
                to_planck(DEFAULT_OWNER_COLD_FUNDS_TAO, decimals),
            )
        )
        calls.append(
            transfer_call(
                substrate,
                owner_hot.ss58_address,
                to_planck(DEFAULT_OWNER_HOT_FUNDS_TAO, decimals),
            )
        )

        register_call = compose_register_network(
            substrate,
            owner_hot.ss58_address,
            owner_cold.ss58_address,
        )
        calls.append(sudo_as_call(substrate, owner_cold.ss58_address, register_call))

    banner(f"Creating {count} scratch subnets in one batch")
    rec = submit_batch_all(substrate, sudo, calls)
    log(f"Scratch subnet batch finalized in block {block_number_at(substrate, rec.block_hash)}")

    after = set(networks_added(substrate))
    created = sorted(n for n in after - before if n != ROOT_NETUID)
    assert_true(len(created) >= count, f"expected at least {count} new subnets, got {created}")

    managed: List[ManagedSubnet] = []

    for netuid, (owner_cold, owner_hot) in zip(created[-count:], generated):
        assert_eq(
            subnet_emission_enabled(substrate, netuid),
            True,
            f"new subnet {netuid} should default emission enabled",
        )

        managed.append(
            ManagedSubnet(
                netuid=netuid,
                owner_ss58=owner_cold.ss58_address,
                owner_hot_ss58=owner_hot.ss58_address,
                created_by_script=True,
            )
        )
        log(
            f"Created scratch subnet {netuid} "
            f"owner={short_ss58(owner_cold.ss58_address)} "
            f"hot={short_ss58(owner_hot.ss58_address)}"
        )

    return managed


def parse_netuids(value: Optional[str]) -> List[int]:
    if not value:
        return []
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def resolve_managed_subnets(
    substrate: SubstrateInterface,
    sudo: Keypair,
    decimals: int,
    requested: List[int],
    force_scratch: bool,
) -> List[ManagedSubnet]:
    managed: List[ManagedSubnet] = []

    if requested:
        for netuid in requested:
            if netuid == ROOT_NETUID:
                continue

            assert_true(subnet_exists(substrate, netuid), f"requested netuid {netuid} does not exist")
            owner = subnet_owner(substrate, netuid)
            assert_true(owner is not None, f"could not read SubnetOwner for netuid {netuid}")

            managed.append(
                ManagedSubnet(
                    netuid=netuid,
                    owner_ss58=str(owner),
                    owner_hot_ss58=subnet_owner_hotkey(substrate, netuid),
                    created_by_script=False,
                )
            )

        assert_true(len(managed) >= MIN_TEST_SUBNETS, f"provide at least {MIN_TEST_SUBNETS} non-root netuids")
        return managed[:MIN_TEST_SUBNETS]

    if not force_scratch:
        for netuid in networks_added(substrate):
            if netuid == ROOT_NETUID:
                continue

            owner = subnet_owner(substrate, netuid)
            if owner:
                managed.append(
                    ManagedSubnet(
                        netuid=netuid,
                        owner_ss58=str(owner),
                        owner_hot_ss58=subnet_owner_hotkey(substrate, netuid),
                        created_by_script=False,
                    )
                )

            if len(managed) >= MIN_TEST_SUBNETS:
                break

    if len(managed) >= MIN_TEST_SUBNETS:
        return managed[:MIN_TEST_SUBNETS]

    needed = MIN_TEST_SUBNETS - len(managed)
    managed.extend(create_scratch_subnets_batch(substrate, sudo, needed, decimals))
    return managed[:MIN_TEST_SUBNETS]


def set_subnet_emission_enabled_calls(
    substrate: SubstrateInterface,
    items: Sequence[Tuple[ManagedSubnet, bool]],
) -> List[Any]:
    calls: List[Any] = []

    for managed, enabled in items:
        inner = compose_call(
            substrate,
            PALLET_ADMIN,
            "sudo_set_subnet_emission_enabled",
            {"netuid": int(managed.netuid), "enabled": bool(enabled)},
        )
        calls.append(sudo_as_call(substrate, managed.owner_ss58, inner))

    return calls


def set_subnet_emission_enabled_batch(
    substrate: SubstrateInterface,
    sudo: Keypair,
    items: Sequence[Tuple[ManagedSubnet, bool]],
) -> None:
    calls = set_subnet_emission_enabled_calls(substrate, items)
    rec = submit_batch_all(substrate, sudo, calls)
    log(f"Toggled {len(items)} subnet(s) in block {block_number_at(substrate, rec.block_hash)}")

    for managed, expected in items:
        assert_eq(
            subnet_emission_enabled(substrate, managed.netuid),
            bool(expected),
            f"SubnetEmissionEnabled mismatch for netuid {managed.netuid}",
        )


def start_subnets_batch(
    substrate: SubstrateInterface,
    sudo: Keypair,
    managed: Sequence[ManagedSubnet],
) -> None:
    for attempt in range(1, START_RETRIES + 1):
        remaining = [
            m
            for m in managed
            if first_emission_block(substrate, m.netuid) is None
            or not subtoken_enabled(substrate, m.netuid)
        ]

        if not remaining:
            log("All selected subnets are already started.")
            return

        calls: List[Any] = []

        for m in remaining:
            inner = compose_call(
                substrate,
                PALLET_SUBTENSOR,
                "start_call",
                {"netuid": int(m.netuid)},
            )
            calls.append(sudo_as_call(substrate, m.owner_ss58, inner))

        log(f"Starting subnets {[m.netuid for m in remaining]} in one batch (attempt {attempt}/{START_RETRIES})")
        rec = submit_batch_all(substrate, sudo, calls, allow_failed=True)
        log(f"start_call batch block {block_number_at(substrate, rec.block_hash)} success={rec.is_success}")

        produce_blocks(substrate, sudo, 1, f"start-observe-{attempt}")

    still = [
        m.netuid
        for m in managed
        if first_emission_block(substrate, m.netuid) is None
        or not subtoken_enabled(substrate, m.netuid)
    ]
    assert_true(not still, f"could not start selected subnets: {still}")


def compose_burned_register(substrate: SubstrateInterface, netuid: int, hotkey: str) -> Any:
    return compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "burned_register",
        {"netuid": int(netuid), "hotkey": hotkey},
    )


def compose_add_stake(
    substrate: SubstrateInterface,
    netuid: int,
    hotkey: str,
    amount_staked: int,
) -> Any:
    return compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "add_stake",
        {
            "netuid": int(netuid),
            "hotkey": hotkey,
            "amount_staked": int(amount_staked),
        },
    )


def add_positive_tao_flow(
    substrate: SubstrateInterface,
    sudo: Keypair,
    managed: Sequence[ManagedSubnet],
    stake_planck: int,
    tag: str,
) -> None:
    hotkeys: List[Keypair] = [
        Keypair.create_from_uri(f"//Alice//SubnetEmissionToggle//StakeHot//{tag}//{m.netuid}")
        for m in managed
    ]

    combined_calls: List[Any] = []

    for m, hot in zip(managed, hotkeys):
        combined_calls.append(compose_burned_register(substrate, m.netuid, hot.ss58_address))
        combined_calls.append(compose_add_stake(substrate, m.netuid, hot.ss58_address, stake_planck))

    log(f"Registering + staking into {[m.netuid for m in managed]} in one batch")

    try:
        rec = submit_batch_all(substrate, sudo, combined_calls)
        log(f"flow setup batch finalized in block {block_number_at(substrate, rec.block_hash)}")
    except Exception as exc:
        log(f"combined register+stake batch failed, falling back to split batches: {simplify_error_message(exc)}")

        reg_calls = [
            compose_burned_register(substrate, m.netuid, hot.ss58_address)
            for m, hot in zip(managed, hotkeys)
        ]
        submit_batch_all(substrate, sudo, reg_calls)

        stake_calls = [
            compose_add_stake(substrate, m.netuid, hot.ss58_address, stake_planck)
            for m, hot in zip(managed, hotkeys)
        ]
        rec = submit_batch_all(substrate, sudo, stake_calls)
        log(f"split flow setup finalized in block {block_number_at(substrate, rec.block_hash)}")


def read_row(substrate: SubstrateInterface, netuid: int) -> EmissionRow:
    return EmissionRow(
        netuid=netuid,
        enabled=subnet_emission_enabled(substrate, netuid),
        tao_in=q_int(substrate, PALLET_SUBTENSOR, "SubnetTaoInEmission", [int(netuid)]),
        alpha_in=q_int(substrate, PALLET_SUBTENSOR, "SubnetAlphaInEmission", [int(netuid)]),
        excess_tao=q_int(substrate, PALLET_SUBTENSOR, "SubnetExcessTao", [int(netuid)]),
        alpha_out=q_int(substrate, PALLET_SUBTENSOR, "SubnetAlphaOutEmission", [int(netuid)]),
    )


def take_snapshot(
    substrate: SubstrateInterface,
    label: str,
    extra_netuids: Optional[Sequence[int]] = None,
) -> Snapshot:
    head = with_retries(substrate, lambda: substrate.get_chain_head())
    block = block_number_at(substrate, head)

    netuids = set(emission_eligible_netuids(substrate))
    if extra_netuids:
        netuids.update(int(n) for n in extra_netuids)

    rows = {netuid: read_row(substrate, netuid) for netuid in sorted(netuids)}

    return Snapshot(
        label=label,
        block_hash=head,
        block_number=block,
        rows=rows,
    )


def produce_and_snapshot(
    substrate: SubstrateInterface,
    signer: Keypair,
    blocks: int,
    label: str,
    selected: Sequence[int],
) -> Snapshot:
    produce_blocks(substrate, signer, blocks, f"observe-{label}")
    return take_snapshot(substrate, label, extra_netuids=selected)


def print_snapshot(snapshot: Snapshot, decimals: int, selected: Sequence[int]) -> None:
    selected_set = set(selected)

    log(
        f"\nSnapshot {snapshot.label} | block={snapshot.block_number} | "
        f"total_pool_tao={fmt_planck(snapshot.total_pool_tao, decimals)}"
    )
    log(" netuid | selected | enabled | tao_in       | excess_tao   | pool_tao     | alpha_in     | alpha_out")

    for netuid, row in sorted(snapshot.rows.items()):
        marker = "*" if netuid in selected_set else " "
        log(
            f"{netuid:6d} | {marker:^8s} | {str(row.enabled):7s} | "
            f"{row.tao_in:12d} | {row.excess_tao:12d} | {row.pool_tao:12d} | "
            f"{row.alpha_in:12d} | {row.alpha_out:12d}"
        )


def wait_for_positive_pool_emission(
    substrate: SubstrateInterface,
    sudo: Keypair,
    managed: Sequence[ManagedSubnet],
    stake_planck: int,
    decimals: int,
) -> Snapshot:
    selected = [m.netuid for m in managed]

    for attempt in range(1, FLOW_SETUP_ATTEMPTS + 1):
        add_positive_tao_flow(
            substrate,
            sudo,
            managed,
            stake_planck * attempt,
            tag=f"attempt-{attempt}-{int(time.time() * 1000)}",
        )

        snapshot = produce_and_snapshot(
            substrate,
            sudo,
            1,
            f"flow-attempt-{attempt}",
            selected,
        )
        print_snapshot(snapshot, decimals, selected)

        selected_pool = snapshot.selected_pool_tao(selected)

        if selected_pool > 0 and all(snapshot.rows[n].alpha_out > 0 for n in selected):
            log(f"✅ Positive TAO-side emission observed after flow setup attempt {attempt}")
            return snapshot

    raise AssertionError(
        "Could not create positive TAO-side pool emission. The feature may still be correct, "
        "but this integration test needs positive SubnetTaoInEmission or SubnetExcessTao to verify redistribution."
    )


def tolerance_for(value: int, tolerance_pct: float) -> int:
    return max(10, int(abs(int(value)) * max(0.0, float(tolerance_pct)) / 100.0))


def assert_total_block_emission(
    snapshot: Snapshot,
    expected_planck: int,
    tolerance_planck: int,
    decimals: int,
    label: str,
) -> None:
    assert_true(expected_planck > 0, "expected block emission must be positive")
    assert_true(len(snapshot.rows) > 0, f"{label}: snapshot has no emission-eligible subnet rows")

    assert_close(
        actual=snapshot.total_pool_tao,
        expected=expected_planck,
        tolerance=tolerance_planck,
        msg=(
            f"{label}: total TAO-side emission across all emission-eligible subnets "
            f"must equal the all-enabled baseline\n"
            f"  observed={fmt_planck(snapshot.total_pool_tao, decimals)} "
            f"expected={fmt_planck(expected_planck, decimals)}"
        ),
    )


def assert_total_pool_preserved(
    before: Snapshot,
    after: Snapshot,
    tolerance_pct: float,
    decimals: int,
    label: str,
) -> None:
    assert_true(before.total_pool_tao > 0, f"{before.label} total pool TAO is zero")
    tolerance = tolerance_for(before.total_pool_tao, tolerance_pct)

    assert_close(
        actual=after.total_pool_tao,
        expected=before.total_pool_tao,
        tolerance=tolerance,
        msg=(
            f"{label}: total TAO-side pool emission should be preserved\n"
            f"  before={fmt_planck(before.total_pool_tao, decimals)} "
            f"after={fmt_planck(after.total_pool_tao, decimals)}"
        ),
    )


def assert_disabled_row(snapshot: Snapshot, netuid: int) -> None:
    row = snapshot.rows[netuid]

    assert_eq(row.enabled, False, f"netuid {netuid} should be disabled")
    assert_eq(row.tao_in, 0, f"disabled netuid {netuid} must have zero SubnetTaoInEmission")
    assert_eq(row.alpha_in, 0, f"disabled netuid {netuid} must have zero SubnetAlphaInEmission")
    assert_eq(row.excess_tao, 0, f"disabled netuid {netuid} must have zero SubnetExcessTao")
    assert_true(row.alpha_out > 0, f"disabled netuid {netuid} must still have non-zero SubnetAlphaOutEmission")


def assert_all_disabled_rows_zero(snapshot: Snapshot) -> None:
    for netuid, row in snapshot.rows.items():
        if not row.enabled:
            assert_eq(row.tao_in, 0, f"disabled netuid {netuid} must have zero SubnetTaoInEmission")
            assert_eq(row.alpha_in, 0, f"disabled netuid {netuid} must have zero SubnetAlphaInEmission")
            assert_eq(row.excess_tao, 0, f"disabled netuid {netuid} must have zero SubnetExcessTao")


def assert_enabled_selected_row(snapshot: Snapshot, netuid: int) -> None:
    row = snapshot.rows[netuid]

    assert_eq(row.enabled, True, f"netuid {netuid} should be enabled")
    assert_true(row.pool_tao > 0, f"enabled selected netuid {netuid} should have positive TAO-side pool emission")
    assert_true(row.alpha_in > 0, f"enabled selected netuid {netuid} should have positive SubnetAlphaInEmission")
    assert_true(row.alpha_out > 0, f"enabled selected netuid {netuid} should have positive SubnetAlphaOutEmission")


def run_phase_assertions(
    snapshot: Snapshot,
    expected_block_emission_planck: int,
    block_emission_tolerance_planck: int,
    decimals: int,
    label: str,
) -> None:
    assert_all_disabled_rows_zero(snapshot)
    assert_total_block_emission(
        snapshot,
        expected_block_emission_planck,
        block_emission_tolerance_planck,
        decimals,
        label,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fast SubnetEmissionEnabled integration test with baseline-derived block-emission invariant checks"
    )
    parser.add_argument("--ws", default=DEFAULT_WS, help=f"Subtensor websocket endpoint, default {DEFAULT_WS}")
    parser.add_argument("--netuids", default=None, help="Comma-separated existing non-root netuids to use, e.g. 1,2,3")
    parser.add_argument("--force-scratch", action="store_true", help="Create fresh scratch subnets instead of reusing existing ones")
    parser.add_argument("--stake-tao", type=float, default=DEFAULT_STAKE_TAO, help="TAO to stake per selected subnet to create TAO flow")
    parser.add_argument(
        "--relative-tolerance-pct",
        type=float,
        default=DEFAULT_RELATIVE_TOLERANCE_PCT,
        help="Relative tolerance for before/after preservation checks",
    )
    parser.add_argument(
        "--expected-block-emission-tao",
        type=float,
        default=None,
        help=(
            "Optional fixed expected total TAO-side pool emission per block. "
            "If omitted, derives from the all-enabled baseline snapshot."
        ),
    )
    parser.add_argument(
        "--block-emission-tolerance-planck",
        type=int,
        default=DEFAULT_BLOCK_EMISSION_TOLERANCE_PLANCK,
        help="Absolute tolerance, in planck, for the expected per-block emission check",
    )

    args = parser.parse_args()

    substrate = connect(args.ws)
    decimals = token_decimals(substrate)
    sudo = Keypair.create_from_uri("//Alice")
    stake_planck = to_planck(args.stake_tao, decimals)

    expected_block_emission_planck: Optional[int] = (
        to_planck(args.expected_block_emission_tao, decimals)
        if args.expected_block_emission_tao is not None
        else None
    )
    block_emission_tolerance_planck = max(1, int(args.block_emission_tolerance_planck))

    banner("SubnetEmissionEnabled fast integration test")
    log(
        f"Connected to {args.ws} | decimals={decimals} | sudo={short_ss58(sudo.ss58_address)} | "
        f"expected_block_emission="
        f"{fmt_planck(expected_block_emission_planck, decimals) if expected_block_emission_planck is not None else 'derived from baseline'} | "
        f"emission_tolerance={block_emission_tolerance_planck} planck"
    )

    ensure_min_balance(substrate, sudo, sudo.ss58_address, DEFAULT_OWNER_COLD_FUNDS_TAO, decimals)
    disable_common_limits(substrate, sudo)

    requested = parse_netuids(args.netuids)
    managed = resolve_managed_subnets(
        substrate,
        sudo,
        decimals,
        requested,
        force_scratch=bool(args.force_scratch),
    )
    selected = [m.netuid for m in managed]
    log(f"Selected subnets: {selected}")

    set_subnet_emission_enabled_batch(substrate, sudo, [(m, True) for m in managed])
    start_subnets_batch(substrate, sudo, managed)

    baseline = wait_for_positive_pool_emission(substrate, sudo, managed, stake_planck, decimals)

    if expected_block_emission_planck is None:
        expected_block_emission_planck = baseline.total_pool_tao
        log(
            "Derived expected per-block TAO-side emission from all-enabled baseline: "
            f"{fmt_planck(expected_block_emission_planck, decimals)}"
        )

    run_phase_assertions(
        baseline,
        expected_block_emission_planck,
        block_emission_tolerance_planck,
        decimals,
        "baseline all enabled",
    )

    n1, n2, n3 = managed[0], managed[1], managed[2]

    banner(f"Phase 1: disable {n2.netuid}")
    set_subnet_emission_enabled_batch(substrate, sudo, [(n2, False)])
    phase1 = produce_and_snapshot(substrate, sudo, 1, f"disable-{n2.netuid}", selected)
    print_snapshot(phase1, decimals, selected)

    run_phase_assertions(
        phase1,
        expected_block_emission_planck,
        block_emission_tolerance_planck,
        decimals,
        f"after disabling subnet {n2.netuid}",
    )
    assert_disabled_row(phase1, n2.netuid)
    assert_enabled_selected_row(phase1, n1.netuid)
    assert_enabled_selected_row(phase1, n3.netuid)
    assert_total_pool_preserved(baseline, phase1, args.relative_tolerance_pct, decimals, "disable one subnet")
    assert_true(
        phase1.selected_pool_tao([n1.netuid, n3.netuid])
        > baseline.selected_pool_tao([n1.netuid, n3.netuid]),
        "enabled selected subnets should receive the disabled subnet's redistributed TAO-side emission",
    )

    banner(f"Phase 2: re-enable {n2.netuid}, disable {n1.netuid}")
    set_subnet_emission_enabled_batch(substrate, sudo, [(n2, True), (n1, False)])
    phase2 = produce_and_snapshot(
        substrate,
        sudo,
        1,
        f"disable-{n1.netuid}-reenable-{n2.netuid}",
        selected,
    )
    print_snapshot(phase2, decimals, selected)

    run_phase_assertions(
        phase2,
        expected_block_emission_planck,
        block_emission_tolerance_planck,
        decimals,
        f"after re-enabling subnet {n2.netuid} and disabling subnet {n1.netuid}",
    )
    assert_disabled_row(phase2, n1.netuid)
    assert_enabled_selected_row(phase2, n2.netuid)
    assert_enabled_selected_row(phase2, n3.netuid)
    assert_total_pool_preserved(phase1, phase2, args.relative_tolerance_pct, decimals, "switch disabled subnet")

    banner(f"Phase 3: disable {n1.netuid} and {n2.netuid}")
    set_subnet_emission_enabled_batch(substrate, sudo, [(n1, False), (n2, False), (n3, True)])
    phase3 = produce_and_snapshot(substrate, sudo, 1, f"disable-{n1.netuid}-{n2.netuid}", selected)
    print_snapshot(phase3, decimals, selected)

    run_phase_assertions(
        phase3,
        expected_block_emission_planck,
        block_emission_tolerance_planck,
        decimals,
        f"after disabling subnets {n1.netuid} and {n2.netuid}",
    )
    assert_disabled_row(phase3, n1.netuid)
    assert_disabled_row(phase3, n2.netuid)
    assert_enabled_selected_row(phase3, n3.netuid)
    assert_total_pool_preserved(phase2, phase3, args.relative_tolerance_pct, decimals, "disable two subnets")

    banner("Phase 4: re-enable all selected subnets")
    set_subnet_emission_enabled_batch(substrate, sudo, [(n1, True), (n2, True), (n3, True)])
    phase4 = produce_and_snapshot(substrate, sudo, 1, "reenable-all", selected)
    print_snapshot(phase4, decimals, selected)

    run_phase_assertions(
        phase4,
        expected_block_emission_planck,
        block_emission_tolerance_planck,
        decimals,
        "after re-enabling all selected subnets",
    )
    for netuid in selected:
        assert_enabled_selected_row(phase4, netuid)
    assert_total_pool_preserved(baseline, phase4, args.relative_tolerance_pct, decimals, "re-enable all")

    banner("All SubnetEmissionEnabled assertions passed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"\nAssertion failed:\n{exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"\nError:\n{simplify_error_message(exc) or exc}", file=sys.stderr)
        sys.exit(1)