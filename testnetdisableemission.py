#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fast testnet integration test for SubnetEmissionEnabled on an existing subnet.

Target defaults:
  endpoint: wss://test.finney.opentensor.ai:443
  netuid:   453
  wallet:   mock
  hotkey:   mock_hot

Expected local / chain addresses:
  coldkey mock:
    5G6wdAdS7hpBuH1tjuZDhpzrGw9Wf71WEVakDCxHDm1cxEQ2
  hotkey mock_hot:
    5FLZJhZ4Exat6YztoVB9JnfGLMaYxmr86TEqXRCr5MHNUHdm

What this script verifies:
  1) Local wallet addresses match the expected coldkey/hotkey.
  2) Chain SubnetOwner / SubnetOwnerHotkey match the expected addresses.
  3) The target subnet is emission eligible.
  4) AdminUtils.sudo_set_subnet_emission_enabled works.
  5) When disabled, target SubnetTaoInEmission, SubnetAlphaInEmission, and
     SubnetExcessTao are zero.
  6) When disabled, target SubnetAlphaOutEmission is preserved when it was
     nonzero before disable.
  7) Aggregate TAO-side pool emission is compared before/after disable.
  8) If the target had nonzero baseline pool emission, the script also asserts
     other subnets receive more TAO-side emission after disabling the target.
  9) The original SubnetEmissionEnabled state is restored in finally.

Important:
  - If the target subnet has zero baseline TAO-side pool emission, that is not a
    test failure. The script still toggles it and compares aggregate before/after.
  - In that zero-baseline case, the script skips only the direct "other subnets
    increased by target share" assertion because there is no target share to
    redistribute.

Run:
    python3 testnetdisableemission.py

Useful options:
    python3 testnetdisableemission.py --map-query-timeout-sec 30
    python3 testnetdisableemission.py --wait-blocks 2
    python3 testnetdisableemission.py --relative-tolerance-pct 2.0
    python3 testnetdisableemission.py --absolute-tolerance-tao 0.01
"""

from __future__ import annotations

import argparse
import ast
import getpass
import os
import signal
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException


DEFAULT_WS = "wss://test.finney.opentensor.ai:443"
DEFAULT_NETUID = 453

DEFAULT_WALLET_NAME = "mock"
DEFAULT_HOTKEY_NAME = "mock_hot"
DEFAULT_WALLET_PATH = "~/.bittensor/wallets"

EXPECTED_COLDKEY_SS58 = "5G6wdAdS7hpBuH1tjuZDhpzrGw9Wf71WEVakDCxHDm1cxEQ2"
EXPECTED_HOTKEY_SS58 = "5FLZJhZ4Exat6YztoVB9JnfGLMaYxmr86TEqXRCr5MHNUHdm"

PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"
PALLET_SYSTEM = "System"

QUERY_RETRIES = 4
QUERY_BACKOFF_SEC = 0.25
SUBMIT_RETRIES = 4
SUBMIT_BACKOFF_SEC = 0.4

DEFAULT_WAIT_BLOCKS = 2
DEFAULT_POLL_SEC = 1.0
DEFAULT_SET_RETRIES = 4
DEFAULT_RETRY_WAIT_BLOCKS = 10
DEFAULT_STORAGE_WAIT_SEC = 30.0
DEFAULT_MAP_QUERY_TIMEOUT_SEC = 30.0

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
        self.block_number = block_number
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


def is_rate_limit_error(exc_or_text: Any) -> bool:
    text = simplify_error_message(exc_or_text).lower()
    return any(
        marker in text
        for marker in (
            "rate",
            "ratelimit",
            "rate limit",
            "ownerhyperparamratelimit",
            "hyperparam",
            "wait",
            "too soon",
            "too early",
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
    log(f"Reading aggregate map {module}.{storage} ...")

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
            log(f"Skipping unparseable {storage} map entry: key={key!r} value={value!r} error={exc}")

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


def create_signed(substrate: SubstrateInterface, signer: Any, call: Any) -> Any:
    return with_retries(
        substrate,
        lambda: substrate.create_signed_extrinsic(call=call, keypair=signer),
        attempts=SUBMIT_RETRIES,
    )


def submit(
    substrate: SubstrateInterface,
    signer: Any,
    call: Any,
    allow_failed: bool = False,
) -> Any:
    """
    Wait for inclusion only. Waiting for finalization on public/testnet websocket
    endpoints can make scripts appear stuck.
    """
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


def head_hash(substrate: SubstrateInterface) -> str:
    return with_retries(substrate, lambda: substrate.get_chain_head())


def block_number_at(substrate: SubstrateInterface, block_hash: str) -> int:
    return q_int(substrate, PALLET_SYSTEM, "Number", [], block_hash=block_hash)


def current_block(substrate: SubstrateInterface) -> int:
    return block_number_at(substrate, head_hash(substrate))


def wait_for_blocks(
    substrate: SubstrateInterface,
    count: int,
    poll_sec: float,
    max_wait_sec: Optional[float] = None,
) -> int:
    start = current_block(substrate)
    target = start + max(0, int(count))
    deadline = time.monotonic() + (max_wait_sec if max_wait_sec is not None else max(60.0, count * 24.0))

    log(f"Waiting for {count} block(s): {start} -> {target}")

    while True:
        now = current_block(substrate)
        if now >= target:
            log(f"Reached block {now}")
            return now

        if time.monotonic() >= deadline:
            raise ScriptTimeout(f"timed out waiting for block {target}; current block is {now}")

        time.sleep(max(0.1, float(poll_sec)))


def env_password(wallet_name: str, key_type: str) -> Optional[str]:
    normalized = wallet_name.upper().replace("-", "_")
    key_type = key_type.upper()

    names = [
        f"BT_{key_type}_PASSWORD",
        f"BT_{key_type}_PW",
        f"BT_{key_type}_PW_{normalized}",
        "BT_WALLET_PASSWORD",
    ]

    for name in names:
        value = os.environ.get(name)
        if value:
            return value

    return None


def call_wallet_getter(getter: Callable[..., Any], password: Optional[str]) -> Any:
    if password is not None:
        try:
            return getter(password=password)
        except TypeError:
            return getter(password)

    try:
        return getter(password=None)
    except TypeError:
        try:
            return getter(None)
        except TypeError:
            return getter()


def get_keypair_with_optional_prompt(
    getter: Callable[..., Any],
    supplied_password: Optional[str],
    label: str,
) -> Any:
    try:
        return call_wallet_getter(getter, supplied_password)
    except Exception as first_exc:
        if supplied_password is not None:
            raise

        log(f"{label} did not unlock without password: {simplify_error_message(first_exc)}")
        password = getpass.getpass(f"Password for {label} (leave blank if unencrypted): ")
        if password == "":
            password = None

        try:
            return call_wallet_getter(getter, password)
        except Exception as second_exc:
            raise RuntimeError(f"failed to unlock {label}: {simplify_error_message(second_exc)}") from second_exc


def load_wallet_via_bittensor(
    wallet_name: str,
    hotkey_name: str,
    wallet_path: str,
    coldkey_password: Optional[str],
    hotkey_password: Optional[str],
) -> Tuple[Any, Any]:
    import bittensor as bt  # type: ignore

    kwargs: Dict[str, Any] = {
        "name": wallet_name,
        "hotkey": hotkey_name,
    }
    if wallet_path:
        kwargs["path"] = str(Path(wallet_path).expanduser())

    wallet = bt.wallet(**kwargs)

    coldkey = get_keypair_with_optional_prompt(
        wallet.get_coldkey,
        coldkey_password,
        f"{wallet_name}/coldkey",
    )

    hotkey = get_keypair_with_optional_prompt(
        wallet.get_hotkey,
        hotkey_password,
        f"{wallet_name}/{hotkey_name}",
    )

    return coldkey, hotkey


def load_keyfile_keypair(path: Path, name: str, password: Optional[str]) -> Any:
    from bittensor_wallet import Keyfile  # type: ignore

    def _load(pw: Optional[str] = None) -> Any:
        try:
            keyfile = Keyfile(str(path), name=name)
        except TypeError:
            keyfile = Keyfile(path=str(path), name=name)
        try:
            return keyfile.get_keypair(password=pw)
        except TypeError:
            return keyfile.get_keypair(pw)

    return get_keypair_with_optional_prompt(_load, password, name)


def load_wallet_via_keyfiles(
    wallet_name: str,
    hotkey_name: str,
    wallet_path: str,
    coldkey_password: Optional[str],
    hotkey_password: Optional[str],
) -> Tuple[Any, Any]:
    root = Path(wallet_path).expanduser() / wallet_name
    cold_path = root / "coldkey"
    hot_path = root / "hotkeys" / hotkey_name

    if not cold_path.exists():
        raise FileNotFoundError(f"coldkey file not found: {cold_path}")
    if not hot_path.exists():
        raise FileNotFoundError(f"hotkey file not found: {hot_path}")

    coldkey = load_keyfile_keypair(cold_path, f"{wallet_name}/coldkey", coldkey_password)
    hotkey = load_keyfile_keypair(hot_path, f"{wallet_name}/{hotkey_name}", hotkey_password)

    return coldkey, hotkey


def load_wallet_keypairs(
    wallet_name: str,
    hotkey_name: str,
    wallet_path: str,
    coldkey_password: Optional[str],
    hotkey_password: Optional[str],
    coldkey_uri: Optional[str],
) -> Tuple[Any, Any]:
    if coldkey_uri:
        log("Loading coldkey from --coldkey-uri and hotkey as address-only fallback.")
        coldkey = Keypair.create_from_uri(coldkey_uri)
        hotkey = Keypair(ss58_address=EXPECTED_HOTKEY_SS58)
        return coldkey, hotkey

    errors: List[str] = []

    try:
        return load_wallet_via_bittensor(
            wallet_name,
            hotkey_name,
            wallet_path,
            coldkey_password,
            hotkey_password,
        )
    except Exception as exc:
        errors.append(f"bittensor wallet load failed: {simplify_error_message(exc)}")

    try:
        return load_wallet_via_keyfiles(
            wallet_name,
            hotkey_name,
            wallet_path,
            coldkey_password,
            hotkey_password,
        )
    except Exception as exc:
        errors.append(f"bittensor_wallet keyfile load failed: {simplify_error_message(exc)}")

    raise RuntimeError("could not load local wallet:\n  - " + "\n  - ".join(errors))


def verify_wallet_and_chain_owner(
    substrate: SubstrateInterface,
    netuid: int,
    coldkey: Any,
    hotkey: Any,
    expected_coldkey_ss58: str,
    expected_hotkey_ss58: str,
) -> None:
    local_cold = str(coldkey.ss58_address)
    local_hot = str(hotkey.ss58_address)

    assert_eq(local_cold, expected_coldkey_ss58, "local coldkey address mismatch")
    assert_eq(local_hot, expected_hotkey_ss58, "local hotkey address mismatch")

    chain_owner = q_ss58(substrate, PALLET_SUBTENSOR, "SubnetOwner", [netuid], required=True)
    assert_eq(chain_owner, expected_coldkey_ss58, f"SubnetOwner mismatch for netuid {netuid}")

    chain_owner_hotkey = q_ss58(substrate, PALLET_SUBTENSOR, "SubnetOwnerHotkey", [netuid], required=False)
    if chain_owner_hotkey is not None:
        assert_eq(chain_owner_hotkey, expected_hotkey_ss58, f"SubnetOwnerHotkey mismatch for netuid {netuid}")
    else:
        log("SubnetOwnerHotkey storage was not readable; continuing after coldkey owner verification.")

    log(f"Verified local + chain owner for netuid {netuid}: cold={short_ss58(local_cold)} hot={short_ss58(local_hot)}")


def subnet_exists(substrate: SubstrateInterface, netuid: int) -> bool:
    return q_bool(substrate, PALLET_SUBTENSOR, "NetworksAdded", [netuid], default=False)


def first_emission_block(substrate: SubstrateInterface, netuid: int) -> Optional[int]:
    try:
        value = query_value(substrate, PALLET_SUBTENSOR, "FirstEmissionBlockNumber", [netuid])
    except Exception:
        return None

    if value is None:
        return None

    try:
        return as_int(value)
    except Exception:
        return None


def subtoken_enabled(substrate: SubstrateInterface, netuid: int) -> bool:
    return q_bool(substrate, PALLET_SUBTENSOR, "SubtokenEnabled", [netuid], default=False)


def subnet_emission_enabled(substrate: SubstrateInterface, netuid: int) -> bool:
    return q_bool(substrate, PALLET_SUBTENSOR, "SubnetEmissionEnabled", [netuid])


def read_target_row(substrate: SubstrateInterface, netuid: int) -> Dict[str, Any]:
    log(f"Reading target subnet storage for netuid {netuid} ...")
    return {
        "netuid": int(netuid),
        "enabled": subnet_emission_enabled(substrate, netuid),
        "tao_in": q_int(substrate, PALLET_SUBTENSOR, "SubnetTaoInEmission", [netuid], default=0),
        "alpha_in": q_int(substrate, PALLET_SUBTENSOR, "SubnetAlphaInEmission", [netuid], default=0),
        "excess_tao": q_int(substrate, PALLET_SUBTENSOR, "SubnetExcessTao", [netuid], default=0),
        "alpha_out": q_int(substrate, PALLET_SUBTENSOR, "SubnetAlphaOutEmission", [netuid], default=0),
    }


def read_aggregate_pool_emission(
    substrate: SubstrateInterface,
    map_query_timeout_sec: float,
) -> Tuple[int, int]:
    tao_in_by_netuid = query_map_values(
        substrate,
        PALLET_SUBTENSOR,
        "SubnetTaoInEmission",
        timeout_sec=map_query_timeout_sec,
    )
    excess_by_netuid = query_map_values(
        substrate,
        PALLET_SUBTENSOR,
        "SubnetExcessTao",
        timeout_sec=map_query_timeout_sec,
    )

    total_tao_in = sum(int(v) for v in tao_in_by_netuid.values())
    total_excess = sum(int(v) for v in excess_by_netuid.values())

    return total_tao_in, total_excess


def take_snapshot(
    substrate: SubstrateInterface,
    label: str,
    target_netuid: int,
    map_query_timeout_sec: float,
) -> Snapshot:
    log(f"Taking snapshot: {label}")

    block_hash = head_hash(substrate)
    block_number = block_number_at(substrate, block_hash)

    target_row = read_target_row(substrate, target_netuid)
    aggregate_tao_in, aggregate_excess_tao = read_aggregate_pool_emission(
        substrate,
        map_query_timeout_sec=map_query_timeout_sec,
    )

    return Snapshot(
        label=label,
        block_hash=block_hash,
        block_number=block_number,
        target_netuid=target_netuid,
        target_row=target_row,
        aggregate_tao_in=aggregate_tao_in,
        aggregate_excess_tao=aggregate_excess_tao,
    )


def print_snapshot(snapshot: Snapshot, decimals: int) -> None:
    row = snapshot.target_row
    pool = int(row["tao_in"]) + int(row["excess_tao"])

    log(
        f"\nSnapshot {snapshot.label} | block={snapshot.block_number}\n"
        f"  aggregate_tao_in      = {snapshot.aggregate_tao_in} ({fmt_planck(snapshot.aggregate_tao_in, decimals)})\n"
        f"  aggregate_excess_tao  = {snapshot.aggregate_excess_tao} ({fmt_planck(snapshot.aggregate_excess_tao, decimals)})\n"
        f"  aggregate_pool_tao    = {snapshot.total_pool_tao} ({fmt_planck(snapshot.total_pool_tao, decimals)})\n"
        f"  target_netuid         = {snapshot.target_netuid}\n"
        f"  target_enabled        = {row['enabled']}\n"
        f"  target_tao_in         = {row['tao_in']} ({fmt_planck(row['tao_in'], decimals)})\n"
        f"  target_excess_tao     = {row['excess_tao']} ({fmt_planck(row['excess_tao'], decimals)})\n"
        f"  target_pool_tao       = {pool} ({fmt_planck(pool, decimals)})\n"
        f"  target_alpha_in       = {row['alpha_in']}\n"
        f"  target_alpha_out      = {row['alpha_out']}"
    )


def compose_set_subnet_emission_enabled(
    substrate: SubstrateInterface,
    netuid: int,
    enabled: bool,
) -> Tuple[Any, str]:
    return compose_first(
        substrate,
        [
            (
                PALLET_ADMIN,
                "sudo_set_subnet_emission_enabled",
                {"netuid": int(netuid), "enabled": bool(enabled)},
            ),
            (
                PALLET_ADMIN,
                "sudo_set_subnet_emission_enabled",
                {"netuid": int(netuid), "subnet_emission_enabled": bool(enabled)},
            ),
            (
                PALLET_ADMIN,
                "sudo_set_subnet_emission_enabled",
                {"netuid": int(netuid), "emission_enabled": bool(enabled)},
            ),
        ],
    )


def wait_until_enabled_state(
    substrate: SubstrateInterface,
    netuid: int,
    expected: bool,
    timeout_sec: float,
    poll_sec: float,
) -> None:
    deadline = time.monotonic() + max(1.0, float(timeout_sec))

    while True:
        actual = subnet_emission_enabled(substrate, netuid)
        if actual == expected:
            return

        if time.monotonic() >= deadline:
            raise ScriptTimeout(
                f"timed out waiting for SubnetEmissionEnabled[{netuid}]={expected}; actual={actual}"
            )

        time.sleep(max(0.1, float(poll_sec)))


def set_subnet_emission_enabled(
    substrate: SubstrateInterface,
    signer: Any,
    netuid: int,
    enabled: bool,
    retries: int,
    retry_wait_blocks: int,
    poll_sec: float,
    storage_wait_sec: float,
) -> None:
    for attempt in range(1, max(1, retries) + 1):
        call, call_name = compose_set_subnet_emission_enabled(substrate, netuid, enabled)

        try:
            rec = submit(substrate, signer, call, allow_failed=True)

            if rec.is_success:
                included_block = block_number_at(substrate, rec.block_hash)
                log(f"{call_name}(netuid={netuid}, enabled={enabled}) included in block {included_block}")
                wait_until_enabled_state(
                    substrate,
                    netuid,
                    enabled,
                    timeout_sec=storage_wait_sec,
                    poll_sec=poll_sec,
                )
                return

            error_message = simplify_error_message(getattr(rec, "error_message", ""))
            log(f"{call_name}(netuid={netuid}, enabled={enabled}) failed attempt {attempt}/{retries}: {error_message}")

            if not is_rate_limit_error(error_message) or attempt >= retries:
                raise RuntimeError(error_message or "extrinsic failed")

        except Exception as exc:
            msg = simplify_error_message(exc)
            log(f"{call_name}(netuid={netuid}, enabled={enabled}) error attempt {attempt}/{retries}: {msg}")

            if not is_rate_limit_error(msg) or attempt >= retries:
                raise

        wait_for_blocks(substrate, retry_wait_blocks, poll_sec)

    raise RuntimeError(f"failed to set SubnetEmissionEnabled={enabled} on netuid {netuid}")


def absolute_and_relative_tolerance(
    expected: int,
    decimals: int,
    relative_pct: float,
    absolute_tao: float,
) -> int:
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


def assert_disabled_target(before: Snapshot, after: Snapshot, netuid: int) -> None:
    before_row = before.target_row
    after_row = after.target_row

    before_pool = before.target_pool_tao
    after_pool = after.target_pool_tao

    assert_eq(after_row["enabled"], False, f"netuid {netuid} should be disabled")
    assert_eq(after_row["tao_in"], 0, f"disabled netuid {netuid} must have zero SubnetTaoInEmission")
    assert_eq(after_row["alpha_in"], 0, f"disabled netuid {netuid} must have zero SubnetAlphaInEmission")
    assert_eq(after_row["excess_tao"], 0, f"disabled netuid {netuid} must have zero SubnetExcessTao")
    assert_eq(after_pool, 0, f"disabled netuid {netuid} must have zero TAO-side pool emission")

    if int(before_row["alpha_out"]) > 0:
        assert_true(
            int(after_row["alpha_out"]) > 0,
            f"disabled netuid {netuid} should still keep alpha_out path non-zero",
        )

    if before_pool > 0:
        assert_true(
            after.other_pool_tao > before.other_pool_tao,
            (
                f"other subnets did not receive redistributed TAO-side emission after disabling {netuid}\n"
                f"  before_other_pool={before.other_pool_tao}\n"
                f"  after_other_pool={after.other_pool_tao}\n"
                f"  disabled_baseline_pool={before_pool}"
            ),
        )
    else:
        log(
            f"netuid {netuid} had zero baseline TAO-side pool emission; "
            "skipping direct other-subnet-increase assertion and relying on aggregate before/after preservation."
        )


def assert_enabled_target_restored(restored: Snapshot, baseline: Snapshot, netuid: int) -> None:
    row = restored.target_row
    pool = restored.target_pool_tao

    assert_eq(row["enabled"], True, f"netuid {netuid} should be re-enabled")

    if baseline.target_pool_tao > 0:
        assert_true(pool > 0, f"re-enabled netuid {netuid} should have positive TAO-side pool emission")

    if int(baseline.target_row["alpha_in"]) > 0:
        assert_true(int(row["alpha_in"]) > 0, f"re-enabled netuid {netuid} should have positive alpha_in")

    if int(baseline.target_row["alpha_out"]) > 0:
        assert_true(int(row["alpha_out"]) > 0, f"re-enabled netuid {netuid} should have positive alpha_out")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Testnet integration test for AdminUtils.sudo_set_subnet_emission_enabled on netuid 453"
    )
    parser.add_argument("--ws", default=DEFAULT_WS)
    parser.add_argument("--netuid", type=int, default=DEFAULT_NETUID)
    parser.add_argument("--wallet-name", default=DEFAULT_WALLET_NAME)
    parser.add_argument("--hotkey-name", default=DEFAULT_HOTKEY_NAME)
    parser.add_argument("--wallet-path", default=DEFAULT_WALLET_PATH)
    parser.add_argument("--coldkey-password", default=None)
    parser.add_argument("--hotkey-password", default=None)
    parser.add_argument("--coldkey-uri", default=None, help="Optional fallback SURI; normally not used for real testnet wallets.")
    parser.add_argument("--expected-coldkey-ss58", default=EXPECTED_COLDKEY_SS58)
    parser.add_argument("--expected-hotkey-ss58", default=EXPECTED_HOTKEY_SS58)
    parser.add_argument("--wait-blocks", type=int, default=DEFAULT_WAIT_BLOCKS)
    parser.add_argument("--poll-sec", type=float, default=DEFAULT_POLL_SEC)
    parser.add_argument("--set-retries", type=int, default=DEFAULT_SET_RETRIES)
    parser.add_argument("--retry-wait-blocks", type=int, default=DEFAULT_RETRY_WAIT_BLOCKS)
    parser.add_argument("--storage-wait-sec", type=float, default=DEFAULT_STORAGE_WAIT_SEC)
    parser.add_argument("--map-query-timeout-sec", type=float, default=DEFAULT_MAP_QUERY_TIMEOUT_SEC)
    parser.add_argument("--relative-tolerance-pct", type=float, default=DEFAULT_RELATIVE_TOLERANCE_PCT)
    parser.add_argument("--absolute-tolerance-tao", type=float, default=DEFAULT_ABSOLUTE_TOLERANCE_TAO)
    args = parser.parse_args()

    coldkey_password = (
        args.coldkey_password
        or env_password(args.wallet_name, "COLDKEY")
        or env_password(args.wallet_name, "COLD")
    )
    hotkey_password = (
        args.hotkey_password
        or env_password(args.wallet_name, "HOTKEY")
        or env_password(args.wallet_name, "HOT")
    )

    banner("SubnetEmissionEnabled testnet test")
    log(f"endpoint: {args.ws}")
    log(f"netuid:   {args.netuid}")
    log(f"wallet:   {args.wallet_name} / {args.hotkey_name}")

    substrate = connect(args.ws)
    decimals = token_decimals(substrate)

    coldkey, hotkey = load_wallet_keypairs(
        wallet_name=args.wallet_name,
        hotkey_name=args.hotkey_name,
        wallet_path=args.wallet_path,
        coldkey_password=coldkey_password,
        hotkey_password=hotkey_password,
        coldkey_uri=args.coldkey_uri,
    )

    log(f"loaded coldkey: {coldkey.ss58_address}")
    log(f"loaded hotkey:  {hotkey.ss58_address}")

    verify_wallet_and_chain_owner(
        substrate=substrate,
        netuid=args.netuid,
        coldkey=coldkey,
        hotkey=hotkey,
        expected_coldkey_ss58=args.expected_coldkey_ss58,
        expected_hotkey_ss58=args.expected_hotkey_ss58,
    )

    log("Checking target subnet eligibility ...")
    assert_true(subnet_exists(substrate, args.netuid), f"netuid {args.netuid} does not exist")
    assert_true(
        first_emission_block(substrate, args.netuid) is not None,
        f"netuid {args.netuid} has no FirstEmissionBlockNumber; run btcli subnet start first",
    )
    assert_true(
        subtoken_enabled(substrate, args.netuid),
        f"netuid {args.netuid} has SubtokenEnabled=false; it is not emission-eligible",
    )

    original_enabled = subnet_emission_enabled(substrate, args.netuid)
    log(f"original SubnetEmissionEnabled[{args.netuid}] = {original_enabled}")

    try:
        if not original_enabled:
            banner("Enabling subnet first to build enabled baseline")
            set_subnet_emission_enabled(
                substrate=substrate,
                signer=coldkey,
                netuid=args.netuid,
                enabled=True,
                retries=args.set_retries,
                retry_wait_blocks=args.retry_wait_blocks,
                poll_sec=args.poll_sec,
                storage_wait_sec=args.storage_wait_sec,
            )
            wait_for_blocks(substrate, args.wait_blocks, args.poll_sec)

        banner("Reading enabled baseline")
        baseline = take_snapshot(
            substrate,
            "baseline-enabled",
            args.netuid,
            map_query_timeout_sec=args.map_query_timeout_sec,
        )
        print_snapshot(baseline, decimals)

        banner(f"Disabling pool-side emission on netuid {args.netuid}")
        set_subnet_emission_enabled(
            substrate=substrate,
            signer=coldkey,
            netuid=args.netuid,
            enabled=False,
            retries=args.set_retries,
            retry_wait_blocks=args.retry_wait_blocks,
            poll_sec=args.poll_sec,
            storage_wait_sec=args.storage_wait_sec,
        )
        wait_for_blocks(substrate, args.wait_blocks, args.poll_sec)

        disabled = take_snapshot(
            substrate,
            "disabled-target",
            args.netuid,
            map_query_timeout_sec=args.map_query_timeout_sec,
        )
        print_snapshot(disabled, decimals)

        assert_disabled_target(baseline, disabled, args.netuid)
        assert_total_pool_preserved(
            before=baseline,
            after=disabled,
            decimals=decimals,
            relative_pct=args.relative_tolerance_pct,
            absolute_tao=args.absolute_tolerance_tao,
            label=f"after disabling netuid {args.netuid}",
        )

        if original_enabled:
            banner(f"Re-enabling pool-side emission on netuid {args.netuid}")
            set_subnet_emission_enabled(
                substrate=substrate,
                signer=coldkey,
                netuid=args.netuid,
                enabled=True,
                retries=args.set_retries,
                retry_wait_blocks=args.retry_wait_blocks,
                poll_sec=args.poll_sec,
                storage_wait_sec=args.storage_wait_sec,
            )
            wait_for_blocks(substrate, args.wait_blocks, args.poll_sec)

            restored_snapshot = take_snapshot(
                substrate,
                "restored-enabled",
                args.netuid,
                map_query_timeout_sec=args.map_query_timeout_sec,
            )
            print_snapshot(restored_snapshot, decimals)

            assert_enabled_target_restored(restored_snapshot, baseline, args.netuid)
            assert_total_pool_preserved(
                before=baseline,
                after=restored_snapshot,
                decimals=decimals,
                relative_pct=args.relative_tolerance_pct,
                absolute_tao=args.absolute_tolerance_tao,
                label=f"after re-enabling netuid {args.netuid}",
            )

        banner("All SubnetEmissionEnabled testnet assertions passed")

    finally:
        try:
            current_enabled = subnet_emission_enabled(substrate, args.netuid)
        except Exception as exc:
            log(f"Could not read final SubnetEmissionEnabled state: {simplify_error_message(exc)}")
            current_enabled = None

        if current_enabled is not None and current_enabled != original_enabled:
            banner(f"Restoring original SubnetEmissionEnabled[{args.netuid}]={original_enabled}")
            try:
                set_subnet_emission_enabled(
                    substrate=substrate,
                    signer=coldkey,
                    netuid=args.netuid,
                    enabled=original_enabled,
                    retries=args.set_retries,
                    retry_wait_blocks=args.retry_wait_blocks,
                    poll_sec=args.poll_sec,
                    storage_wait_sec=args.storage_wait_sec,
                )
                wait_for_blocks(substrate, args.wait_blocks, args.poll_sec)
            except Exception as exc:
                log(
                    "WARNING: failed to restore original state. "
                    f"SubnetEmissionEnabled[{args.netuid}] may still be {current_enabled}. "
                    f"Error: {simplify_error_message(exc)}"
                )

        try:
            final_enabled = subnet_emission_enabled(substrate, args.netuid)
            log(f"final SubnetEmissionEnabled[{args.netuid}] = {final_enabled}")
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