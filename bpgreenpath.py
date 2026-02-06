#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Green-path E2E: Utility.batch and Proxy.proxy still work with inner call = Subtensor::add_stake.

This version FIXES your case where:
  - start_call failed with SubtensorModule.SubnetNotExists
  - add_stake (inside Utility.batch) failed with a raw Module error like:
      {'Module': {'index': 7, 'error': '0x5b000000'}}
    (which your node decodes as SubtensorModule.SubtokenDisabled)

Key fixes:
  1) We do NOT assume the requested --netuid exists.
     We proactively ensure a usable subnet by:
       - trying start_call(netuid)
       - if that errors with SubnetNotExists (or we can’t prove netuid exists),
         we register a NEW subnet via register_network(hotkey=HOT),
         then call start_call(new_netuid).
  2) We decode Module errors using py-substrate-interface helpers when available
     (get_runtime_error / get_metadata_error), and fall back safely.
  3) Even if the BatchInterrupted error stays “raw”, we still remediate once
     by creating a new subnet we own and retrying.

Assertions:
  - Utility.batch([add_stake]) must produce Utility::BatchCompleted (not BatchInterrupted)
  - Proxy.proxy(real=COLD, call=add_stake) must produce Proxy::ProxyExecuted(Ok)
  - Best-effort: Stake increases (if Stake storage can be read)

Deps:
  pip install substrate-interface

Usage:
  python3 bpgreenpath.py --ws ws://127.0.0.1:9945
"""

import argparse
import time
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException


# ──────────────────────────────────────────────────────────────────────────────
# Connection / chain helpers
# ──────────────────────────────────────────────────────────────────────────────

def connect(url: str) -> SubstrateInterface:
    si = SubstrateInterface(url=url)
    last_err = None
    for _ in range(40):
        try:
            si.init_runtime()
            _ = si.get_metadata()
            return si
        except Exception as e:
            last_err = e
            time.sleep(0.25)
    raise RuntimeError(f"Could not init runtime/metadata from {url}: {last_err}")


def token_decimals(substrate: SubstrateInterface) -> int:
    d = getattr(substrate, "token_decimals", 9)
    if isinstance(d, list) and d and isinstance(d[0], int):
        return int(d[0])
    if isinstance(d, int):
        return int(d)
    return 9


def get_block_number(substrate: SubstrateInterface, block_hash: str) -> int:
    try:
        hdr = substrate.get_block_header(block_hash=block_hash)
    except Exception:
        return 0
    v = getattr(hdr, "value", hdr)
    if isinstance(v, dict) and "header" in v:
        v = v["header"]
    if not isinstance(v, dict):
        return 0
    n = v.get("number")
    if isinstance(n, int):
        return n
    if isinstance(n, str):
        s = n.strip()
        if s.startswith(("0x", "0X")):
            try:
                return int(s, 16)
            except Exception:
                return 0
        try:
            return int(s)
        except Exception:
            return 0
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Compose/submit helpers
# ──────────────────────────────────────────────────────────────────────────────

def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def submit_signed(
    substrate: SubstrateInterface,
    who: Keypair,
    call,
    wait_finalization: bool,
):
    xt = substrate.create_signed_extrinsic(call=call, keypair=who, era="00")
    try:
        rec = substrate.submit_extrinsic(
            xt, wait_for_inclusion=True, wait_for_finalization=bool(wait_finalization)
        )
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e
    return rec


def try_compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]) -> bool:
    try:
        _ = substrate.compose_call(call_module=module, call_function=function, call_params=params)
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Funding helpers (local/dev friendly)
# ──────────────────────────────────────────────────────────────────────────────

def account_free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0


def transfer_keep_alive(
    substrate: SubstrateInterface,
    signer: Keypair,
    dest_ss58: str,
    amount_planck: int,
    wait_finalization: bool,
) -> None:
    amount_planck = int(amount_planck)
    call = None
    for fn in ("transfer_keep_alive", "transfer"):
        try:
            call = compose_call(substrate, "Balances", fn, {"dest": dest_ss58, "value": amount_planck})
            break
        except Exception:
            call = None
    if call is None:
        raise RuntimeError("Could not compose Balances::transfer_keep_alive or Balances::transfer")

    rec = submit_signed(substrate, signer, call, wait_finalization=wait_finalization)
    if not getattr(rec, "is_success", False):
        raise RuntimeError(f"Balances transfer failed: {getattr(rec, 'error_message', None)}")


def ensure_funded_planck(
    substrate: SubstrateInterface,
    faucet: Keypair,
    dest_ss58: str,
    min_balance_planck: int,
    wait_finalization: bool,
) -> None:
    have = account_free_balance(substrate, dest_ss58)
    need = int(min_balance_planck)
    if have >= need:
        return
    delta = int((need - have) * 1.1) + 1  # 10% headroom
    transfer_keep_alive(substrate, faucet, dest_ss58, delta, wait_finalization=wait_finalization)


# ──────────────────────────────────────────────────────────────────────────────
# Event parsing + DispatchError decoding
# ──────────────────────────────────────────────────────────────────────────────

def unwrap_value(x: Any) -> Any:
    if x is None:
        return None
    if isinstance(x, dict) and "value" in x:
        return x["value"]
    if hasattr(x, "value"):
        try:
            return x.value
        except Exception:
            return x
    return x


def normalize_event(rec: Any) -> Tuple[Optional[str], Optional[str], Any]:
    v = getattr(rec, "value", rec)
    if not isinstance(v, dict):
        return None, None, None

    ev = v.get("event", v)
    ev = getattr(ev, "value", ev)
    if not isinstance(ev, dict):
        return None, None, None

    section = (
        ev.get("section")
        or ev.get("module_id")
        or ev.get("pallet")
        or ev.get("module")
        or ev.get("call_module")
    )
    method = (
        ev.get("method")
        or ev.get("event_id")
        or ev.get("event")
        or ev.get("name")
    )

    data = None
    for key in ("data", "attributes", "params", "values"):
        if key in ev:
            data = ev.get(key)
            break

    return (
        str(section) if section is not None else None,
        str(method) if method is not None else None,
        data,
    )


def has_event(events: list, section: str, method: str) -> bool:
    for rec in events or []:
        sec, meth, _ = normalize_event(rec)
        if sec == section and meth == method:
            return True
    return False


def extract_batch_interrupted_error_raw(events: list) -> Optional[Any]:
    """
    Utility::BatchInterrupted { index, error }
    Return raw 'error' which often looks like:
      {'Module': {'index': 7, 'error': '0x5b000000'}}
    """
    for rec in events or []:
        sec, meth, data = normalize_event(rec)
        if sec != "Utility" or meth != "BatchInterrupted":
            continue
        data = unwrap_value(data)
        if isinstance(data, dict):
            return unwrap_value(data.get("error"))
        if isinstance(data, list) and len(data) >= 2:
            return unwrap_value(data[1])
        return data
    return None


def extract_proxy_executed_result_raw(events: list) -> Tuple[bool, Optional[Any]]:
    """
    Proxy::ProxyExecuted { result: DispatchResult }
    Return (ok, err_raw)
    """
    for rec in events or []:
        sec, meth, data = normalize_event(rec)
        if sec != "Proxy" or meth != "ProxyExecuted":
            continue
        data = unwrap_value(data)
        if isinstance(data, dict):
            r = unwrap_value(data.get("result"))
            if isinstance(r, dict) and "Ok" in r:
                return True, None
            if isinstance(r, dict) and "Err" in r:
                return False, unwrap_value(r.get("Err"))
            return False, r
        if isinstance(data, list) and data:
            r0 = unwrap_value(data[0])
            if isinstance(r0, dict) and "Ok" in r0:
                return True, None
            if isinstance(r0, dict) and "Err" in r0:
                return False, unwrap_value(r0.get("Err"))
            return False, r0
        return False, data
    return False, None


def _as_int(x: Any) -> Optional[int]:
    x = unwrap_value(x)
    if x is None:
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        if not s:
            return None
        if s.startswith(("0x", "0X")):
            try:
                return int(s, 16)
            except Exception:
                return None
        try:
            return int(s)
        except Exception:
            return None
    return None


def _hex_to_bytes(x: Any) -> Optional[bytes]:
    x = unwrap_value(x)
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    if isinstance(x, str):
        s = x.strip()
        if s.startswith(("0x", "0X")):
            s = s[2:]
        if not s:
            return b""
        try:
            return bytes.fromhex(s)
        except Exception:
            return None
    return None


def extract_module_error_indices(err: Any) -> Optional[Tuple[int, int]]:
    """
    From {'Module': {'index': <pallet_index>, 'error': '0x....'}} -> (pallet_index, error_index_u32)
    """
    err = unwrap_value(err)
    if not isinstance(err, dict) or "Module" not in err:
        return None
    m = unwrap_value(err.get("Module"))
    if not isinstance(m, dict):
        return None
    pallet_index = _as_int(m.get("index"))
    err_bytes = _hex_to_bytes(m.get("error"))
    if pallet_index is None or err_bytes is None:
        return None
    if len(err_bytes) >= 4:
        error_index = int.from_bytes(err_bytes[:4], "little", signed=False)
    else:
        error_index = int.from_bytes(err_bytes, "little", signed=False)
    return int(pallet_index), int(error_index)


def decode_dispatch_error(substrate: SubstrateInterface, err: Any) -> str:
    """
    Best-effort turn err into 'Pallet.ErrorName' using py-substrate-interface helpers
    when possible. Falls back to stringified raw error.
    """
    err = unwrap_value(err)
    if err is None:
        return "None"
    if isinstance(err, str):
        return err

    mi = extract_module_error_indices(err)
    if mi is None:
        return str(err)

    pallet_index, error_index = mi

    # Prefer library helpers (these are the most reliable across metadata formats)
    for helper in ("get_runtime_error", "get_metadata_error"):
        fn = getattr(substrate, helper, None)
        if fn is None:
            continue
        try:
            out = fn(pallet_index, error_index)
            # out might be dict, tuple, or object
            if isinstance(out, dict):
                pallet = out.get("pallet") or out.get("module") or out.get("section") or out.get("pallet_name")
                name = out.get("name") or out.get("error") or out.get("error_name")
                if pallet and name:
                    return f"{pallet}.{name}"
                if name:
                    return str(name)
            if isinstance(out, (list, tuple)) and len(out) >= 2:
                pallet = out[0]
                name = out[1]
                if pallet and name:
                    return f"{pallet}.{name}"
            if hasattr(out, "pallet") and hasattr(out, "name"):
                return f"{getattr(out, 'pallet')}.{getattr(out, 'name')}"
            if hasattr(out, "module") and hasattr(out, "name"):
                return f"{getattr(out, 'module')}.{getattr(out, 'name')}"
            if hasattr(out, "name"):
                return str(getattr(out, "name"))
        except Exception:
            pass

    # Manual metadata scan fallback
    try:
        md = substrate.get_metadata()
        pallets = getattr(md, "pallets", None) or []
        for p in pallets:
            p_idx = getattr(p, "index", None)
            p_idx = _as_int(getattr(p_idx, "value", p_idx))
            if p_idx != pallet_index:
                continue
            pallet_name = str(getattr(p, "name", f"pallet_{pallet_index}"))
            errors = getattr(p, "errors", None) or getattr(p, "error", None)
            if errors is not None:
                try:
                    if 0 <= error_index < len(errors):
                        e_meta = errors[error_index]
                        e_name = getattr(e_meta, "name", None)
                        if e_name is None and isinstance(e_meta, dict):
                            e_name = e_meta.get("name")
                        if e_name:
                            return f"{pallet_name}.{e_name}"
                except Exception:
                    pass
            return f"{pallet_name}.Error({error_index})"
    except Exception:
        pass

    return str(err)


def err_has(decoded: str, needle: str) -> bool:
    return needle.lower() in (decoded or "").lower()


# ──────────────────────────────────────────────────────────────────────────────
# Subtensor helpers: resolve pallet + subnet preparation
# ──────────────────────────────────────────────────────────────────────────────

def resolve_subtensor_pallet(substrate: SubstrateInterface) -> str:
    md = substrate.get_metadata()
    for p in getattr(md, "pallets", []) or []:
        name = str(getattr(p, "name", ""))
        if "subtensor" not in name.lower():
            continue
        # Probe compose
        if try_compose_call(substrate, name, "add_stake",
                            {"hotkey": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "netuid": 0, "amount_staked": 0}):
            return name
        if try_compose_call(substrate, name, "add_stake",
                            {"hotkey": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "netuid": 0, "amount": 0}):
            return name
        if try_compose_call(substrate, name, "add_stake",
                            {"hotkey": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "netuid": 0, "value": 0}):
            return name
    for fallback in ("SubtensorModule", "Subtensor"):
        try:
            substrate.get_metadata_call_function(fallback, "add_stake")
            return fallback
        except Exception:
            pass
    raise RuntimeError("Could not resolve Subtensor pallet exposing add_stake")


def networks_added_dynamic(substrate: SubstrateInterface, subtensor: str) -> List[int]:
    """
    Best-effort read NetworksAdded keys.
    If unreadable, returns [].
    """
    nets: List[int] = []
    try:
        for key, val in substrate.query_map(subtensor, "NetworksAdded"):
            if not val or val.value is None:
                continue
            if not bool(val.value):
                continue
            kv = key.value
            try:
                if isinstance(kv, dict) and "NetUid" in kv:
                    n = int(kv["NetUid"])
                else:
                    n = int(kv)
                if n != 0:
                    nets.append(n)
            except Exception:
                continue
    except Exception:
        pass
    return sorted(set(nets))


def register_new_subnet(
    substrate: SubstrateInterface,
    subtensor: str,
    owner_cold: Keypair,
    owner_hot_ss58: str,
    wait_finalization: bool,
) -> int:
    before = set(networks_added_dynamic(substrate, subtensor))
    call = compose_call(substrate, subtensor, "register_network", {"hotkey": owner_hot_ss58})
    rec = submit_signed(substrate, owner_cold, call, wait_finalization=wait_finalization)
    if not getattr(rec, "is_success", False):
        raise RuntimeError(f"{subtensor}.register_network failed: {getattr(rec, 'error_message', None)}")

    after = set(networks_added_dynamic(substrate, subtensor))
    new_nets = sorted(after - before)
    if new_nets:
        return int(new_nets[-1])
    if after:
        return int(max(after))
    raise RuntimeError("register_network succeeded but could not detect new netuid")


def try_start_call(
    substrate: SubstrateInterface,
    subtensor: str,
    cold: Keypair,
    netuid: int,
    wait_finalization: bool,
) -> Tuple[bool, str]:
    """
    Best-effort enable subtoken; returns (ok, decoded_err_or_ok_string).
    """
    candidates = ["start_call", "start_subnet", "enable_subtoken", "activate_subnet"]
    for fn in candidates:
        if not try_compose_call(substrate, subtensor, fn, {"netuid": int(netuid)}):
            continue
        call = compose_call(substrate, subtensor, fn, {"netuid": int(netuid)})
        rec = submit_signed(substrate, cold, call, wait_finalization=wait_finalization)
        if getattr(rec, "is_success", False):
            return True, "Ok"
        # error_message is often already "SubtensorModule.SubnetNotExists" etc
        em = str(getattr(rec, "error_message", "") or "")
        return False, em or "Failed"
    return False, "NoStartCallExtrinsicFound"


def ensure_hotkey_registered(
    substrate: SubstrateInterface,
    subtensor: str,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    wait_finalization: bool,
) -> None:
    # Best-effort burned_register(netuid, hotkey)
    if not try_compose_call(substrate, subtensor, "burned_register", {"netuid": int(netuid), "hotkey": hot_ss58}):
        return
    try:
        call = compose_call(substrate, subtensor, "burned_register", {"netuid": int(netuid), "hotkey": hot_ss58})
        rec = submit_signed(substrate, cold, call, wait_finalization=wait_finalization)
        # ignore failure (already registered, etc.)
        _ = rec
    except Exception:
        pass


def ensure_subnet_ready(
    substrate: SubstrateInterface,
    subtensor: str,
    cold: Keypair,
    hot_ss58: str,
    requested_netuid: int,
    wait_finalization: bool,
) -> int:
    """
    Ensure we have a netuid that:
      - exists (otherwise we create a new subnet we own)
      - has start_call executed (best-effort; if not found we still proceed)
    """
    netuid = int(requested_netuid)

    # If NetworksAdded is readable and clearly indicates netuid does not exist, create.
    nets = networks_added_dynamic(substrate, subtensor)
    if nets and netuid not in nets:
        # requested net doesn't exist -> create new
        new_netuid = register_new_subnet(substrate, subtensor, cold, hot_ss58, wait_finalization)
        ok, msg = try_start_call(substrate, subtensor, cold, new_netuid, wait_finalization)
        # even if start_call fails, we still return new netuid and rely on add_stake retry logic
        ensure_hotkey_registered(substrate, subtensor, cold, hot_ss58, new_netuid, wait_finalization)
        if not ok:
            print(f"[i] start_call(new_netuid={new_netuid}) failed: {msg}")
        return new_netuid

    # Otherwise: try start_call on requested netuid; if it says SubnetNotExists, create new.
    ok, msg = try_start_call(substrate, subtensor, cold, netuid, wait_finalization)
    if not ok and err_has(msg, "SubnetNotExists"):
        new_netuid = register_new_subnet(substrate, subtensor, cold, hot_ss58, wait_finalization)
        ok2, msg2 = try_start_call(substrate, subtensor, cold, new_netuid, wait_finalization)
        ensure_hotkey_registered(substrate, subtensor, cold, hot_ss58, new_netuid, wait_finalization)
        if not ok2:
            print(f"[i] start_call(new_netuid={new_netuid}) failed: {msg2}")
        return new_netuid

    # Net exists (or start_call not available / other error). Register hotkey best-effort and continue.
    ensure_hotkey_registered(substrate, subtensor, cold, hot_ss58, netuid, wait_finalization)
    return netuid


def compose_add_stake_call(
    substrate: SubstrateInterface,
    subtensor: str,
    hot_ss58: str,
    netuid: int,
    amount_planck: int,
):
    last_err = None
    for field in ("amount_staked", "amount", "value"):
        try:
            return substrate.compose_call(
                call_module=subtensor,
                call_function="add_stake",
                call_params={"hotkey": hot_ss58, "netuid": int(netuid), field: int(amount_planck)},
            )
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Unable to compose {subtensor}.add_stake. Last error: {last_err}")


# ──────────────────────────────────────────────────────────────────────────────
# Stake query (best-effort)
# ──────────────────────────────────────────────────────────────────────────────

def _to_int(v: Any) -> Optional[int]:
    v = unwrap_value(v)
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        if s.startswith(("0x", "0X")):
            try:
                return int(s, 16)
            except Exception:
                return None
        try:
            return int(s)
        except Exception:
            return None
    if isinstance(v, dict):
        for k in ("value", "bits", "free", "total", "stake", "amount"):
            if k in v:
                got = _to_int(v[k])
                if got is not None:
                    return got
        if len(v) == 1:
            return _to_int(list(v.values())[0])
    return None


def query_stake_planck(
    substrate: SubstrateInterface,
    subtensor: str,
    cold_ss58: str,
    hot_ss58: str,
    netuid: int,
) -> Optional[int]:
    # Try a few plausible key shapes
    key_candidates = [
        [hot_ss58, int(netuid)],
        [cold_ss58, hot_ss58, int(netuid)],
        [hot_ss58, cold_ss58, int(netuid)],
        [cold_ss58, hot_ss58],
        [hot_ss58, cold_ss58],
    ]
    for keys in key_candidates:
        try:
            v = substrate.query(subtensor, "Stake", keys)
            n = _to_int(getattr(v, "value", v))
            if n is not None:
                return int(n)
        except Exception:
            continue
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Proxy relationship setup
# ──────────────────────────────────────────────────────────────────────────────

def get_proxies_value(substrate: SubstrateInterface, proxy_module: str, real_ss58: str) -> Any:
    q = substrate.query(proxy_module, "Proxies", [real_ss58])
    return getattr(q, "value", q)


def has_delegate_proxy(proxies_value: Any, delegate_ss58: str) -> bool:
    if proxies_value is None:
        return False
    if isinstance(proxies_value, (list, tuple)) and len(proxies_value) >= 1:
        proxies_list = proxies_value[0]
    else:
        return False
    if not isinstance(proxies_list, list):
        return False
    for item in proxies_list:
        if isinstance(item, dict):
            d = item.get("delegate") or item.get("delegatee")
            if d == delegate_ss58:
                return True
    return False


def compose_add_proxy_call_with_candidates(
    substrate: SubstrateInterface,
    proxy_module: str,
    delegate_ss58: str,
    delay: int,
    proxy_type_str: str,
):
    cand_keys: List[Any] = []
    s = (proxy_type_str or "").strip()
    if s:
        cand_keys.extend([s, s.lower(), s.capitalize()])
    cand_keys.extend(["Any", "any"])

    candidates: List[Any] = []
    for k in cand_keys:
        candidates.append(k)
        candidates.append({k: None})
        candidates.append({k: {}})
    candidates.append(0)

    last_err = None
    for pt in candidates:
        try:
            return substrate.compose_call(
                call_module=proxy_module,
                call_function="add_proxy",
                call_params={"delegate": delegate_ss58, "proxy_type": pt, "delay": int(delay)},
            )
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Could not compose {proxy_module}.add_proxy. Last error: {last_err}")


def ensure_proxy_relationship(
    substrate: SubstrateInterface,
    proxy_module: str,
    real_kp: Keypair,
    delegate_ss58: str,
    proxy_type_str: str,
    wait_finalization: bool,
) -> None:
    proxies_val = get_proxies_value(substrate, proxy_module, real_kp.ss58_address)
    if has_delegate_proxy(proxies_val, delegate_ss58):
        return
    add_call = compose_add_proxy_call_with_candidates(
        substrate, proxy_module, delegate_ss58, delay=0, proxy_type_str=proxy_type_str
    )
    rec = submit_signed(substrate, real_kp, add_call, wait_finalization=wait_finalization)
    if not getattr(rec, "is_success", False):
        raise RuntimeError(f"add_proxy failed: {getattr(rec, 'error_message', None)}")


# ──────────────────────────────────────────────────────────────────────────────
# One-shot executions
# ──────────────────────────────────────────────────────────────────────────────

def run_batch_add_stake_once(
    substrate: SubstrateInterface,
    utility_module: str,
    cold: Keypair,
    add_stake_call,
    wait_finalization: bool,
) -> Tuple[Any, bool, str]:
    batch_call = compose_call(substrate, utility_module, "batch", {"calls": [add_stake_call]})
    rec = submit_signed(substrate, cold, batch_call, wait_finalization=wait_finalization)
    if not getattr(rec, "is_success", False):
        return rec, False, str(getattr(rec, "error_message", "") or "ExtrinsicFailed")

    events = getattr(rec, "triggered_events", None) or []
    if has_event(events, "Utility", "BatchInterrupted"):
        err_raw = extract_batch_interrupted_error_raw(events)
        decoded = decode_dispatch_error(substrate, err_raw)
        # decoded might still be raw; we return it anyway
        return rec, False, decoded

    if not has_event(events, "Utility", "BatchCompleted"):
        return rec, False, "Missing Utility::BatchCompleted"

    return rec, True, "Ok"


def run_proxy_add_stake_once(
    substrate: SubstrateInterface,
    proxy_module: str,
    real_ss58: str,
    delegate: Keypair,
    add_stake_call,
    wait_finalization: bool,
) -> Tuple[Any, bool, str]:
    proxy_call = compose_call(
        substrate, proxy_module, "proxy",
        {"real": real_ss58, "force_proxy_type": None, "call": add_stake_call},
    )
    rec = submit_signed(substrate, delegate, proxy_call, wait_finalization=wait_finalization)
    if not getattr(rec, "is_success", False):
        return rec, False, str(getattr(rec, "error_message", "") or "ExtrinsicFailed")

    events = getattr(rec, "triggered_events", None) or []
    ok, err_raw = extract_proxy_executed_result_raw(events)
    if ok:
        return rec, True, "Ok"
    decoded = decode_dispatch_error(substrate, err_raw)
    return rec, False, decoded


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="E2E: Utility.batch + Proxy.proxy greenpath with Subtensor::add_stake inner call.")
    ap.add_argument("--ws", default="ws://127.0.0.1:9945")
    ap.add_argument("--wait-finalization", action="store_true")

    ap.add_argument("--faucet-uri", default="//Alice")
    ap.add_argument("--cold-uri", default="//Alice")
    ap.add_argument("--delegate-uri", default="//Bob")
    ap.add_argument("--hot-uri", default="//Charlie")

    ap.add_argument("--utility-module", default="Utility")
    ap.add_argument("--proxy-module", default="Proxy")
    ap.add_argument("--proxy-type", default="Any")

    ap.add_argument("--netuid", type=int, default=3)
    ap.add_argument("--stake-tao", type=float, default=1.0)
    ap.add_argument("--lock-fund-hint-tao", type=float, default=5000.0)

    args = ap.parse_args()

    substrate = connect(args.ws)
    decimals = token_decimals(substrate)

    faucet = Keypair.create_from_uri(args.faucet_uri)
    cold = Keypair.create_from_uri(args.cold_uri)
    delegate = Keypair.create_from_uri(args.delegate_uri)
    hot = Keypair.create_from_uri(args.hot_uri)

    subtensor = resolve_subtensor_pallet(substrate)

    amount_planck = int(round(float(args.stake_tao) * (10 ** decimals)))
    if amount_planck <= 0:
        raise RuntimeError("--stake-tao must be > 0")

    # Fund cold/delegate enough for stake + fees + (possibly) subnet registration lock.
    cold_min = max(
        amount_planck * 3,
        int(50 * (10 ** decimals)),
        int(args.lock_fund_hint_tao * (10 ** decimals)),
    )
    delegate_min = int(10 * (10 ** decimals))
    ensure_funded_planck(substrate, faucet, cold.ss58_address, cold_min, wait_finalization=bool(args.wait_finalization))
    ensure_funded_planck(substrate, faucet, delegate.ss58_address, delegate_min, wait_finalization=bool(args.wait_finalization))

    # Ensure proxy relationship exists (cold -> delegate)
    ensure_proxy_relationship(
        substrate,
        proxy_module=args.proxy_module,
        real_kp=cold,
        delegate_ss58=delegate.ss58_address,
        proxy_type_str=str(args.proxy_type),
        wait_finalization=bool(args.wait_finalization),
    )

    # Ensure we have a netuid that actually exists (fixes SubnetNotExists) and is usable.
    netuid = ensure_subnet_ready(
        substrate,
        subtensor=subtensor,
        cold=cold,
        hot_ss58=hot.ss58_address,
        requested_netuid=int(args.netuid),
        wait_finalization=bool(args.wait_finalization),
    )

    print(f"[i] Using {subtensor}::add_stake  hot={hot.ss58_address}  netuid={netuid}  amount={amount_planck} planck")

    stake_before = query_stake_planck(substrate, subtensor, cold.ss58_address, hot.ss58_address, netuid) or 0
    print(f"[i] stake_before: {stake_before}")

    def build_add_stake() -> Any:
        return compose_add_stake_call(substrate, subtensor, hot.ss58_address, netuid, amount_planck)

    # ── A) Utility.batch([add_stake]) with ONE remediation retry ──────────────
    add_stake_call = build_add_stake()
    rec_batch, ok_batch, batch_msg = run_batch_add_stake_once(
        substrate, args.utility_module, cold, add_stake_call, wait_finalization=bool(args.wait_finalization)
    )

    if not ok_batch:
        # If it smells like subnet/subtoken issues OR decoding is not available, remediate once.
        if (err_has(batch_msg, "SubtokenDisabled")
            or err_has(batch_msg, "SubnetNotExists")
            or err_has(batch_msg, "Module")  # undecoded Module error; treat as likely subnet readiness issue
            or ("{'Module':" in batch_msg)):  # raw dict stringified
            # Create a NEW subnet we own and retry once.
            new_netuid = register_new_subnet(substrate, subtensor, cold, hot.ss58_address, wait_finalization=bool(args.wait_finalization))
            _ok, _msg = try_start_call(substrate, subtensor, cold, new_netuid, wait_finalization=bool(args.wait_finalization))
            ensure_hotkey_registered(substrate, subtensor, cold, hot.ss58_address, new_netuid, wait_finalization=bool(args.wait_finalization))
            netuid = new_netuid

            # Recompute stake_before under the new netuid (correctness)
            stake_before = query_stake_planck(substrate, subtensor, cold.ss58_address, hot.ss58_address, netuid) or 0

            add_stake_call = build_add_stake()
            rec_batch, ok_batch, batch_msg = run_batch_add_stake_once(
                substrate, args.utility_module, cold, add_stake_call, wait_finalization=bool(args.wait_finalization)
            )

    if not ok_batch:
        raise RuntimeError(f"Utility.batch inner add_stake failed: {batch_msg}")

    bn_batch = get_block_number(substrate, rec_batch.block_hash)
    print(f"[✓] Utility.batch(add_stake) included in block #{bn_batch}")

    stake_after_batch = query_stake_planck(substrate, subtensor, cold.ss58_address, hot.ss58_address, netuid)
    if stake_after_batch is not None:
        if stake_after_batch < stake_before + amount_planck:
            raise RuntimeError(
                f"Stake did not increase as expected after batch. "
                f"before={stake_before}, after={stake_after_batch}, expected_at_least={stake_before + amount_planck}"
            )

    # ── B) Proxy.proxy(real=cold, call=add_stake) ─────────────────────────────
    rec_proxy, ok_proxy, proxy_msg = run_proxy_add_stake_once(
        substrate, args.proxy_module, cold.ss58_address, delegate, add_stake_call, wait_finalization=bool(args.wait_finalization)
    )

    if not ok_proxy:
        # If proxy failed due to subnet readiness, try start_call once then retry.
        if err_has(proxy_msg, "SubtokenDisabled") or err_has(proxy_msg, "SubnetNotExists"):
            _ok, _msg = try_start_call(substrate, subtensor, cold, netuid, wait_finalization=bool(args.wait_finalization))
            rec_proxy, ok_proxy, proxy_msg = run_proxy_add_stake_once(
                substrate, args.proxy_module, cold.ss58_address, delegate, add_stake_call, wait_finalization=bool(args.wait_finalization)
            )

    if not ok_proxy:
        raise RuntimeError(f"Proxy.proxy inner add_stake failed: {proxy_msg}")

    bn_proxy = get_block_number(substrate, rec_proxy.block_hash)
    print(f"[✓] Proxy.proxy(add_stake) included in block #{bn_proxy}")

    stake_after_proxy = query_stake_planck(substrate, subtensor, cold.ss58_address, hot.ss58_address, netuid)
    if stake_after_proxy is not None:
        expected_min = stake_before + 2 * amount_planck
        if stake_after_proxy < expected_min:
            raise RuntimeError(
                f"Stake did not increase as expected after proxy. "
                f"before={stake_before}, after={stake_after_proxy}, expected_at_least={expected_min}"
            )

    print("[✓] PASS: Utility.batch and Proxy.proxy both executed add_stake successfully.")


if __name__ == "__main__":
    main()
