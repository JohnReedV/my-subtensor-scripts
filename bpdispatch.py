#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Submit + assert batch/proxy dispatch class + priority (quiet output),
AND also print + assert the priority for the *exact extrinsic bytes that landed in the block*.

Default inner call is an *Operational* one (root-only) to exercise old behavior:
  <auto-detected pallet>.set_pending_childkey_cooldown(cooldown)

We build & submit:
  A) Utility.batch([inner_call])                 signed by --signer-uri (default //Alice)
  B) Proxy.proxy(real=Alice, call=batch_call)    signed by --delegate-uri (default //Bob)

Proxy is auto-setup if needed by submitting Proxy.add_proxy (Alice -> Bob) first.

How we measure:
- Dispatch class (outer) via RPC: payment_queryInfo
- Priority (outer) via runtime API (RPC state_call):
    TaggedTransactionQueue_validate_transaction
  We decode ValidTransaction.priority from SCALE bytes.

No hardcoded priorities:
- Detect validate_transaction arg layout (2-arg vs 3-arg) once.
- Learn the chain’s "Normal-bucket priority" dynamically by probing System.remark.

"In-block priority" assertion (what you asked for):
- After inclusion, we fetch the block body, find the exact submitted extrinsic hex,
  then recompute its priority against the block PARENT state and print it as:
    (block_priority=<n>)
- We assert block_priority == the pre-submit priority we computed for that exact extrinsic bytes.

Output (kept short):
  [i] Inner call: ...
  [✓]/[x] Utility.batch: dispatch_class=Normal|Operational  priority=<pool>
  [✓]/[x] Proxy.proxy:   dispatch_class=Normal|Operational  priority=<pool>
  [i] Utility.batch included in block #... (block_priority=<n>)
  [i] Proxy.proxy included in block #... (block_priority=<n>)
  [✓] All assertions passed.  OR  [!] Assertions failed.

Deps:
  pip install substrate-interface
"""

import argparse
import json
import time
from typing import Any, Dict, Optional, Tuple, List

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException


# ──────────────────────────────────────────────────────────────────────────────
# RPC helpers
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


def rpc_call(substrate: SubstrateInterface, method: str, params: Optional[list] = None) -> Any:
    params = params or []
    try:
        resp = substrate.rpc_request(method, params)
    except SubstrateRequestException as e:
        raise RuntimeError(f"RPC error calling {method}: {e}") from e

    if not isinstance(resp, dict):
        return resp
    if resp.get("error") is not None:
        raise RuntimeError(f"RPC {method} returned error: {resp['error']}")
    return resp.get("result")


def best_hash(substrate: SubstrateInterface) -> str:
    for m in ("chain_getFinalizedHead", "chain_getBlockHash"):
        try:
            h = rpc_call(substrate, m, [])
            if isinstance(h, str) and h.startswith("0x") and len(h) > 10:
                return h
        except Exception:
            pass
    raise RuntimeError("Could not determine chain head hash")


def get_block_number_from_header_number(n: Any) -> int:
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


def get_block_parent_and_extrinsics(substrate: SubstrateInterface, block_hash: str) -> Tuple[str, int, List[str]]:
    res = rpc_call(substrate, "chain_getBlock", [block_hash])
    if not isinstance(res, dict):
        raise RuntimeError(f"chain_getBlock returned non-dict: {res!r}")
    block = res.get("block") or {}
    header = block.get("header") or {}
    parent = header.get("parentHash") or ""
    number = get_block_number_from_header_number(header.get("number"))
    extrinsics = block.get("extrinsics") or []
    if not isinstance(extrinsics, list):
        extrinsics = []
    extrinsics = [x for x in extrinsics if isinstance(x, str)]
    if not (isinstance(parent, str) and parent.startswith("0x") and len(parent) > 10):
        raise RuntimeError(f"Could not read parentHash from chain_getBlock header: {header!r}")
    return parent, number, extrinsics


# ──────────────────────────────────────────────────────────────────────────────
# Small helpers
# ──────────────────────────────────────────────────────────────────────────────

def parse_json_dict(s: str) -> Dict[str, Any]:
    try:
        v = json.loads(s)
    except Exception as e:
        raise RuntimeError(f"--inner-params is not valid JSON: {e}") from e
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise RuntimeError("--inner-params must be a JSON object (dict)")
    return v


def normalize_class(raw: Any) -> str:
    if raw is None:
        return ""
    return str(raw).strip().lower()


def class_bucket(raw_dispatch_class: Any) -> str:
    # Two buckets: Operational vs Normal (everything else)
    return "Operational" if normalize_class(raw_dispatch_class) == "operational" else "Normal"


def hex_to_bytes(hx: str) -> bytes:
    if not isinstance(hx, str) or not hx.startswith("0x"):
        raise ValueError(f"Expected 0x hex, got: {hx!r}")
    return bytes.fromhex(hx[2:])


def bytes_to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def extrinsic_hex(xt: Any) -> str:
    if hasattr(xt, "data"):
        d = getattr(xt, "data")
        if hasattr(d, "to_hex"):
            return d.to_hex()
        if hasattr(d, "toHex"):
            return d.toHex()
        if isinstance(d, str) and d.startswith("0x"):
            return d
    s = str(xt)
    if isinstance(s, str) and s.startswith("0x"):
        return s
    raise RuntimeError("Could not extract extrinsic hex")


def find_extrinsic_index(extrinsics: List[str], xt_hex: str) -> Optional[int]:
    target = (xt_hex or "").lower()
    for i, ex in enumerate(extrinsics):
        if isinstance(ex, str) and ex.lower() == target:
            return i
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Call composition helpers
# ──────────────────────────────────────────────────────────────────────────────

def try_compose_call(
    substrate: SubstrateInterface,
    module: str,
    function: str,
    params: Dict[str, Any],
) -> Optional[Any]:
    try:
        return substrate.compose_call(call_module=module, call_function=function, call_params=params)
    except Exception:
        return None


def resolve_pallet_for_call(
    substrate: SubstrateInterface,
    call_function: str,
    probe_params: Dict[str, Any],
) -> str:
    md = substrate.get_metadata()
    pallets = getattr(md, "pallets", None) or []
    for p in pallets:
        name = str(getattr(p, "name", "")) or ""
        if not name:
            continue
        if try_compose_call(substrate, name, call_function, probe_params) is not None:
            return name
    raise RuntimeError(f"Could not find any pallet exposing call '{call_function}'")


def pick_default_operational_inner_call(substrate: SubstrateInterface, cooldown: int) -> Tuple[str, str, Dict[str, Any]]:
    fn = "set_pending_childkey_cooldown"
    pallet = resolve_pallet_for_call(substrate, fn, {"cooldown": 0})
    return (pallet, fn, {"cooldown": int(cooldown)})


def create_signed_xt(substrate: SubstrateInterface, signer: Keypair, call: Any, tip_planck: int) -> Any:
    try:
        return substrate.create_signed_extrinsic(call=call, keypair=signer, era="00", tip=int(tip_planck))
    except TypeError:
        return substrate.create_signed_extrinsic(call=call, keypair=signer, era="00")


# ──────────────────────────────────────────────────────────────────────────────
# Dispatch bucket via payment_queryInfo
# ──────────────────────────────────────────────────────────────────────────────

def payment_query_info(substrate: SubstrateInterface, xt_hex: str, at_hash: str) -> Dict[str, Any]:
    last_err = None
    for params in ([xt_hex, at_hash], [xt_hex]):
        try:
            res = rpc_call(substrate, "payment_queryInfo", params)
            if isinstance(res, dict):
                return res
            raise RuntimeError(f"payment_queryInfo returned non-dict: {res!r}")
        except Exception as e:
            last_err = e
    raise RuntimeError(f"payment_queryInfo failed: {last_err}")


def dispatch_bucket_from_hex(substrate: SubstrateInterface, xt_hex: str, at_hash: str) -> str:
    pqi = payment_query_info(substrate, xt_hex, at_hash)
    raw_class = pqi.get("class", pqi.get("dispatchClass"))
    return class_bucket(raw_class)


# ──────────────────────────────────────────────────────────────────────────────
# Priority via TaggedTransactionQueue_validate_transaction (state_call)
# ──────────────────────────────────────────────────────────────────────────────

def state_call(substrate: SubstrateInterface, method: str, data: bytes, at_hash: str) -> bytes:
    res_hex = rpc_call(substrate, "state_call", [method, bytes_to_hex(data), at_hash])
    if not isinstance(res_hex, str) or not res_hex.startswith("0x"):
        raise RuntimeError(f"state_call returned non-hex: {res_hex!r}")
    return hex_to_bytes(res_hex)


def decode_priority_from_transaction_validity(result_bytes: bytes) -> int:
    """
    TransactionValidity = Result<ValidTransaction, TransactionValidityError>
      0x00 => Ok(ValidTransaction...)
      0x01 => Err(...)
    ValidTransaction starts with priority: u64 (LE)
    """
    if not result_bytes:
        raise RuntimeError("validate_transaction returned empty bytes")
    tag = result_bytes[0]
    if tag == 0x01:
        raise RuntimeError("validate_transaction returned Err(...)")
    if tag != 0x00:
        raise RuntimeError("validate_transaction returned unknown discriminant")
    if len(result_bytes) < 9:
        raise RuntimeError("validate_transaction Ok too short to contain priority")
    return int.from_bytes(result_bytes[1:9], "little", signed=False)


def validate_transaction_priority_state_call_hex(
    substrate: SubstrateInterface,
    xt_hex: str,
    at_hash: str,
    arg_layout: int,
) -> int:
    """
    Calls runtime API: TaggedTransactionQueue_validate_transaction via state_call.

      layout=2: (TransactionSource::External, tx)
      layout=3: (TransactionSource::External, tx, at_hash)

    TransactionSource::External enum index = 2.
    """
    method = "TaggedTransactionQueue_validate_transaction"
    source_external = bytes([2])
    tx_bytes = hex_to_bytes(xt_hex)

    if arg_layout == 2:
        data = source_external + tx_bytes
    elif arg_layout == 3:
        data = source_external + tx_bytes + hex_to_bytes(at_hash)
    else:
        raise ValueError(f"Invalid arg_layout: {arg_layout}")

    out = state_call(substrate, method, data, at_hash)
    return decode_priority_from_transaction_validity(out)


def detect_layout_and_normal_priority(
    substrate: SubstrateInterface,
    signer: Keypair,
    at_hash: str,
    tip_planck: int,
) -> Tuple[int, int]:
    """
    Detect validate_transaction arg layout by probing System.remark (Normal bucket),
    and return (layout, normal_priority).
    """
    remark_call = try_compose_call(substrate, "System", "remark", {"remark": "0x00"})
    if remark_call is None:
        raise RuntimeError("Could not compose System.remark for baseline priority probe")

    remark_xt = create_signed_xt(substrate, signer, remark_call, tip_planck)
    remark_hex = extrinsic_hex(remark_xt)

    if dispatch_bucket_from_hex(substrate, remark_hex, at_hash) != "Normal":
        raise RuntimeError("Baseline System.remark is not Normal-bucket on this chain")

    last_err = None
    for layout in (2, 3):  # try 2-arg first (safer)
        try:
            prio = validate_transaction_priority_state_call_hex(substrate, remark_hex, at_hash, layout)
            return layout, prio
        except Exception as e:
            last_err = e

    raise RuntimeError(f"Could not determine validate_transaction arg layout: {last_err}")


# ──────────────────────────────────────────────────────────────────────────────
# Proxy setup (ensure add_proxy exists)
# ──────────────────────────────────────────────────────────────────────────────

def get_proxies_value(substrate: SubstrateInterface, proxy_module: str, real_ss58: str) -> Any:
    try:
        q = substrate.query(proxy_module, "Proxies", [real_ss58])
    except Exception as e:
        raise RuntimeError(f"Could not query {proxy_module}.Proxies storage: {e}") from e
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
) -> Any:
    cand_keys = []
    s = (proxy_type_str or "").strip()
    if s:
        cand_keys.extend([s, s.lower(), s.capitalize()])
    cand_keys.extend(["Any", "any"])

    candidates = []
    for k in cand_keys:
        candidates.append(k)
        candidates.append({k: None})
        candidates.append({k: {}})

    candidates.append(0)  # last resort: enum index 0

    last = None
    for pt in candidates:
        call = try_compose_call(
            substrate,
            proxy_module,
            "add_proxy",
            {"delegate": delegate_ss58, "proxy_type": pt, "delay": int(delay)},
        )
        if call is not None:
            return call
        last = pt

    raise RuntimeError(
        f"Could not compose {proxy_module}.add_proxy with proxy_type candidates (last tried: {last!r}). "
        f"Pass --proxy-type with the correct variant name for your runtime."
    )


def ensure_proxy_relationship(
    substrate: SubstrateInterface,
    proxy_module: str,
    real_kp: Keypair,
    delegate_ss58: str,
    proxy_type_str: str,
    tip_planck: int,
    wait_finalization: bool,
) -> None:
    proxies_val = get_proxies_value(substrate, proxy_module, real_kp.ss58_address)
    if has_delegate_proxy(proxies_val, delegate_ss58):
        return

    add_call = compose_add_proxy_call_with_candidates(
        substrate,
        proxy_module,
        delegate_ss58=delegate_ss58,
        delay=0,
        proxy_type_str=proxy_type_str,
    )
    add_xt = create_signed_xt(substrate, real_kp, add_call, tip_planck)

    receipt = substrate.submit_extrinsic(
        add_xt,
        wait_for_inclusion=True,
        wait_for_finalization=bool(wait_finalization),
    )
    if not getattr(receipt, "is_success", False):
        raise RuntimeError(f"Failed to add proxy: {getattr(receipt, 'error_message', None)}")


# ──────────────────────────────────────────────────────────────────────────────
# Checks + submit helpers
# ──────────────────────────────────────────────────────────────────────────────

def run_check_pre_submit(
    substrate: SubstrateInterface,
    xt: Any,
    at_hash: str,
    normal_priority: int,
    layout: int,
) -> Tuple[bool, int, str, str]:
    """
    Returns:
      ok, prio, bucket, xt_hex
    """
    xt_hex = extrinsic_hex(xt)
    bucket = dispatch_bucket_from_hex(substrate, xt_hex, at_hash)
    prio = validate_transaction_priority_state_call_hex(substrate, xt_hex, at_hash, layout)
    ok = (bucket == "Normal") and (prio == normal_priority)
    return ok, prio, bucket, xt_hex


def submit_and_get_blockhash(
    substrate: SubstrateInterface,
    xt: Any,
    wait_finalization: bool,
) -> str:
    receipt = substrate.submit_extrinsic(
        xt,
        wait_for_inclusion=True,
        wait_for_finalization=bool(wait_finalization),
    )
    bh = getattr(receipt, "block_hash", None)
    if not isinstance(bh, str) or not bh.startswith("0x"):
        raise RuntimeError("Could not read block_hash from receipt")
    return bh


def assert_and_print_in_block_priority(
    substrate: SubstrateInterface,
    included_block_hash: str,
    xt_hex: str,
    expected_priority: int,
    layout: int,
    label: str,
) -> bool:
    """
    Compute priority for the exact extrinsic bytes that landed in the block by:
      - finding it in the block body
      - recomputing validate_transaction priority against the block PARENT state
    Always prints the block_priority.
    """
    parent_hash, block_num, extrinsics = get_block_parent_and_extrinsics(substrate, included_block_hash)
    idx = find_extrinsic_index(extrinsics, xt_hex)
    if idx is None:
        print(f"[x] {label} included in block #{block_num} (block_priority=ERR)")
        return False

    prio_in_block = validate_transaction_priority_state_call_hex(substrate, xt_hex, parent_hash, layout)
    print(f"[i] {label} included in block #{block_num} (block_priority={prio_in_block})")
    return prio_in_block == int(expected_priority)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ws", default="ws://127.0.0.1:9945")

    # Real signer (submits Utility.batch and also authorizes proxy via add_proxy)
    ap.add_argument("--signer-uri", default="//Alice")

    # Delegate signer (submits Proxy.proxy)
    ap.add_argument("--delegate-uri", default="//Bob")

    ap.add_argument("--utility-module", default="Utility")
    ap.add_argument("--proxy-module", default="Proxy")

    ap.add_argument("--no-batch", action="store_true")
    ap.add_argument("--no-proxy", action="store_true")

    # Default Operational inner call param:
    ap.add_argument("--cooldown", type=int, default=123)

    # Optional explicit override of inner call:
    ap.add_argument("--inner-module", default="")
    ap.add_argument("--inner-call", default="")
    ap.add_argument("--inner-params", default="")

    ap.add_argument("--proxy-type", default="Any")
    ap.add_argument("--tip-planck", type=int, default=0)
    ap.add_argument("--wait-finalization", action="store_true")

    args = ap.parse_args()

    substrate = connect(args.ws)

    real_kp = Keypair.create_from_uri(args.signer_uri)
    delegate_kp = Keypair.create_from_uri(args.delegate_uri)

    # Detect runtime API layout + baseline Normal priority (no hardcoding)
    head0 = best_hash(substrate)
    layout, normal_prio = detect_layout_and_normal_priority(substrate, real_kp, head0, int(args.tip_planck))

    # Inner call (used INSIDE the batch)
    if args.inner_module.strip() and args.inner_call.strip():
        inner_params = parse_json_dict(args.inner_params) if args.inner_params.strip() else {}
        inner_desc = (args.inner_module.strip(), args.inner_call.strip(), inner_params)
    else:
        inner_desc = pick_default_operational_inner_call(substrate, int(args.cooldown))

    inner_module, inner_fn, inner_params = inner_desc
    inner_call = try_compose_call(substrate, inner_module, inner_fn, inner_params)
    if inner_call is None:
        raise RuntimeError(
            f"Could not compose inner call {inner_module}.{inner_fn} params={inner_params}. "
            f"Pass --inner-module/--inner-call/--inner-params explicitly."
        )

    print(f"[i] Inner call: {inner_module}.{inner_fn} params={inner_params}")

    # Build the batch call ONCE (used both for direct batch and as proxied call)
    batch_call = try_compose_call(substrate, args.utility_module, "batch", {"calls": [inner_call]})
    if batch_call is None:
        raise RuntimeError(f"Could not compose {args.utility_module}.batch (check --utility-module).")

    # Ensure proxy relationship exists (Alice -> Bob)
    if not args.no_proxy:
        ensure_proxy_relationship(
            substrate,
            proxy_module=args.proxy_module,
            real_kp=real_kp,
            delegate_ss58=delegate_kp.ss58_address,
            proxy_type_str=str(args.proxy_type),
            tip_planck=int(args.tip_planck),
            wait_finalization=bool(args.wait_finalization),
        )

    # Fresh head for checks (state may have changed due to add_proxy)
    head = best_hash(substrate)

    ok_all = True

    # Track pre-submit priority + hex so we can assert it matches after inclusion.
    batch_xt = None
    proxy_xt = None

    batch_hex = None
    proxy_hex = None

    batch_prio = None
    proxy_prio = None

    # ── Pre-submit checks ─────────────────────────────────────────────────────
    if not args.no_batch:
        batch_xt = create_signed_xt(substrate, real_kp, batch_call, int(args.tip_planck))
        ok, prio, bucket, hx = run_check_pre_submit(substrate, batch_xt, head, normal_prio, layout)
        print(f"[{'✓' if ok else 'x'}] {args.utility_module}.batch: dispatch_class={bucket}  priority={prio}")
        ok_all = ok_all and ok
        batch_prio = prio
        batch_hex = hx

    if not args.no_proxy:
        proxy_call = try_compose_call(
            substrate,
            args.proxy_module,
            "proxy",
            {"real": real_kp.ss58_address, "force_proxy_type": None, "call": batch_call},
        )
        if proxy_call is None:
            raise RuntimeError(f"Could not compose {args.proxy_module}.proxy (check --proxy-module).")

        proxy_xt = create_signed_xt(substrate, delegate_kp, proxy_call, int(args.tip_planck))
        ok, prio, bucket, hx = run_check_pre_submit(substrate, proxy_xt, head, normal_prio, layout)
        print(f"[{'✓' if ok else 'x'}] {args.proxy_module}.proxy: dispatch_class={bucket}  priority={prio}")
        ok_all = ok_all and ok
        proxy_prio = prio
        proxy_hex = hx

    # ── Submit and assert + PRINT in-block priority ───────────────────────────
    if batch_xt is not None and batch_hex is not None and batch_prio is not None:
        bh = submit_and_get_blockhash(substrate, batch_xt, bool(args.wait_finalization))
        ok_all = ok_all and assert_and_print_in_block_priority(
            substrate,
            included_block_hash=bh,
            xt_hex=batch_hex,
            expected_priority=int(batch_prio),
            layout=layout,
            label=f"{args.utility_module}.batch",
        )

    if proxy_xt is not None and proxy_hex is not None and proxy_prio is not None:
        bh = submit_and_get_blockhash(substrate, proxy_xt, bool(args.wait_finalization))
        ok_all = ok_all and assert_and_print_in_block_priority(
            substrate,
            included_block_hash=bh,
            xt_hex=proxy_hex,
            expected_priority=int(proxy_prio),
            layout=layout,
            label=f"{args.proxy_module}.proxy",
        )

    if ok_all:
        print("[✓] All assertions passed.")
        return

    print("[!] Assertions failed.")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
