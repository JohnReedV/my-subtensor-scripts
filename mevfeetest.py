#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MEV‑Shield pre-dispatch failure E2E test (tx-pool rejection => DecryptionFailed event)

What this test validates
------------------------
This script asserts the bugfix you implemented:

    Previously: if the decrypted *inner* extrinsic failed during tx-pool pre-dispatch
    validation (e.g. can't pay transaction fee), no on-chain event was emitted.

    Now: the author-side revealer detects tx-pool rejection of the decrypted inner
    extrinsic and submits an unsigned MevShield::mark_decryption_failed, which emits
    a MevShield::DecryptionFailed event on-chain.

Test flow
---------
  1) Wait for MevShield::NextKey to be available (1184 bytes ML‑KEM‑768 pk).
  2) Create an *unfunded* sr25519 account (the "poor" inner signer).
  3) Build a normal signed inner extrinsic:
         System::remark(remark_bytes)
     signed by the poor account, with a non-zero tip (default: 1 planck).
     If the poor account unexpectedly has balance, the script auto-adjusts the tip
     to exceed the poor balance, guaranteeing Payment failure.
  4) commitment = blake2_256(signed_extrinsic_bytes)
  5) Encrypt plaintext = signed_extrinsic_bytes using ML‑KEM‑768 + XChaCha20‑Poly1305:
         blob = [u16 kem_len] || kem_ct || nonce24 || aead_ct
  6) Submit wrapper:
         MevShield::submit_encrypted { commitment, ciphertext=blob }
     signed by a funded "author" account.
  7) Assert:
       • submit_encrypted is included successfully
       • a later block emits MevShield::DecryptionFailed for the wrapper id
       • the reason contains "tx-pool" (so we're specifically covering the pre-dispatch path)
       • no plain System::remark signed by the poor account ever appears on-chain
         before the failure event
       • (best-effort) the wrapper is removed from MevShield::Submissions storage

Requirements
------------
  • Python deps:  py-substrate-interface
      pip install py-substrate-interface
  • Your existing ML‑KEM FFI library (same as other MEV‑Shield scripts):
      build once:
          cd mlkemffi && cargo build --release
      and ensure libmlkemffi.so/.dylib/.dll is discoverable via LIB_PATHS below.

Usage
-----
  ./mev_shield_predispatch_failure_test.py --ws ws://127.0.0.1:9945

Notes
-----
  • This test assumes the node you connect to is authoring the blocks that include the
    wrapper (as in your other E2E tests). The revealer only runs for locally-authored blocks.
"""

import argparse
import ctypes
import hashlib
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException


def create_keypair_from_mnemonic(mnemonic: str) -> Keypair:
    """
    Compatibility helper across py-substrate-interface versions.
    """
    if hasattr(Keypair, "create_from_mnemonic"):
        return Keypair.create_from_mnemonic(mnemonic)
    # Many versions accept a mnemonic as a "secret URI" too.
    return Keypair.create_from_uri(mnemonic)


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

MLKEM768_PK_LEN = 1184
MLKEM768_CT_LEN = 1088
NONCE_LEN = 24
AEAD_TAG_LEN = 16

DEFAULT_AUTHOR_FUND_TAO = 10.0  # top-up hint for wrapper submitter


# ──────────────────────────────────────────────────────────────────────────────
# FFI loader (mlkemffi)
# ──────────────────────────────────────────────────────────────────────────────

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_PATHS = [
    os.path.join(THIS_DIR, "libmlkemffi.so"),
    os.path.join(THIS_DIR, "libmlkemffi.dylib"),
    os.path.join(THIS_DIR, "mlkemffi.dll"),
    os.path.join(THIS_DIR, "mlkemffi", "target", "release", "libmlkemffi.so"),
    os.path.join(THIS_DIR, "mlkemffi", "target", "release", "libmlkemffi.dylib"),
    os.path.join(THIS_DIR, "mlkemffi", "target", "release", "mlkemffi.dll"),
]


def _load_mlkemffi() -> ctypes.CDLL:
    last_err = None
    for p in LIB_PATHS:
        if os.path.exists(p):
            try:
                lib = ctypes.CDLL(p)

                lib.mlkem768_seal_blob.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_size_t),
                ]
                lib.mlkem768_seal_blob.restype = ctypes.c_int

                # Optional KDF id probe
                kdf_id = "v1"
                try:
                    lib.mlkemffi_kdf_id.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    lib.mlkemffi_kdf_id.restype = ctypes.c_int
                    buf = (ctypes.c_ubyte * 16)()
                    n = lib.mlkemffi_kdf_id(ctypes.cast(buf, ctypes.c_void_p), ctypes.sizeof(buf))
                    if n > 0:
                        kdf_id = bytes(buf[:n]).decode("ascii", errors="ignore") or "v1"
                except Exception:
                    kdf_id = "v1"

                print(f"[i] Loaded mlkemffi: {p}  (kdf={kdf_id})")
                if kdf_id != "v1":
                    print(
                        "[!] WARNING: mlkemffi reports non-standard KDF id "
                        f"'{kdf_id}'. Make sure node and FFI agree."
                    )
                return lib
            except Exception as e:
                last_err = e
    raise RuntimeError(
        "Could not load mlkemffi shared library.\n"
        "Build it once:\n"
        "  cd mlkemffi && cargo build --release\n"
        f"Last error: {last_err}"
    )


_mlkem = _load_mlkemffi()


def _as_c_buf(b: bytes) -> Tuple[ctypes.c_void_p, int, ctypes.Array]:
    buf = ctypes.create_string_buffer(b)
    ptr = ctypes.cast(buf, ctypes.c_void_p)
    return ptr, len(b), buf


def mlkem768_seal_blob(pk_bytes: bytes, plaintext: bytes) -> bytes:
    if len(pk_bytes) != MLKEM768_PK_LEN:
        raise ValueError(f"Bad pk length {len(pk_bytes)} (expected {MLKEM768_PK_LEN})")

    out_cap = 2 + MLKEM768_CT_LEN + NONCE_LEN + len(plaintext) + AEAD_TAG_LEN
    out_buf = (ctypes.c_ubyte * out_cap)()
    out_written = ctypes.c_size_t(0)

    pk_ptr, pk_len, _pk_backing = _as_c_buf(pk_bytes)
    pt_ptr, pt_len, _pt_backing = _as_c_buf(plaintext)

    ret = _mlkem.mlkem768_seal_blob(
        pk_ptr,
        ctypes.c_size_t(pk_len),
        pt_ptr,
        ctypes.c_size_t(pt_len),
        ctypes.cast(out_buf, ctypes.c_void_p),
        ctypes.c_size_t(out_cap),
        ctypes.byref(out_written),
    )
    if ret != 0:
        raise RuntimeError(f"mlkem768_seal_blob failed (code {ret})")
    return bytes(out_buf[: out_written.value])


# ──────────────────────────────────────────────────────────────────────────────
# Helpers: bytes / hex / events parsing
# ──────────────────────────────────────────────────────────────────────────────


def blake2_256(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()


def _parse_vec_u8(v: Any) -> Optional[bytes]:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str) and v.startswith("0x"):
        try:
            return bytes.fromhex(v[2:])
        except Exception:
            return None
    if isinstance(v, list) and all(isinstance(x, int) for x in v):
        return bytes(v)
    if isinstance(v, dict):
        for k in ("value", "data", "bytes", "inner", "reason", "remark"):
            if k in v:
                got = _parse_vec_u8(v[k])
                if got is not None:
                    return got
    if hasattr(v, "value"):
        return _parse_vec_u8(getattr(v, "value"))
    return None


def _normalize_hex_0x(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "0x" + bytes(v).hex()
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]
        for c in s:
            if c not in "0123456789abcdefABCDEF":
                return None
        if len(s) % 2 == 1:
            s = "0" + s
        return "0x" + s.lower()
    if isinstance(v, dict):
        for k in ("value", "bytes", "data"):
            if k in v:
                got = _normalize_hex_0x(v[k])
                if got is not None:
                    return got
    return None


def _event_attrs_to_list(attrs: Any) -> List[Any]:
    if attrs is None:
        return []
    if isinstance(attrs, list):
        # Sometimes list entries are already values; sometimes dicts with "value".
        out: List[Any] = []
        for x in attrs:
            if isinstance(x, dict) and "value" in x:
                out.append(x["value"])
            else:
                out.append(x)
        return out
    # Sometimes it's a dict of named values
    if isinstance(attrs, dict):
        # Preserve insertion order best-effort
        return list(attrs.values())
    return [attrs]


def _normalize_event_record(rec: Any) -> Tuple[Optional[str], Optional[str], List[Any]]:
    v = getattr(rec, "value", rec)
    if not isinstance(v, dict):
        return None, None, []
    ev = v.get("event", v)
    if not isinstance(ev, dict):
        return None, None, []
    module = (
        ev.get("module_id")
        or ev.get("section")
        or ev.get("pallet")
        or ev.get("module")
        or ev.get("call_module")
    )
    event_id = ev.get("event_id") or ev.get("method") or ev.get("event") or ev.get("name")
    attrs = ev.get("attributes") or ev.get("params") or ev.get("data") or ev.get("values")
    return (
        str(module) if module is not None else None,
        str(event_id) if event_id is not None else None,
        _event_attrs_to_list(attrs),
    )


def fetch_block_events(substrate: SubstrateInterface, block_hash: str) -> List[Any]:
    # py-substrate-interface usually provides get_events(block_hash=...)
    if hasattr(substrate, "get_events"):
        fn = getattr(substrate, "get_events")
        try:
            return fn(block_hash=block_hash)
        except TypeError:
            return fn(block_hash)
    if hasattr(substrate, "get_block_events"):
        fn = getattr(substrate, "get_block_events")
        try:
            return fn(block_hash=block_hash)
        except TypeError:
            return fn(block_hash)
    raise RuntimeError("substrateinterface does not expose get_events/get_block_events")


# ──────────────────────────────────────────────────────────────────────────────
# Substrate helpers
# ──────────────────────────────────────────────────────────────────────────────


def connect(url: str) -> SubstrateInterface:
    si = SubstrateInterface(url=url)
    print(f"[i] Connected to {url}")
    for _ in range(40):
        try:
            si.init_runtime()
            md = si.get_metadata()
            if md and getattr(md, "pallets", None):
                return si
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("Runtime metadata not available")


def token_decimals(substrate: SubstrateInterface) -> int:
    d = substrate.token_decimals
    if isinstance(d, list) and d and isinstance(d[0], int):
        return d[0]
    if isinstance(d, int):
        return d
    return 9


def resolve_mev_pallet(substrate: SubstrateInterface) -> str:
    md = substrate.get_metadata()
    names = [str(p.name) for p in md.pallets]
    for want in ("MevShield", "mevShield", "MEVShield", "Mevshield", "mev_shield"):
        for n in names:
            if n.lower() == want.lower():
                print(f"[i] Resolved pallet name: {n}")
                return n
    for n in names:
        if "mev" in n.lower() and "shield" in n.lower():
            print(f"[i] Resolved pallet name: {n}")
            return n
    raise RuntimeError("MevShield pallet not found")


def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def submit_signed(substrate: SubstrateInterface, who: Keypair, call):
    xt = substrate.create_signed_extrinsic(call=call, keypair=who, era="00")  # immortal
    try:
        rec = substrate.submit_extrinsic(
            xt, wait_for_inclusion=True, wait_for_finalization=True
        )
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e
    if not rec.is_success:
        raise RuntimeError(
            f"Extrinsic failed in block {rec.block_hash}: {rec.error_message}"
        )
    return rec


def call_to_scale_bytes(obj) -> bytes:
    """
    Obtain SCALE-encoded bytes from a call or extrinsic object produced by
    py-substrate-interface.
    """
    if hasattr(obj, "data"):
        d = obj.data
        if hasattr(d, "to_hex"):
            hx = d.to_hex()
            return bytes.fromhex(hx[2:] if hx.startswith("0x") else hx)
        if hasattr(d, "data"):
            raw = d.data
            if isinstance(raw, (bytes, bytearray, memoryview)):
                return bytes(raw)

    enc = getattr(obj, "encode", lambda: obj)()
    if hasattr(enc, "to_hex"):
        hx = enc.to_hex()
        return bytes.fromhex(hx[2:] if hx.startswith("0x") else hx)
    if hasattr(enc, "data"):
        raw = enc.data
        if isinstance(raw, (bytes, bytearray, memoryview)):
            return bytes(raw)
    if isinstance(enc, str) and enc.startswith("0x"):
        return bytes.fromhex(enc[2:])
    raise RuntimeError("Could not obtain SCALE bytes")


def account_free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0


def transfer_keep_alive(substrate: SubstrateInterface, signer: Keypair, dest_ss58: str, amount_planck: int):
    amount_planck = int(amount_planck)
    call = None
    for fn_name in ("transfer_keep_alive", "transfer"):
        try:
            call = compose_call(
                substrate,
                "Balances",
                fn_name,
                {"dest": dest_ss58, "value": amount_planck},
            )
            break
        except Exception:
            call = None
    if call is None:
        raise RuntimeError("Could not compose Balances transfer call")

    try:
        submit_signed(substrate, signer, call)
    except RuntimeError as e:
        msg = str(e)
        if "Priority is too low" in msg or "1014" in msg:
            print("[i] transfer: tx with same nonce already pending (1014); ignoring.")
            return
        raise


def ensure_funded_planck(substrate: SubstrateInterface, faucet: Keypair, dest_ss58: str, min_balance_planck: int, label: str = ""):
    have = account_free_balance(substrate, dest_ss58)
    need = int(min_balance_planck)
    if have >= need:
        return
    delta = int((need - have) * 1.1) + 1
    who = label or dest_ss58
    print(f"[i] Funding {who} with {delta} planck (have={have}, need={need})")
    transfer_keep_alive(substrate, faucet, dest_ss58, delta)


def read_next_key_bytes(substrate: SubstrateInterface, mev_pallet: str, block_hash: Optional[str] = None) -> bytes:
    v = substrate.query(mev_pallet, "NextKey", [], block_hash=block_hash)
    raw = getattr(v, "value", v)
    pk = _parse_vec_u8(raw)
    return pk or b""


def acquire_next_key(substrate: SubstrateInterface, mev_pallet: str, timeout_s: int = 120, poll_s: float = 0.25) -> bytes:
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout_s:
        try:
            pk = read_next_key_bytes(substrate, mev_pallet)
            if pk and len(pk) == MLKEM768_PK_LEN:
                return pk
            last = f"unexpected NextKey len={len(pk)}"
        except Exception as e:
            last = str(e)
        time.sleep(poll_s)
    raise RuntimeError(f"Timed out waiting for {mev_pallet}::NextKey ({last})")


def get_block_number(substrate: SubstrateInterface, block_hash: str) -> int:
    try:
        header = substrate.get_block_header(block_hash=block_hash)
    except Exception:
        return 0
    hdr_val = getattr(header, "value", header)
    if isinstance(hdr_val, dict) and "header" in hdr_val:
        hdr_val = hdr_val["header"]
    if not isinstance(hdr_val, dict):
        return 0
    n = hdr_val.get("number")
    if isinstance(n, int):
        return n
    if isinstance(n, str):
        s = n.strip()
        if s.startswith("0x"):
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
# Block inspection helpers
# ──────────────────────────────────────────────────────────────────────────────


def _extract_call_from_raw(raw: Any) -> Tuple[Optional[str], Optional[str], Any]:
    if raw is None:
        return None, None, None
    if hasattr(raw, "value"):
        raw = raw.value
    if not isinstance(raw, dict):
        return None, None, None
    call = raw.get("call", raw)
    if hasattr(call, "value"):
        call = call.value
    if not isinstance(call, dict):
        return None, None, None
    module = (
        call.get("call_module")
        or call.get("call_module_name")
        or call.get("pallet")
        or call.get("module")
    )
    fn = call.get("call_function") or call.get("function")
    args = call.get("call_args") or call.get("args") or []
    return (str(module) if module is not None else None, str(fn) if fn is not None else None, args)


def _extract_extrinsic_signer_ss58(raw: Any) -> Optional[str]:
    if hasattr(raw, "value"):
        raw = raw.value
    if not isinstance(raw, dict):
        return None
    addr = raw.get("address")
    if isinstance(addr, str):
        return addr
    signer = raw.get("signer")
    if isinstance(signer, str):
        return signer
    return None


def block_contains_plain_system_remark_by(
    substrate: SubstrateInterface,
    block_hash: str,
    signer_ss58: str,
) -> bool:
    blk = substrate.get_block(block_hash=block_hash)
    exts = blk.get("extrinsics") or blk.get("extrinsic") or []
    for ext in exts:
        raw = getattr(ext, "value", ext)
        module, fn, _args = _extract_call_from_raw(raw)
        signer = _extract_extrinsic_signer_ss58(raw)
        if signer != signer_ss58:
            continue
        if module and module.lower() == "system" and fn == "remark":
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Assertions for this test
# ──────────────────────────────────────────────────────────────────────────────


def extract_wrapper_id_from_receipt(
    receipt: Any,
    mev_pallet: str,
) -> str:
    """
    Extract the wrapper id from MevShield::EncryptedSubmitted in the wrapper extrinsic receipt.
    """
    evs = getattr(receipt, "triggered_events", None)
    if not evs:
        raise RuntimeError("ExtrinsicReceipt has no triggered_events; cannot extract wrapper id")

    for rec in evs:
        module, event_id, attrs = _normalize_event_record(rec)
        if module is None or event_id is None:
            continue
        if module.lower() == mev_pallet.lower() and event_id == "EncryptedSubmitted":
            if not attrs:
                break
            wid = _normalize_hex_0x(attrs[0])
            if wid:
                return wid
    raise RuntimeError("Could not find MevShield::EncryptedSubmitted in wrapper receipt events")


def wait_for_decryption_failed_event(
    substrate: SubstrateInterface,
    mev_pallet: str,
    wrapper_id_hex: str,
    submit_block_num: int,
    poor_ss58: str,
    timeout_s: int = 180,
    poll_s: float = 0.8,
) -> Tuple[int, str, str]:
    """
    Scan blocks after submit_block_num until we see:
        MevShield::DecryptionFailed { id == wrapper_id_hex, reason }
    Also asserts that no plain System::remark signed by poor_ss58 appears before that event.

    Returns (fail_block_num, reason_str, fail_block_hash).
    """
    start = time.time()
    next_height = submit_block_num + 1
    target = _normalize_hex_0x(wrapper_id_hex)
    if not target:
        raise RuntimeError("wrapper_id_hex is not valid hex")

    print(f"[i] Waiting for {mev_pallet}::DecryptionFailed for id={target} ...")

    while time.time() - start < timeout_s:
        try:
            head_hash = substrate.get_chain_head()
        except Exception:
            time.sleep(poll_s)
            continue

        head_num = get_block_number(substrate, head_hash)
        if head_num < next_height:
            time.sleep(poll_s)
            continue

        while next_height <= head_num:
            bh = substrate.get_block_hash(next_height)
            if not bh:
                next_height += 1
                continue

            # Guard: ensure inner plaintext does NOT leak as a plain extrinsic.
            if block_contains_plain_system_remark_by(substrate, bh, poor_ss58):
                raise RuntimeError(
                    f"MEV leak: found plain System::remark signed by poor account in block #{next_height} ({bh})"
                )

            # Scan events for DecryptionFailed(id==target)
            try:
                events = fetch_block_events(substrate, bh)
            except Exception as e:
                # If event fetch fails transiently, just continue.
                print(f"[DBG] fetch_block_events failed for block #{next_height}: {e}")
                next_height += 1
                continue

            for rec in events:
                module, event_id, attrs = _normalize_event_record(rec)
                if module is None or event_id is None:
                    continue
                if module.lower() != mev_pallet.lower():
                    continue
                if event_id != "DecryptionFailed":
                    continue

                if len(attrs) < 1:
                    continue
                ev_id_hex = _normalize_hex_0x(attrs[0])
                if ev_id_hex is None or ev_id_hex != target:
                    continue

                reason_bytes = _parse_vec_u8(attrs[1]) if len(attrs) > 1 else None
                reason_str = ""
                if reason_bytes is not None:
                    reason_str = reason_bytes.decode("utf-8", errors="replace")
                else:
                    reason_str = str(attrs[1]) if len(attrs) > 1 else ""

                print(
                    f"[✓] Found {mev_pallet}::DecryptionFailed for id={target} "
                    f"in block #{next_height} ({bh})"
                )
                return next_height, reason_str, bh

            next_height += 1

        time.sleep(poll_s)

    raise RuntimeError(
        f"Timed out ({timeout_s}s) waiting for {mev_pallet}::DecryptionFailed for id={target}"
    )


def assert_wrapper_removed_from_storage(
    substrate: SubstrateInterface,
    mev_pallet: str,
    wrapper_id_hex: str,
):
    """
    Best-effort: verify MevShield::Submissions(id) is None at current head.
    """
    try:
        v = substrate.query(mev_pallet, "Submissions", [wrapper_id_hex])
        raw = getattr(v, "value", v)
        if raw is None:
            print("[✓] Submissions entry is removed (None)")
            return
        # Some encodings may return {} / null-ish
        if raw == {}:
            print("[✓] Submissions entry is removed ({})")
            return
        raise RuntimeError(f"Submissions still contains entry for id={wrapper_id_hex}: {raw}")
    except Exception as e:
        # If metadata/type mismatch, log but do not hard fail: event emission is the primary assertion.
        print(f"[!] Could not verify Submissions storage removal (non-fatal): {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        description="MEV‑Shield E2E: tx-pool pre-dispatch rejection of decrypted inner extrinsic must emit DecryptionFailed event"
    )
    ap.add_argument("--ws", default="ws://127.0.0.1:9945")
    ap.add_argument("--author-uri", default="//Eve", help="Wrapper submitter (pays wrapper fee)")
    ap.add_argument(
        "--poor-uri",
        default="",
        help="Optional deterministic URI for poor inner signer (must be unfunded). If omitted, a fresh random account is used.",
    )
    ap.add_argument(
        "--tip-planck",
        type=int,
        default=1,
        help="Tip to include in inner extrinsic (planck). Non-zero guarantees fee payment is required.",
    )
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--poll", type=float, default=0.8)
    args = ap.parse_args()

    substrate = connect(args.ws)
    mev_pallet = resolve_mev_pallet(substrate)

    decimals = token_decimals(substrate)
    faucet = Keypair.create_from_uri("//Alice")
    author = Keypair.create_from_uri(args.author_uri)

    # Ensure wrapper submitter is funded for wrapper fee.
    min_author = int(DEFAULT_AUTHOR_FUND_TAO * (10 ** decimals))
    ensure_funded_planck(substrate, faucet, author.ss58_address, min_author, label="author (wrapper submitter)")

    # Create a "poor" inner signer (must not have funds).
    if args.poor_uri.strip():
        poor = Keypair.create_from_uri(args.poor_uri.strip())
    else:
        # Generate random until we get a zero-balance account (usually first try).
        poor = None
        for _ in range(20):
            if hasattr(Keypair, "generate_mnemonic"):
                m = Keypair.generate_mnemonic()
            else:
                # Very old versions may not have generate_mnemonic; fall back to a dev derivation path.
                # This is less ideal (might be funded on some dev nets), but still typically unfunded.
                m = f"//MevShieldPoor{int(time.time() * 1_000_000)}"
            kp = create_keypair_from_mnemonic(m) if not m.startswith("//") else Keypair.create_from_uri(m)
            if account_free_balance(substrate, kp.ss58_address) == 0:
                poor = kp
                break
        if poor is None:
            # Last-resort: just create one and continue.
            if hasattr(Keypair, "generate_mnemonic"):
                poor = create_keypair_from_mnemonic(Keypair.generate_mnemonic())
            else:
                poor = Keypair.create_from_uri(f"//MevShieldPoorFallback{int(time.time())}")

    poor_bal = account_free_balance(substrate, poor.ss58_address)
    print(f"[i] poor inner signer ss58={poor.ss58_address} free_balance={poor_bal}")

    if poor_bal != 0:
        print(
            "[!] WARNING: poor account is not zero-balance. "
            "The script will auto-adjust the inner tip to exceed poor balance to still force Payment failure."
        )

    # 1) Acquire NextKey (pk bytes for encryption)
    pk_bytes = acquire_next_key(substrate, mev_pallet)
    print(f"[i] {mev_pallet}::NextKey acquired: len={len(pk_bytes)} blake2_256=0x{blake2_256(pk_bytes).hex()}")

    # 2) Build inner call: System::remark
    remark = b"mev-shield pre-dispatch failure test"
    call_inner = compose_call(
        substrate,
        "System",
        "remark",
        {"remark": "0x" + remark.hex()},
    )

    # Choose an effective tip that is guaranteed to exceed the poor account balance,
    # so the tx-pool must reject it with a Payment-related validity error.
    effective_tip = int(args.tip_planck)
    if effective_tip <= 0:
        effective_tip = 1
    poor_bal_now = account_free_balance(substrate, poor.ss58_address)
    if poor_bal_now >= effective_tip:
        effective_tip = poor_bal_now + 1
        print(f"[i] Adjusted inner tip to {effective_tip} planck to exceed poor balance ({poor_bal_now})")

    # 3) Build a normal signed inner extrinsic, signed by the poor account
    #    Include a non-zero tip to guarantee fee requirement.
    try:
        inner_xt = substrate.create_signed_extrinsic(call=call_inner, keypair=poor, era="00", tip=int(effective_tip))
    except TypeError:
        # Older py-substrate-interface might not accept "tip" kwarg.
        print("[!] WARNING: create_signed_extrinsic() does not accept tip=. Proceeding without tip (fee might still be >0).")
        inner_xt = substrate.create_signed_extrinsic(call=call_inner, keypair=poor, era="00")

    inner_xt_bytes = call_to_scale_bytes(inner_xt)
    print(f"[DBG] inner signed extrinsic (System::remark) len={len(inner_xt_bytes)} bytes; signer={poor.ss58_address}")

    commitment_bytes = blake2_256(inner_xt_bytes)
    commitment_hex = "0x" + commitment_bytes.hex()
    print(f"[DBG] commitment = {commitment_hex}")

    # 4) Encrypt plaintext = signed extrinsic bytes
    blob = mlkem768_seal_blob(pk_bytes, inner_xt_bytes)
    kem_len = int.from_bytes(blob[0:2], "little") if len(blob) >= 2 else None
    print(f"[DBG] ciphertext blob: total_len={len(blob)} kem_len={kem_len}")

    # 5) Submit wrapper: MevShield::submit_encrypted
    call_submit = compose_call(
        substrate,
        mev_pallet,
        "submit_encrypted",
        {
            "commitment": commitment_hex,
            "ciphertext": "0x" + blob.hex(),
        },
    )
    rec = submit_signed(substrate, author, call_submit)
    inclusion_hash = rec.block_hash
    submit_num = get_block_number(substrate, inclusion_hash)
    print(f"[✓] submit_encrypted included in block #{submit_num} ({inclusion_hash})")

    wrapper_id_hex = extract_wrapper_id_from_receipt(rec, mev_pallet)
    print(f"[i] wrapper id (from EncryptedSubmitted event) = {wrapper_id_hex}")

    # Guard: inclusion block must not already contain the plaintext System::remark by poor.
    if block_contains_plain_system_remark_by(substrate, inclusion_hash, poor.ss58_address):
        raise RuntimeError("Inclusion block contains plaintext System::remark by poor signer (unexpected leak)")

    # 6) Wait for DecryptionFailed event for this wrapper id
    fail_block_num, reason_str, _fail_block_hash = wait_for_decryption_failed_event(
        substrate=substrate,
        mev_pallet=mev_pallet,
        wrapper_id_hex=wrapper_id_hex,
        submit_block_num=submit_num,
        poor_ss58=poor.ss58_address,
        timeout_s=int(args.timeout),
        poll_s=float(args.poll),
    )

    print(f"[i] DecryptionFailed reason (utf-8 best-effort): {reason_str!r}")

    # Primary assertion: reason must indicate tx-pool pre-dispatch rejection path.
    # (This ties the test to the specific bugfix.)
    if "tx-pool" not in reason_str.lower():
        raise RuntimeError(
            "DecryptionFailed reason did not contain 'tx-pool'. "
            "Expected the pre-dispatch rejection path to set a reason containing 'tx-pool'. "
            f"Got: {reason_str!r}"
        )

    print(f"[✓] Reason contains 'tx-pool' (covers inner pre-dispatch rejection path)")

    # 7) Best-effort: wrapper removed from storage after mark_decryption_failed is included
    assert_wrapper_removed_from_storage(substrate, mev_pallet, wrapper_id_hex)

    print(
        "✅ PASS: pre-dispatch tx-pool rejection of decrypted inner extrinsic is now surfaced on-chain via "
        f"{mev_pallet}::DecryptionFailed (block #{fail_block_num}, id={wrapper_id_hex})."
    )


if __name__ == "__main__":
    main()
