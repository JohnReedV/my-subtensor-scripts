#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MEV‑Shield add_stake E2E:
  • Reads MevShield::NextKey { public_key: Vec<u8>(1184), epoch: u64 }
  • Builds plaintext (signer, nonce<u32>, Era::Immortal, call, MultiSignature)
  • Calls Rust FFI to produce blob:
      [u16 kem_len=1088 LE][kem_ct 1088B][nonce24][aead_ct]
  • Submits mev_shield::submit_encrypted
  • Waits for stake increase

Crypto details:
  • ML‑KEM‑768 (Kyber) for KEM
  • XChaCha20‑Poly1305 for AEAD
  • AEAD key = ML‑KEM shared secret (direct, 32 bytes; no HKDF)

Dependencies:
  python3 -m pip install --user substrate-interface

Build FFI once:
  cd mlkemffi && cargo build --release
  (ensure the produced .so/.dylib/.dll is found by this script)
"""

import argparse
import ctypes
import hashlib
import os
import struct
import sys
import time
from typing import Any, Dict, Optional, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException
from substrateinterface.utils.ss58 import ss58_decode

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

MLKEM768_PK_LEN = 1184
MLKEM768_CT_LEN = 1088
NONCE_LEN = 24
AEAD_TAG_LEN = 16

# ──────────────────────────────────────────────────────────────────────────────
# FFI loader
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
    """
    Load the mlkemffi shared library and (optionally) probe its KDF id.

    Recent versions use direct-from-ML‑KEM shared secret ("v1").
    Older HKDF-based builds may expose a different id; if the probe
    is missing we assume "v1" as long as encryption/decryption agree.
    """
    last_err = None
    for p in LIB_PATHS:
        if os.path.exists(p):
            try:
                lib = ctypes.CDLL(p)

                # mlkem768_seal_blob:
                #   int mlkem768_seal_blob(
                #       const uint8_t *pk_ptr, size_t pk_len,
                #       const uint8_t *pt_ptr, size_t pt_len,
                #       uint8_t *out_ptr, size_t out_len,
                #       size_t *written_out);
                lib.mlkem768_seal_blob.argtypes = [
                    ctypes.c_void_p, ctypes.c_size_t,
                    ctypes.c_void_p, ctypes.c_size_t,
                    ctypes.c_void_p, ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_size_t),
                ]
                lib.mlkem768_seal_blob.restype = ctypes.c_int

                # Optional KDF id probe:
                kdf_id = "v1"  # default: modern direct-from-ss
                try:
                    # If present, this is:
                    #   int mlkemffi_kdf_id(uint8_t *out, size_t out_len)
                    lib.mlkemffi_kdf_id.argtypes = [
                        ctypes.c_void_p,
                        ctypes.c_size_t,
                    ]
                    lib.mlkemffi_kdf_id.restype = ctypes.c_int

                    buf = (ctypes.c_ubyte * 16)()
                    n = lib.mlkemffi_kdf_id(
                        ctypes.cast(buf, ctypes.c_void_p),
                        ctypes.sizeof(buf),
                    )
                    if n > 0:
                        kdf_id = bytes(buf[:n]).decode("ascii", errors="ignore") or "v1"
                except Exception:
                    # If the symbol doesn't exist we just assume "v1".
                    kdf_id = "v1"

                print(f"[i] Loaded mlkemffi: {p}  (kdf={kdf_id})")
                if kdf_id != "v1":
                    print(
                        "[!] WARNING: mlkemffi reports non-standard KDF id "
                        f"'{kdf_id}'. Make sure your node and FFI agree on the "
                        "KDF or rebuild mlkemffi from the same commit as the node."
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
    """Keep a stable backing buffer alive for the duration of the FFI call."""
    buf = ctypes.create_string_buffer(b)  # mutable, NUL-safe
    ptr = ctypes.cast(buf, ctypes.c_void_p)
    return ptr, len(b), buf


def mlkem768_seal_blob(pk_bytes: bytes, plaintext: bytes) -> bytes:
    """
    Call into Rust FFI to build:

        [u16 kem_len=1088 LE][kem_ct 1088B][nonce24][aead_ct]

    where:
      • kem_ct is produced by ML‑KEM‑768 encapsulation
      • shared secret is 32 bytes
      • AEAD key = shared secret (direct)
      • AEAD = XChaCha20-Poly1305
    """
    if len(pk_bytes) != MLKEM768_PK_LEN:
        raise ValueError(f"Bad pk length {len(pk_bytes)} (expected {MLKEM768_PK_LEN})")

    out_cap = 2 + MLKEM768_CT_LEN + NONCE_LEN + len(plaintext) + AEAD_TAG_LEN
    out_buf = (ctypes.c_ubyte * out_cap)()
    out_written = ctypes.c_size_t(0)

    pk_ptr, pk_len, _pk_backing = _as_c_buf(pk_bytes)
    pt_ptr, pt_len, _pt_backing = _as_c_buf(plaintext)

    ret = _mlkem.mlkem768_seal_blob(
        pk_ptr, ctypes.c_size_t(pk_len),
        pt_ptr, ctypes.c_size_t(pt_len),
        ctypes.cast(out_buf, ctypes.c_void_p),
        ctypes.c_size_t(out_cap),
        ctypes.byref(out_written),
    )
    if ret != 0:
        raise RuntimeError(f"mlkem768_seal_blob failed (code {ret})")
    return bytes(out_buf[:out_written.value])


# ──────────────────────────────────────────────────────────────────────────────
# Helpers for reading Vec<u8> from RPC JSON
# ──────────────────────────────────────────────────────────────────────────────

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
        for k in ("value", "data", "bytes", "inner", "public_key"):
            if k in v:
                got = _parse_vec_u8(v[k])
                if got is not None:
                    return got
    if hasattr(v, "value"):
        return _parse_vec_u8(getattr(v, "value"))
    return None


# ──────────────────────────────────────────────────────────────────────────────
# MevShield::NextKey access (encrypt to the upcoming key)
# ──────────────────────────────────────────────────────────────────────────────

def read_next_key_bytes_and_epoch(
    substrate: SubstrateInterface,
    pallet: str,
) -> Tuple[bytes, int]:
    """
    Read MevShield::NextKey { public_key: Vec<u8>, epoch: u64 }.

    We encrypt to *NextKey* so that by the time the decrypt window opens,
    the corresponding secret key is `current_sk` on the author node.
    """
    v = substrate.query(pallet, "NextKey", [])
    kv = getattr(v, "value", None)
    if not isinstance(kv, dict):
        raise RuntimeError("NextKey not set yet (None)")

    pk_field = kv.get("public_key")
    if pk_field is None:
        raise RuntimeError("NextKey.public_key missing")

    pk_bytes = _parse_vec_u8(pk_field)
    if not pk_bytes:
        raise RuntimeError("NextKey.public_key parse error")

    epoch = int(kv.get("epoch", 0))
    return pk_bytes, epoch


def acquire_next_key(
    substrate: SubstrateInterface,
    pallet: str,
    timeout_s: int = 120,
    poll_s: float = 0.25,
) -> Tuple[bytes, int]:
    """
    Poll MevShield::NextKey until we have a well-formed ML‑KEM‑768 key.

    Returns (public_key_bytes, epoch) where:
        len(public_key_bytes) == MLKEM768_PK_LEN
        epoch is the key_epoch we will pass to submit_encrypted.
    """
    t0 = time.time()
    last_err: Optional[str] = None

    while time.time() - t0 < timeout_s:
        try:
            pk, epoch = read_next_key_bytes_and_epoch(substrate, pallet)
            if len(pk) == MLKEM768_PK_LEN:
                return pk, epoch
            last_err = f"unexpected NextKey.public_key length {len(pk)}"
        except Exception as e:
            last_err = str(e)
        time.sleep(poll_s)

    raise RuntimeError(f"Timed out reading MevShield::NextKey ({last_err})")


# ──────────────────────────────────────────────────────────────────────────────
# Substrate helpers & utilities
# ──────────────────────────────────────────────────────────────────────────────

def blake2_256(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()


def connect(url: str) -> SubstrateInterface:
    si = SubstrateInterface(url=url)
    print(f"[i] Connected to {url}")
    # Wait for metadata to be ready
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


def resolve_subtensor_pallet(substrate: SubstrateInterface) -> str:
    md = substrate.get_metadata()
    for p in md.pallets:
        name = str(p.name)
        if "subtensor" in name.lower():
            print(f"[i] Resolved Subtensor pallet: {name}")
            return name
    for name in ("SubtensorModule", "Subtensor"):
        try:
            _ = substrate.get_metadata_call_function(name, "add_stake")
            print(f"[i] Resolved Subtensor pallet via default: {name}")
            return name
        except Exception:
            pass
    raise RuntimeError("Subtensor pallet not found")


def compose_call(substrate, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def submit_signed(substrate, who: Keypair, call):
    xt = substrate.create_signed_extrinsic(call=call, keypair=who, era='00')  # Immortal
    try:
        rec = substrate.submit_extrinsic(xt, wait_for_inclusion=True, wait_for_finalization=True)
    except SubstrateRequestException as e:
        raise RuntimeError(f"Extrinsic submission failed: {e}") from e
    if not rec.is_success:
        raise RuntimeError(f"Extrinsic failed in block {rec.block_hash}: {rec.error_message}")
    return rec


def get_genesis_hash_bytes(substrate: SubstrateInterface) -> bytes:
    hx = substrate.get_block_hash(0)
    return bytes.fromhex(hx[2:]) if isinstance(hx, str) and hx.startswith("0x") else bytes(32)


def account_nonce(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        return int(substrate.get_account_nonce(ss58))
    except Exception:
        info = substrate.query("System", "Account", [ss58]).value
        if isinstance(info, dict) and "nonce" in info:
            return int(info["nonce"])
        return 0


def call_to_scale_bytes(call) -> bytes:
    if hasattr(call, "data"):
        d = call.data
        if hasattr(d, "to_hex"):
            hx = d.to_hex()
            return bytes.fromhex(hx[2:] if hx.startswith("0x") else hx)
        if hasattr(d, "data"):
            raw = d.data
            if isinstance(raw, (bytes, bytearray, memoryview)):
                return bytes(raw)
    enc = call.encode()
    if hasattr(enc, "to_hex"):
        hx = enc.to_hex()
        return bytes.fromhex(hx[2:] if hx.startswith("0x") else hx)
    if hasattr(enc, "data"):
        raw = enc.data
        if isinstance(raw, (bytes, bytearray, memoryview)):
            return bytes(raw)
    if isinstance(enc, str) and enc.startswith("0x"):
        return bytes.fromhex(enc[2:])
    raise RuntimeError("Could not obtain SCALE bytes for call")


# ──────────────────────────────────────────────────────────────────────────────
# Subtensor helpers
# ──────────────────────────────────────────────────────────────────────────────

def ensure_hotkey_registered(substrate: SubstrateInterface, cold: Keypair, hot_ss58: str,
                             netuid: int, module: str):
    try:
        call = compose_call(substrate, module, "burned_register",
                            {"netuid": int(netuid), "hotkey": hot_ss58})
        submit_signed(substrate, cold, call)
    except Exception:
        pass  # best-effort


def compose_add_stake(substrate: SubstrateInterface, module: str,
                      hot_ss58: str, netuid: int, amount_planck: int):
    for field in ("amount_staked", "amount", "value"):
        try:
            return substrate.compose_call(
                call_module=module,
                call_function="add_stake",
                call_params={"hotkey": hot_ss58, "netuid": int(netuid), field: int(amount_planck)}
            )
        except Exception:
            pass
    raise RuntimeError("Unable to compose add_stake (tried amount_staked/amount/value)")


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("0x"):
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
    if hasattr(v, "value"):
        return _to_int(getattr(v, "value"))
    return None


def read_stake(substrate: SubstrateInterface, module: str, hot_ss58: str, netuid: int) -> int:
    for storage in ("Stake", "StakeOf", "StakeFor", "StakePerHotkeyAndSubNet", "StakePerHotkeyAndSubnet"):
        try:
            v = substrate.query(module, storage, [hot_ss58, netuid])
            got = _to_int(v)
            if got is not None:
                return got
        except Exception:
            pass
    for storage in ("TotalHotkeyStake", "HotkeyTotalStake", "Stake"):
        try:
            v = substrate.query(module, storage, [hot_ss58])
            got = _to_int(v)
            if got is not None:
                return got
        except Exception:
            pass
    return 0


def wait_for_stake_increase(substrate: SubstrateInterface, module: str,
                            hot_ss58: str, netuid: int,
                            start: int, min_delta: int,
                            timeout_s: int = 180, poll_s: float = 0.8) -> Tuple[int, int]:
    t0 = time.time()
    last = start
    while time.time() - t0 < timeout_s:
        now = read_stake(substrate, module, hot_ss58, netuid)
        if now - start >= min_delta:
            return now, now - start
        last = now
        time.sleep(poll_s)
    raise RuntimeError(f"Stake did not increase by {min_delta} within {timeout_s}s (last={last}).")


# ─────────────────────────────────────────────────────────────────────────────-
# MevShield helpers
# ─────────────────────────────────────────────────────────────────────────────-

def get_epoch(substrate: SubstrateInterface, pallet: str) -> int:
    try:
        v = substrate.query(pallet, "Epoch", [])
        return int(v.value)
    except Exception:
        return 0


# ─────────────────────────────────────────────────────────────────────────────-
# Main
# ─────────────────────────────────────────────────────────────────────────────-

def main():
    ap = argparse.ArgumentParser(
        description="MEV‑Shield add_stake using MevShield::NextKey (public_key, epoch)"
    )
    ap.add_argument("--ws", default="ws://127.0.0.1:9945")
    ap.add_argument("--netuid", type=int, default=3)
    ap.add_argument("--stake", type=float, default=5.0, help="Stake in TAO to add")
    ap.add_argument("--author-uri", default="//Eve", help="Wrapper fee payer")
    ap.add_argument("--cold-uri",   default="//OwnerCold", help="Inner signer (signs plaintext)")
    ap.add_argument("--hot-uri",    default="//Staker1Hot", help="Target hotkey")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    substrate = connect(args.ws)
    mev_pallet = resolve_mev_pallet(substrate)
    subtensor  = resolve_subtensor_pallet(substrate)
    decimals   = token_decimals(substrate)

    author = Keypair.create_from_uri(args.author_uri)
    cold   = Keypair.create_from_uri(args.cold_uri)
    hot    = Keypair.create_from_uri(args.hot_uri)

    # Ensure hotkey registered (best-effort)
    ensure_hotkey_registered(substrate, cold, hot.ss58_address, args.netuid, subtensor)

    # Stake before
    stake_before = read_stake(substrate, subtensor, hot.ss58_address, args.netuid)
    print(f"[i] stake_before (net {args.netuid}): {stake_before}")

    # Compose inner add_stake
    amount_planck = int(round(args.stake * (10 ** decimals)))
    call = None
    last_err: Optional[Exception] = None
    for params in [
        {"hotkey": hot.ss58_address, "netuid": args.netuid, "amount_staked": amount_planck},
        {"hotkey": hot.ss58_address, "netuid": args.netuid, "amount": amount_planck},
        {"hotkey": hot.ss58_address, "netuid": args.netuid, "value": amount_planck},
    ]:
        try:
            call = compose_call(substrate, subtensor, "add_stake", params)
            break
        except Exception as e:
            last_err = e
    if call is None:
        raise RuntimeError(f"Could not compose add_stake: {last_err}")
    call_bytes = call_to_scale_bytes(call)

    # Build payload_core: (signer, nonce<u32>, Era::Immortal = 0x00, call SCALE)
    signer_raw32 = ss58_decode(cold.ss58_address)
    if isinstance(signer_raw32, str) and signer_raw32.startswith("0x"):
        signer_raw32 = bytes.fromhex(signer_raw32[2:])
    elif isinstance(signer_raw32, str):
        try:
            signer_raw32 = bytes.fromhex(signer_raw32)
        except Exception:
            signer_raw32 = bytes(32)
    signer_raw32 = bytes(signer_raw32)

    nonce_u32 = account_nonce(substrate, cold.ss58_address) & 0xFFFFFFFF
    payload_core = signer_raw32 + struct.pack("<I", nonce_u32) + b"\x00" + call_bytes

    # Domain-separated signature: "mev-shield:v1" || genesis || payload_core
    genesis = get_genesis_hash_bytes(substrate)
    sig64   = cold.sign(b"mev-shield:v1" + genesis + payload_core)
    multisig = b"\x01" + sig64  # MultiSignature::Sr25519
    plaintext = payload_core + multisig

    # Read the *announced next* ML‑KEM public key + its epoch.
    pk_bytes, epoch_next = acquire_next_key(substrate, mev_pallet)
    if len(pk_bytes) != MLKEM768_PK_LEN:
        raise RuntimeError(
            f"NextKey.public_key length {len(pk_bytes)} != {MLKEM768_PK_LEN}"
        )

    # Encrypt with Rust FFI (Kyber/ML‑KEM‑768 + XChaCha20-Poly1305),
    # AEAD key = shared_secret (must match node-side derive_aead_key).
    blob = mlkem768_seal_blob(pk_bytes, plaintext)

    # Commitment over (signer, nonce, mortality, call)
    commitment_hex = "0x" + blake2_256(payload_core).hex()

    # We use the epoch attached to NextKey itself as key_epoch.
    curr_epoch = get_epoch(substrate, mev_pallet)
    if epoch_next < curr_epoch:
        # Very stale NextKey: re-read once; if still stale, just proceed and let
        # the chain reject it with BadEpoch.
        pk_bytes, epoch_next = acquire_next_key(substrate, mev_pallet)
        blob = mlkem768_seal_blob(pk_bytes, plaintext)

    key_epoch = int(epoch_next)
    print(f"[i] Using MevShield::NextKey epoch={key_epoch} (chain Epoch={curr_epoch})")

    # Submit wrapper for NEXT epoch (or current, if NextKey happens to match)
    call_submit = compose_call(substrate, mev_pallet, "submit_encrypted", {
        "key_epoch": key_epoch,
        "commitment": commitment_hex,
        "ciphertext": "0x" + blob.hex(),
        "payload_version": 1,
        "max_weight": {"ref_time": 5_000_000_000, "proof_size": 128_000},
    })
    rec = submit_signed(substrate, author, call_submit)
    print(f"[✓] submit_encrypted accepted; block={rec.block_hash}, key_epoch={key_epoch}")

    # Assert stake increased
    after, delta = wait_for_stake_increase(
        substrate=substrate,
        module=subtensor,
        hot_ss58=hot.ss58_address,
        netuid=args.netuid,
        start=stake_before,
        min_delta=amount_planck,
        timeout_s=args.timeout,
        poll_s=0.8,
    )
    print(f"[i] stake_after: {after}  (Δ={delta})")
    print(f"✅ PASS: stake increased by at least {amount_planck} planck.")


if __name__ == "__main__":
    main()
