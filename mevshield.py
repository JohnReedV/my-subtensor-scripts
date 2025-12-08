#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MEV‑Shield add_stake E2E (v2, direct-extrinsic reveal):

  • Reads MevShield::NextKey as Vec<u8>(1184) ML‑KEM public key.
  • Builds a *normal signed extrinsic* for:
        Subtensor::add_stake(hotkey=H, netuid=N, amount=A)
    with signer C (cold account).
  • commitment = blake2_256(signed_extrinsic_bytes).
  • Plaintext for encryption is exactly the SCALE-encoded signed extrinsic:
        plaintext = signed_extrinsic_bytes
  • Encrypts plaintext with ML‑KEM‑768 + XChaCha20‑Poly1305 to:
        blob = [u16 kem_len] || kem_ct || nonce24 || aead_ct
  • Submits MevShield::submit_encrypted { commitment, ciphertext = blob }.
  • The node’s author‑side workers decrypt the wrapper in the last window
    of the slot, reconstruct the signed extrinsic, and submit it into the
    local tx pool.
  • The script asserts MEV‑hiding *at the block level* for this specific stake:

      Let the inner call be:
        Subtensor::add_stake(hotkey=H, netuid=N, amount=A) with signer C.

      1. Inclusion block B_submit:
           - contains MevShield::submit_encrypted with our commitment,
           - has NO plain Subtensor::add_stake(H, N, A) signed by C.

      2. For every block B > B_submit and < B_reveal:
           - NO plain Subtensor::add_stake(H, N, A) signed by C.

      3. A later block B_reveal:
           - contains a plain Subtensor::add_stake(H, N, A) with signer C.

  • The script does NOT assert that stake actually changed; only that the
    first on‑chain plaintext representation of this stake appears later,
    after an intermediate encrypted-only representation.

Crypto details (must match node):

  • ML‑KEM‑768 (Kyber) for KEM.
  • XChaCha20‑Poly1305 for AEAD.
  • Shared secret is 32 bytes.
  • AEAD key = shared secret (direct, no HKDF).
  • AAD = [] (empty).
  • Ciphertext blob layout:
        [u16 kem_len LE][kem_ct kem_len bytes][nonce24][aead_ct]
"""

import argparse
import ctypes
import hashlib
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

MLKEM768_PK_LEN = 1184
MLKEM768_CT_LEN = 1088
NONCE_LEN = 24
AEAD_TAG_LEN = 16

# How much TAO to pre‑fund the subnet owner with to cover the lock cost (in TAO)
DEFAULT_LOCK_FUND_HINT_TAO = 5_000.0  # generous for localnet

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
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
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
# Helpers for reading Vec<u8> / hex / SCALE from RPC JSON
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


def _normalize_hex_0x(v: Any) -> Optional[str]:
    """
    Normalize various hex-ish representations to a canonical '0x..' lowercase string.
    """
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


# ─────────────────────────────────────────────────────────────────────────────-
# MevShield key access (NextKey / CurrentKey)
# ─────────────────────────────────────────────────────────────────────────────-


def read_next_key_bytes(
    substrate: SubstrateInterface,
    pallet: str,
    block_hash: Optional[str] = None,
) -> bytes:
    """
    Read MevShield::NextKey as a plain Vec<u8> ML‑KEM‑768 public key.
    If block_hash is provided, read it at that block.
    """
    v = substrate.query(pallet, "NextKey", [], block_hash=block_hash)
    raw = getattr(v, "value", v)
    pk_bytes = _parse_vec_u8(raw)
    return pk_bytes or b""


def read_current_key_bytes(
    substrate: SubstrateInterface,
    pallet: str,
    block_hash: Optional[str] = None,
) -> bytes:
    """
    Read MevShield::CurrentKey as a plain Vec<u8> ML‑KEM‑768 public key.
    If block_hash is provided, read it at that block.
    """
    v = substrate.query(pallet, "CurrentKey", [], block_hash=block_hash)
    raw = getattr(v, "value", v)
    pk_bytes = _parse_vec_u8(raw)
    return pk_bytes or b""


def acquire_next_key(
    substrate: SubstrateInterface,
    pallet: str,
    timeout_s: int = 120,
    poll_s: float = 0.25,
) -> bytes:
    """
    Poll MevShield::NextKey until we have a well-formed ML‑KEM‑768 key.

    Returns `public_key_bytes` where len(public_key_bytes) == MLKEM768_PK_LEN.
    """
    t0 = time.time()
    last_err: Optional[str] = None

    while time.time() - t0 < timeout_s:
        try:
            pk = read_next_key_bytes(substrate, pallet)
            if pk and len(pk) == MLKEM768_PK_LEN:
                return pk
            last_err = f"unexpected NextKey length {len(pk)}"
        except Exception as e:
            last_err = str(e)
        time.sleep(poll_s)

    raise RuntimeError(f"Timed out reading MevShield::NextKey ({last_err})")


# ─────────────────────────────────────────────────────────────────────────────-
# Substrate helpers & utilities
# ─────────────────────────────────────────────────────────────────────────────-


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
    xt = substrate.create_signed_extrinsic(call=call, keypair=who, era="00")  # Immortal
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


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
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


def get_block_number(substrate: SubstrateInterface, block_hash: str) -> int:
    """
    Robustly get a block's number given its hash.
    """
    try:
        header = substrate.get_block_header(block_hash=block_hash)
    except Exception:
        return 0

    hdr_val = getattr(header, "value", header)
    if isinstance(hdr_val, dict) and "header" in hdr_val:
        hdr_val = hdr_val["header"]

    if not isinstance(hdr_val, dict):
        return 0

    number = hdr_val.get("number")

    if isinstance(number, int):
        return number
    if isinstance(number, str):
        s = number.strip()
        if not s:
            return 0
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


# ─────────────────────────────────────────────────────────────────────────────-
# Funding helpers (faucet, balances)
# ─────────────────────────────────────────────────────────────────────────────-


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
):
    """
    Transfer funds from signer -> dest, tolerating 'Priority is too low (1014)'
    as 'we already have a tx in the pool for this nonce'.
    """
    amount_planck = int(amount_planck)

    # Try transfer_keep_alive, then fall back to transfer if needed
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
        raise RuntimeError(
            "Could not compose Balances::transfer_keep_alive or Balances::transfer"
        )

    try:
        submit_signed(substrate, signer, call)
    except RuntimeError as e:
        msg = str(e)
        if "Priority is too low" in msg or "code': 1014" in msg or "1014" in msg:
            print(
                "[i] transfer_keep_alive: tx with same nonce already in pool (1014); "
                "treating as already pending and not fatal for funding."
            )
            return
        raise


def ensure_funded_planck(
    substrate: SubstrateInterface,
    faucet: Keypair,
    dest_ss58: str,
    min_balance_planck: int,
    label: str = "",
):
    """
    Ensure dest_ss58 has at least min_balance_planck free balance by transferring from faucet.
    """
    have = account_free_balance(substrate, dest_ss58)
    need = int(min_balance_planck)
    if have >= need:
        return

    delta = int((need - have) * 1.1) + 1  # 10% headroom for fees
    who = label or dest_ss58
    print(
        f"[i] Funding {who} with {delta} planck from {faucet.ss58_address} "
        f"(have={have}, need={need})"
    )
    transfer_keep_alive(substrate, faucet, dest_ss58, delta)


# ─────────────────────────────────────────────────────────────────────────────-
# Subtensor / subnet helpers
# ─────────────────────────────────────────────────────────────────────────────-


def networks_added_dynamic(
    substrate: SubstrateInterface, subtensor_pallet: str
) -> List[int]:
    """
    Read all netuids from SubtensorModule::NetworksAdded (or equivalent).
    """
    nets: List[int] = []
    try:
        for key, val in substrate.query_map(subtensor_pallet, "NetworksAdded"):
            if not val or val.value is None:
                continue
            if not bool(val.value):
                continue
            kv = key.value
            if isinstance(kv, dict) and "NetUid" in kv:
                n = int(kv["NetUid"])
            else:
                n = int(kv)
            if n != 0:
                nets.append(n)
    except Exception:
        pass
    return sorted(set(nets))


def ensure_hotkey_registered(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    module: str,
):
    """
    Best-effort burned_register(cold -> hotkey) for this subnet.
    """
    try:
        call = compose_call(
            substrate,
            module,
            "burned_register",
            {"netuid": int(netuid), "hotkey": hot_ss58},
        )
        submit_signed(substrate, cold, call)
    except Exception:
        # Already registered, throttled, etc. — safe to ignore for this test.
        pass


def compose_add_stake(
    substrate: SubstrateInterface,
    module: str,
    hot_ss58: str,
    netuid: int,
    amount_planck: int,
):
    last_err: Optional[Exception] = None
    for field in ("amount_staked", "amount", "value"):
        try:
            return substrate.compose_call(
                call_module=module,
                call_function="add_stake",
                call_params={
                    "hotkey": hot_ss58,
                    "netuid": int(netuid),
                    field: int(amount_planck),
                },
            )
        except Exception as e:
            last_err = e
    raise RuntimeError(
        "Unable to compose add_stake (tried amount_staked/amount/value). "
        f"Last error: {last_err}"
    )


def ensure_subnet_exists_or_register(
    substrate: SubstrateInterface,
    subtensor_pallet: str,
    faucet: Keypair,
    owner_cold: Keypair,
    owner_hot_ss58: str,
    requested_netuid: int,
    decimals: int,
    lock_funding_hint_tao: float = DEFAULT_LOCK_FUND_HINT_TAO,
) -> Tuple[int, bool]:
    """
    Ensure there is a usable subnet:

      * If requested_netuid already exists in NetworksAdded, just use it.
      * Otherwise:
          - fund owner_cold enough to pay subnet lock cost
          - register_network(origin=owner_cold, hotkey=owner_hot)
          - return the new netuid.

    Returns (netuid, did_register_new)
    """
    existing = networks_added_dynamic(substrate, subtensor_pallet)
    if existing:
        print(f"[i] Existing subnets (NetworksAdded): {existing}")
    else:
        print("[i] No subnets found in NetworksAdded yet.")

    if requested_netuid in existing:
        print(
            f"[i] Requested netuid={requested_netuid} exists; "
            "will use it as-is (no register_network)."
        )
        return requested_netuid, False

    print(
        f"[i] Requested netuid={requested_netuid} does not exist yet. "
        f"Existing nets: {existing}. Registering a new subnet via register_network."
    )

    before = set(existing)

    # Pre-fund owner_cold to comfortably pay the subnet lock.
    lock_min_planck = int(lock_funding_hint_tao * (10 ** decimals))
    ensure_funded_planck(
        substrate,
        faucet,
        owner_cold.ss58_address,
        lock_min_planck,
        label="owner_cold (lock pre-fund)",
    )

    call = compose_call(
        substrate,
        subtensor_pallet,
        "register_network",
        {"hotkey": owner_hot_ss58},
    )

    rec = submit_signed(substrate, owner_cold, call)
    print(f"[i] register_network submitted in block {rec.block_hash}")

    after = set(networks_added_dynamic(substrate, subtensor_pallet))
    new_nets = sorted(after - before)
    if not new_nets:
        if after:
            guess = max(after)
            print(
                "[!] register_network succeeded but no new net detected; "
                f"falling back to highest netuid={guess}."
            )
            return guess, True
        raise RuntimeError(
            "register_network succeeded but did not create a detectable subnet "
            "(NetworksAdded unchanged)."
        )

    new_netuid = new_nets[-1]
    print(
        f"[i] New subnet registered with netuid={new_netuid} "
        f"(existing nets now: {sorted(after)})"
    )
    return new_netuid, True


def ensure_subtoken_enabled_for_net(
    substrate: SubstrateInterface,
    subtensor_pallet: str,
    owner_cold: Keypair,
    netuid: int,
):
    """
    Best-effort: call Subtensor::start_call(netuid) as the subnet owner (owner_cold)
    to enable the subtoken. If it fails, we log and continue; add_stake will
    still fail with SubtokenDisabled if subtoken isn't actually enabled.
    """
    try:
        call = compose_call(
            substrate,
            subtensor_pallet,
            "start_call",
            {"netuid": int(netuid)},
        )
    except Exception as e:
        print(
            f"[!] Could not compose {subtensor_pallet}::start_call for netuid={netuid}: {e}"
        )
        return

    try:
        rec = submit_signed(substrate, owner_cold, call)
        print(
            f"[i] start_call for netuid={netuid} succeeded in block {rec.block_hash}; "
            "Subtoken should now be enabled."
        )
    except RuntimeError as e:
        print(
            f"[!] start_call for netuid={netuid} failed (Subtoken may already be enabled "
            f"or origin not owner): {e}"
        )


# ─────────────────────────────────────────────────────────────────────────────-
# Block / call inspection helpers for MEV assertions
# ─────────────────────────────────────────────────────────────────────────────-


def _extract_call_from_raw(raw: Any) -> Tuple[Optional[str], Optional[str], Any]:
    """
    Given an extrinsic or nested call value, return:
        (call_module, call_function, call_args_raw)
    """
    if raw is None:
        return None, None, None

    if hasattr(raw, "value"):
        raw = raw.value

    if not isinstance(raw, dict):
        return None, None, None

    # Either the value is the call or it's under "call".
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
    return module, fn, args


def _args_as_dict(args_raw: Any) -> Dict[str, Any]:
    """
    Convert call_args list or dict into a {name: value} mapping.
    """
    if isinstance(args_raw, dict):
        return dict(args_raw)
    out: Dict[str, Any] = {}
    if isinstance(args_raw, list):
        for item in args_raw:
            if isinstance(item, dict):
                name = item.get("name")
                if name:
                    out[name] = item.get("value")
    return out


def _extract_extrinsic_signer_ss58(raw: Any) -> Optional[str]:
    """
    Try to extract the signer SS58 address from an extrinsic value as returned by
    substrate.get_block().
    """
    if hasattr(raw, "value"):
        raw = raw.value
    if not isinstance(raw, dict):
        return None

    # py-substrate-interface typically exposes 'address' for the signer
    addr = raw.get("address")
    if isinstance(addr, str):
        return addr

    signer = raw.get("signer")
    if isinstance(signer, str):
        return signer

    return None


def _is_plain_add_stake_for_tx(
    call_args_raw: Any,
    hot_ss58: str,
    netuid: int,
    amount_planck: int,
) -> bool:
    """
    Returns True if these call args look like:
        SubtensorModule::add_stake(hotkey=hot_ss58, netuid=netuid, amount≈amount_planck)
    """
    args = _args_as_dict(call_args_raw)
    if args.get("hotkey") != hot_ss58:
        return False

    netuid_v = _to_int(args.get("netuid"))
    if netuid_v != netuid:
        return False

    amount_v = _to_int(
        args.get("amount_staked") or args.get("amount") or args.get("value")
    )
    if amount_v is None:
        return False

    # Allow >= in case runtime adds slightly more due to fees / rounding
    return amount_v >= amount_planck


def _is_our_submit_encrypted(
    module: Optional[str],
    fn: Optional[str],
    args_raw: Any,
    mev_pallet: str,
    commitment_hex: str,
) -> bool:
    """
    Does this call look like MevShield::submit_encrypted with our commitment?
    """
    if module is None or fn is None:
        return False
    if module.lower() != mev_pallet.lower() or fn != "submit_encrypted":
        return False

    args = _args_as_dict(args_raw)
    commit_val = args.get("commitment")
    c = _normalize_hex_0x(commit_val)
    target = _normalize_hex_0x(commitment_hex)
    return c is not None and target is not None and c == target


# ─────────────────────────────────────────────────────────────────────────────-
# High-level MEV assertions (blocks only, no pool)
# ─────────────────────────────────────────────────────────────────────────────-


def assert_reveal_hidden(
    substrate: SubstrateInterface,
    mev_pallet: str,
    subtensor_pallet: str,
    cold_ss58: str,
    hot_ss58: str,
    netuid: int,
    amount_planck: int,
    commitment_hex: str,
    inclusion_block_hash: str,
    timeout_s: int = 180,
    poll_s: float = 0.8,
) -> Tuple[int, int]:
    """
    MEV‑hiding assertion for this specific encrypted add_stake, assuming the
    plaintext is a *full signed extrinsic*:

      1. The inclusion block contains our MevShield::submit_encrypted(commitment)
         and NO plain Subtensor::add_stake for (cold, hot, netuid, amount).

      2. For all blocks after inclusion and before reveal there is NO such
         plain Subtensor::add_stake.

      3. A strictly later block contains a plain Subtensor::add_stake with
         (hot, netuid, amount) and signer == cold.

    Returns (submit_block_number, reveal_block_number).
    """
    if not inclusion_block_hash:
        raise RuntimeError("Inclusion block hash is empty; cannot assert MEV safety")

    submit_num = get_block_number(substrate, inclusion_block_hash)
    print(f"[i] submit_encrypted included in block #{submit_num} ({inclusion_block_hash})")

    # Log CurrentKey / NextKey at submit block (runtime view)
    try:
        curr_at_submit = read_current_key_bytes(substrate, mev_pallet, inclusion_block_hash)
        next_at_submit = read_next_key_bytes(substrate, mev_pallet, inclusion_block_hash)
        curr_submit_hash = (
            "0x" + blake2_256(curr_at_submit).hex() if curr_at_submit else "None"
        )
        next_submit_hash = (
            "0x" + blake2_256(next_at_submit).hex() if next_at_submit else "None"
        )
        print(
            f"[DBG] Runtime CurrentKey@submit block #{submit_num}: len={len(curr_at_submit)}, hash={curr_submit_hash}"
        )
        print(
            f"[DBG] Runtime NextKey@submit block #{submit_num}:    len={len(next_at_submit)}, hash={next_submit_hash}"
        )
    except Exception as e:
        print(f"[DBG] Failed to query CurrentKey/NextKey at submit block: {e}")

    # --- 1) Check inclusion block contents ---
    block = substrate.get_block(block_hash=inclusion_block_hash)
    extrinsics = block.get("extrinsics") or block.get("extrinsic") or []

    submit_idx: Optional[int] = None
    bad_inclusion: list = []

    for idx, ext in enumerate(extrinsics):
        raw = getattr(ext, "value", ext)
        module, fn, args_raw = _extract_call_from_raw(raw)
        signer_ss58 = _extract_extrinsic_signer_ss58(raw)

        # Locate our submit_encrypted
        if _is_our_submit_encrypted(module, fn, args_raw, mev_pallet, commitment_hex):
            submit_idx = idx

        # Look for visible leaks in inclusion block: a plain add_stake for *this* stake.
        if (
            module
            and module.lower() == subtensor_pallet.lower()
            and fn == "add_stake"
            and signer_ss58 == cold_ss58
            and _is_plain_add_stake_for_tx(
                args_raw, hot_ss58=hot_ss58, netuid=netuid, amount_planck=amount_planck
            )
        ):
            bad_inclusion.append(("Subtensor::add_stake", idx))

    if submit_idx is None:
        raise RuntimeError(
            "submit_encrypted with matching commitment not found in inclusion block; "
            "did the extrinsic get reorged or filtered?"
        )

    print(f"[i] Located submit_encrypted at index {submit_idx} in block #{submit_num}")

    if bad_inclusion:
        details = ", ".join(f"{kind}@{idx}" for kind, idx in bad_inclusion)
        raise RuntimeError(
            "Inclusion block already contains visible MEV-leaking extrinsics for this stake: "
            + details
        )

    print(
        f"[✓] Inclusion block #{submit_num} contains only encrypted payload for this stake; "
        "no visible Subtensor::add_stake."
    )

    # --- 2) Scan subsequent blocks until reveal ---
    print(
        f"[i] Waiting for first plain Subtensor::add_stake for "
        f"(cold={cold_ss58}, hot={hot_ss58}, netuid={netuid}, amount={amount_planck})"
    )

    start = time.time()
    next_height = submit_num + 1
    reveal_block_num: Optional[int] = None
    reveal_xt_index: Optional[int] = None
    reveal_block_hash: Optional[str] = None

    while time.time() - start < timeout_s:
        # Determine current head
        try:
            head_hash = substrate.get_chain_head()
        except Exception:
            time.sleep(poll_s)
            continue

        head_num = get_block_number(substrate, head_hash)
        if head_num < next_height:
            time.sleep(poll_s)
            continue

        found_reveal_here = False

        while next_height <= head_num:
            bh = substrate.get_block_hash(next_height)
            if not bh:
                next_height += 1
                continue

            blk = substrate.get_block(block_hash=bh)
            exts = blk.get("extrinsics") or blk.get("extrinsic") or []
            found_add = False
            reveal_idx_here: Optional[int] = None

            for idx, ext in enumerate(exts):
                raw = getattr(ext, "value", ext)
                module, fn, args_raw = _extract_call_from_raw(raw)
                signer_ss58 = _extract_extrinsic_signer_ss58(raw)

                if (
                    module
                    and module.lower() == subtensor_pallet.lower()
                    and fn == "add_stake"
                    and signer_ss58 == cold_ss58
                    and _is_plain_add_stake_for_tx(
                        args_raw,
                        hot_ss58=hot_ss58,
                        netuid=netuid,
                        amount_planck=amount_planck,
                    )
                ):
                    found_add = True
                    reveal_idx_here = idx
                    break

            if found_add:
                reveal_block_num = next_height
                reveal_xt_index = reveal_idx_here
                reveal_block_hash = bh
                print(
                    f"[i] Plain Subtensor::add_stake for our stake found in "
                    f"block #{next_height} (extrinsic index {reveal_xt_index})"
                )
                found_reveal_here = True
                break
            else:
                print(
                    f"[✓] Block #{next_height}: this stake is still MEV‑hidden "
                    f"(no visible Subtensor::add_stake for this (cold,hot,netuid,amount))."
                )

            next_height += 1

        if found_reveal_here:
            break

        time.sleep(poll_s)

    if reveal_block_num is None:
        raise RuntimeError(
            f"Timed out ({timeout_s}s) while waiting for plain Subtensor::add_stake "
            "for this add_stake."
        )

    if reveal_block_num <= submit_num:
        raise RuntimeError(
            f"add_stake appeared at block #{reveal_block_num}, which is not strictly "
            f"after submit_encrypted block #{submit_num}; this violates delayed reveal."
        )

    # Log CurrentKey / NextKey at reveal block (runtime view)
    if reveal_block_hash is not None:
        try:
            curr_at_reveal = read_current_key_bytes(substrate, mev_pallet, reveal_block_hash)
            next_at_reveal = read_next_key_bytes(substrate, mev_pallet, reveal_block_hash)
            curr_reveal_hash = (
                "0x" + blake2_256(curr_at_reveal).hex() if curr_at_reveal else "None"
            )
            next_reveal_hash = (
                "0x" + blake2_256(next_at_reveal).hex() if next_at_reveal else "None"
            )
            print(
                f"[DBG] Runtime CurrentKey@reveal block #{reveal_block_num}: len={len(curr_at_reveal)}, hash={curr_reveal_hash}"
            )
            print(
                f"[DBG] Runtime NextKey@reveal block #{reveal_block_num}:    len={len(next_at_reveal)}, hash={next_reveal_hash}"
            )
        except Exception as e:
            print(f"[DBG] Failed to query CurrentKey/NextKey at reveal block: {e}")

    print(
        f"[✓] MEV‑safe (block-level): plain add_stake for this stake appeared later in block "
        f"#{reveal_block_num}, after encrypted submit_encrypted in block #{submit_num}."
    )

    return submit_num, reveal_block_num


# ─────────────────────────────────────────────────────────────────────────────-
# Main
# ─────────────────────────────────────────────────────────────────────────────-


def main():
    ap = argparse.ArgumentParser(
        description=(
            "MEV‑Shield add_stake using MevShield::NextKey (Vec<u8> ML‑KEM public key) and "
            "asserting that the inner add_stake is first represented on-chain in encrypted "
            "form (submit_encrypted) and only later as a plain Subtensor::add_stake extrinsic."
        )
    )
    ap.add_argument("--ws", default="ws://127.0.0.1:9945")
    ap.add_argument("--netuid", type=int, default=3)
    ap.add_argument("--stake", type=float, default=5.0, help="Stake in TAO to add")
    ap.add_argument("--author-uri", default="//Eve", help="Wrapper fee payer")
    ap.add_argument("--cold-uri", default="//OwnerCold", help="Inner signer (signs extrinsic)")
    ap.add_argument("--hot-uri", default="//Staker1Hot", help="Target hotkey")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    substrate = connect(args.ws)
    mev_pallet = resolve_mev_pallet(substrate)
    subtensor = resolve_subtensor_pallet(substrate)
    decimals = token_decimals(substrate)

    author = Keypair.create_from_uri(args.author_uri)
    cold = Keypair.create_from_uri(args.cold_uri)
    hot = Keypair.create_from_uri(args.hot_uri)
    faucet = Keypair.create_from_uri("//Alice")

    # Amount for this test
    amount_planck = int(round(args.stake * (10 ** decimals)))

    # Ensure cold/hot have enough TAO for fees + stake
    cold_min = max(amount_planck * 2, int(20 * (10 ** decimals)))
    hot_min = max(amount_planck, int(2 * (10 ** decimals)))

    ensure_funded_planck(substrate, faucet, cold.ss58_address, cold_min, label="cold")
    ensure_funded_planck(substrate, faucet, hot.ss58_address, hot_min, label="hot")

    # Ensure subnet exists (or register a new one we own), and enable subtoken if new.
    netuid, did_register = ensure_subnet_exists_or_register(
        substrate=substrate,
        subtensor_pallet=subtensor,
        faucet=faucet,
        owner_cold=cold,
        owner_hot_ss58=hot.ss58_address,
        requested_netuid=args.netuid,
        decimals=decimals,
        lock_funding_hint_tao=DEFAULT_LOCK_FUND_HINT_TAO,
    )

    if did_register:
        ensure_subtoken_enabled_for_net(substrate, subtensor, cold, netuid)
    else:
        print(
            f"[i] Using existing netuid={netuid}; assuming Subtoken is already enabled "
            "for this subnet. If not, add_stake will fail with SubtokenDisabled."
        )

    # Ensure hotkey is registered on this subnet (best-effort)
    ensure_hotkey_registered(substrate, cold, hot.ss58_address, netuid, subtensor)

    # (Informational) stake before
    stake_before = 0
    try:
        info = substrate.query(subtensor, "Stake", [hot.ss58_address, netuid])
        stake_before = _to_int(info) or 0
    except Exception:
        pass
    print(f"[i] stake_before (net {netuid}): {stake_before}")

    # Compose inner add_stake call
    call = compose_add_stake(substrate, subtensor, hot.ss58_address, netuid, amount_planck)

    # Build a *normal signed extrinsic* (cold signer) that we will encrypt as plaintext.
    inner_xt = substrate.create_signed_extrinsic(call=call, keypair=cold, era="00")
    inner_xt_bytes = call_to_scale_bytes(inner_xt)

    print(f"[DBG] inner signed extrinsic: len={len(inner_xt_bytes)} bytes")

    # Read the *announced next* ML‑KEM public key.
    pk_bytes = acquire_next_key(substrate, mev_pallet)
    if len(pk_bytes) != MLKEM768_PK_LEN:
        raise RuntimeError(f"NextKey length {len(pk_bytes)} != {MLKEM768_PK_LEN}")

    print(
        f"[DBG] Client view: NextKey len={len(pk_bytes)}, blake2_256=0x{blake2_256(pk_bytes).hex()}"
    )
    try:
        curr_now = read_current_key_bytes(substrate, mev_pallet)
        if curr_now:
            print(
                f"[DBG] Client view: CurrentKey len={len(curr_now)}, blake2_256=0x{blake2_256(curr_now).hex()}"
            )
        else:
            print("[DBG] Client view: CurrentKey not set (len=0)")
    except Exception as e:
        print(f"[DBG] Failed to query CurrentKey at client time: {e}")

    # commitment = blake2_256(signed_extrinsic_bytes)
    commitment_bytes = blake2_256(inner_xt_bytes)
    commitment_hex = "0x" + commitment_bytes.hex()

    print(f"[DBG] commitment_hex (extrinsic bytes) = {commitment_hex}")

    # Encrypt plaintext = signed extrinsic bytes with Rust FFI (Kyber/ML‑KEM‑768 + XChaCha20-Poly1305)
    blob = mlkem768_seal_blob(pk_bytes, inner_xt_bytes)
    kem_len = int.from_bytes(blob[0:2], "little") if len(blob) >= 2 else None
    print(f"[DBG] ciphertext blob: total_len={len(blob)}, kem_len={kem_len}")

    print("[i] Using MevShield::NextKey and commitment = blake2_256(signed_extrinsic_bytes)")

    # Submit encrypted wrapper
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
    print(f"[✓] submit_encrypted accepted; block={rec.block_hash}")

    # MEV‑safety assertion: encrypted-only representation until later plain add_stake.
    submit_num, reveal_num = assert_reveal_hidden(
        substrate=substrate,
        mev_pallet=mev_pallet,
        subtensor_pallet=subtensor,
        cold_ss58=cold.ss58_address,
        hot_ss58=hot.ss58_address,
        netuid=netuid,
        amount_planck=amount_planck,
        commitment_hex=commitment_hex,
        inclusion_block_hash=rec.block_hash,
        timeout_s=args.timeout,
        poll_s=0.8,
    )

    print(
        f"[i] MEV‑Shield flow: submit_encrypted in block #{submit_num}, "
        f"plain add_stake in block #{reveal_num}"
    )

    # Optional: show stake_after (informational only; NO assertion)
    stake_after = 0
    try:
        info = substrate.query(subtensor, "Stake", [hot.ss58_address, netuid])
        stake_after = _to_int(info) or 0
    except Exception:
        pass
    print(f"[i] stake_after (net {netuid}): {stake_after}")

    print(
        "✅ PASS: MEV‑Shield behaviour verified — for this stake, the first on-chain "
        "representation was the encrypted submit_encrypted wrapper; the first visible "
        "plain Subtensor::add_stake for (cold, hot, netuid, amount) appeared only in a "
        "later block."
    )


if __name__ == "__main__":
    main()
