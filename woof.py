#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MEV‑Shield add_stake fee probe:

  • Compares fees for:
      1) Plain Subtensor::add_stake (signed by cold)
      2) Encrypted add_stake using MevShield::submit_encrypted + execute_revealed

  • Measures, in planck and TAO (network fees only, NOT the 5 TAO stake):
      - Fee paid by cold for the plain add_stake.
      - Fee paid by author for submit_encrypted.
      - Any additional fee paid by author or cold when execute_revealed runs.
      - Total encrypted fee (author + cold).

  • Uses the same ML‑KEM‑768 + XChaCha20‑Poly1305 scheme:
      NextKey (ML‑KEM pubkey) → key_hash = blake2_256(NextKey_bytes)
      payload_core = signer(32) || key_hash(32) || SCALE(call)
      commitment = blake2_256(payload_core)
      message = "mev-shield:v1" || genesis_hash || payload_core
      signature = cold.sign(message)
      plaintext = payload_core || 0x01 || sr25519_signature(64)
      blob = [u16 kem_len][kem_ct][nonce24][aead_ct]

  • Assumptions:
      - There is a MevShield pallet deployed (storage NextKey / CurrentKey, calls submit_encrypted, execute_revealed).
      - There is a Subtensor pallet with add_stake(hotkey, netuid, amount_*).
      - There is a faucet (//Alice) with enough funds.

Usage example:

  python mev_shield_fee_probe.py \
      --ws ws://127.0.0.1:9945 \
      --netuid 3 \
      --stake 5.0 \
      --author-uri //Eve \
      --cold-uri //OwnerCold \
      --hot-uri //Staker1Hot

NOTE: By default, author and cold are separate. You can make them the same
(e.g. --author-uri //OwnerCold) if you want "user" to be a single account.
"""

import argparse
import ctypes
import hashlib
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException
from substrateinterface.utils.ss58 import ss58_decode

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

MLKEM768_PK_LEN = 1184
MLKEM768_CT_LEN = 1088
NONCE_LEN = 24
AEAD_TAG_LEN = 16

DEFAULT_LOCK_FUND_HINT_TAO = 5_000.0  # generous for localnet

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_PATHS = [
    os.path.join(THIS_DIR, "libmlkemffi.so"),
    os.path.join(THIS_DIR, "libmlkemffi.dylib"),
    os.path.join(THIS_DIR, "mlkemffi.dll"),
    os.path.join(THIS_DIR, "mlkemffi", "target", "release", "libmlkemffi.so"),
    os.path.join(THIS_DIR, "mlkemffi", "target", "release", "libmlkemffi.dylib"),
    os.path.join(THIS_DIR, "mlkemffi", "target", "release", "mlkemffi.dll"),
]

# ──────────────────────────────────────────────────────────────────────────────
# FFI loader (mlkem768_seal_blob)
# ──────────────────────────────────────────────────────────────────────────────


def _load_mlkemffi() -> ctypes.CDLL:
    """
    Load the mlkemffi shared library and configure mlkem768_seal_blob.

    Recent versions use direct-from-ML‑KEM shared secret ("v1").
    """
    last_err = None
    for p in LIB_PATHS:
        if os.path.exists(p):
            try:
                lib = ctypes.CDLL(p)

                # int mlkem768_seal_blob(
                #     const uint8_t *pk_ptr, size_t pk_len,
                #     const uint8_t *pt_ptr, size_t pt_len,
                #     uint8_t *out_ptr, size_t out_len,
                #     size_t *written_out
                # );
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

                # (Optional) KDF id probe
                kdf_id = "v1"
                try:
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
                    kdf_id = "v1"

                print(f"[i] Loaded mlkemffi: {p} (kdf={kdf_id})")
                if kdf_id != "v1":
                    print(
                        "[!] WARNING: mlkemffi reports non-standard KDF id "
                        f"'{kdf_id}'. Ensure node and FFI agree on the KDF."
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
    buf = ctypes.create_string_buffer(b)
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

    pk_ptr, pk_len, _ = _as_c_buf(pk_bytes)
    pt_ptr, pt_len, _ = _as_c_buf(plaintext)

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
# Helpers for bytes / hex / SCALE / blake2_256
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
        for k in ("value", "bytes", "data", "inner", "public_key"):
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
        if s.startswith(("0x", "0X")):
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
                return _normalize_hex_0x(v[k])
    return None


def blake2_256(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()


# ──────────────────────────────────────────────────────────────────────────────
# Substrate / metadata helpers
# ──────────────────────────────────────────────────────────────────────────────


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
                print(f"[i] Resolved MevShield pallet: {n}")
                return n
    for n in names:
        if "mev" in n.lower() and "shield" in n.lower():
            print(f"[i] Resolved MevShield pallet (fuzzy): {n}")
            return n
    raise RuntimeError("MevShield pallet not found in metadata")


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
    """
    Submit a signed extrinsic and wait for inclusion and finalization.
    """
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

    number = hdr_val.get("number", None)
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


# ──────────────────────────────────────────────────────────────────────────────
# Balances, funding, stake helpers
# ──────────────────────────────────────────────────────────────────────────────


def account_free_balance(
    substrate: SubstrateInterface,
    ss58: str,
    block_hash: Optional[str] = None,
) -> int:
    try:
        info = substrate.query("System", "Account", [ss58], block_hash=block_hash).value
        return int(info["data"]["free"])
    except Exception:
        return 0


def transfer_keep_alive(
    substrate: SubstrateInterface,
    signer: Keypair,
    dest_ss58: str,
    amount_planck: int,
):
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
                "treating as already pending."
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
    have = account_free_balance(substrate, dest_ss58)
    need = int(min_balance_planck)
    if have >= need:
        return
    delta = int((need - have) * 1.1) + 1
    who = label or dest_ss58
    print(
        f"[i] Funding {who} with {delta} planck from {faucet.ss58_address} "
        f"(have={have}, need={need})"
    )
    transfer_keep_alive(substrate, faucet, dest_ss58, delta)


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
        for k in ("value", "bits", "free", "amount", "total", "stake"):
            if k in v:
                got = _to_int(v[k])
                if got is not None:
                    return got
        if len(v) == 1:
            return _to_int(list(v.values())[0])
    if hasattr(v, "value"):
        return _to_int(getattr(v, "value"))
    return None


def get_stake(
    substrate: SubstrateInterface,
    subtensor_pallet: str,
    hot_ss58: str,
    netuid: int,
    block_hash: Optional[str] = None,
) -> int:
    try:
        info = substrate.query(
            subtensor_pallet,
            "Stake",
            [hot_ss58, int(netuid)],
            block_hash=block_hash,
        )
        return _to_int(info) or 0
    except Exception:
        return 0


# ──────────────────────────────────────────────────────────────────────────────
# Subtensor / subnet helpers
# ──────────────────────────────────────────────────────────────────────────────


def networks_added_dynamic(
    substrate: SubstrateInterface,
    subtensor_pallet: str,
) -> List[int]:
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
    existing = networks_added_dynamic(substrate, subtensor_pallet)
    if existing:
        print(f"[i] Existing subnets (NetworksAdded): {existing}")
    else:
        print("[i] No subnets found in NetworksAdded yet.")

    if requested_netuid in existing:
        print(
            f"[i] Requested netuid={requested_netuid} exists; using it as-is "
            "(no register_network)."
        )
        return requested_netuid, False

    print(
        f"[i] Requested netuid={requested_netuid} does not exist yet. "
        f"Existing nets: {existing}. Registering a new subnet."
    )

    before = set(existing)
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

    attempts = 0
    while True:
        attempts += 1
        try:
            rec = submit_signed(substrate, owner_cold, call)
            print(f"[i] register_network submitted in block {rec.block_hash}")
            break
        except RuntimeError as e:
            msg = str(e)
            if "CannotAffordLockCost" in msg:
                bal = account_free_balance(substrate, owner_cold.ss58_address)
                extra_min = bal * 3 + int(1_000 * (10 ** decimals))
                print(
                    "[i] register_network failed with CannotAffordLockCost; "
                    f"increasing owner_cold funds to at least {extra_min} and retrying."
                )
                ensure_funded_planck(
                    substrate,
                    faucet,
                    owner_cold.ss58_address,
                    extra_min,
                    label="owner_cold (lock retry)",
                )
                if attempts >= 4:
                    raise RuntimeError(
                        "Unable to satisfy subnet lock cost after multiple funding attempts."
                    ) from e
                continue
            if "Priority is too low" in msg or "code': 1014" in msg or "1014" in msg:
                print(
                    "[i] register_network: tx with same nonce already in pool (1014). "
                    "Waiting for subnet to appear in NetworksAdded."
                )
                start = time.time()
                while time.time() - start < 60:
                    after = set(networks_added_dynamic(substrate, subtensor_pallet))
                    new_nets = sorted(after - before)
                    if new_nets:
                        new_net = new_nets[-1]
                        print(
                            f"[i] New subnet {new_net} detected in NetworksAdded "
                            "after pending register_network."
                        )
                        return new_net, True
                    time.sleep(1.0)
                raise RuntimeError(
                    "register_network appears duplicated (1014) but subnet did not appear "
                    "within 60s."
                ) from e
            raise

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
            "register_network succeeded but NetworksAdded did not change."
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
            f"[!] start_call for netuid={netuid} failed (likely already enabled "
            f"or wrong origin): {e}"
        )


def ensure_hotkey_registered(
    substrate: SubstrateInterface,
    cold: Keypair,
    hot_ss58: str,
    netuid: int,
    subtensor_pallet: str,
):
    try:
        call = compose_call(
            substrate,
            subtensor_pallet,
            "burned_register",
            {"netuid": int(netuid), "hotkey": hot_ss58},
        )
        submit_signed(substrate, cold, call)
    except Exception:
        # Already registered, throttled, etc. — safe to ignore.
        pass


def compose_add_stake(
    substrate: SubstrateInterface,
    subtensor_pallet: str,
    hot_ss58: str,
    netuid: int,
    amount_planck: int,
):
    last_err: Optional[Exception] = None
    for field in ("amount_staked", "amount", "value"):
        try:
            return substrate.compose_call(
                call_module=subtensor_pallet,
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


# ──────────────────────────────────────────────────────────────────────────────
# MevShield key access
# ──────────────────────────────────────────────────────────────────────────────


def read_next_key_bytes(
    substrate: SubstrateInterface,
    pallet: str,
    block_hash: Optional[str] = None,
) -> bytes:
    v = substrate.query(pallet, "NextKey", [], block_hash=block_hash)
    raw = getattr(v, "value", v)
    pk_bytes = _parse_vec_u8(raw)
    return pk_bytes or b""


def acquire_next_key(
    substrate: SubstrateInterface,
    pallet: str,
    timeout_s: int = 120,
    poll_s: float = 0.25,
) -> bytes:
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


def get_genesis_hash_bytes(substrate: SubstrateInterface) -> bytes:
    hx = substrate.get_block_hash(0)
    if isinstance(hx, str) and hx.startswith("0x"):
        return bytes.fromhex(hx[2:])
    return bytes(32)


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
# Call decoding helpers (for locating execute_revealed)
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
    return module, fn, args


def _args_as_dict(args_raw: Any) -> Dict[str, Any]:
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


def _is_our_execute_revealed(
    call_args_raw: Any,
    subtensor_pallet: str,
    cold_ss58: str,
    hot_ss58: str,
    netuid: int,
    amount_planck: int,
    expected_key_hash_hex: str,
) -> bool:
    args = _args_as_dict(call_args_raw)

    signer = args.get("signer")
    if isinstance(signer, str):
        if signer != cold_ss58:
            return False
    else:
        signer_bytes = _parse_vec_u8(signer)
        if signer_bytes is None:
            return False
        try:
            cold_raw = ss58_decode(cold_ss58)
            if isinstance(cold_raw, str) and cold_raw.startswith("0x"):
                cold_raw = bytes.fromhex(cold_raw[2:])
            elif isinstance(cold_raw, str):
                cold_raw = bytes.fromhex(cold_raw)
        except Exception:
            return False
        if bytes(signer_bytes) != bytes(cold_raw):
            return False

    key_hash_val = args.get("key_hash")
    actual_key_hash = _normalize_hex_0x(key_hash_val)
    target_key_hash = _normalize_hex_0x(expected_key_hash_hex)
    if not actual_key_hash or not target_key_hash or actual_key_hash != target_key_hash:
        return False

    inner_call_raw = args.get("call")
    inner_module, inner_fn, inner_args_raw = _extract_call_from_raw(inner_call_raw)
    if inner_module != subtensor_pallet or inner_fn != "add_stake":
        return False

    inner_args = _args_as_dict(inner_args_raw)
    if inner_args.get("hotkey") != hot_ss58:
        return False

    inner_netuid = _to_int(inner_args.get("netuid"))
    if inner_netuid != netuid:
        return False

    inner_amount = _to_int(
        inner_args.get("amount_staked")
        or inner_args.get("amount")
        or inner_args.get("value")
    )
    if inner_amount != amount_planck:
        return False

    return True


def wait_for_execute_revealed_block(
    substrate: SubstrateInterface,
    mev_pallet: str,
    subtensor_pallet: str,
    cold_ss58: str,
    hot_ss58: str,
    netuid: int,
    amount_planck: int,
    expected_key_hash_hex: str,
    submit_block_num: int,
    timeout_s: int = 180,
    poll_s: float = 0.8,
) -> Tuple[int, str]:
    """
    Scan blocks after submit_block_num until we find MevShield::execute_revealed
    for this specific stake (identified by cold, hot, netuid, amount, key_hash).
    """
    start = time.time()
    next_height = submit_block_num + 1
    print(
        f"[i] Waiting for execute_revealed after block #{submit_block_num} "
        f"(timeout={timeout_s}s)…"
    )

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

            blk = substrate.get_block(block_hash=bh)
            exts = blk.get("extrinsics") or blk.get("extrinsic") or []

            for idx, ext in enumerate(exts):
                raw = getattr(ext, "value", ext)
                module, fn, args_raw = _extract_call_from_raw(raw)
                if (
                    module
                    and module.lower() == mev_pallet.lower()
                    and fn == "execute_revealed"
                    and _is_our_execute_revealed(
                        args_raw,
                        subtensor_pallet=subtensor_pallet,
                        cold_ss58=cold_ss58,
                        hot_ss58=hot_ss58,
                        netuid=netuid,
                        amount_planck=amount_planck,
                        expected_key_hash_hex=expected_key_hash_hex,
                    )
                ):
                    print(
                        f"[i] Found execute_revealed for this stake in "
                        f"block #{next_height} (extrinsic index {idx})."
                    )
                    return next_height, bh

            next_height += 1

        time.sleep(poll_s)

    raise RuntimeError(
        f"Timed out ({timeout_s}s) while waiting for execute_revealed for this stake."
    )


# ──────────────────────────────────────────────────────────────────────────────
# Fee experiments
# ──────────────────────────────────────────────────────────────────────────────


def run_plain_add_stake_fee_test(
    substrate: SubstrateInterface,
    subtensor_pallet: str,
    cold: Keypair,
    hot: Keypair,
    netuid: int,
    amount_planck: int,
    decimals: int,
) -> Dict[str, Any]:
    """
    Compute network fee for plain add_stake as:

        fee = (cold.free_before - cold.free_after) - stake_component

    where stake_component is guessed as:
        - stake_delta from pallet::Stake if non-zero and reasonable, else
        - amount_planck (the requested stake).
    """
    cold_ss58 = cold.ss58_address
    hot_ss58 = hot.ss58_address

    free_before = account_free_balance(substrate, cold_ss58)
    stake_before = get_stake(substrate, subtensor_pallet, hot_ss58, netuid)

    print(
        f"[i] Running plain add_stake: cold={cold_ss58}, hot={hot_ss58}, "
        f"netuid={netuid}, amount={amount_planck} planck"
    )

    call = compose_add_stake(substrate, subtensor_pallet, hot_ss58, netuid, amount_planck)
    rec = submit_signed(substrate, cold, call)

    block_hash = rec.block_hash
    block_num = get_block_number(substrate, block_hash)

    free_after = account_free_balance(substrate, cold_ss58, block_hash=block_hash)
    stake_after = get_stake(substrate, subtensor_pallet, hot_ss58, netuid, block_hash)

    stake_delta = stake_after - stake_before
    cold_diff_total = free_before - free_after  # includes stake + fee

    # Guess how much of cold_diff_total is stake vs fee.
    if stake_delta > 0 and stake_delta <= cold_diff_total:
        stake_component = stake_delta
    else:
        stake_component = min(amount_planck, cold_diff_total)

    fee_planck = cold_diff_total - stake_component

    print(f"[i] Plain add_stake included in block #{block_num} ({block_hash})")
    print(
        f"[i] cold.free_before={free_before}, cold.free_after={free_after}, "
        f"cold_diff_total={cold_diff_total}"
    )
    print(
        f"[i] stake_before={stake_before}, stake_after={stake_after}, "
        f"stake_delta={stake_delta} planck (≈ {stake_delta / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[i] stake_component_used_for_fee = {stake_component} planck "
        f"(≈ {stake_component / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[i] plain_add_stake_network_fee = {fee_planck} planck "
        f"(≈ {fee_planck / (10 ** decimals):.9f} TAO)"
    )

    return {
        "block_num": block_num,
        "block_hash": block_hash,
        "free_before": free_before,
        "free_after": free_after,
        "stake_before": stake_before,
        "stake_after": stake_after,
        "stake_delta": stake_delta,
        "cold_diff_total": cold_diff_total,
        "stake_component": stake_component,
        "fee_net_planck": fee_planck,
    }


def run_encrypted_add_stake_fee_test(
    substrate: SubstrateInterface,
    mev_pallet: str,
    subtensor_pallet: str,
    author: Keypair,
    cold: Keypair,
    hot: Keypair,
    netuid: int,
    amount_planck: int,
    decimals: int,
    timeout_s: int = 180,
) -> Dict[str, Any]:
    """
    Compute network fees for encrypted path:

      author_fee_total = author.free_before - author.free_after_reveal
      cold_diff_total  = cold.free_before - cold.free_after_reveal  (stake + cold_fee)
      cold_fee_only    = cold_diff_total - stake_component_guess

    where stake_component_guess is either pallet::Stake delta if reasonable,
    or amount_planck (the requested stake).
    """
    author_ss58 = author.ss58_address
    cold_ss58 = cold.ss58_address
    hot_ss58 = hot.ss58_address

    # Compose inner add_stake
    inner_call = compose_add_stake(substrate, subtensor_pallet, hot_ss58, netuid, amount_planck)
    inner_call_bytes = call_to_scale_bytes(inner_call)

    # Read NextKey and derive key_hash
    pk_bytes = acquire_next_key(substrate, mev_pallet)
    if len(pk_bytes) != MLKEM768_PK_LEN:
        raise RuntimeError(f"NextKey length {len(pk_bytes)} != {MLKEM768_PK_LEN}")
    print(
        f"[DBG] Client view: NextKey len={len(pk_bytes)}, "
        f"blake2_256=0x{blake2_256(pk_bytes).hex()}"
    )

    key_hash_bytes = blake2_256(pk_bytes)
    key_hash_hex = "0x" + key_hash_bytes.hex()

    # Build payload_core = signer(32) || key_hash(32) || SCALE(call)
    signer_raw32 = ss58_decode(cold_ss58)
    if isinstance(signer_raw32, str) and signer_raw32.startswith("0x"):
        signer_raw32 = bytes.fromhex(signer_raw32[2:])
    elif isinstance(signer_raw32, str):
        try:
            signer_raw32 = bytes.fromhex(signer_raw32)
        except Exception:
            signer_raw32 = bytes(32)
    signer_raw32 = bytes(signer_raw32)

    payload_core = signer_raw32 + key_hash_bytes + inner_call_bytes
    commitment_hex = "0x" + blake2_256(payload_core).hex()

    print(
        "[DBG] payload_core segments: "
        f"signer_len={len(signer_raw32)}, key_hash_len={len(key_hash_bytes)}, "
        f"call_len={len(inner_call_bytes)}, total_len={len(payload_core)}"
    )
    print(f"[DBG] key_hash_hex (client) = {key_hash_hex}")
    print(f"[DBG] commitment_hex (client) = {commitment_hex}")

    # Domain-separated signature: "mev-shield:v1" || genesis || payload_core
    genesis = get_genesis_hash_bytes(substrate)
    msg = b"mev-shield:v1" + genesis + payload_core
    sig64 = cold.sign(msg)
    multisig = b"\x01" + sig64
    plaintext = payload_core + multisig

    print(f"[DBG] plaintext_len={len(plaintext)}")

    # Encrypt with Rust FFI
    blob = mlkem768_seal_blob(pk_bytes, plaintext)
    kem_len = int.from_bytes(blob[0:2], "little") if len(blob) >= 2 else None
    print(
        f"[DBG] ciphertext blob: total_len={len(blob)}, kem_len={kem_len}"
    )

    # Measure balances & stake before we send submit_encrypted
    author_free_before = account_free_balance(substrate, author_ss58)
    cold_free_before = account_free_balance(substrate, cold_ss58)
    stake_before = get_stake(substrate, subtensor_pallet, hot_ss58, netuid)

    print(
        f"[i] Running encrypted add_stake via MevShield::submit_encrypted "
        f"(author={author_ss58}, cold={cold_ss58}, hot={hot_ss58}, "
        f"netuid={netuid}, amount={amount_planck} planck)"
    )

    # Send submit_encrypted
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
    submit_block_hash = rec.block_hash
    submit_block_num = get_block_number(substrate, submit_block_hash)

    author_free_after_submit = account_free_balance(
        substrate, author_ss58, block_hash=submit_block_hash
    )
    cold_free_after_submit = account_free_balance(
        substrate, cold_ss58, block_hash=submit_block_hash
    )
    stake_after_submit = get_stake(
        substrate, subtensor_pallet, hot_ss58, netuid, block_hash=submit_block_hash
    )

    print(
        f"[i] submit_encrypted included in block #{submit_block_num} "
        f"({submit_block_hash})"
    )

    # Wait for execute_revealed
    reveal_block_num, reveal_block_hash = wait_for_execute_revealed_block(
        substrate=substrate,
        mev_pallet=mev_pallet,
        subtensor_pallet=subtensor_pallet,
        cold_ss58=cold_ss58,
        hot_ss58=hot_ss58,
        netuid=netuid,
        amount_planck=amount_planck,
        expected_key_hash_hex=key_hash_hex,
        submit_block_num=submit_block_num,
        timeout_s=timeout_s,
        poll_s=0.8,
    )

    # Balances & stake after reveal
    author_free_after_reveal = account_free_balance(
        substrate, author_ss58, block_hash=reveal_block_hash
    )
    cold_free_after_reveal = account_free_balance(
        substrate, cold_ss58, block_hash=reveal_block_hash
    )
    stake_after_reveal = get_stake(
        substrate, subtensor_pallet, hot_ss58, netuid, block_hash=reveal_block_hash
    )

    # Deltas
    stake_delta_total = stake_after_reveal - stake_before
    author_fee_submit = author_free_before - author_free_after_submit
    author_fee_between_submit_and_reveal = (
        author_free_after_submit - author_free_after_reveal
    )
    author_fee_total = author_free_before - author_free_after_reveal

    cold_diff_total = cold_free_before - cold_free_after_reveal  # stake + fee

    # Guess how much of cold_diff_total is stake; prefer pallet::Stake delta if usable.
    if stake_delta_total > 0 and stake_delta_total <= cold_diff_total:
        stake_component = stake_delta_total
    else:
        stake_component = min(amount_planck, cold_diff_total)

    cold_fee_only = cold_diff_total - stake_component

    print("──────────────── Encrypted path fee breakdown ────────────────")
    print(f"[i] submit_block  #{submit_block_num} ({submit_block_hash})")
    print(f"[i] reveal_block  #{reveal_block_num} ({reveal_block_hash})")
    print(
        f"[i] author.free_before={author_free_before}, "
        f"after_submit={author_free_after_submit}, "
        f"after_reveal={author_free_after_reveal}"
    )
    print(
        f"[i] cold.free_before={cold_free_before}, "
        f"after_submit={cold_free_after_submit}, "
        f"after_reveal={cold_free_after_reveal}, "
        f"cold_diff_total={cold_diff_total}"
    )
    print(
        f"[i] stake_before={stake_before}, stake_after_submit={stake_after_submit}, "
        f"stake_after_reveal={stake_after_reveal}, "
        f"stake_delta_total={stake_delta_total} planck "
        f"(≈ {stake_delta_total / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[i] stake_component_used_for_fee = {stake_component} planck "
        f"(≈ {stake_component / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[i] author_fee_submit = {author_fee_submit} planck "
        f"(≈ {author_fee_submit / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[i] author_fee_between_submit_and_reveal = "
        f"{author_fee_between_submit_and_reveal} planck "
        f"(≈ {author_fee_between_submit_and_reveal / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[i] author_fee_total (encrypted path) = {author_fee_total} planck "
        f"(≈ {author_fee_total / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[i] cold_network_fee_only (encrypted path) = "
        f"{cold_fee_only} planck "
        f"(≈ {cold_fee_only / (10 ** decimals):.9f} TAO)"
    )

    if abs(author_fee_between_submit_and_reveal) < 5:  # tiny tolerance
        print(
            "  → No additional fee appears to be charged to the author when "
            "execute_revealed runs (within small tolerance)."
        )
    else:
        print(
            "  → WARNING: author balance changed between submit and reveal by "
            f"{author_fee_between_submit_and_reveal} planck."
        )

    if abs(cold_fee_only) < 5:
        print(
            "  → Cold signer paid ~0 additional network fee beyond the staked amount "
            "for the encrypted path."
        )
    else:
        print(
            "  → Cold signer appears to have paid non‑zero extra fee on encrypted path "
            f"(fee-only={cold_fee_only} planck)."
        )

    return {
        "submit_block_num": submit_block_num,
        "submit_block_hash": submit_block_hash,
        "reveal_block_num": reveal_block_num,
        "reveal_block_hash": reveal_block_hash,
        "author_free_before": author_free_before,
        "author_free_after_submit": author_free_after_submit,
        "author_free_after_reveal": author_free_after_reveal,
        "cold_free_before": cold_free_before,
        "cold_free_after_submit": cold_free_after_submit,
        "cold_free_after_reveal": cold_free_after_reveal,
        "stake_before": stake_before,
        "stake_after_submit": stake_after_submit,
        "stake_after_reveal": stake_after_reveal,
        "stake_delta_total": stake_delta_total,
        "cold_diff_total": cold_diff_total,
        "stake_component": stake_component,
        "author_fee_submit": author_fee_submit,
        "author_fee_between_submit_and_reveal": author_fee_between_submit_and_reveal,
        "author_fee_total": author_fee_total,
        "cold_fee_only": cold_fee_only,
        "key_hash_hex": key_hash_hex,
        "commitment_hex": commitment_hex,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        description=(
            "MEV‑Shield add_stake fee comparison:\n"
            "  • Plain Subtensor::add_stake (signed by cold)\n"
            "  • Encrypted add_stake via MevShield::submit_encrypted + execute_revealed\n"
            "Prints per‑account network fees (excluding the 5 TAO stake) and a total\n"
            "encrypted fee for comparison."
        )
    )
    ap.add_argument("--ws", default="ws://127.0.0.1:9945")
    ap.add_argument("--netuid", type=int, default=3)
    ap.add_argument("--stake", type=float, default=5.0, help="Stake in TAO to add")
    ap.add_argument("--author-uri", default="//Eve", help="submit_encrypted signer")
    ap.add_argument("--cold-uri", default="//OwnerCold", help="Plain add_stake signer / inner signer")
    ap.add_argument("--hot-uri", default="//Staker1Hot", help="Target hotkey")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    substrate = connect(args.ws)
    mev_pallet = resolve_mev_pallet(substrate)
    subtensor_pallet = resolve_subtensor_pallet(substrate)
    decimals = token_decimals(substrate)

    author = Keypair.create_from_uri(args.author_uri)
    cold = Keypair.create_from_uri(args.cold_uri)
    hot = Keypair.create_from_uri(args.hot_uri)
    faucet = Keypair.create_from_uri("//Alice")

    amount_planck = int(round(args.stake * (10 ** decimals)))

    # Ensure accounts are funded for tests
    cold_min = max(amount_planck * 3, int(30 * (10 ** decimals)))
    hot_min = max(amount_planck, int(2 * (10 ** decimals)))
    author_min = int(10 * (10 ** decimals))

    ensure_funded_planck(substrate, faucet, cold.ss58_address, cold_min, label="cold")
    ensure_funded_planck(substrate, faucet, hot.ss58_address, hot_min, label="hot")
    ensure_funded_planck(substrate, faucet, author.ss58_address, author_min, label="author")

    # Ensure subnet exists and is enabled; ensure hotkey registered
    netuid, did_register = ensure_subnet_exists_or_register(
        substrate=substrate,
        subtensor_pallet=subtensor_pallet,
        faucet=faucet,
        owner_cold=cold,
        owner_hot_ss58=hot.ss58_address,
        requested_netuid=args.netuid,
        decimals=decimals,
        lock_funding_hint_tao=DEFAULT_LOCK_FUND_HINT_TAO,
    )
    if did_register:
        ensure_subtoken_enabled_for_net(substrate, subtensor_pallet, cold, netuid)
    else:
        print(
            f"[i] Using existing netuid={netuid}; assuming subtoken already enabled."
        )
    ensure_hotkey_registered(substrate, cold, hot.ss58_address, netuid, subtensor_pallet)

    print("\n==================== Plain add_stake fee test ====================")
    plain_res = run_plain_add_stake_fee_test(
        substrate=substrate,
        subtensor_pallet=subtensor_pallet,
        cold=cold,
        hot=hot,
        netuid=netuid,
        amount_planck=amount_planck,
        decimals=decimals,
    )

    print("\n================== Encrypted add_stake fee test ==================")
    enc_res = run_encrypted_add_stake_fee_test(
        substrate=substrate,
        mev_pallet=mev_pallet,
        subtensor_pallet=subtensor_pallet,
        author=author,
        cold=cold,
        hot=hot,
        netuid=netuid,
        amount_planck=amount_planck,
        decimals=decimals,
        timeout_s=args.timeout,
    )

    print("\n=========================== Summary ==============================")
    plain_fee_net = plain_res["fee_net_planck"]
    enc_author_fee = enc_res["author_fee_total"]      # fee-only for author
    enc_cold_fee = enc_res["cold_fee_only"]           # fee-only for cold
    enc_total_fee = enc_author_fee + enc_cold_fee

    print(
        f"[SUMMARY] Plain add_stake NETWORK fee (cold signer)      : "
        f"{plain_fee_net} planck (≈ {plain_fee_net / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[SUMMARY] Encrypted add_stake NETWORK fee (author)       : "
        f"{enc_author_fee} planck (≈ {enc_author_fee / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[SUMMARY] Encrypted add_stake NETWORK fee (cold signer)  : "
        f"{enc_cold_fee} planck (≈ {enc_cold_fee / (10 ** decimals):.9f} TAO)"
    )
    print(
        f"[SUMMARY] Encrypted add_stake TOTAL NETWORK fee          : "
        f"{enc_total_fee} planck (≈ {enc_total_fee / (10 ** decimals):.9f} TAO)"
    )

    # The two numbers you really care about:
    print("\n--- Comparison (fees only, stake excluded) ---")
    print(
        f"Plain add_stake fee: "
        f"{plain_fee_net / (10 ** decimals):.9f} TAO"
    )
    print(
        f"Encrypted add_stake TOTAL fee (author + cold): "
        f"{enc_total_fee / (10 ** decimals):.9f} TAO"
    )

    if plain_fee_net > 0:
        print(
            f"[SUMMARY] Ratio encrypted_total / plain            : "
            f"{enc_total_fee / plain_fee_net:.4f}x"
        )

    print(
        "\nInterpretation hints:\n"
        "  • Plain fee is the network fee charged on a normal signed add_stake.\n"
        "  • Encrypted TOTAL fee = author fee (submit_encrypted) + cold fee\n"
        "    (execute_revealed), excluding the staked TAO amount itself.\n"
        "  • This lets you directly compare 'how much more / less the user pays'\n"
        "    when using MEV‑Shield vs a plain add_stake.\n"
    )


if __name__ == "__main__":
    main()
