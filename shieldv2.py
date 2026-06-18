#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shield v2 localnet E2E test.

Run:

    python3 ./shieldv2.py --self-check
    rm -rf "$HOME/.cache/subtensor-shieldv2-e2e"
    python3 ./shieldv2.py

This script:
  - does not require a subtensor repo checkout in this directory;
  - does not search for helper files;
  - embeds and builds the small Shield v2 IBE/TLE encryptor itself;
  - uses explicit account nonces for every outer/inner signed extrinsic;
  - retries/rebuilds the Shield envelope with a fresh target if the chain advances;
  - optionally installs dev-only IBE epoch/block keys through sudo storage writes if no live DKG keys are present.

It tests:
  - submit_encrypted green path;
  - submit_conditional_encrypted green path with AtBlock;
  - plaintext inner extrinsic absent from block bodies before reveal;
  - balance changes only after target/reveal.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException


SCRIPT_VERSION = "shieldv2.py 2026-06-18-21-explicit-nonces-inline"
CACHE_VERSION = "v2-tle-helper-2026-06-18-21-explicit-nonces-inline"

IBE_TARGET_LOOKAHEAD_BLOCKS = 2
KEY_ID_LEN = 16
DEV_EPOCH = 9_000_000


RUST_HELPER_CARGO_TOML = r'''
[package]
name = "subtensor_shieldv2_encrypt_helper"
version = "0.1.0"
edition = "2021"
resolver = "2"

[dependencies]
anyhow = "1"
ark-ec = "0.4.2"
ark-ff = "0.4.2"
ark-serialize = "0.4.2"
ark-bls12-381 = { version = "0.4.0", features = ["curve"] }
blake2 = "0.10"
hex = "0.4"
parity-scale-codec = { version = "3.7.5", features = ["derive"] }
rand_core = { version = "0.6", features = ["getrandom"] }
tle = { git = "https://github.com/ideal-lab5/timelock", rev = "5416406cfd32799e31e1795393d4916894de4468" }
twox-hash = "1.6"
'''

RUST_HELPER_MAIN = r'''
use anyhow::{anyhow, bail, Context, Result};
use ark_ec::Group;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use parity_scale_codec::Encode;
use rand_core::{OsRng, RngCore};
use std::hash::Hasher;
use tle::{
    curves::drand::TinyBLS381,
    ibe::fullident::Identity,
    stream_ciphers::AESGCMStreamCipherProvider,
    tlock::tle,
};
use twox_hash::XxHash64;

const MEV_SHIELD_IBE_VERSION: u16 = 1;
const MEV_SHIELD_IBE_MAGIC: [u8; 4] = *b"MSI2";
const KEY_ID_LEN: usize = 16;
const IBE_DOMAIN: &[u8] = b"bittensor.mev-shield.v2.block-identity";

#[derive(Encode)]
struct IbeEncryptedExtrinsicV1 {
    magic: [u8; 4],
    version: u16,
    epoch: u64,
    target_block: u64,
    key_id: [u8; KEY_ID_LEN],
    commitment: [u8; 32],
    ciphertext: Vec<u8>,
}

#[derive(Encode)]
struct IbeEpochPublicKeyForScale {
    epoch: u64,
    key_id: [u8; KEY_ID_LEN],
    master_public_key: Vec<u8>,
    total_weight: u128,
    threshold_weight: u128,
    public_atoms: Vec<IbeDkgPublicShareAtomV1ForScale>,
    first_block: u64,
    last_block: u64,
}

#[derive(Encode)]
struct IbeDkgPublicShareAtomV1ForScale {
    share_id: u32,
    weight: u128,
    public_share: Vec<u8>,
}

#[derive(Encode)]
struct IbeBlockDecryptionKeyV1ForScale {
    version: u16,
    epoch: u64,
    target_block: u64,
    key_id: [u8; KEY_ID_LEN],
    identity_decryption_key: Vec<u8>,
    finalized_ordering_block_number: u64,
    finalized_ordering_block_hash: [u8; 32],
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

fn fixed<const N: usize>(s: &str, name: &str) -> Result<[u8; N]> {
    let bytes = decode_hex(s).with_context(|| format!("decode {name}"))?;
    if bytes.len() != N {
        bail!("{name} must be {N} bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn blake2b<const N: usize>(data: &[u8]) -> [u8; N] {
    use blake2::digest::{Update, VariableOutput};

    let mut hasher = blake2::Blake2bVar::new(N).expect("valid blake2b output length");
    hasher.update(data);

    let mut out = [0u8; N];
    hasher
        .finalize_variable(&mut out)
        .expect("fixed-size output buffer has correct length");
    out
}

fn blake2b_256(data: &[u8]) -> [u8; 32] {
    blake2b::<32>(data)
}

fn blake2_128(data: &[u8]) -> [u8; 16] {
    blake2b::<16>(data)
}

fn twox64(data: &[u8], seed: u64) -> [u8; 8] {
    let mut h = XxHash64::with_seed(seed);
    h.write(data);
    h.finish().to_le_bytes()
}

fn twox128(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&twox64(data, 0));
    out[8..].copy_from_slice(&twox64(data, 1));
    out
}

fn storage_prefix(pallet: &str, item: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&twox128(pallet.as_bytes()));
    out.extend_from_slice(&twox128(item.as_bytes()));
    out
}

fn twox64_concat_key(encoded_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&twox64(encoded_key, 0));
    out.extend_from_slice(encoded_key);
    out
}

fn blake2_128_concat_key(encoded_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&blake2_128(encoded_key));
    out.extend_from_slice(encoded_key);
    out
}

fn epoch_key_storage_key(pallet: &str, epoch: u64) -> Vec<u8> {
    let mut out = storage_prefix(pallet, "IbeEpochKeys");
    out.extend_from_slice(&twox64_concat_key(&epoch.encode()));
    out
}

fn latest_epoch_storage_key(pallet: &str) -> Vec<u8> {
    storage_prefix(pallet, "LatestPublishedIbeEpoch")
}

fn block_key_storage_key(
    pallet: &str,
    epoch: u64,
    target_block: u64,
    key_id: [u8; KEY_ID_LEN],
) -> Vec<u8> {
    let tuple_key = (epoch, target_block, key_id).encode();
    let mut out = storage_prefix(pallet, "IbeBlockDecryptionKeys");
    out.extend_from_slice(&blake2_128_concat_key(&tuple_key));
    out
}

fn block_identity_bytes(
    genesis_hash: [u8; 32],
    epoch: u64,
    target_block: u64,
    key_id: [u8; KEY_ID_LEN],
) -> Vec<u8> {
    (IBE_DOMAIN, genesis_hash, epoch, target_block, key_id).encode()
}

fn dev_msk(
    genesis_hash: [u8; 32],
    epoch: u64,
    key_id: [u8; KEY_ID_LEN],
) -> ark_bls12_381::Fr {
    let seed = (
        b"subtensor-shieldv2-python-dev-msk-v1".as_slice(),
        genesis_hash,
        epoch,
        key_id,
    )
        .encode();
    let material = blake2b_256(&seed);
    ark_bls12_381::Fr::from_le_bytes_mod_order(&material)
}

fn master_public_key_bytes(msk: ark_bls12_381::Fr) -> Result<Vec<u8>> {
    let mpk = ark_bls12_381::G2Projective::generator() * msk;
    let mut out = Vec::new();
    mpk.serialize_compressed(&mut out)
        .map_err(|e| anyhow!("serialize master public key failed: {e}"))?;
    Ok(out)
}

fn identity_key_bytes(
    genesis_hash: [u8; 32],
    epoch: u64,
    target_block: u64,
    key_id: [u8; KEY_ID_LEN],
    msk: ark_bls12_381::Fr,
) -> Result<Vec<u8>> {
    let identity_bytes = block_identity_bytes(genesis_hash, epoch, target_block, key_id);
    let identity = Identity::new(IBE_DOMAIN, vec![identity_bytes]);
    let identity_key = identity.extract::<TinyBLS381>(msk).0;

    let mut out = Vec::new();
    identity_key
        .serialize_compressed(&mut out)
        .map_err(|e| anyhow!("serialize identity key failed: {e}"))?;
    Ok(out)
}

fn json_pair(key: &[u8], value: &[u8]) -> String {
    format!(
        "{{\"key\":\"0x{}\",\"value\":\"0x{}\"}}",
        hex::encode(key),
        hex::encode(value)
    )
}

fn cmd_encrypt(args: &[String]) -> Result<()> {
    if args.len() != 6 {
        usage();
    }

    let genesis_hash = fixed::<32>(&args[0], "genesis_hash")?;
    let epoch: u64 = args[1].parse().context("parse epoch")?;
    let target_block: u64 = args[2].parse().context("parse target_block")?;
    let key_id = fixed::<16>(&args[3], "key_id")?;
    let master_public_key_bytes_arg =
        decode_hex(&args[4]).context("decode master_public_key")?;
    let plaintext = decode_hex(&args[5]).context("decode plaintext")?;

    let mut mpk_slice: &[u8] = &master_public_key_bytes_arg;
    let master_public_key =
        ark_bls12_381::G2Projective::deserialize_compressed(&mut mpk_slice)
            .map_err(|e| anyhow!("invalid compressed master public key: {e}"))?;

    let identity_bytes = block_identity_bytes(genesis_hash, epoch, target_block, key_id);
    let identity = Identity::new(IBE_DOMAIN, vec![identity_bytes]);

    let mut symmetric_key = [0u8; 32];
    OsRng.fill_bytes(&mut symmetric_key);

    let ciphertext = tle::<TinyBLS381, AESGCMStreamCipherProvider, OsRng>(
        master_public_key,
        symmetric_key,
        &plaintext,
        identity,
        OsRng,
    )
    .map_err(|e| anyhow!("TLE encryption failed: {e:?}"))?;

    let mut ciphertext_bytes = Vec::new();
    ciphertext
        .serialize_compressed(&mut ciphertext_bytes)
        .map_err(|e| anyhow!("serialize TLE ciphertext failed: {e}"))?;

    let envelope = IbeEncryptedExtrinsicV1 {
        magic: MEV_SHIELD_IBE_MAGIC,
        version: MEV_SHIELD_IBE_VERSION,
        epoch,
        target_block,
        key_id,
        commitment: blake2b_256(&plaintext),
        ciphertext: ciphertext_bytes,
    };

    println!("0x{}", hex::encode(envelope.encode()));
    Ok(())
}

fn cmd_epoch_storage(args: &[String]) -> Result<()> {
    if args.len() != 6 {
        usage();
    }

    let pallet = &args[0];
    let genesis_hash = fixed::<32>(&args[1], "genesis_hash")?;
    let epoch: u64 = args[2].parse().context("parse epoch")?;
    let first_block: u64 = args[3].parse().context("parse first_block")?;
    let last_block: u64 = args[4].parse().context("parse last_block")?;
    let key_id = fixed::<16>(&args[5], "key_id")?;

    let msk = dev_msk(genesis_hash, epoch, key_id);
    let master_public_key = master_public_key_bytes(msk)?;

    let epoch_key = IbeEpochPublicKeyForScale {
        epoch,
        key_id,
        master_public_key: master_public_key.clone(),
        total_weight: 1,
        threshold_weight: 1,
        public_atoms: Vec::new(),
        first_block,
        last_block,
    };

    let epoch_value = epoch_key.encode();
    let epoch_key_storage = epoch_key_storage_key(pallet, epoch);
    let latest_key = latest_epoch_storage_key(pallet);
    let latest_value = epoch.encode();

    println!(
        "{{\"epoch\":{},\"key_id\":\"0x{}\",\"master_public_key\":\"0x{}\",\"pairs\":[{},{}]}}",
        epoch,
        hex::encode(key_id),
        hex::encode(master_public_key),
        json_pair(&epoch_key_storage, &epoch_value),
        json_pair(&latest_key, &latest_value),
    );

    Ok(())
}

fn cmd_block_key_storage(args: &[String]) -> Result<()> {
    if args.len() != 7 {
        usage();
    }

    let pallet = &args[0];
    let genesis_hash = fixed::<32>(&args[1], "genesis_hash")?;
    let epoch: u64 = args[2].parse().context("parse epoch")?;
    let target_block: u64 = args[3].parse().context("parse target_block")?;
    let key_id = fixed::<16>(&args[4], "key_id")?;
    let finalized_ordering_block_number: u64 =
        args[5].parse().context("parse finalized_ordering_block_number")?;
    let finalized_ordering_block_hash =
        fixed::<32>(&args[6], "finalized_ordering_block_hash")?;

    let msk = dev_msk(genesis_hash, epoch, key_id);
    let identity_decryption_key =
        identity_key_bytes(genesis_hash, epoch, target_block, key_id, msk)?;

    let key_value = IbeBlockDecryptionKeyV1ForScale {
        version: MEV_SHIELD_IBE_VERSION,
        epoch,
        target_block,
        key_id,
        identity_decryption_key,
        finalized_ordering_block_number,
        finalized_ordering_block_hash,
    }
    .encode();

    let storage_key = block_key_storage_key(pallet, epoch, target_block, key_id);
    println!("{{\"pairs\":[{}]}}", json_pair(&storage_key, &key_value));

    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage:
  encrypt <genesis> <epoch> <target> <key_id> <master_public_key> <plaintext>
  epoch-storage <pallet> <genesis> <epoch> <first_block> <last_block> <key_id>
  block-key-storage <pallet> <genesis> <epoch> <target_block> <key_id> <finalized_number> <finalized_hash>"
    );
    std::process::exit(2);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 2 {
        match args[1].as_str() {
            "encrypt" => return cmd_encrypt(&args[2..]),
            "epoch-storage" => return cmd_epoch_storage(&args[2..]),
            "block-key-storage" => return cmd_block_key_storage(&args[2..]),
            _ => {}
        }
    }

    if args.len() == 7 {
        return cmd_encrypt(&args[1..]);
    }

    usage();
}
'''


@dataclass
class IbeEpochKey:
    epoch: int
    key_id: bytes
    master_public_key: bytes
    first_block: int
    last_block: int


def strip_0x(value: str) -> str:
    return value[2:] if value.startswith(("0x", "0X")) else value


def hex_0x(data: bytes) -> str:
    return "0x" + data.hex()


def blake2_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def parse_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        s = strip_0x(value)
        try:
            return bytes.fromhex(s)
        except Exception:
            return value.encode()
    if isinstance(value, list) and all(isinstance(x, int) for x in value):
        return bytes(value)
    if hasattr(value, "value"):
        return parse_bytes(value.value)
    if isinstance(value, dict):
        for key in ("value", "data", "bytes", "inner", "key_id", "master_public_key"):
            if key in value:
                got = parse_bytes(value[key])
                if got:
                    return got
    return b""


def to_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        try:
            return int(s, 16) if s.startswith(("0x", "0X")) else int(s)
        except Exception:
            return default
    if hasattr(value, "value"):
        return to_int(value.value, default)
    if isinstance(value, dict):
        for key in ("value", "bits", "free", "total", "amount", "block", "epoch", "nonce"):
            if key in value:
                return to_int(value[key], default)
        if len(value) == 1:
            return to_int(next(iter(value.values())), default)
    return default


def call_to_scale_bytes(obj: Any) -> bytes:
    if hasattr(obj, "data"):
        data = obj.data
        if hasattr(data, "to_hex"):
            return bytes.fromhex(strip_0x(data.to_hex()))
        if hasattr(data, "data") and isinstance(data.data, (bytes, bytearray)):
            return bytes(data.data)

    encoded = obj.encode() if hasattr(obj, "encode") else obj

    if hasattr(encoded, "to_hex"):
        return bytes.fromhex(strip_0x(encoded.to_hex()))
    if hasattr(encoded, "data") and isinstance(encoded.data, (bytes, bytearray)):
        return bytes(encoded.data)
    if isinstance(encoded, str) and encoded.startswith("0x"):
        return bytes.fromhex(strip_0x(encoded))
    if isinstance(encoded, (bytes, bytearray)):
        return bytes(encoded)

    raise RuntimeError(f"could not get SCALE bytes from {type(obj)}")


def validate_embedded_helper() -> None:
    embedded = RUST_HELPER_CARGO_TOML + "\n" + RUST_HELPER_MAIN
    bad_markers = [
        "use w3f_bls::EngineBLS",
        "github.com/opentensor/bls",
        "fix-no-std",
        "v2-tle-helper-2026-06-18-2",
    ]

    for marker in bad_markers:
        if marker in embedded:
            raise RuntimeError(f"stale embedded helper marker remains: {marker!r}")

    if "w3f-bls" in RUST_HELPER_CARGO_TOML:
        raise RuntimeError("direct w3f-bls dependency remains in helper Cargo.toml")

    if CACHE_VERSION != "v2-tle-helper-2026-06-18-21-explicit-nonces-inline":
        raise RuntimeError(f"unexpected cache version: {CACHE_VERSION}")


def self_check() -> None:
    validate_embedded_helper()
    print(f"[i] {SCRIPT_VERSION}")
    print(f"[✓] cache version: {CACHE_VERSION}")
    print("[✓] no direct w3f-bls dependency in helper Cargo.toml")
    print("[✓] no use w3f_bls::EngineBLS in embedded Rust")
    print("[✓] no opentensor/bls helper dependency")


def purge_old_encryptor_caches(cache_root: Path) -> None:
    if not cache_root.exists():
        return
    for path in cache_root.glob("v2-tle-helper-*"):
        if path.name != CACHE_VERSION and path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def ensure_encryptor() -> Path:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise RuntimeError("cargo is required for the one-time embedded Shield v2 encryptor build")

    validate_embedded_helper()

    base_cache = Path.home() / ".cache" / "subtensor-shieldv2-e2e"
    purge_old_encryptor_caches(base_cache)

    project_dir = base_cache / CACHE_VERSION / "helper-src"
    binary = project_dir / "target" / "release" / "subtensor_shieldv2_encrypt_helper"
    if sys.platform.startswith("win"):
        binary = binary.with_suffix(".exe")

    cargo_toml = project_dir / "Cargo.toml"
    main_rs = project_dir / "src" / "main.rs"

    if cargo_toml.exists() and cargo_toml.read_text(encoding="utf-8") != RUST_HELPER_CARGO_TOML:
        shutil.rmtree(project_dir, ignore_errors=True)

    if main_rs.exists() and main_rs.read_text(encoding="utf-8") != RUST_HELPER_MAIN:
        shutil.rmtree(project_dir, ignore_errors=True)

    if binary.exists():
        return binary

    print(f"[i] Building embedded Shield v2 encryptor {CACHE_VERSION} once under {project_dir}")

    (project_dir / "src").mkdir(parents=True, exist_ok=True)
    cargo_toml.write_text(RUST_HELPER_CARGO_TOML, encoding="utf-8")
    main_rs.write_text(RUST_HELPER_MAIN, encoding="utf-8")

    lock = project_dir / "Cargo.lock"
    if lock.exists():
        lock.unlink()

    try:
        subprocess.run([cargo, "build", "--release"], cwd=str(project_dir), check=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "embedded Shield v2 encryptor build failed. Run "
            "`python3 ./shieldv2.py --self-check`; if it does not show "
            f"{SCRIPT_VERSION!r}, replace your local file with this script."
        ) from exc

    if not binary.exists():
        raise RuntimeError(f"expected encryptor binary missing after build: {binary}")

    return binary


def connect(ws: str) -> SubstrateInterface:
    substrate = SubstrateInterface(url=ws)
    for _ in range(80):
        try:
            substrate.init_runtime()
            md = substrate.get_metadata()
            if md and getattr(md, "pallets", None):
                print(f"[i] Connected to {ws}")
                return substrate
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("runtime metadata not available")


def token_decimals(substrate: SubstrateInterface) -> int:
    decimals = substrate.token_decimals
    if isinstance(decimals, list) and decimals and isinstance(decimals[0], int):
        return decimals[0]
    if isinstance(decimals, int):
        return decimals
    return 9


def to_planck(amount_tao: float, decimals: int) -> int:
    return int(round(amount_tao * (10 ** decimals)))


def rpc_result(response: Any, method: str) -> Any:
    if isinstance(response, dict):
        if response.get("error") is not None:
            raise RuntimeError(f"{method} failed: {response['error']}")
        if "result" in response:
            return response["result"]
    return response


def chain_head(substrate: SubstrateInterface) -> str:
    return substrate.get_chain_head()


def get_block_hash(substrate: SubstrateInterface, number: int) -> Optional[str]:
    result = rpc_result(
        substrate.rpc_request("chain_getBlockHash", [int(number)]),
        "chain_getBlockHash",
    )
    return str(result) if result else None


def block_number(substrate: SubstrateInterface, block_hash: Optional[str] = None) -> int:
    try:
        header = substrate.get_block_header(block_hash=block_hash)
        value = getattr(header, "value", header)
        if isinstance(value, dict) and "header" in value:
            value = value["header"]
        if isinstance(value, dict):
            return to_int(value.get("number"))
    except Exception:
        pass

    try:
        return to_int(substrate.query("System", "Number", [], block_hash=block_hash))
    except Exception:
        return 0


def block_extrinsic_hexes(substrate: SubstrateInterface, block_hash: str) -> List[str]:
    result = rpc_result(substrate.rpc_request("chain_getBlock", [block_hash]), "chain_getBlock")
    if not isinstance(result, dict):
        return []
    block = result.get("block")
    if not isinstance(block, dict):
        return []
    return [str(x).lower() for x in block.get("extrinsics", [])]


def resolve_pallet(substrate: SubstrateInterface, exact: Sequence[str], contains: Sequence[str]) -> str:
    names = [str(p.name) for p in substrate.get_metadata().pallets]

    for wanted in exact:
        for name in names:
            if name.lower() == wanted.lower():
                print(f"[i] Resolved pallet: {name}")
                return name

    for name in names:
        low = name.lower()
        if all(part.lower() in low for part in contains):
            print(f"[i] Resolved pallet: {name}")
            return name

    raise RuntimeError(f"could not resolve pallet from metadata; tried {exact}")


def compose_call(substrate: SubstrateInterface, module: str, function: str, params: Dict[str, Any]):
    return substrate.compose_call(call_module=module, call_function=function, call_params=params)


def account_next_index(substrate: SubstrateInterface, ss58: str) -> int:
    for method in ("system_accountNextIndex", "account_nextIndex"):
        try:
            result = rpc_result(substrate.rpc_request(method, [ss58]), method)
            nonce = to_int(result, default=-1)
            if nonce >= 0:
                return nonce
        except Exception:
            pass

    try:
        info = substrate.query("System", "Account", [ss58])
        raw = getattr(info, "value", info)
        if isinstance(raw, dict):
            nonce = to_int(raw.get("nonce"), default=-1)
            if nonce >= 0:
                return nonce
    except Exception:
        pass

    raise RuntimeError(f"could not resolve next account nonce for {ss58}")


def create_signed_extrinsic_with_fresh_nonce(
    substrate: SubstrateInterface,
    signer: Keypair,
    call: Any,
    immortal: bool = False,
):
    nonce = account_next_index(substrate, signer.ss58_address)
    kwargs = {
        "call": call,
        "keypair": signer,
        "nonce": nonce,
    }
    if immortal:
        kwargs["era"] = "00"

    try:
        xt = substrate.create_signed_extrinsic(**kwargs)
    except TypeError as exc:
        raise RuntimeError(
            "substrate-interface create_signed_extrinsic does not accept explicit nonce. "
            "Upgrade substrate-interface; this Shield v2 test requires explicit nonces."
        ) from exc

    return xt, nonce


def submit_signed_once(
    substrate: SubstrateInterface,
    signer: Keypair,
    call: Any,
    immortal: bool = False,
    require_success: bool = True,
):
    xt, nonce = create_signed_extrinsic_with_fresh_nonce(
        substrate,
        signer,
        call,
        immortal=immortal,
    )

    try:
        receipt = substrate.submit_extrinsic(
            xt,
            wait_for_inclusion=True,
            wait_for_finalization=False,
        )
    except SubstrateRequestException as exc:
        raise RuntimeError(
            f"extrinsic submission failed "
            f"(signer={signer.ss58_address}, nonce={nonce}): {exc}"
        ) from exc

    if require_success and not receipt.is_success:
        raise RuntimeError(
            f"extrinsic failed in block {receipt.block_hash} "
            f"(signer={signer.ss58_address}, nonce={nonce}): {receipt.error_message}"
        )

    return receipt


def is_stale_or_nonce_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    markers = [
        "transaction is outdated",
        "invalid transaction",
        "stale",
        "outdated",
        "priority is too low",
        "already imported",
        "temporarily banned",
        "1010",
        "1014",
    ]
    return any(marker in msg for marker in markers)


def submit_signed_retry(
    substrate: SubstrateInterface,
    signer: Keypair,
    call_builder,
    attempts: int = 8,
    immortal: bool = False,
):
    last: Optional[BaseException] = None

    for attempt in range(1, attempts + 1):
        call = call_builder()
        try:
            return submit_signed_once(
                substrate,
                signer,
                call,
                immortal=immortal,
                require_success=True,
            )
        except BaseException as exc:
            last = exc
            if not is_stale_or_nonce_error(exc):
                raise
            print(f"[i] retrying signed extrinsic after stale/nonce race ({attempt}/{attempts}): {exc}")
            time.sleep(0.25)

    raise RuntimeError(f"failed after {attempts} attempts; last={last}")


def free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    try:
        info = substrate.query("System", "Account", [ss58]).value
        return int(info["data"]["free"])
    except Exception:
        return 0


def wait_balance(
    substrate: SubstrateInterface,
    ss58: str,
    minimum: int,
    timeout_s: int,
    poll_s: float,
    drive_signer: Optional[Keypair] = None,
) -> Tuple[int, int]:
    start = time.time()
    last = free_balance(substrate, ss58)

    while time.time() - start < timeout_s:
        head = block_number(substrate, chain_head(substrate))
        bal = free_balance(substrate, ss58)
        last = bal
        if bal >= minimum:
            return head, bal

        if drive_signer is not None:
            try:
                produce_heartbeat(substrate, drive_signer, "wait-balance")
            except Exception:
                pass

        time.sleep(poll_s)

    raise RuntimeError(f"timed out waiting for balance >= {minimum}; last={last}")


def transfer(substrate: SubstrateInterface, signer: Keypair, dest: str, amount: int) -> None:
    before = free_balance(substrate, dest)
    target = before + int(amount)

    def builder():
        try:
            return compose_call(substrate, "Balances", "transfer_keep_alive", {"dest": dest, "value": int(amount)})
        except Exception:
            return compose_call(substrate, "Balances", "transfer", {"dest": dest, "value": int(amount)})

    submit_signed_retry(substrate, signer, builder, immortal=False)
    wait_balance(substrate, dest, target, timeout_s=60, poll_s=0.35)


def ensure_funded(
    substrate: SubstrateInterface,
    faucet: Keypair,
    dest: Keypair,
    min_balance: int,
    label: str,
) -> None:
    have = free_balance(substrate, dest.ss58_address)
    if have >= min_balance:
        print(f"[i] {label} funded: {have}")
        return

    delta = int((min_balance - have) * 1.10) + 1
    print(f"[i] Funding {label}: {delta} planck")
    transfer(substrate, faucet, dest.ss58_address, delta)


def produce_heartbeat(substrate: SubstrateInterface, signer: Keypair, tag: str):
    head = block_number(substrate, chain_head(substrate))
    call = compose_call(
        substrate,
        "System",
        "remark",
        {"remark": bytes(f"shieldv2-{tag}-{head}-{time.time_ns()}", "utf-8")},
    )
    return submit_signed_once(substrate, signer, call, immortal=False, require_success=True)


def decode_epoch_key(value: Any) -> Optional[IbeEpochKey]:
    raw = getattr(value, "value", value)
    if not isinstance(raw, dict):
        return None

    epoch = to_int(raw.get("epoch"))
    key_id = parse_bytes(raw.get("key_id"))
    master_public_key = parse_bytes(raw.get("master_public_key"))
    first_block = to_int(raw.get("first_block"))
    last_block = to_int(raw.get("last_block"))

    if len(key_id) != KEY_ID_LEN or not master_public_key:
        return None

    return IbeEpochKey(epoch, key_id, master_public_key, first_block, last_block)


def active_ibe_key(
    substrate: SubstrateInterface,
    mev_pallet: str,
    target_block: int,
) -> Optional[IbeEpochKey]:
    try:
        entries = substrate.query_map(mev_pallet, "IbeEpochKeys")
    except Exception as exc:
        raise RuntimeError(f"could not query {mev_pallet}::IbeEpochKeys: {exc}") from exc

    keys: List[IbeEpochKey] = []
    for _storage_key, value in entries:
        key = decode_epoch_key(value)
        if key and key.first_block <= target_block <= key.last_block:
            keys.append(key)

    if not keys:
        return None

    keys.sort(key=lambda k: (k.first_block, k.epoch))
    return keys[-1]


def coverage_missing(substrate: SubstrateInterface, mev_pallet: str) -> Tuple[int, List[int]]:
    head = block_number(substrate, chain_head(substrate))
    missing = [
        b
        for b in (head, head + 1, head + IBE_TARGET_LOOKAHEAD_BLOCKS)
        if active_ibe_key(substrate, mev_pallet, b) is None
    ]
    return head, missing


def helper_json(helper: Path, *args: str) -> Dict[str, Any]:
    out = subprocess.check_output([str(helper), *map(str, args)], text=True).strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"helper returned non-JSON output for {args}: {out!r}") from exc


def encrypt_envelope(
    helper: Path,
    genesis_hash: str,
    epoch_key: IbeEpochKey,
    target_block: int,
    plaintext: bytes,
) -> str:
    out = subprocess.check_output(
        [
            str(helper),
            "encrypt",
            genesis_hash,
            str(epoch_key.epoch),
            str(target_block),
            epoch_key.key_id.hex(),
            epoch_key.master_public_key.hex(),
            plaintext.hex(),
        ],
        text=True,
    ).strip()

    if not out.startswith("0x"):
        raise RuntimeError(f"encryptor returned bad output: {out!r}")

    return out


def compose_system_set_storage(substrate: SubstrateInterface, pairs: List[Dict[str, str]]):
    kv = [(p["key"], p["value"]) for p in pairs]
    candidates = [
        {"items": kv},
        {"items": [[p["key"], p["value"]] for p in pairs]},
        {"items": [{"key": p["key"], "value": p["value"]} for p in pairs]},
    ]

    last = None
    for params in candidates:
        try:
            return compose_call(substrate, "System", "set_storage", params)
        except Exception as exc:
            last = exc

    raise RuntimeError(f"could not compose System.set_storage: {last}")


def sudo_set_storage(
    substrate: SubstrateInterface,
    sudo: Keypair,
    pairs: List[Dict[str, str]],
) -> None:
    if not pairs:
        return

    inner = compose_system_set_storage(substrate, pairs)

    def builder():
        return compose_call(substrate, "Sudo", "sudo", {"call": inner})

    receipt = submit_signed_retry(substrate, sudo, builder, immortal=False)
    print(f"[i] dev storage bootstrap included in block #{block_number(substrate, receipt.block_hash)}")


def dev_epoch_key_id(genesis_hash: str) -> bytes:
    return blake2_256(
        b"subtensor-shieldv2-python-dev-key-id-v1" + bytes.fromhex(strip_0x(genesis_hash))
    )[:KEY_ID_LEN]


def is_dev_epoch_key(genesis_hash: str, key: IbeEpochKey) -> bool:
    return key.epoch == DEV_EPOCH and key.key_id == dev_epoch_key_id(genesis_hash)


def bootstrap_dev_ibe_epoch_if_needed(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    sudo: Keypair,
    timeout_s: int,
    poll_s: float,
    enabled: bool,
) -> bool:
    start = time.time()

    while time.time() - start < timeout_s:
        head, missing = coverage_missing(substrate, mev_pallet)
        if not missing:
            print(f"[✓] IBE key coverage ready at head #{head}")
            return False

        if not enabled:
            try:
                produce_heartbeat(substrate, sudo, "wait-ibe-coverage")
            except Exception:
                pass
            time.sleep(poll_s)
            continue

        break

    head, missing = coverage_missing(substrate, mev_pallet)
    if not missing:
        print(f"[✓] IBE key coverage ready at head #{head}")
        return False

    if not enabled:
        raise RuntimeError(f"timed out waiting for IBE key coverage (head={head}, missing={missing})")

    epoch = DEV_EPOCH
    key_id = dev_epoch_key_id(genesis_hash)
    first_block = 0
    last_block = max(head + 10_000, head + timeout_s * 4 + 64)

    print(
        "[!] No active Shield v2 IBE epoch keys found; installing a dev-only "
        f"epoch key for local E2E testing: epoch={epoch}, blocks={first_block}..{last_block}"
    )

    data = helper_json(
        helper,
        "epoch-storage",
        mev_pallet,
        genesis_hash,
        str(epoch),
        str(first_block),
        str(last_block),
        key_id.hex(),
    )

    sudo_set_storage(substrate, sudo, data["pairs"])

    head2, missing2 = coverage_missing(substrate, mev_pallet)
    if missing2:
        raise RuntimeError(
            f"dev IBE epoch storage was written but coverage is still missing: "
            f"head={head2}, missing={missing2}"
        )

    print(f"[✓] Dev IBE epoch coverage ready at head #{head2}")
    return True


def install_dev_block_key(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    sudo: Keypair,
    epoch_key: IbeEpochKey,
    target_block: int,
) -> None:
    finalized_number = max(0, int(target_block) - 1)
    finalized_hash = get_block_hash(substrate, finalized_number) or "0x" + "00" * 32
    if not finalized_hash.startswith("0x"):
        finalized_hash = "0x" + "00" * 32

    data = helper_json(
        helper,
        "block-key-storage",
        mev_pallet,
        genesis_hash,
        str(epoch_key.epoch),
        str(target_block),
        epoch_key.key_id.hex(),
        str(finalized_number),
        finalized_hash,
    )

    print(f"[i] Installing dev-only block key for target #{target_block}")
    sudo_set_storage(substrate, sudo, data["pairs"])

    # The key is written in the body of the sudo block. The queue drains in
    # on_initialize of a following block, so drive one block.
    produce_heartbeat(substrate, sudo, f"after-block-key-{target_block}")


def build_inner_transfer(
    substrate: SubstrateInterface,
    sender: Keypair,
    recipient: str,
    amount: int,
) -> Tuple[bytes, str]:
    call = compose_call(
        substrate,
        "Balances",
        "transfer_keep_alive",
        {"dest": recipient, "value": int(amount)},
    )

    inner_xt, inner_nonce = create_signed_extrinsic_with_fresh_nonce(
        substrate,
        sender,
        call,
        immortal=True,
    )
    inner_bytes = call_to_scale_bytes(inner_xt)

    print(f"[i] built encrypted inner transfer with sender nonce={inner_nonce}")

    return inner_bytes, hex_0x(inner_bytes)


def submit_encrypted_call(substrate: SubstrateInterface, mev_pallet: str, envelope_hex: str):
    return compose_call(substrate, mev_pallet, "submit_encrypted", {"ciphertext": envelope_hex})


def submit_conditional_call(
    substrate: SubstrateInterface,
    mev_pallet: str,
    envelope_hex: str,
    target_block: int,
    lifetime_blocks: int,
):
    condition_shapes = [
        {"AtBlock": {"block": int(target_block)}},
        {"AtBlock": int(target_block)},
        {"at_block": {"block": int(target_block)}},
    ]

    last = None
    for condition in condition_shapes:
        try:
            return compose_call(
                substrate,
                mev_pallet,
                "submit_conditional_encrypted",
                {
                    "ciphertext": envelope_hex,
                    "condition": condition,
                    "lifetime_blocks": int(lifetime_blocks),
                },
            )
        except Exception as exc:
            last = exc

    raise RuntimeError(f"could not compose submit_conditional_encrypted AtBlock: {last}")


def assert_inner_absent(
    substrate: SubstrateInterface,
    inner_hex: str,
    start_block: int,
    end_block: int,
) -> None:
    needle = inner_hex.lower()

    for n in range(start_block, end_block + 1):
        bh = get_block_hash(substrate, n)
        if not bh:
            continue
        if needle in block_extrinsic_hexes(substrate, bh):
            raise AssertionError(f"plain inner extrinsic appeared in block body at #{n}")


def wait_until_block(
    substrate: SubstrateInterface,
    target: int,
    timeout_s: int,
    poll_s: float,
    drive_signer: Optional[Keypair] = None,
) -> int:
    start = time.time()

    while time.time() - start < timeout_s:
        head = block_number(substrate, chain_head(substrate))
        if head >= target:
            return head

        if drive_signer is not None:
            try:
                produce_heartbeat(substrate, drive_signer, f"wait-block-{target}")
            except Exception:
                pass

        time.sleep(poll_s)

    raise RuntimeError(f"timed out waiting for block {target}")


def build_submit_encrypted_for_fresh_target(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    inner_bytes: bytes,
) -> Tuple[Any, int, IbeEpochKey, str]:
    head = block_number(substrate, chain_head(substrate))
    target = head + IBE_TARGET_LOOKAHEAD_BLOCKS
    key = active_ibe_key(substrate, mev_pallet, target)
    if key is None:
        raise RuntimeError(f"no active IBE key for target block {target}")

    envelope = encrypt_envelope(helper, genesis_hash, key, target, inner_bytes)
    call = submit_encrypted_call(substrate, mev_pallet, envelope)
    return call, target, key, envelope


def build_submit_conditional_for_fresh_target(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    inner_bytes: bytes,
    delay: int,
    lifetime: int,
) -> Tuple[Any, int, IbeEpochKey, str]:
    head = block_number(substrate, chain_head(substrate))
    target = head + max(IBE_TARGET_LOOKAHEAD_BLOCKS, int(delay))
    key = active_ibe_key(substrate, mev_pallet, target)
    if key is None:
        raise RuntimeError(f"no active IBE key for conditional target block {target}")

    envelope = encrypt_envelope(helper, genesis_hash, key, target, inner_bytes)
    call = submit_conditional_call(substrate, mev_pallet, envelope, target, lifetime)
    return call, target, key, envelope


def submit_rebuilding_envelope(
    substrate: SubstrateInterface,
    outer: Keypair,
    builder,
    drive_signer: Keypair,
    attempts: int = 12,
) -> Tuple[Any, int, IbeEpochKey]:
    last: Optional[BaseException] = None

    for attempt in range(1, attempts + 1):
        call, target, key, _envelope = builder()
        outer_nonce = account_next_index(substrate, outer.ss58_address)

        print(
            f"[i] submit attempt {attempt}/{attempts}: "
            f"fresh target=#{target}, epoch={key.epoch}, key_id=0x{key.key_id.hex()}, "
            f"outer_nonce={outer_nonce}"
        )

        try:
            receipt = submit_signed_once(
                substrate,
                outer,
                call,
                immortal=True,
                require_success=True,
            )
            return receipt, target, key
        except BaseException as exc:
            last = exc
            if not is_stale_or_nonce_error(exc):
                raise

            print(f"[i] stale/outdated target or nonce race; driving one block and rebuilding envelope: {exc}")
            try:
                produce_heartbeat(substrate, drive_signer, "stale-retry")
            except Exception:
                time.sleep(0.5)

    raise RuntimeError(f"failed to submit after {attempts} fresh target attempts; last={last}")


def run_submit_encrypted(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    outer: Keypair,
    sender: Keypair,
    recipient: Keypair,
    amount: int,
    timeout: int,
    poll: float,
    allow_dev_storage: bool,
    sudo: Keypair,
) -> None:
    print("\n=== submit_encrypted green path ===")

    before = free_balance(substrate, recipient.ss58_address)
    inner_bytes, inner_hex = build_inner_transfer(
        substrate,
        sender,
        recipient.ss58_address,
        amount,
    )
    commitment = hex_0x(blake2_256(inner_bytes))
    print(f"[i] inner commitment={commitment}")

    receipt, target, key = submit_rebuilding_envelope(
        substrate,
        outer,
        lambda: build_submit_encrypted_for_fresh_target(
            substrate,
            mev_pallet,
            helper,
            genesis_hash,
            inner_bytes,
        ),
        drive_signer=sudo,
    )

    submit_block = block_number(substrate, receipt.block_hash)

    if inner_hex.lower() in block_extrinsic_hexes(substrate, receipt.block_hash):
        raise AssertionError(f"plain inner extrinsic appeared in submit block #{submit_block}")

    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        install_dev_block_key(substrate, mev_pallet, helper, genesis_hash, sudo, key, target)

    reveal_block, bal = wait_balance(
        substrate,
        recipient.ss58_address,
        before + amount,
        timeout_s=timeout,
        poll_s=poll,
        drive_signer=sudo,
    )

    if reveal_block < target:
        raise AssertionError(f"transfer executed before target: reveal=#{reveal_block}, target=#{target}")

    assert_inner_absent(substrate, inner_hex, submit_block, reveal_block)

    print(
        f"[✓] submit_encrypted passed: submit=#{submit_block}, "
        f"target=#{target}, executed_by=#{reveal_block}, balance={bal}"
    )


def run_submit_conditional(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    outer: Keypair,
    sender: Keypair,
    recipient: Keypair,
    amount: int,
    delay: int,
    lifetime: int,
    timeout: int,
    poll: float,
    allow_dev_storage: bool,
    sudo: Keypair,
) -> None:
    print("\n=== submit_conditional_encrypted green path ===")

    before = free_balance(substrate, recipient.ss58_address)
    inner_bytes, inner_hex = build_inner_transfer(
        substrate,
        sender,
        recipient.ss58_address,
        amount,
    )
    commitment = hex_0x(blake2_256(inner_bytes))
    print(f"[i] inner commitment={commitment}")

    receipt, target, key = submit_rebuilding_envelope(
        substrate,
        outer,
        lambda: build_submit_conditional_for_fresh_target(
            substrate,
            mev_pallet,
            helper,
            genesis_hash,
            inner_bytes,
            delay,
            lifetime,
        ),
        drive_signer=sudo,
    )

    submit_block = block_number(substrate, receipt.block_hash)

    if inner_hex.lower() in block_extrinsic_hexes(substrate, receipt.block_hash):
        raise AssertionError(f"plain inner extrinsic appeared in submit block #{submit_block}")

    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        install_dev_block_key(substrate, mev_pallet, helper, genesis_hash, sudo, key, target)

    now = block_number(substrate, chain_head(substrate))
    if now < target and free_balance(substrate, recipient.ss58_address) != before:
        raise AssertionError(f"conditional transfer executed before AtBlock: now=#{now}, target=#{target}")

    wait_until_block(substrate, target, timeout_s=timeout, poll_s=poll, drive_signer=sudo)

    reveal_block, bal = wait_balance(
        substrate,
        recipient.ss58_address,
        before + amount,
        timeout_s=timeout,
        poll_s=poll,
        drive_signer=sudo,
    )

    if reveal_block < target:
        raise AssertionError(f"conditional transfer executed before AtBlock: reveal=#{reveal_block}, target=#{target}")

    assert_inner_absent(substrate, inner_hex, submit_block, reveal_block)

    print(
        f"[✓] submit_conditional_encrypted passed: submit=#{submit_block}, "
        f"AtBlock=#{target}, executed_by=#{reveal_block}, balance={bal}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ws", default="ws://127.0.0.1:9945")
    parser.add_argument("--outer-uri", default="//Eve")
    parser.add_argument("--sender-uri", default="//Bob")
    parser.add_argument("--recipient-uri", default="//Charlie")
    parser.add_argument("--conditional-recipient-uri", default="//Dave")
    parser.add_argument("--faucet-uri", default="//Alice")
    parser.add_argument("--amount-tao", type=float, default=0.1)
    parser.add_argument("--conditional-delay", type=int, default=4)
    parser.add_argument("--conditional-lifetime", type=int, default=32)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--poll", type=float, default=0.8)
    parser.add_argument(
        "--no-dev-bootstrap",
        action="store_true",
        help="do not install dev IBE epoch/block keys if live DKG keys are missing",
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="verify this script embeds the fixed helper and exit",
    )
    args = parser.parse_args()

    if args.self_check:
        self_check()
        return 0

    print(f"[i] {SCRIPT_VERSION}")

    helper = ensure_encryptor()
    substrate = connect(args.ws)

    mev_pallet = resolve_pallet(
        substrate,
        exact=("MevShield", "MEVShield", "Mevshield"),
        contains=("mev", "shield"),
    )

    decimals = token_decimals(substrate)

    genesis_hash = str(
        rpc_result(substrate.rpc_request("chain_getBlockHash", [0]), "chain_getBlockHash")
    )
    if not genesis_hash.startswith("0x"):
        raise RuntimeError(f"bad genesis hash: {genesis_hash}")

    outer = Keypair.create_from_uri(args.outer_uri)
    sender = Keypair.create_from_uri(args.sender_uri)
    recipient = Keypair.create_from_uri(args.recipient_uri)
    conditional_recipient = Keypair.create_from_uri(args.conditional_recipient_uri)
    faucet = Keypair.create_from_uri(args.faucet_uri)

    amount = to_planck(args.amount_tao, decimals)

    print(f"[i] decimals={decimals} amount={amount} planck genesis={genesis_hash}")

    ensure_funded(substrate, faucet, outer, to_planck(10, decimals), "outer signer")
    ensure_funded(substrate, faucet, sender, max(to_planck(20, decimals), amount * 4), "inner sender")

    installed_dev_epoch = bootstrap_dev_ibe_epoch_if_needed(
        substrate=substrate,
        mev_pallet=mev_pallet,
        helper=helper,
        genesis_hash=genesis_hash,
        sudo=faucet,
        timeout_s=args.timeout,
        poll_s=args.poll,
        enabled=not args.no_dev_bootstrap,
    )

    # Even if the dev epoch was installed by a previous script run, keep dev block-key
    # installation enabled whenever the active key is the deterministic dev key.
    allow_dev_storage = not args.no_dev_bootstrap or installed_dev_epoch

    run_submit_encrypted(
        substrate=substrate,
        mev_pallet=mev_pallet,
        helper=helper,
        genesis_hash=genesis_hash,
        outer=outer,
        sender=sender,
        recipient=recipient,
        amount=amount,
        timeout=args.timeout,
        poll=args.poll,
        allow_dev_storage=allow_dev_storage,
        sudo=faucet,
    )

    run_submit_conditional(
        substrate=substrate,
        mev_pallet=mev_pallet,
        helper=helper,
        genesis_hash=genesis_hash,
        outer=outer,
        sender=sender,
        recipient=conditional_recipient,
        amount=amount,
        delay=args.conditional_delay,
        lifetime=args.conditional_lifetime,
        timeout=args.timeout,
        poll=args.poll,
        allow_dev_storage=allow_dev_storage,
        sudo=faucet,
    )

    print("\n✅ PASS: Shield v2 submit_encrypted and submit_conditional_encrypted green paths passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"\nAssertion failed:\n{exc}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as exc:
        print(f"\nError:\n{exc}", file=sys.stderr)
        raise SystemExit(1)