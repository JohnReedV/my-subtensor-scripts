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
- signs the outer Shield wrapper with a short mortal era, as required by CheckMortality;
- optionally installs dev-only IBE epoch/block keys through sudo storage writes if no live DKG keys are present.

It tests:
- submit_encrypted green path with inner SubtensorModule.add_stake;
- submit_encrypted complex path with inner Utility.batch_all([Balances.transfer, SubtensorModule.add_stake]);
- decrypted-but-failing inner add_stake overdraw path, including failure event and no alpha mutation;
- submit_conditional_encrypted near AtBlock green path;
- submit_conditional_encrypted farther-away AtBlock path, proving it does not fire early;
- missing dev block-key no-brick path, when the no-brick runtime patch is present;
- plaintext inner extrinsics absent from block bodies before reveal;
- stake alpha changes only after target/reveal;
- inner signed nonces advance across repeated encrypted submissions.
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


SCRIPT_VERSION = "shieldv2.py 2026-06-18-29-expanded-coverage"
CACHE_VERSION = "v2-tle-helper-2026-06-18-21-explicit-nonces-inline"

IBE_TARGET_LOOKAHEAD_BLOCKS = 2
KEY_ID_LEN = 16
DEV_EPOCH = 9_000_000

# The runtime CheckMortality extension for the Shield calls rejects immortal
# submit_encrypted / submit_conditional_encrypted wrappers and mortal eras > 8.
# Keep the encrypted inner extrinsic immortal; only the outer wrapper must be mortal.
SHIELD_OUTER_ERA_PERIOD = 8
VERBOSE = False


def logv(message: str) -> None:
    if VERBOSE:
        print(message)



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
    let master_public_key_bytes_arg = decode_hex(&args[4]).context("decode master_public_key")?;
    let plaintext = decode_hex(&args[5]).context("decode plaintext")?;

    let mut mpk_slice: &[u8] = &master_public_key_bytes_arg;
    let master_public_key = ark_bls12_381::G2Projective::deserialize_compressed(&mut mpk_slice)
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
    let finalized_ordering_block_number: u64 = args[5]
        .parse()
        .context("parse finalized_ordering_block_number")?;
    let finalized_ordering_block_hash = fixed::<32>(&args[6], "finalized_ordering_block_hash")?;

    let msk = dev_msk(genesis_hash, epoch, key_id);
    let identity_decryption_key = identity_key_bytes(genesis_hash, epoch, target_block, key_id, msk)?;
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
        "usage:\n  encrypt <genesis> <epoch> <target> <key_id> <master_public_key> <plaintext>\n  epoch-storage <pallet> <genesis> <epoch> <first_block> <last_block> <key_id>\n  block-key-storage <pallet> <genesis> <epoch> <target_block> <key_id> <finalized_number> <finalized_hash>"
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
    if isinstance(value, (list, tuple)) and value:
        return to_int(value[0], default)
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
    print(f"[✓] outer Shield wrapper era period: {SHIELD_OUTER_ERA_PERIOD} blocks")
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
        if VERBOSE:
            subprocess.run([cargo, "build", "--release"], cwd=str(project_dir), check=True)
        else:
            result = subprocess.run(
                [cargo, "build", "--release"],
                cwd=str(project_dir),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            if result.returncode != 0:
                print(result.stdout, file=sys.stderr)
                raise subprocess.CalledProcessError(result.returncode, result.args, output=result.stdout)
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


def plain_value(value: Any) -> Any:
    if hasattr(value, "value"):
        return plain_value(value.value)
    if isinstance(value, dict):
        return {str(k): plain_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain_value(v) for v in value]
    return value


def system_events(substrate: SubstrateInterface, block_hash: str) -> List[Dict[str, Any]]:
    try:
        raw = substrate.query("System", "Events", [], block_hash=block_hash)
        value = plain_value(raw)
        return value if isinstance(value, list) else []
    except Exception:
        return []


def event_parts(record: Dict[str, Any]) -> Tuple[str, str, Any]:
    rec = plain_value(record)
    if not isinstance(rec, dict):
        return "", "", None
    ev = rec.get("event", rec)
    if not isinstance(ev, dict):
        return "", "", None
    module = ev.get("module_id") or ev.get("module") or ev.get("pallet") or ""
    name = ev.get("event_id") or ev.get("variant") or ev.get("name") or ""
    attrs = ev.get("attributes", ev.get("params", None))
    return str(module), str(name), plain_value(attrs)


def attr_value(attrs: Any, name: str, index: Optional[int] = None, default: Any = None) -> Any:
    attrs = plain_value(attrs)
    if isinstance(attrs, dict):
        lname = name.lower()
        for key, value in attrs.items():
            if str(key).lower() == lname:
                return value
        return default
    if isinstance(attrs, list):
        lname = name.lower()
        for item in attrs:
            item = plain_value(item)
            if isinstance(item, dict):
                keys = {str(k).lower(): v for k, v in item.items()}
                item_name = keys.get("name") or keys.get("type") or keys.get("field")
                if item_name is not None and str(item_name).lower() == lname:
                    return keys.get("value", keys.get("data", default))
        if index is not None and 0 <= index < len(attrs):
            return attrs[index]
    return default


def summarize_relevant_events(substrate: SubstrateInterface, block_number_value: int) -> str:
    bh = get_block_hash(substrate, block_number_value)
    if not bh:
        return f"block #{block_number_value}: <hash unavailable>"
    rows: List[str] = []
    for rec in system_events(substrate, bh):
        module, name, attrs = event_parts(rec)
        ml = module.lower()
        if ("shield" in ml) or module in ("SubtensorModule", "Balances", "Sudo", "System"):
            if isinstance(attrs, dict):
                compact = ", ".join(f"{k}={v}" for k, v in list(attrs.items())[:5])
            elif isinstance(attrs, list):
                compact = ", ".join(str(x) for x in attrs[:5])
            else:
                compact = ""
            rows.append(f"{module}.{name}({compact})")
    if not rows:
        return f"block #{block_number_value}: <no decoded relevant events>"
    return f"block #{block_number_value}: " + " | ".join(rows)


def shield_execution_success_in_block(
    substrate: SubstrateInterface,
    block_number_value: int,
    event_name: str,
) -> Optional[bool]:
    bh = get_block_hash(substrate, block_number_value)
    if not bh:
        return None
    for rec in system_events(substrate, bh):
        module, name, attrs = event_parts(rec)
        if "shield" not in module.lower():
            continue
        if name != event_name:
            continue
        success = attr_value(attrs, "success", 1, None)
        if isinstance(success, bool):
            return success
        if isinstance(success, str):
            if success.lower() in ("true", "yes", "1"):
                return True
            if success.lower() in ("false", "no", "0"):
                return False
        if success is not None:
            return bool(success)
    return None


def wait_for_shield_success_event(
    substrate: SubstrateInterface,
    start_block: int,
    event_name: str,
    label: str,
    timeout_s: int,
    poll_s: float,
    drive_signer: Optional[Keypair] = None,
) -> Optional[int]:
    start = time.time()
    checked_until = start_block - 1
    while time.time() - start < timeout_s:
        head = block_number(substrate, chain_head(substrate))
        for n in range(max(start_block, checked_until + 1), head + 1):
            status = shield_execution_success_in_block(substrate, n, event_name)
            if status is True:
                return n
            if status is False:
                raise RuntimeError(
                    f"{label} revealed at block #{n}, but Shield reported success=false.\n"
                    f"{summarize_relevant_events(substrate, n)}"
                )
            checked_until = n
        if drive_signer is not None:
            try:
                produce_heartbeat(substrate, drive_signer, f"wait-shield-{label}")
            except Exception:
                pass
        time.sleep(poll_s)
    return None


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


def mortal_era(substrate: SubstrateInterface, period: int) -> Dict[str, int]:
    period = int(period)
    if period <= 0:
        raise ValueError(f"mortal era period must be positive, got {period}")
    if period > SHIELD_OUTER_ERA_PERIOD:
        raise ValueError(
            f"Shield outer era period must be <= {SHIELD_OUTER_ERA_PERIOD}, got {period}"
        )
    current = block_number(substrate, chain_head(substrate))
    return {"period": period, "current": current}


def create_signed_extrinsic_with_fresh_nonce(
    substrate: SubstrateInterface,
    signer: Keypair,
    call: Any,
    immortal: bool = False,
    era_period: Optional[int] = None,
):
    if immortal and era_period is not None:
        raise ValueError("use either immortal=True or era_period=..., not both")

    nonce = account_next_index(substrate, signer.ss58_address)
    kwargs: Dict[str, Any] = {
        "call": call,
        "keypair": signer,
        "nonce": nonce,
    }
    if era_period is not None:
        kwargs["era"] = mortal_era(substrate, int(era_period))
    elif immortal:
        kwargs["era"] = "00"

    try:
        xt = substrate.create_signed_extrinsic(**kwargs)
    except TypeError as exc:
        raise RuntimeError(
            "substrate-interface create_signed_extrinsic does not accept explicit nonce/era. "
            "Upgrade substrate-interface; this Shield v2 test requires explicit nonces and mortal eras."
        ) from exc
    return xt, nonce


def submit_signed_once(
    substrate: SubstrateInterface,
    signer: Keypair,
    call: Any,
    immortal: bool = False,
    era_period: Optional[int] = None,
    require_success: bool = True,
):
    xt, nonce = create_signed_extrinsic_with_fresh_nonce(
        substrate,
        signer,
        call,
        immortal=immortal,
        era_period=era_period,
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
    era_period: Optional[int] = None,
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
                era_period=era_period,
                require_success=True,
            )
        except BaseException as exc:
            last = exc
            if not is_stale_or_nonce_error(exc):
                raise
            print(f"[i] retrying signed extrinsic after stale/nonce race ({attempt}/{attempts}): {exc}")
            time.sleep(0.25)
    raise RuntimeError(f"failed after {attempts} attempts; last={last}")


def free_balance_at(
    substrate: SubstrateInterface,
    ss58: str,
    block_hash: Optional[str] = None,
) -> int:
    try:
        info = substrate.query("System", "Account", [ss58], block_hash=block_hash).value
        return int(info["data"]["free"])
    except Exception:
        return 0


def free_balance(substrate: SubstrateInterface, ss58: str) -> int:
    return free_balance_at(substrate, ss58, None)


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
        logv(f"[i] {label} funded: {have}")
        return
    delta = int((min_balance - have) * 1.10) + 1
    print(f"[i] funding {label}: +{delta} planck")
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


PALLET_SUBTENSOR = "SubtensorModule"
PALLET_ADMIN = "AdminUtils"


def query_value(
    substrate: SubstrateInterface,
    pallet: str,
    item: str,
    params: Optional[List[Any]] = None,
    block_hash: Optional[str] = None,
    default: Any = None,
) -> Any:
    try:
        obj = substrate.query(pallet, item, params or [], block_hash=block_hash)
        return getattr(obj, "value", obj)
    except Exception:
        return default


def networks_added(substrate: SubstrateInterface) -> List[int]:
    nets = set()
    try:
        for key, value in substrate.query_map(PALLET_SUBTENSOR, "NetworksAdded"):
            is_added = getattr(value, "value", value)
            if bool(is_added):
                nets.add(to_int(key))
    except Exception:
        pass
    if nets:
        return sorted(nets)

    total = to_int(query_value(substrate, PALLET_SUBTENSOR, "TotalNetworks", default=0))
    for netuid in range(max(0, total) + 4):
        if bool(query_value(substrate, PALLET_SUBTENSOR, "NetworksAdded", [netuid], default=False)):
            nets.add(netuid)
    return sorted(nets)


def total_networks(substrate: SubstrateInterface) -> int:
    return to_int(query_value(substrate, PALLET_SUBTENSOR, "TotalNetworks", default=0))


def hotkey_registered_on_network_at(
    substrate: SubstrateInterface,
    netuid: int,
    hotkey: str,
    block_hash: Optional[str] = None,
) -> bool:
    # Uids is DMAP(netuid, hotkey) -> uid, OptionQuery.
    uid = query_value(substrate, PALLET_SUBTENSOR, "Uids", [int(netuid), hotkey], block_hash=block_hash, default=None)
    if uid is not None:
        return True
    # Some historical metadata wrappers decode absent Option as 0/None inconsistently.
    member = query_value(substrate, PALLET_SUBTENSOR, "IsNetworkMember", [hotkey, int(netuid)], block_hash=block_hash, default=False)
    return bool(member)


def total_hotkey_alpha(
    substrate: SubstrateInterface,
    netuid: int,
    hotkey: str,
    block_hash: Optional[str] = None,
) -> int:
    # TotalHotkeyAlpha is DMAP(hotkey, netuid) -> alpha.
    val = query_value(
        substrate,
        PALLET_SUBTENSOR,
        "TotalHotkeyAlpha",
        [hotkey, int(netuid)],
        block_hash=block_hash,
        default=0,
    )
    parsed = to_int(val, 0)
    if parsed != 0:
        return parsed
    # Defensive fallback for old/custom metadata orderings.
    val2 = query_value(
        substrate,
        PALLET_SUBTENSOR,
        "TotalHotkeyAlpha",
        [int(netuid), hotkey],
        block_hash=block_hash,
        default=0,
    )
    return max(parsed, to_int(val2, 0))


def wait_hotkey_alpha_increase(
    substrate: SubstrateInterface,
    netuid: int,
    hotkey: str,
    before: int,
    timeout_s: int,
    poll_s: float,
    drive_signer: Optional[Keypair] = None,
) -> Tuple[int, int]:
    start = time.time()
    last = total_hotkey_alpha(substrate, netuid, hotkey)
    while time.time() - start < timeout_s:
        head = block_number(substrate, chain_head(substrate))
        alpha = total_hotkey_alpha(substrate, netuid, hotkey)
        last = alpha
        if alpha > before:
            return head, alpha
        if drive_signer is not None:
            try:
                produce_heartbeat(substrate, drive_signer, f"wait-alpha-{netuid}")
            except Exception:
                pass
        time.sleep(poll_s)
    raise RuntimeError(
        f"timed out waiting for TotalHotkeyAlpha({hotkey}, {netuid}) to increase "
        f"above {before}; last={last}"
    )


def sudo_wrap_call(substrate: SubstrateInterface, call: Any) -> Any:
    return compose_call(substrate, "Sudo", "sudo", {"call": call})


def try_sudo_call(substrate: SubstrateInterface, sudo: Keypair, pallet: str, function: str, params: Dict[str, Any], label: str) -> bool:
    try:
        call = compose_call(substrate, pallet, function, params)
        submit_signed_retry(substrate, sudo, lambda: sudo_wrap_call(substrate, call), immortal=False)
        logv(f"[i] sudo {label}: ok")
        return True
    except Exception as exc:
        logv(f"[i] sudo {label}: skipped ({exc})")
        return False


def maybe_relax_subnet_creation_limits(substrate: SubstrateInterface, sudo: Keypair) -> None:
    current = networks_added(substrate)
    desired_limit = max((max(current) if current else 0) + 8, len(current) + 8, 16)
    limit_shapes = [
        (PALLET_ADMIN, "sudo_set_subnet_limit", {"max_subnets": desired_limit}),
        (PALLET_ADMIN, "sudo_set_subnet_limit", {"subnet_limit": desired_limit}),
        (PALLET_ADMIN, "sudo_set_subnet_limit", {"value": desired_limit}),
    ]
    for pallet, function, params in limit_shapes:
        if try_sudo_call(substrate, sudo, pallet, function, params, f"{pallet}.{function}={desired_limit}"):
            break

    rate_limit_shapes = [
        (PALLET_ADMIN, "sudo_set_network_rate_limit", {"rate_limit": 0}),
        (PALLET_ADMIN, "sudo_set_network_rate_limit", {"network_rate_limit": 0}),
        (PALLET_ADMIN, "sudo_set_tx_rate_limit", {"tx_rate_limit": 0}),
        (PALLET_ADMIN, "sudo_set_tx_rate_limit", {"value": 0}),
        (PALLET_ADMIN, "sudo_set_owner_hparam_rate_limit", {"epochs": 0}),
        (PALLET_ADMIN, "sudo_set_owner_hparam_rate_limit", {"owner_hparam_rate_limit": 0}),
    ]
    for pallet, function, params in rate_limit_shapes:
        try_sudo_call(substrate, sudo, pallet, function, params, f"{pallet}.{function}=0")


def subtoken_enabled(substrate: SubstrateInterface, netuid: int, block_hash: Optional[str] = None) -> bool:
    return bool(query_value(substrate, PALLET_SUBTENSOR, "SubtokenEnabled", [int(netuid)], block_hash=block_hash, default=False))


def ensure_subtoken_enabled_for_add_stake(
    substrate: SubstrateInterface,
    sudo: Keypair,
    netuid: int,
    label: str,
    attempts: int = 8,
) -> None:
    if subtoken_enabled(substrate, netuid):
        logv(f"[i] subtoken already enabled for netuid={netuid}")
        return

    candidates = [
        {"netuid": int(netuid), "subtoken_enabled": True},
        {"netuid": int(netuid), "enabled": True},
        {"netuid": int(netuid), "value": True},
    ]
    last: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        for params in candidates:
            try:
                call = compose_call(substrate, PALLET_ADMIN, "sudo_set_subtoken_enabled", params)
                receipt = submit_signed_retry(
                    substrate,
                    sudo,
                    lambda call=call: sudo_wrap_call(substrate, call),
                    immortal=False,
                )
                included = block_number(substrate, receipt.block_hash)
                if subtoken_enabled(substrate, netuid):
                    print(f"[✓] subtoken enabled: netuid={netuid}, block=#{included}")
                    return
                last = RuntimeError("sudo_set_subtoken_enabled included but SubtokenEnabled is still false")
            except Exception as exc:
                last = exc
                logv(f"[i] enable subtoken candidate skipped: params={params} err={exc}")
        if attempt < attempts:
            try:
                produce_heartbeat(substrate, sudo, f"subtoken-enable-{netuid}-{attempt}")
            except Exception:
                time.sleep(0.5)
    raise RuntimeError(
        f"could not enable SubtokenEnabled for scratch subnet {netuid}; "
        f"encrypted add_stake would fail SubtokenDisabled. last={last}"
    )


def is_register_network_param_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    markers = [
        "parameter '",
        'parameter "',
        "not specified",
        "unknown parameter",
        "unexpected parameter",
        "unexpected keyword",
        "missing required",
        "missing value",
    ]
    return any(marker in text for marker in markers)


def register_network(substrate: SubstrateInterface, signer: Keypair, owner_hot_ss58: str, owner_cold_ss58: str):
    candidates = [
        {"hotkey": owner_hot_ss58},
        {"hotkey": owner_hot_ss58, "coldkey": owner_cold_ss58},
        {"hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"owner_hotkey": owner_hot_ss58, "owner_coldkey": owner_cold_ss58},
        {"owner_hot": owner_hot_ss58, "owner_cold": owner_cold_ss58},
    ]
    shape_errors: List[str] = []
    for params in candidates:
        try:
            call = compose_call(substrate, PALLET_SUBTENSOR, "register_network", params)
        except Exception as exc:
            if is_register_network_param_error(exc):
                shape_errors.append(f"keys={sorted(params.keys())}: {exc}")
                continue
            raise
        return submit_signed_once(substrate, signer, call, immortal=False, require_success=True)
    joined = " | ".join(shape_errors) if shape_errors else "no candidate parameter shape composed"
    raise RuntimeError(f"register_network could not match any known parameter shape: {joined}")


def register_network_with_retry(
    substrate: SubstrateInterface,
    signer: Keypair,
    owner_hot_ss58: str,
    owner_cold_ss58: str,
    attempts: int = 6,
):
    last: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        try:
            return register_network(substrate, signer, owner_hot_ss58, owner_cold_ss58)
        except BaseException as exc:
            last = exc
            text = str(exc).lower()
            if ("rate" in text or "ratelimit" in text or "custom error: 6" in text) and attempt < attempts:
                print(f"[i] register_network rate-limited; driving one block and retrying ({attempt}/{attempts})")
                try:
                    produce_heartbeat(substrate, signer, "register-network-backoff")
                except Exception:
                    time.sleep(0.5)
                continue
            raise
    raise RuntimeError(f"register_network_with_retry failed; last={last}")


def ensure_scratch_subnet(
    substrate: SubstrateInterface,
    sudo: Keypair,
    owner_cold: Keypair,
    owner_hot: Keypair,
    decimals: int,
    label: str,
    min_owner_cold: int,
    min_owner_hot: int,
    min_stake_funds: int,
) -> int:
    print(f"\n=== scratch subnet setup: {label} ===")
    before = set(networks_added(substrate))
    maybe_relax_subnet_creation_limits(substrate, sudo)
    ensure_funded(substrate, sudo, owner_cold, max(min_owner_cold, min_stake_funds), f"{label} subnet owner/stake cold")
    ensure_funded(substrate, sudo, owner_hot, min_owner_hot, f"{label} subnet owner hot")
    receipt = register_network_with_retry(
        substrate,
        owner_cold,
        owner_hot.ss58_address,
        owner_cold.ss58_address,
    )
    reg_block = block_number(substrate, receipt.block_hash)
    after = set(networks_added(substrate))
    created = sorted(n for n in after if n not in before and n != 0)
    if not created:
        # Some local dev runtimes update TotalNetworks first and NetworksAdded one block later.
        try:
            produce_heartbeat(substrate, sudo, f"network-visible-{label}")
        except Exception:
            pass
        after = set(networks_added(substrate))
        created = sorted(n for n in after if n not in before and n != 0)
    if not created:
        total = total_networks(substrate)
        candidates = [n for n in range(max(1, total + 2)) if n not in before and n != 0]
        created = candidates[-1:] if candidates else []
    if not created:
        raise RuntimeError(f"register_network did not create a visible scratch subnet for {label}")
    netuid = int(created[-1])
    if not hotkey_registered_on_network_at(substrate, netuid, owner_hot.ss58_address):
        # Let one more block import any registration side effects before failing.
        try:
            produce_heartbeat(substrate, sudo, f"hotkey-visible-{label}-{netuid}")
        except Exception:
            pass
    if not hotkey_registered_on_network_at(substrate, netuid, owner_hot.ss58_address):
        raise RuntimeError(
            f"scratch subnet {netuid} was created but owner hotkey is not registered there; "
            "add_stake would fail NonAssociatedColdKey/HotKeyNotRegisteredInNetwork"
        )
    ensure_subtoken_enabled_for_add_stake(substrate, sudo, netuid, label)
    ensure_funded(substrate, sudo, owner_cold, min_stake_funds, f"{label} stake cold post-registration")
    print(f"[✓] scratch subnet ready: label={label}, netuid={netuid}, registered=#{reg_block}")
    logv(f"[i] {label} owner_hot={owner_hot.ss58_address}")
    return netuid


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
    """Install a dev-only block key into runtime storage before target on_initialize.

    This is only a localnet fallback for deterministic dev epoch keys. It must be
    included in block target-1 so the key exists in parent state when
    on_initialize(target) drains the encrypted queue. Installing it in target's
    body is too late and can make the proposer repeatedly build invalid blocks.
    """
    target_block = int(target_block)
    latest_safe_parent = target_block - 2
    head = block_number(substrate, chain_head(substrate))
    if head > latest_safe_parent:
        raise RuntimeError(
            f"missed dev block-key staging window for target #{target_block}: "
            f"head is #{head}, but key-storage sudo must be submitted by parent "
            f"#{latest_safe_parent} so it lands in block #{target_block - 1}"
        )

    while head < latest_safe_parent:
        produce_heartbeat(substrate, sudo, f"pre-stage-block-key-{target_block}")
        head = block_number(substrate, chain_head(substrate))

    finalized_number = max(0, target_block - 1)
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
    print(f"[i] staged dev block key for target #{target_block}")
    receipt = submit_signed_retry(
        substrate,
        sudo,
        lambda: compose_call(
            substrate,
            "Sudo",
            "sudo",
            {"call": compose_system_set_storage(substrate, data["pairs"])},
        ),
        immortal=False,
    )
    included = block_number(substrate, receipt.block_hash)
    if included >= target_block:
        raise RuntimeError(
            f"dev block key landed in block #{included}, which is too late for "
            f"target #{target_block}; it must land in #{target_block - 1}"
        )
    # Return after the staging write lands. Callers may assert state at this
    # pre-reveal block before waiting for the target/reveal block.
    return receipt


def compose_add_stake_call(
    substrate: SubstrateInterface,
    hotkey_ss58: str,
    netuid: int,
    amount_staked: int,
) -> Any:
    return compose_call(
        substrate,
        PALLET_SUBTENSOR,
        "add_stake",
        {
            "hotkey": hotkey_ss58,
            "netuid": int(netuid),
            "amount_staked": int(amount_staked),
        },
    )


def compose_balance_transfer_call(substrate: SubstrateInterface, dest: str, value: int) -> Tuple[Any, str]:
    candidates = [
        ("transfer_keep_alive", {"dest": dest, "value": int(value)}),
        ("transfer_allow_death", {"dest": dest, "value": int(value)}),
        ("transfer", {"dest": dest, "value": int(value)}),
    ]
    last: Optional[BaseException] = None
    for function, params in candidates:
        try:
            return compose_call(substrate, "Balances", function, params), f"Balances.{function}"
        except Exception as exc:
            last = exc
    raise RuntimeError(f"could not compose a balances transfer call: {last}")


def compose_utility_batch_call(substrate: SubstrateInterface, calls: List[Any]) -> Tuple[Any, str]:
    candidates = [
        ("batch_all", {"calls": calls}),
        ("batch", {"calls": calls}),
    ]
    last: Optional[BaseException] = None
    for function, params in candidates:
        try:
            return compose_call(substrate, "Utility", function, params), f"Utility.{function}"
        except Exception as exc:
            last = exc
    raise RuntimeError(
        "could not compose Utility.batch_all or Utility.batch; "
        f"the complex encrypted-inner test requires the Utility pallet. last={last}"
    )


def build_signed_inner_call(
    substrate: SubstrateInterface,
    signer: Keypair,
    call: Any,
    label: str,
) -> Tuple[bytes, str, int]:
    inner_xt, inner_nonce = create_signed_extrinsic_with_fresh_nonce(
        substrate,
        signer,
        call,
        immortal=True,
    )
    inner_bytes = call_to_scale_bytes(inner_xt)
    print(
        f"[i] inner {label}: nonce={inner_nonce}, bytes={len(inner_bytes)}, "
        f"commitment={hex_0x(blake2_256(inner_bytes))}"
    )
    return inner_bytes, hex_0x(inner_bytes), inner_nonce


def build_inner_add_stake(
    substrate: SubstrateInterface,
    cold: Keypair,
    hotkey_ss58: str,
    netuid: int,
    amount_staked: int,
    label: str = "add_stake",
) -> Tuple[bytes, str]:
    call = compose_add_stake_call(substrate, hotkey_ss58, netuid, amount_staked)
    inner_bytes, inner_hex, _nonce = build_signed_inner_call(substrate, cold, call, label)
    return inner_bytes, inner_hex


def build_inner_batch_transfer_and_add_stake(
    substrate: SubstrateInterface,
    cold: Keypair,
    hotkey_ss58: str,
    netuid: int,
    amount_staked: int,
    transfer_dest_ss58: str,
    transfer_amount: int,
) -> Tuple[bytes, str, str]:
    transfer_call, transfer_name = compose_balance_transfer_call(
        substrate,
        transfer_dest_ss58,
        int(transfer_amount),
    )
    stake_call = compose_add_stake_call(substrate, hotkey_ss58, netuid, amount_staked)
    batch_call, batch_name = compose_utility_batch_call(substrate, [transfer_call, stake_call])
    inner_bytes, inner_hex, _nonce = build_signed_inner_call(
        substrate,
        cold,
        batch_call,
        f"{batch_name}({transfer_name} + SubtensorModule.add_stake)",
    )
    return inner_bytes, inner_hex, batch_name


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


def shield_event_present_in_block(
    substrate: SubstrateInterface,
    block_number_value: int,
    event_name: str,
) -> bool:
    bh = get_block_hash(substrate, block_number_value)
    if not bh:
        return False
    for rec in system_events(substrate, bh):
        module, name, _attrs = event_parts(rec)
        if "shield" in module.lower() and name == event_name:
            return True
    return False


def wait_for_shield_event_present(
    substrate: SubstrateInterface,
    start_block: int,
    event_name: str,
    label: str,
    timeout_s: int,
    poll_s: float,
    drive_signer: Optional[Keypair] = None,
) -> Optional[int]:
    start = time.time()
    checked_until = start_block - 1
    while time.time() - start < timeout_s:
        head = block_number(substrate, chain_head(substrate))
        for n in range(max(start_block, checked_until + 1), head + 1):
            if shield_event_present_in_block(substrate, n, event_name):
                return n
            checked_until = n
        if drive_signer is not None:
            try:
                produce_heartbeat(substrate, drive_signer, f"wait-event-{label}")
            except Exception:
                pass
        time.sleep(poll_s)
    return None


def wait_for_shield_status_event(
    substrate: SubstrateInterface,
    start_block: int,
    event_name: str,
    expected_success: bool,
    label: str,
    timeout_s: int,
    poll_s: float,
    drive_signer: Optional[Keypair] = None,
) -> int:
    start = time.time()
    checked_until = start_block - 1
    while time.time() - start < timeout_s:
        head = block_number(substrate, chain_head(substrate))
        for n in range(max(start_block, checked_until + 1), head + 1):
            status = shield_execution_success_in_block(substrate, n, event_name)
            if status is expected_success:
                return n
            if status is not None and status is not expected_success:
                raise RuntimeError(
                    f"{label} had unexpected {event_name}.success={status} at block #{n}.\n"
                    f"{summarize_relevant_events(substrate, n)}"
                )
            checked_until = n
        if drive_signer is not None:
            try:
                produce_heartbeat(substrate, drive_signer, f"wait-status-{label}")
            except Exception:
                pass
        time.sleep(poll_s)
    raise RuntimeError(f"timed out waiting for {event_name}.success={expected_success} for {label}")


def choose_submit_encrypted_target(
    substrate: SubstrateInterface,
    mev_pallet: str,
    genesis_hash: str,
    allow_dev_storage: bool,
) -> Tuple[int, IbeEpochKey]:
    head = block_number(substrate, chain_head(substrate))
    target = head + IBE_TARGET_LOOKAHEAD_BLOCKS
    key = active_ibe_key(substrate, mev_pallet, target)
    if key is None:
        raise RuntimeError(f"no active IBE key for target block {target}")

    # The production path uses target=head+2 and relies on a pre-runtime digest
    # in the target block. The dev storage fallback cannot write a key into the
    # target block body, because on_initialize(target) has already run. Give the
    # fallback one staging block so the sudo storage write lands at target-1.
    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        staged_target = head + IBE_TARGET_LOOKAHEAD_BLOCKS + 1
        staged_key = active_ibe_key(substrate, mev_pallet, staged_target)
        if staged_key is None:
            raise RuntimeError(f"no active IBE key for staged dev target block {staged_target}")
        return staged_target, staged_key

    return target, key


def build_submit_encrypted_for_fresh_target(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    inner_bytes: bytes,
    allow_dev_storage: bool = False,
) -> Tuple[Any, int, IbeEpochKey, str]:
    target, key = choose_submit_encrypted_target(
        substrate, mev_pallet, genesis_hash, allow_dev_storage
    )
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
    allow_dev_storage: bool = False,
) -> Tuple[Any, int, IbeEpochKey, str]:
    head = block_number(substrate, chain_head(substrate))
    effective_delay = max(IBE_TARGET_LOOKAHEAD_BLOCKS, int(delay))
    base_target = head + effective_delay
    key = active_ibe_key(substrate, mev_pallet, base_target)
    if key is None:
        raise RuntimeError(f"no active IBE key for conditional target block {base_target}")
    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        # Same reason as submit_encrypted: body-storage dev keys need target-1
        # staging, so do not let a fired conditional target the immediately due
        # child block.
        base_target = max(base_target, head + IBE_TARGET_LOOKAHEAD_BLOCKS + 1)
        key = active_ibe_key(substrate, mev_pallet, base_target)
        if key is None:
            raise RuntimeError(f"no active IBE key for staged conditional target block {base_target}")
    envelope = encrypt_envelope(helper, genesis_hash, key, base_target, inner_bytes)
    call = submit_conditional_call(substrate, mev_pallet, envelope, base_target, lifetime)
    return call, base_target, key, envelope


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
            f"[i] submit attempt {attempt}/{attempts}: target=#{target}, "
            f"outer_nonce={outer_nonce}, era={SHIELD_OUTER_ERA_PERIOD}"
        )
        logv(f"[i] target epoch={key.epoch}, key_id=0x{key.key_id.hex()}")
        try:
            receipt = submit_signed_once(
                substrate,
                outer,
                call,
                era_period=SHIELD_OUTER_ERA_PERIOD,
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
    stake_cold: Keypair,
    stake_hot: Keypair,
    netuid: int,
    amount: int,
    timeout: int,
    poll: float,
    allow_dev_storage: bool,
    sudo: Keypair,
) -> None:
    print("\n=== regular v2: encrypted add_stake ===")
    before_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address)
    before_cold_free = free_balance(substrate, stake_cold.ss58_address)
    inner_bytes, inner_hex = build_inner_add_stake(
        substrate,
        stake_cold,
        stake_hot.ss58_address,
        netuid,
        amount,
        label="add_stake",
    )
    print(f"[i] before: alpha={before_alpha}, cold_free={before_cold_free}")

    receipt, target, key = submit_rebuilding_envelope(
        substrate,
        outer,
        lambda: build_submit_encrypted_for_fresh_target(
            substrate,
            mev_pallet,
            helper,
            genesis_hash,
            inner_bytes,
            allow_dev_storage,
        ),
        drive_signer=sudo,
    )
    submit_block = block_number(substrate, receipt.block_hash)
    if inner_hex.lower() in block_extrinsic_hexes(substrate, receipt.block_hash):
        raise AssertionError(f"plain inner add_stake extrinsic appeared in submit block #{submit_block}")
    submit_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address, receipt.block_hash)
    if submit_alpha != before_alpha:
        raise AssertionError(
            f"add_stake executed in submit block before reveal: before={before_alpha}, submit={submit_alpha}"
        )

    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        staging_receipt = install_dev_block_key(substrate, mev_pallet, helper, genesis_hash, sudo, key, target)
        staging_block = block_number(substrate, staging_receipt.block_hash)
        staging_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address, staging_receipt.block_hash)
        if staging_block < target and staging_alpha != before_alpha:
            raise AssertionError(
                f"add_stake executed at staging block #{staging_block} before target #{target}: "
                f"before={before_alpha}, staging={staging_alpha}"
            )

    wait_until_block(substrate, target, timeout_s=timeout, poll_s=poll, drive_signer=sudo)
    event_reveal = wait_for_shield_success_event(
        substrate,
        target,
        "IbeEncryptedExtrinsicExecuted",
        "regular encrypted add_stake",
        timeout_s=max(5, timeout // 2),
        poll_s=poll,
        drive_signer=sudo,
    )
    reveal_block, after_alpha = wait_hotkey_alpha_increase(
        substrate,
        netuid,
        stake_hot.ss58_address,
        before_alpha,
        timeout_s=timeout,
        poll_s=poll,
        drive_signer=sudo,
    )
    if event_reveal is not None:
        reveal_block = max(reveal_block, event_reveal)
    after_cold_free = free_balance(substrate, stake_cold.ss58_address)
    if reveal_block < target:
        raise AssertionError(f"add_stake executed before target: reveal=#{reveal_block}, target=#{target}")
    if after_cold_free >= before_cold_free:
        raise AssertionError(
            f"add_stake alpha increased but cold free balance did not decrease: "
            f"before={before_cold_free}, after={after_cold_free}"
        )
    assert_inner_absent(substrate, inner_hex, submit_block, reveal_block)
    print(
        f"[✓] encrypted add_stake: netuid={netuid}, submit=#{submit_block}, "
        f"target=#{target}, reveal=#{reveal_block}, alpha={before_alpha}->{after_alpha}, "
        f"cold_free={before_cold_free}->{after_cold_free}"
    )


def run_submit_encrypted_complex_batch(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    outer: Keypair,
    stake_cold: Keypair,
    stake_hot: Keypair,
    transfer_probe: Keypair,
    netuid: int,
    stake_amount: int,
    transfer_amount: int,
    timeout: int,
    poll: float,
    allow_dev_storage: bool,
    sudo: Keypair,
) -> None:
    print("\n=== regular v2: complex encrypted inner batch ===")
    before_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address)
    before_cold_free = free_balance(substrate, stake_cold.ss58_address)
    before_probe_free = free_balance(substrate, transfer_probe.ss58_address)
    inner_bytes, inner_hex, batch_name = build_inner_batch_transfer_and_add_stake(
        substrate,
        stake_cold,
        stake_hot.ss58_address,
        netuid,
        stake_amount,
        transfer_probe.ss58_address,
        transfer_amount,
    )
    print(
        f"[i] before: alpha={before_alpha}, cold_free={before_cold_free}, "
        f"probe_free={before_probe_free}, batch={batch_name}"
    )

    receipt, target, key = submit_rebuilding_envelope(
        substrate,
        outer,
        lambda: build_submit_encrypted_for_fresh_target(
            substrate,
            mev_pallet,
            helper,
            genesis_hash,
            inner_bytes,
            allow_dev_storage,
        ),
        drive_signer=sudo,
    )
    submit_block = block_number(substrate, receipt.block_hash)
    if inner_hex.lower() in block_extrinsic_hexes(substrate, receipt.block_hash):
        raise AssertionError(f"plain inner batch extrinsic appeared in submit block #{submit_block}")
    submit_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address, receipt.block_hash)
    submit_probe_free = free_balance_at(substrate, transfer_probe.ss58_address, receipt.block_hash)
    if submit_alpha != before_alpha or submit_probe_free != before_probe_free:
        raise AssertionError(
            "complex batch executed in submit block before reveal: "
            f"alpha {before_alpha}->{submit_alpha}, probe {before_probe_free}->{submit_probe_free}"
        )

    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        staging_receipt = install_dev_block_key(substrate, mev_pallet, helper, genesis_hash, sudo, key, target)
        staging_block = block_number(substrate, staging_receipt.block_hash)
        staging_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address, staging_receipt.block_hash)
        staging_probe_free = free_balance_at(substrate, transfer_probe.ss58_address, staging_receipt.block_hash)
        if staging_block < target and (staging_alpha != before_alpha or staging_probe_free != before_probe_free):
            raise AssertionError(
                f"complex batch executed at staging block #{staging_block} before target #{target}: "
                f"alpha {before_alpha}->{staging_alpha}, probe {before_probe_free}->{staging_probe_free}"
            )

    wait_until_block(substrate, target, timeout_s=timeout, poll_s=poll, drive_signer=sudo)
    event_reveal = wait_for_shield_success_event(
        substrate,
        target,
        "IbeEncryptedExtrinsicExecuted",
        "complex encrypted inner batch",
        timeout_s=max(5, timeout // 2),
        poll_s=poll,
        drive_signer=sudo,
    )
    reveal_block, after_alpha = wait_hotkey_alpha_increase(
        substrate,
        netuid,
        stake_hot.ss58_address,
        before_alpha,
        timeout_s=timeout,
        poll_s=poll,
        drive_signer=sudo,
    )
    wait_balance(
        substrate,
        transfer_probe.ss58_address,
        before_probe_free + transfer_amount,
        timeout_s=timeout,
        poll_s=poll,
        drive_signer=sudo,
    )
    if event_reveal is not None:
        reveal_block = max(reveal_block, event_reveal)
    after_cold_free = free_balance(substrate, stake_cold.ss58_address)
    after_probe_free = free_balance(substrate, transfer_probe.ss58_address)
    if reveal_block < target:
        raise AssertionError(f"complex batch executed before target: reveal=#{reveal_block}, target=#{target}")
    if after_probe_free < before_probe_free + transfer_amount:
        raise AssertionError(
            f"complex batch did not transfer to probe: before={before_probe_free}, after={after_probe_free}, "
            f"expected at least {before_probe_free + transfer_amount}"
        )
    if after_cold_free >= before_cold_free:
        raise AssertionError(
            f"complex batch alpha/probe changed but cold free did not decrease: "
            f"before={before_cold_free}, after={after_cold_free}"
        )
    assert_inner_absent(substrate, inner_hex, submit_block, reveal_block)
    print(
        f"[✓] complex encrypted batch: submit=#{submit_block}, target=#{target}, reveal=#{reveal_block}, "
        f"alpha={before_alpha}->{after_alpha}, probe={before_probe_free}->{after_probe_free}, "
        f"cold_free={before_cold_free}->{after_cold_free}"
    )


def run_invalid_inner_add_stake_failure(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    outer: Keypair,
    stake_cold: Keypair,
    stake_hot: Keypair,
    netuid: int,
    timeout: int,
    poll: float,
    allow_dev_storage: bool,
    sudo: Keypair,
) -> None:
    print("\n=== regular v2: decrypted inner failure ===")
    before_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address)
    before_cold_free = free_balance(substrate, stake_cold.ss58_address)
    bad_amount = min((1 << 64) - 1, before_cold_free + max(before_cold_free // 5, 1_000_000_000))
    inner_bytes, inner_hex = build_inner_add_stake(
        substrate,
        stake_cold,
        stake_hot.ss58_address,
        netuid,
        bad_amount,
        label="add_stake overdraw (expected failure)",
    )
    print(f"[i] before: alpha={before_alpha}, cold_free={before_cold_free}, bad_amount={bad_amount}")

    receipt, target, key = submit_rebuilding_envelope(
        substrate,
        outer,
        lambda: build_submit_encrypted_for_fresh_target(
            substrate,
            mev_pallet,
            helper,
            genesis_hash,
            inner_bytes,
            allow_dev_storage,
        ),
        drive_signer=sudo,
    )
    submit_block = block_number(substrate, receipt.block_hash)
    if inner_hex.lower() in block_extrinsic_hexes(substrate, receipt.block_hash):
        raise AssertionError(f"plain invalid inner add_stake appeared in submit block #{submit_block}")

    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        install_dev_block_key(substrate, mev_pallet, helper, genesis_hash, sudo, key, target)

    wait_until_block(substrate, target, timeout_s=timeout, poll_s=poll, drive_signer=sudo)
    reveal_block = wait_for_shield_status_event(
        substrate,
        target,
        "IbeEncryptedExtrinsicExecuted",
        False,
        "invalid inner add_stake",
        timeout_s=max(5, timeout // 2),
        poll_s=poll,
        drive_signer=sudo,
    )
    after_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address)
    if after_alpha != before_alpha:
        raise AssertionError(f"invalid add_stake mutated alpha: before={before_alpha}, after={after_alpha}")
    if not shield_event_present_in_block(substrate, reveal_block, "IbeSubmissionDepositForfeited"):
        raise AssertionError(
            "invalid inner execution reported success=false but did not emit "
            f"IbeSubmissionDepositForfeited in reveal block #{reveal_block}.\n"
            f"{summarize_relevant_events(substrate, reveal_block)}"
        )
    wait_until_block(substrate, reveal_block + 1, timeout_s=timeout, poll_s=poll, drive_signer=sudo)
    assert_inner_absent(substrate, inner_hex, submit_block, reveal_block)
    print(
        f"[✓] invalid inner add_stake failed safely: submit=#{submit_block}, "
        f"target=#{target}, reveal=#{reveal_block}, alpha stayed {after_alpha}"
    )


def run_submit_conditional(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    outer: Keypair,
    stake_cold: Keypair,
    stake_hot: Keypair,
    netuid: int,
    amount: int,
    delay: int,
    lifetime: int,
    timeout: int,
    poll: float,
    allow_dev_storage: bool,
    sudo: Keypair,
    label: str,
    min_blocks_after_submit: Optional[int] = None,
) -> None:
    print(f"\n=== conditional v2: {label} ===")
    before_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address)
    before_cold_free = free_balance(substrate, stake_cold.ss58_address)
    inner_bytes, inner_hex = build_inner_add_stake(
        substrate,
        stake_cold,
        stake_hot.ss58_address,
        netuid,
        amount,
        label=f"conditional add_stake ({label})",
    )
    print(f"[i] before: alpha={before_alpha}, cold_free={before_cold_free}, requested_delay={delay}")

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
            allow_dev_storage,
        ),
        drive_signer=sudo,
    )
    submit_block = block_number(substrate, receipt.block_hash)
    if min_blocks_after_submit is not None and target - submit_block < int(min_blocks_after_submit):
        raise AssertionError(
            f"conditional AtBlock was not far enough: submit=#{submit_block}, "
            f"target=#{target}, gap={target - submit_block}, expected>={min_blocks_after_submit}"
        )
    if inner_hex.lower() in block_extrinsic_hexes(substrate, receipt.block_hash):
        raise AssertionError(f"plain inner add_stake extrinsic appeared in submit block #{submit_block}")
    submit_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address, receipt.block_hash)
    if submit_alpha != before_alpha:
        raise AssertionError(
            f"conditional add_stake executed in submit block before AtBlock: before={before_alpha}, submit={submit_alpha}"
        )

    if allow_dev_storage and is_dev_epoch_key(genesis_hash, key):
        staging_receipt = install_dev_block_key(substrate, mev_pallet, helper, genesis_hash, sudo, key, target)
        staging_block = block_number(substrate, staging_receipt.block_hash)
        staging_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address, staging_receipt.block_hash)
        if staging_block < target and staging_alpha != before_alpha:
            raise AssertionError(
                f"conditional add_stake executed at staging block #{staging_block} before AtBlock #{target}: "
                f"before={before_alpha}, staging={staging_alpha}"
            )
        if staging_block < target:
            print(f"[i] AtBlock guard held through staging block #{staging_block}; target=#{target}")

    now = block_number(substrate, chain_head(substrate))
    if now < target and total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address) != before_alpha:
        raise AssertionError(f"conditional add_stake executed before AtBlock: now=#{now}, target=#{target}")

    wait_until_block(substrate, target, timeout_s=timeout, poll_s=poll, drive_signer=sudo)
    event_reveal = wait_for_shield_success_event(
        substrate,
        target,
        "ConditionalIbeExecuted",
        f"conditional add_stake {label}",
        timeout_s=max(5, timeout // 2),
        poll_s=poll,
        drive_signer=sudo,
    )
    reveal_block, after_alpha = wait_hotkey_alpha_increase(
        substrate,
        netuid,
        stake_hot.ss58_address,
        before_alpha,
        timeout_s=timeout,
        poll_s=poll,
        drive_signer=sudo,
    )
    if event_reveal is not None:
        reveal_block = max(reveal_block, event_reveal)
    after_cold_free = free_balance(substrate, stake_cold.ss58_address)
    if reveal_block < target:
        raise AssertionError(f"conditional add_stake executed before AtBlock: reveal=#{reveal_block}, target=#{target}")
    if after_cold_free >= before_cold_free:
        raise AssertionError(
            f"conditional add_stake alpha increased but cold free balance did not decrease: "
            f"before={before_cold_free}, after={after_cold_free}"
        )
    assert_inner_absent(substrate, inner_hex, submit_block, reveal_block)
    print(
        f"[✓] conditional add_stake ({label}): netuid={netuid}, submit=#{submit_block}, "
        f"AtBlock=#{target}, reveal=#{reveal_block}, alpha={before_alpha}->{after_alpha}, "
        f"cold_free={before_cold_free}->{after_cold_free}"
    )


def run_missing_block_key_no_brick(
    substrate: SubstrateInterface,
    mev_pallet: str,
    helper: Path,
    genesis_hash: str,
    outer: Keypair,
    stake_cold: Keypair,
    stake_hot: Keypair,
    netuid: int,
    amount: int,
    timeout: int,
    poll: float,
    allow_dev_storage: bool,
    sudo: Keypair,
) -> None:
    print("\n=== no-brick: missing dev block key ===")
    head = block_number(substrate, chain_head(substrate))
    target, key = choose_submit_encrypted_target(substrate, mev_pallet, genesis_hash, allow_dev_storage=True)
    if not (allow_dev_storage and is_dev_epoch_key(genesis_hash, key)):
        print("[i] missing-key no-brick test skipped: active IBE key is not the deterministic dev key")
        return

    before_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address)
    inner_bytes, inner_hex = build_inner_add_stake(
        substrate,
        stake_cold,
        stake_hot.ss58_address,
        netuid,
        amount,
        label="add_stake without staged block key (expected abort)",
    )
    # Build the envelope explicitly for the target chosen above and deliberately
    # do not call install_dev_block_key(). This tests the runtime no-brick path.
    envelope = encrypt_envelope(helper, genesis_hash, key, target, inner_bytes)
    call = submit_encrypted_call(substrate, mev_pallet, envelope)
    print(f"[i] before: head=#{head}, target=#{target}, alpha={before_alpha}; intentionally not staging block key")
    receipt = submit_signed_once(
        substrate,
        outer,
        call,
        era_period=SHIELD_OUTER_ERA_PERIOD,
        require_success=True,
    )
    submit_block = block_number(substrate, receipt.block_hash)
    if inner_hex.lower() in block_extrinsic_hexes(substrate, receipt.block_hash):
        raise AssertionError(f"plain missing-key inner appeared in submit block #{submit_block}")

    wait_until_block(substrate, target, timeout_s=timeout, poll_s=poll, drive_signer=sudo)
    abort_block = wait_for_shield_event_present(
        substrate,
        target,
        "IbeBlockKeyUnavailable",
        "missing-key-abort",
        timeout_s=max(10, timeout // 2),
        poll_s=poll,
        drive_signer=sudo,
    )
    if abort_block is None:
        # Older no-brick patches may only expose the generic success=false event.
        abort_block = wait_for_shield_status_event(
            substrate,
            target,
            "IbeEncryptedExtrinsicExecuted",
            False,
            "missing-key-abort",
            timeout_s=max(10, timeout // 2),
            poll_s=poll,
            drive_signer=sudo,
        )
    after_alpha = total_hotkey_alpha(substrate, netuid, stake_hot.ss58_address)
    if after_alpha != before_alpha:
        raise AssertionError(f"missing-key abort mutated alpha: before={before_alpha}, after={after_alpha}")
    wait_until_block(substrate, abort_block + 1, timeout_s=timeout, poll_s=poll, drive_signer=sudo)
    assert_inner_absent(substrate, inner_hex, submit_block, abort_block)
    print(
        f"[✓] missing block key aborted without bricking: submit=#{submit_block}, "
        f"target=#{target}, abort=#{abort_block}, alpha stayed {after_alpha}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ws", default="ws://127.0.0.1:9945")
    parser.add_argument("--outer-uri", default="//Eve")
    parser.add_argument("--stake-cold-uri", default=None, help="coldkey for the first scratch subnet + encrypted add_stake; defaults to a unique //Alice-derived key")
    parser.add_argument("--stake-hot-uri", default=None, help="hotkey registered on the first scratch subnet; defaults to a unique //Alice-derived key")
    parser.add_argument("--regular-probe-uri", default=None, help="recipient used by the complex encrypted Utility.batch_all transfer test")
    parser.add_argument("--conditional-stake-cold-uri", default=None, help="coldkey for the conditional scratch subnet + encrypted add_stake; defaults to a unique //Alice-derived key")
    parser.add_argument("--conditional-stake-hot-uri", default=None, help="hotkey registered on the conditional scratch subnet; defaults to a unique //Alice-derived key")
    parser.add_argument("--scratch-tag", default=None, help="stable tag for deterministic default scratch keys; omitted means genesis/time based")
    parser.add_argument("--verbose", action="store_true", help="print skipped metadata fallbacks and scratch key URIs")
    parser.add_argument("--faucet-uri", default="//Alice")
    parser.add_argument("--stake-tao", type=float, default=0.1)
    parser.add_argument("--complex-stake-tao", type=float, default=0.2)
    parser.add_argument("--complex-transfer-tao", type=float, default=0.01)
    parser.add_argument("--subnet-owner-min-tao", type=float, default=50_000.0)
    parser.add_argument("--subnet-owner-hot-min-tao", type=float, default=5.0)
    parser.add_argument("--conditional-delay", type=int, default=4)
    parser.add_argument("--far-conditional-delay", type=int, default=12)
    parser.add_argument("--conditional-lifetime", type=int, default=32)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--poll", type=float, default=0.8)
    parser.add_argument(
        "--no-dev-bootstrap",
        action="store_true",
        help="do not install dev IBE epoch/block keys if live DKG keys are missing",
    )
    parser.add_argument("--skip-invalid-inner-test", action="store_true")
    parser.add_argument("--skip-missing-key-test", action="store_true")
    parser.add_argument("--basic-only", action="store_true", help="run only the original two green-path add_stake tests")
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="verify this script embeds the fixed helper and exit",
    )
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = bool(args.verbose)

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

    scratch_tag = args.scratch_tag or f"{strip_0x(genesis_hash)[:8]}-{int(time.time())}"
    stake_cold_uri = args.stake_cold_uri or f"//Alice//ShieldV2AddStakeCold//{scratch_tag}//regular"
    stake_hot_uri = args.stake_hot_uri or f"//Alice//ShieldV2AddStakeHot//{scratch_tag}//regular"
    regular_probe_uri = args.regular_probe_uri or f"//Alice//ShieldV2AddStakeProbe//{scratch_tag}//regular"
    conditional_stake_cold_uri = (
        args.conditional_stake_cold_uri
        or f"//Alice//ShieldV2AddStakeCold//{scratch_tag}//conditional"
    )
    conditional_stake_hot_uri = (
        args.conditional_stake_hot_uri
        or f"//Alice//ShieldV2AddStakeHot//{scratch_tag}//conditional"
    )

    outer = Keypair.create_from_uri(args.outer_uri)
    stake_cold = Keypair.create_from_uri(stake_cold_uri)
    stake_hot = Keypair.create_from_uri(stake_hot_uri)
    regular_probe = Keypair.create_from_uri(regular_probe_uri)
    conditional_stake_cold = Keypair.create_from_uri(conditional_stake_cold_uri)
    conditional_stake_hot = Keypair.create_from_uri(conditional_stake_hot_uri)
    faucet = Keypair.create_from_uri(args.faucet_uri)

    print(f"[i] scratch tag={scratch_tag}")
    logv(f"[i] regular stake cold uri={stake_cold_uri}, hot uri={stake_hot_uri}, probe uri={regular_probe_uri}")
    logv(f"[i] conditional stake cold uri={conditional_stake_cold_uri}, hot uri={conditional_stake_hot_uri}")

    amount = to_planck(args.stake_tao, decimals)
    complex_amount = to_planck(args.complex_stake_tao, decimals)
    complex_transfer_amount = to_planck(args.complex_transfer_tao, decimals)
    owner_min = to_planck(args.subnet_owner_min_tao, decimals)
    owner_hot_min = to_planck(args.subnet_owner_hot_min_tao, decimals)
    stake_funds_min = max(owner_min, (amount * 8) + (complex_amount * 4) + complex_transfer_amount + to_planck(25, decimals))
    print(
        f"[i] genesis={genesis_hash[:10]}… decimals={decimals} "
        f"stake={amount} complex_stake={complex_amount} transfer={complex_transfer_amount} planck"
    )

    ensure_funded(substrate, faucet, outer, to_planck(10, decimals), "outer signer")

    netuid = ensure_scratch_subnet(
        substrate=substrate,
        sudo=faucet,
        owner_cold=stake_cold,
        owner_hot=stake_hot,
        decimals=decimals,
        label="regular",
        min_owner_cold=owner_min,
        min_owner_hot=owner_hot_min,
        min_stake_funds=stake_funds_min,
    )
    conditional_netuid = ensure_scratch_subnet(
        substrate=substrate,
        sudo=faucet,
        owner_cold=conditional_stake_cold,
        owner_hot=conditional_stake_hot,
        decimals=decimals,
        label="conditional",
        min_owner_cold=owner_min,
        min_owner_hot=owner_hot_min,
        min_stake_funds=stake_funds_min,
    )

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

    # Even if the dev epoch was installed by a previous script run, keep dev
    # block-key installation enabled whenever the active key is the deterministic dev key.
    allow_dev_storage = not args.no_dev_bootstrap or installed_dev_epoch

    run_submit_encrypted(
        substrate=substrate,
        mev_pallet=mev_pallet,
        helper=helper,
        genesis_hash=genesis_hash,
        outer=outer,
        stake_cold=stake_cold,
        stake_hot=stake_hot,
        netuid=netuid,
        amount=amount,
        timeout=args.timeout,
        poll=args.poll,
        allow_dev_storage=allow_dev_storage,
        sudo=faucet,
    )

    if not args.basic_only:
        run_submit_encrypted_complex_batch(
            substrate=substrate,
            mev_pallet=mev_pallet,
            helper=helper,
            genesis_hash=genesis_hash,
            outer=outer,
            stake_cold=stake_cold,
            stake_hot=stake_hot,
            transfer_probe=regular_probe,
            netuid=netuid,
            stake_amount=complex_amount,
            transfer_amount=complex_transfer_amount,
            timeout=args.timeout,
            poll=args.poll,
            allow_dev_storage=allow_dev_storage,
            sudo=faucet,
        )

        if not args.skip_invalid_inner_test:
            run_invalid_inner_add_stake_failure(
                substrate=substrate,
                mev_pallet=mev_pallet,
                helper=helper,
                genesis_hash=genesis_hash,
                outer=outer,
                stake_cold=stake_cold,
                stake_hot=stake_hot,
                netuid=netuid,
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
        stake_cold=conditional_stake_cold,
        stake_hot=conditional_stake_hot,
        netuid=conditional_netuid,
        amount=amount,
        delay=args.conditional_delay,
        lifetime=args.conditional_lifetime,
        timeout=args.timeout,
        poll=args.poll,
        allow_dev_storage=allow_dev_storage,
        sudo=faucet,
        label="near AtBlock",
    )

    if not args.basic_only:
        far_gap = max(4, int(args.far_conditional_delay) - 2)
        run_submit_conditional(
            substrate=substrate,
            mev_pallet=mev_pallet,
            helper=helper,
            genesis_hash=genesis_hash,
            outer=outer,
            stake_cold=conditional_stake_cold,
            stake_hot=conditional_stake_hot,
            netuid=conditional_netuid,
            amount=amount,
            delay=args.far_conditional_delay,
            lifetime=max(args.conditional_lifetime, args.far_conditional_delay + 8),
            timeout=args.timeout,
            poll=args.poll,
            allow_dev_storage=allow_dev_storage,
            sudo=faucet,
            label="far AtBlock",
            min_blocks_after_submit=far_gap,
        )

        if not args.skip_missing_key_test:
            run_missing_block_key_no_brick(
                substrate=substrate,
                mev_pallet=mev_pallet,
                helper=helper,
                genesis_hash=genesis_hash,
                outer=outer,
                stake_cold=stake_cold,
                stake_hot=stake_hot,
                netuid=netuid,
                amount=amount,
                timeout=args.timeout,
                poll=args.poll,
                allow_dev_storage=allow_dev_storage,
                sudo=faucet,
            )

    print("\n✅ PASS: Shield v2 expanded encrypted add_stake suite passed.")
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
