// mlkemffi/src/lib.rs

#![no_std]

use core::slice;
use libc::c_int;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};

use ml_kem::{Encoded, MlKem768Params};
use ml_kem::kem::{EncapsulationKey, Encapsulate};
use ml_kem::EncodedSizeUser;

const NONCE_LEN: usize = 24;

/// Use the ML‑KEM shared secret directly as the AEAD key.
///
/// Canonical "v1" KDF:
///   AEAD key = shared_secret (32 bytes), no HKDF / hashing.
fn derive_aead_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    *shared_secret
}

/// Optional probe so the Python side can verify which KDF this .so uses.
///
/// Returns the ASCII string "v1" on success, meaning:
///   - key = raw ML‑KEM shared secret (32 bytes)
///   - aad = [] (empty)
#[no_mangle]
pub extern "C" fn mlkemffi_kdf_id(out_ptr: *mut u8, out_len: usize) -> c_int {
    if out_ptr.is_null() || out_len == 0 {
        return -1;
    }
    let label = b"v1";
    let n = label.len().min(out_len);

    // SAFETY: caller guarantees out_ptr points to at least out_len bytes.
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, out_len) };
    out[..n].copy_from_slice(&label[..n]);
    n as c_int
}

/// Encrypt `plaintext` to `pk` using ML‑KEM‑768 + XChaCha20Poly1305.
///
/// Blob layout:
///   [u16 kem_len LE][kem_ct (kem_len bytes)][nonce24][aead_ct]
///
/// AEAD parameters:
///   • key = shared_secret (32 bytes, from ML‑KEM), no HKDF
///   • nonce = 24 random bytes
///   • aad = [] (empty)
#[no_mangle]
pub extern "C" fn mlkem768_seal_blob(
    pk_ptr: *const u8,
    pk_len: usize,
    pt_ptr: *const u8,
    pt_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
    written_out: *mut usize,
) -> c_int {
    if pk_ptr.is_null() || pt_ptr.is_null() || out_ptr.is_null() || written_out.is_null() {
        return -1;
    }

    // SAFETY: caller guarantees these pointers and lengths are valid.
    let pk_bytes = unsafe { slice::from_raw_parts(pk_ptr, pk_len) };
    let pt_bytes = unsafe { slice::from_raw_parts(pt_ptr, pt_len) };
    let out_buf  = unsafe { slice::from_raw_parts_mut(out_ptr, out_len) };

    // 1) Rebuild EncapsulationKey from raw bytes
    let enc_pk = match Encoded::<EncapsulationKey<MlKem768Params>>::try_from(pk_bytes) {
        Ok(e) => e,
        Err(_) => return -2,
    };
    let pk = EncapsulationKey::<MlKem768Params>::from_bytes(&enc_pk);

    // 2) Encapsulate
    let (ct, ss) = match pk.encapsulate(&mut OsRng) {
        Ok((ct, ss)) => (ct, ss),
        Err(_) => return -3,
    };

    let kem_ct_bytes: &[u8] = ct.as_ref();
    let kem_ct_len = kem_ct_bytes.len();
    if kem_ct_len > u16::MAX as usize {
        return -4;
    }

    let ss_bytes: &[u8] = ss.as_ref();
    if ss_bytes.len() != 32 {
        return -5;
    }
    let mut ss32 = [0u8; 32];
    ss32.copy_from_slice(ss_bytes);

    // AEAD key = shared secret (no HKDF, no hashing)
    let aead_key = derive_aead_key(&ss32);

    // 3) AEAD encrypt plaintext with XChaCha20-Poly1305, AAD = [].
    let aead = XChaCha20Poly1305::new((&aead_key).into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let nonce_x = XNonce::from_slice(&nonce);
    let aead_ct = match aead.encrypt(nonce_x, Payload { msg: pt_bytes, aad: &[] }) {
        Ok(ct) => ct,
        Err(_) => return -6,
    };

    // 4) Output: [u16 kem_len][kem_ct][nonce24][aead_ct]
    let total_len = 2 + kem_ct_len + NONCE_LEN + aead_ct.len();
    if total_len > out_len {
        return -7;
    }

    out_buf[0..2].copy_from_slice(&(kem_ct_len as u16).to_le_bytes());
    out_buf[2..2 + kem_ct_len].copy_from_slice(kem_ct_bytes);

    let nonce_start = 2 + kem_ct_len;
    out_buf[nonce_start..nonce_start + NONCE_LEN].copy_from_slice(&nonce);

    let aead_start = nonce_start + NONCE_LEN;
    out_buf[aead_start..aead_start + aead_ct.len()].copy_from_slice(&aead_ct);

    unsafe { *written_out = total_len; }
    0
}
