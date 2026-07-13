#![allow(clippy::missing_safety_doc)]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;
use zeroize::Zeroize;

const MODULUS_LENGTH: usize = 4096;

#[repr(C)]
pub enum RsaErrorCode {
    Success = 0,
    InvalidSeed = 1,
    GenerationFailed = 2,
    InvalidOutput = 3,
}

#[repr(C)]
pub struct RsaResult {
    pub error_code: c_uint,
    pub error_message: *mut c_char,
    pub p_bytes: *mut u8,
    pub q_bytes: *mut u8,
    pub p_len: usize,
    pub q_len: usize,
}

impl RsaResult {
    fn success(p: Vec<u8>, q: Vec<u8>) -> Self {
        let p_len = p.len();
        let q_len = q.len();
        let p_ptr = Box::into_raw(p.into_boxed_slice()) as *mut u8;
        let q_ptr = Box::into_raw(q.into_boxed_slice()) as *mut u8;

        Self {
            error_code: RsaErrorCode::Success as c_uint,
            error_message: ptr::null_mut(),
            p_bytes: p_ptr,
            q_bytes: q_ptr,
            p_len,
            q_len,
        }
    }

    fn error(code: RsaErrorCode, message: &str) -> Self {
        let c_msg = CString::new(message).unwrap_or_else(|_| CString::new("Unknown error").unwrap());
        Self {
            error_code: code as c_uint,
            error_message: c_msg.into_raw(),
            p_bytes: ptr::null_mut(),
            q_bytes: ptr::null_mut(),
            p_len: 0,
            q_len: 0,
        }
    }
}

fn is_all_zero_or_ff(seed: &[u8]) -> bool {
    seed.iter().all(|byte| *byte == 0) || seed.iter().all(|byte| *byte == 0xff)
}

fn rsa_seed(seed: &[u8]) -> Result<[u8; 32], String> {
    let mut intermediate;
    let mut hash = seed;
    for _ in 0..2 {
        intermediate = Sha256::digest(hash);
        hash = &intermediate[..];
    }
    hash.try_into()
        .map_err(|_| "failed to derive RSA seed".to_string())
}

fn generate_rsa_primes(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if is_all_zero_or_ff(seed) {
        return Err("invalid seed".to_string());
    }

    let seed_len = seed.len();
    if !matches!(seed_len, 16 | 32 | 64) {
        return Err(format!(
            "invalid seed length: {seed_len}, expected 16, 32, or 64 bytes"
        ));
    }

    let mut derived_seed = rsa_seed(seed)?;
    let mut rng = ChaCha20Rng::from_seed(derived_seed);
    derived_seed.zeroize();

    let private_key = RsaPrivateKey::new(&mut rng, MODULUS_LENGTH)
        .map_err(|error| format!("generate rsa private key failed: {error}"))?;
    let primes = private_key.primes();
    if primes.len() < 2 {
        return Err("invalid RSA key: less than 2 primes".to_string());
    }

    Ok((primes[0].to_bytes_be(), primes[1].to_bytes_be()))
}

#[no_mangle]
pub unsafe extern "C" fn generate_rsa_primes_from_seed(
    seed: *const u8,
    seed_len: usize,
) -> RsaResult {
    if seed.is_null() || seed_len == 0 {
        return RsaResult::error(RsaErrorCode::InvalidSeed, "invalid seed: null pointer or zero length");
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    match generate_rsa_primes(seed_slice) {
        Ok((p, q)) => RsaResult::success(p, q),
        Err(error) if error.contains("seed") => RsaResult::error(RsaErrorCode::InvalidSeed, &error),
        Err(error) => RsaResult::error(RsaErrorCode::GenerationFailed, &error),
    }
}

#[no_mangle]
pub unsafe extern "C" fn free_rsa_result(result: *mut RsaResult) {
    if result.is_null() {
        return;
    }

    let result = &*result;

    if !result.error_message.is_null() {
        let _ = CString::from_raw(result.error_message);
    }

    if !result.p_bytes.is_null() && result.p_len > 0 {
        let p_slice_ptr: *mut [u8] = ptr::slice_from_raw_parts_mut(result.p_bytes, result.p_len);
        let _ = Box::from_raw(p_slice_ptr);
    }

    if !result.q_bytes.is_null() && result.q_len > 0 {
        let q_slice_ptr: *mut [u8] = ptr::slice_from_raw_parts_mut(result.q_bytes, result.q_len);
        let _ = Box::from_raw(q_slice_ptr);
    }
}
