use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{RsaPublicKey, decrypt_into, parse_pem_public_key};
use std::slice;

#[repr(C)]
pub enum Bhderr {
    Ok = 0,
    InvalidArg = 1,
    KeyParse = 2,
    Utf8 = 3,
    OutputTooSmall = 4,
    Internal = 5,
}

/// # Safety
///
/// * `pem_ptr` must point to a valid allocation of at least `pem_len` bytes.
/// * `out_key` must be a valid pointer to receive the key handle.
/// * **Ownership:** The caller owns the output handle and MUST free it using `bhd_key_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhd_key_new(
    pem_ptr: *const u8,
    pem_len: usize,
    out_key: *mut *mut RsaPublicKey,
) -> i32 {
    if pem_ptr.is_null() || out_key.is_null() {
        return Bhderr::InvalidArg as i32;
    }

    let pem_bytes = unsafe { slice::from_raw_parts(pem_ptr, pem_len) };

    let pem_str = match std::str::from_utf8(pem_bytes) {
        Ok(s) => s,
        Err(_) => return Bhderr::Utf8 as i32,
    };

    match parse_pem_public_key(pem_str) {
        Ok(key) => {
            unsafe { *out_key = Box::into_raw(Box::new(key)) };
            Bhderr::Ok as i32
        }
        Err(_) => Bhderr::KeyParse as i32,
    }
}

/// # Safety
///
/// * `key_ptr` must be a valid pointer obtained from `bhd_key_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhd_key_free(key_ptr: *mut RsaPublicKey) {
    if !key_ptr.is_null() {
        let x = unsafe { Box::from_raw(key_ptr) };
        drop(x);
    }
}

/// # Safety
///
/// * `key_ptr` must be a valid, non-null pointer to an `RsaPublicKey`.
/// * `out_size` must be a valid pointer to receive the size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhd_get_size(
    key_ptr: *const RsaPublicKey,
    encrypted_len: usize,
    out_size: *mut usize,
) -> i32 {
    if key_ptr.is_null() || out_size.is_null() {
        return Bhderr::InvalidArg as i32;
    }

    let key = unsafe { &*key_ptr };
    let size = if encrypted_len < key.size {
        encrypted_len
    } else {
        encrypted_len.div_ceil(key.size) * (key.size - 1)
    };

    unsafe { *out_size = size };
    Bhderr::Ok as i32
}

/// # Safety
///
/// * `key_ptr` must be a valid pointer to an `RsaPublicKey`.
/// * `data_ptr` must point to at least `data_len` valid bytes.
/// * `out_ptr` must point to a writable buffer of at least `out_cap` bytes.
/// * `out_written` must be a valid pointer to receive the bytes written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhd_decrypt(
    key_ptr: *const RsaPublicKey,
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    if key_ptr.is_null()
        || out_written.is_null()
        || (data_len > 0 && data_ptr.is_null())
        || (out_cap > 0 && out_ptr.is_null())
    {
        return Bhderr::InvalidArg as i32;
    }

    let key = unsafe { &*key_ptr };
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };

    let required_size = if data_len < key.size {
        data_len
    } else {
        data_len.div_ceil(key.size) * (key.size - 1)
    };

    if out_cap < required_size {
        return Bhderr::OutputTooSmall as i32;
    }

    if required_size == 0 {
        unsafe { *out_written = 0 };
        return Bhderr::Ok as i32;
    }

    let out_slice = unsafe { slice::from_raw_parts_mut(out_ptr, required_size) };

    if data_len < key.size {
        out_slice.copy_from_slice(data);
        unsafe { *out_written = data_len };
        return Bhderr::Ok as i32;
    }

    run_decryption(data, out_slice, key, key.size, key.size - 1);

    unsafe { *out_written = required_size };
    Bhderr::Ok as i32
}

fn run_decryption(
    data: &[u8],
    result: &mut [u8],
    pub_key: &RsaPublicKey,
    in_size: usize,
    out_size: usize,
) {
    let n = &pub_key.n;
    let e = &pub_key.e;

    let in_chunk_iter = data.par_chunks_exact(in_size);
    let remainder = in_chunk_iter.remainder();

    in_chunk_iter
        .zip(result.par_chunks_exact_mut(out_size))
        .for_each(|(in_chunk, out_chunk)| {
            decrypt_into(in_chunk, n, e, out_chunk);
        });

    if !remainder.is_empty()
        && let Some(last_out_chunk) = result.chunks_mut(out_size).last()
    {
        let mut padded_block = Vec::with_capacity(in_size);
        padded_block.extend_from_slice(remainder);
        padded_block.resize(in_size, 0);

        decrypt_into(&padded_block, n, e, last_out_chunk);
    }
}
