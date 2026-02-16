use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{RsaPublicKey, decrypt_into, parse_pem_public_key};
use std::slice;

/// # Safety
///
/// * `pem_ptr` must point to a valid allocation of at least `pem_len` bytes.
/// * The memory pointed to by `pem_ptr` must not be modified for the duration of this call.
/// * Returns a null pointer if the PEM is invalid UTF-8 or fails to parse as an RSA key.
/// * **Ownership:** The caller owns the returned pointer and MUST free it using `bhd_key_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhd_key_new(pem_ptr: *const u8, pem_len: usize) -> *mut RsaPublicKey {
    let pem_bytes = unsafe { slice::from_raw_parts(pem_ptr, pem_len) };
    let Ok(pem_str) = std::str::from_utf8(pem_bytes) else {
        return std::ptr::null_mut();
    };

    match parse_pem_public_key(pem_str) {
        Ok(key) => Box::into_raw(Box::new(key)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// * `key_ptr` must be a valid pointer obtained from `bhd_key_new`.
/// * This function must only be called ONCE per pointer.
/// * After this call, the `key_ptr` is invalid and must not be used again.
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhd_get_size(key_ptr: *const RsaPublicKey, encrypted_len: usize) -> usize {
    let key = unsafe { &*key_ptr };
    if encrypted_len < key.size {
        return encrypted_len;
    }
    encrypted_len.div_ceil(key.size) * (key.size - 1)
}

/// # Safety
///
/// * `key_ptr` must be a valid, non-null pointer to an `RsaPublicKey`.
/// * `data_ptr` must point to at least `data_len` valid bytes.
/// * `out_ptr` must point to a writable buffer allocated with at least the size
///   returned by `bhd_get_size`.
/// * The buffers pointed to by `data_ptr` and `out_ptr` must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhd_decrypt(
    key_ptr: *const RsaPublicKey,
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
) -> usize {
    let key = unsafe { &*key_ptr };
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };

    // FIX: Match the CLI's early exit for small/unencrypted files.
    // If we don't do this, FFI tries to decrypt raw plaintext and outputs garbage.
    if data_len < key.size {
        let out_slice = unsafe { slice::from_raw_parts_mut(out_ptr, data_len) };
        out_slice.copy_from_slice(data);
        return data_len;
    }

    let out_size = unsafe { bhd_get_size(key_ptr, data_len) };
    let out_slice = unsafe { slice::from_raw_parts_mut(out_ptr, out_size) };

    run_decryption(data, out_slice, key, key.size, key.size - 1);

    out_size
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
