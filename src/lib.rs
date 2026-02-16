pub mod ffi;

use malachite::base::num::arithmetic::traits::ModPow;
use malachite::natural::Natural;
use malachite::platform::Limb;
pub struct RsaPublicKey {
    pub n: Natural,
    pub e: Natural,
    pub size: usize,
}

pub fn natural_from_bytes_be(bytes: &[u8]) -> Natural {
    const LIMB_SIZE: usize = std::mem::size_of::<Limb>();
    let remainder_len = bytes.len() % LIMB_SIZE;
    let mut limbs = Vec::with_capacity(bytes.len().div_ceil(LIMB_SIZE));

    for chunk in bytes[remainder_len..].rchunks_exact(LIMB_SIZE) {
        limbs.push(Limb::from_be_bytes(chunk.try_into().unwrap()));
    }

    if remainder_len > 0 {
        let mut limb = 0 as Limb;
        for &b in &bytes[..remainder_len] {
            limb = (limb << 8) | (b as Limb);
        }
        limbs.push(limb);
    }
    Natural::from_owned_limbs_asc(limbs)
}

pub fn natural_to_bytes_be_into(n: &Natural, output: &mut [u8]) {
    const LIMB_SIZE: usize = std::mem::size_of::<Limb>();
    output.fill(0);
    for (chunk, limb) in output.rchunks_mut(LIMB_SIZE).zip(n.limbs()) {
        let bytes = limb.to_be_bytes();
        match chunk.first_chunk_mut() {
            Some(c) => *c = bytes,
            None => chunk.copy_from_slice(&bytes[LIMB_SIZE - chunk.len()..]),
        }
    }
}

pub fn decrypt_into(block: &[u8], n: &Natural, e: &Natural, output: &mut [u8]) {
    let c = natural_from_bytes_be(block);
    let m = (&c).mod_pow(e, n);
    natural_to_bytes_be_into(&m, output);
}

pub fn parse_der_length(der: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    if der[0] < 0x80 {
        Ok((der[0] as usize, 1))
    } else {
        let num_bytes = (der[0] & 0x7F) as usize;
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (der[1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

pub fn parse_der_integer(der: &[u8]) -> Result<(Vec<u8>, usize), Box<dyn std::error::Error>> {
    if der[0] != 0x02 {
        return Err("Expected INTEGER".into());
    }

    let (length, len_bytes) = parse_der_length(&der[1..])?;
    let start = 1 + len_bytes;
    let mut bytes = der[start..start + length].to_vec();
    if !bytes.is_empty() && bytes[0] == 0x00 {
        bytes.remove(0);
    }

    Ok((bytes, start + length))
}

pub fn parse_pem_public_key(pem: &str) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let base64_content: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::{Engine, engine::general_purpose::STANDARD};
    let der = STANDARD.decode(&base64_content)?;

    parse_der_rsa_public_key(&der)
}

pub fn parse_der_rsa_public_key(der: &[u8]) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let mut pos = 0;
    if der[pos] != 0x30 {
        return Err("Expected SEQUENCE".into());
    }
    pos += 1;

    pos += parse_der_length(&der[pos..])?.1;
    let (n_bytes, n_len) = parse_der_integer(&der[pos..])?;
    pos += n_len;
    let (e_bytes, _) = parse_der_integer(&der[pos..])?;

    let n = natural_from_bytes_be(&n_bytes);
    let e = natural_from_bytes_be(&e_bytes);

    let size = n_bytes.len();

    Ok(RsaPublicKey { n, e, size })
}
