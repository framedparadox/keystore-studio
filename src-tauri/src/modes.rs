//! Cipher modes the keystore codecs need whose nonce and tag sizes are only known at run time, or
//! that no crate in the dependency tree provides: AES-CCM (RFC 3610), which Bouncy Castle's BCFKS
//! uses with a 12-byte nonce and an 8-byte tag; AES key wrap with padding (RFC 5649), BCFKS's
//! alternative; and RC4, for PKCS#12 files written with the export ciphers of the 1990s.
//!
//! Each is checked against its published vectors below and, through the keystore tests, against
//! files written by Bouncy Castle and OpenSSL.

use crate::util::Res;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

/// The tag did not verify: a wrong key (so a wrong password) or altered data.
pub const AUTH_FAILED: &str = "authentication failed";

enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Res<Aes> {
        let bad = |_| "invalid AES key".to_string();
        Ok(match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).map_err(bad)?),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).map_err(bad)?),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).map_err(bad)?),
            n => return Err(format!("unsupported: an AES key is 16, 24 or 32 bytes, not {n}")),
        })
    }

    fn encrypt(&self, block: &mut [u8; 16]) {
        let b = GenericArray::from_mut_slice(block);
        match self {
            Aes::A128(c) => c.encrypt_block(b),
            Aes::A192(c) => c.encrypt_block(b),
            Aes::A256(c) => c.encrypt_block(b),
        }
    }

    fn decrypt(&self, block: &mut [u8; 16]) {
        let b = GenericArray::from_mut_slice(block);
        match self {
            Aes::A128(c) => c.decrypt_block(b),
            Aes::A192(c) => c.decrypt_block(b),
            Aes::A256(c) => c.decrypt_block(b),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// AES-CCM
// ---------------------------------------------------------------------------------------------

/// Checks the sizes RFC 3610 allows and that the message length fits its length field.
fn ccm_check(nonce: &[u8], tag_len: usize, msg_len: usize) -> Res<()> {
    if !(7..=13).contains(&nonce.len()) {
        return Err(format!("unsupported: an AES-CCM nonce is 7 to 13 bytes, not {}", nonce.len()));
    }
    if !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2) {
        return Err(format!("unsupported: an AES-CCM tag is 4 to 16 bytes, not {tag_len}"));
    }
    let l = 15 - nonce.len();
    if l < 8 && (msg_len as u64) >> (8 * l) != 0 {
        return Err("invalid: the data is too long for this AES-CCM nonce size".into());
    }
    Ok(())
}

/// The CBC-MAC over B0, the associated data and the message (the untruncated tag T).
fn ccm_mac(aes: &Aes, nonce: &[u8], tag_len: usize, aad: &[u8], msg: &[u8]) -> [u8; 16] {
    let l = 15 - nonce.len();
    let mut x = [0u8; 16];
    x[0] = (if aad.is_empty() { 0 } else { 0x40 }) | ((((tag_len - 2) / 2) as u8) << 3) | (l as u8 - 1);
    x[1..1 + nonce.len()].copy_from_slice(nonce);
    x[16 - l..].copy_from_slice(&(msg.len() as u64).to_be_bytes()[8 - l..]);
    aes.encrypt(&mut x);
    // A short final block is zero-padded, which for an XOR means leaving the rest untouched.
    let absorb = |data: &[u8], x: &mut [u8; 16]| {
        for chunk in data.chunks(16) {
            for (i, b) in chunk.iter().enumerate() {
                x[i] ^= b;
            }
            aes.encrypt(x);
        }
    };
    if !aad.is_empty() {
        let mut header = Vec::with_capacity(aad.len() + 10);
        if aad.len() < 0xFF00 {
            header.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        } else if aad.len() <= u32::MAX as usize {
            header.extend_from_slice(&[0xFF, 0xFE]);
            header.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        } else {
            header.extend_from_slice(&[0xFF, 0xFF]);
            header.extend_from_slice(&(aad.len() as u64).to_be_bytes());
        }
        header.extend_from_slice(aad);
        absorb(&header, &mut x);
    }
    absorb(msg, &mut x);
    x
}

/// Key stream block S_i.
fn ccm_stream(aes: &Aes, nonce: &[u8], counter: u64) -> [u8; 16] {
    let l = 15 - nonce.len();
    let mut a = [0u8; 16];
    a[0] = l as u8 - 1;
    a[1..1 + nonce.len()].copy_from_slice(nonce);
    a[16 - l..].copy_from_slice(&counter.to_be_bytes()[8 - l..]);
    aes.encrypt(&mut a);
    a
}

fn ccm_xor(aes: &Aes, nonce: &[u8], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let s = ccm_stream(aes, nonce, i as u64 + 1);
        for (b, k) in chunk.iter_mut().zip(s) {
            *b ^= k;
        }
    }
}

/// AES-CCM encryption. Returns the ciphertext followed by the `tag_len`-byte tag.
pub fn aes_ccm_encrypt(key: &[u8], nonce: &[u8], tag_len: usize, aad: &[u8], plaintext: &[u8]) -> Res<Vec<u8>> {
    ccm_check(nonce, tag_len, plaintext.len())?;
    let aes = Aes::new(key)?;
    let tag = ccm_mac(&aes, nonce, tag_len, aad, plaintext);
    let mut out = plaintext.to_vec();
    ccm_xor(&aes, nonce, &mut out);
    let s0 = ccm_stream(&aes, nonce, 0);
    out.extend(tag.iter().zip(s0).take(tag_len).map(|(t, s)| t ^ s));
    Ok(out)
}

/// AES-CCM decryption of ciphertext followed by its tag. Fails with [`AUTH_FAILED`] when the tag
/// does not verify.
pub fn aes_ccm_decrypt(key: &[u8], nonce: &[u8], tag_len: usize, aad: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    if data.len() < tag_len {
        return Err(AUTH_FAILED.into());
    }
    ccm_check(nonce, tag_len, data.len() - tag_len)?;
    let aes = Aes::new(key)?;
    let (ciphertext, tag) = data.split_at(data.len() - tag_len);
    let mut plain = ciphertext.to_vec();
    ccm_xor(&aes, nonce, &mut plain);
    let expected = ccm_mac(&aes, nonce, tag_len, aad, &plain);
    let s0 = ccm_stream(&aes, nonce, 0);
    // Compared without an early exit, so the time taken does not depend on where they differ.
    let diff = expected.iter().zip(s0).zip(tag).fold(0u8, |acc, ((t, s), got)| acc | ((t ^ s) ^ got));
    if diff != 0 {
        return Err(AUTH_FAILED.into());
    }
    Ok(plain)
}

// ---------------------------------------------------------------------------------------------
// AES key wrap with padding
// ---------------------------------------------------------------------------------------------

/// The upper half of the RFC 5649 alternative initial value; the lower half is the length.
const KWP_ICV: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// RFC 5649 unwrap. Fails with [`AUTH_FAILED`] when the integrity value does not check.
pub fn aes_kwp_unwrap(key: &[u8], data: &[u8]) -> Res<Vec<u8>> {
    let aes = Aes::new(key)?;
    if data.len() < 16 || !data.len().is_multiple_of(8) {
        return Err(AUTH_FAILED.into());
    }
    let n = data.len() / 8 - 1;
    let mut a = [0u8; 8];
    let mut r: Vec<[u8; 8]> = data[8..].chunks(8).map(|c| c.try_into().unwrap()).collect();
    if n == 1 {
        // A single block is one ECB decryption rather than the six-round unwrap.
        let mut b: [u8; 16] = data.try_into().unwrap();
        aes.decrypt(&mut b);
        a.copy_from_slice(&b[..8]);
        r[0].copy_from_slice(&b[8..]);
    } else {
        a.copy_from_slice(&data[..8]);
        for j in (0..6).rev() {
            for i in (1..=n).rev() {
                let t = (n * j + i) as u64;
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&(u64::from_be_bytes(a) ^ t).to_be_bytes());
                b[8..].copy_from_slice(&r[i - 1]);
                aes.decrypt(&mut b);
                a.copy_from_slice(&b[..8]);
                r[i - 1].copy_from_slice(&b[8..]);
            }
        }
    }
    let padded = r.concat();
    let len = u32::from_be_bytes(a[4..].try_into().unwrap()) as usize;
    // 8(n-1) < length <= 8n, and everything after it is zero.
    if a[..4] != KWP_ICV || len > padded.len() || len + 8 <= padded.len() || padded[len..].iter().any(|b| *b != 0) {
        return Err(AUTH_FAILED.into());
    }
    Ok(padded[..len].to_vec())
}

/// RFC 5649 wrap.
pub fn aes_kwp_wrap(key: &[u8], plaintext: &[u8]) -> Res<Vec<u8>> {
    let aes = Aes::new(key)?;
    if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
        return Err("invalid: nothing to wrap".into());
    }
    let mut a = [0u8; 8];
    a[..4].copy_from_slice(&KWP_ICV);
    a[4..].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    let mut padded = plaintext.to_vec();
    padded.resize(plaintext.len().div_ceil(8) * 8, 0);
    let mut r: Vec<[u8; 8]> = padded.chunks(8).map(|c| c.try_into().unwrap()).collect();
    let n = r.len();
    if n == 1 {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&a);
        b[8..].copy_from_slice(&r[0]);
        aes.encrypt(&mut b);
        return Ok(b.to_vec());
    }
    for j in 0..6 {
        for i in 1..=n {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[i - 1]);
            aes.encrypt(&mut b);
            let t = (n * j + i) as u64;
            a.copy_from_slice(&(u64::from_be_bytes(b[..8].try_into().unwrap()) ^ t).to_be_bytes());
            r[i - 1].copy_from_slice(&b[8..]);
        }
    }
    Ok([a.as_slice(), r.concat().as_slice()].concat())
}

// ---------------------------------------------------------------------------------------------
// RC4
// ---------------------------------------------------------------------------------------------

/// RC4 key stream applied in place. Encryption and decryption are the same operation.
pub fn rc4(key: &[u8], data: &mut [u8]) {
    if key.is_empty() {
        return;
    }
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for b in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *b ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// RFC 3610 section 8, packet vectors 1 and 2.
    #[test]
    fn ccm_matches_rfc3610_vectors() {
        let key = h("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let cases = [
            (&key, "00000003020100A0A1A2A3A4A5", 8usize, "0001020304050607", "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E", "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0"),
            (&key, "00000004030201A0A1A2A3A4A5", 8, "0001020304050607", "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916"),
        ];
        for (key, nonce, tag_len, aad, plain, expected) in cases {
            let (nonce, aad, plain, expected) = (h(nonce), h(aad), h(plain), h(expected));
            let sealed = aes_ccm_encrypt(key, &nonce, tag_len, &aad, &plain).unwrap();
            assert_eq!(hex::encode_upper(&sealed), hex::encode_upper(&expected));
            assert_eq!(aes_ccm_decrypt(key, &nonce, tag_len, &aad, &sealed).unwrap(), plain);
            // Any change to the ciphertext, the tag or the associated data is caught.
            for at in [0, sealed.len() / 2, sealed.len() - 1] {
                let mut bad = sealed.clone();
                bad[at] ^= 0x01;
                assert_eq!(aes_ccm_decrypt(key, &nonce, tag_len, &aad, &bad).unwrap_err(), AUTH_FAILED);
            }
            assert_eq!(aes_ccm_decrypt(key, &nonce, tag_len, b"other", &sealed).unwrap_err(), AUTH_FAILED);
        }
    }

    #[test]
    fn ccm_round_trips_every_size_bouncy_castle_can_name() {
        let key = [7u8; 32];
        for nonce_len in 7..=13 {
            for tag_len in [4, 6, 8, 10, 12, 14, 16] {
                for len in [0usize, 1, 15, 16, 17, 100] {
                    let nonce = vec![3u8; nonce_len];
                    let plain: Vec<u8> = (0..len as u8).collect();
                    let sealed = aes_ccm_encrypt(&key, &nonce, tag_len, &[], &plain).unwrap();
                    assert_eq!(sealed.len(), len + tag_len);
                    assert_eq!(aes_ccm_decrypt(&key, &nonce, tag_len, &[], &sealed).unwrap(), plain);
                }
            }
        }
        assert!(aes_ccm_encrypt(&key, &[0u8; 6], 8, &[], b"x").is_err());
        assert!(aes_ccm_encrypt(&key, &[0u8; 12], 7, &[], b"x").is_err());
        assert!(aes_ccm_encrypt(&[0u8; 5], &[0u8; 12], 8, &[], b"x").is_err());
        assert_eq!(aes_ccm_decrypt(&key, &[0u8; 12], 8, &[], b"short").unwrap_err(), AUTH_FAILED);
    }

    /// RFC 5649 section 6.
    #[test]
    fn kwp_matches_rfc5649_vectors() {
        let kek = h("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        for (plain, wrapped) in
            [("c37b7e6492584340bed12207808941155068f738", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"), ("466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f")]
        {
            let (plain, wrapped) = (h(plain), h(wrapped));
            assert_eq!(hex::encode(aes_kwp_wrap(&kek, &plain).unwrap()), hex::encode(&wrapped));
            assert_eq!(aes_kwp_unwrap(&kek, &wrapped).unwrap(), plain);
            let mut bad = wrapped.clone();
            bad[3] ^= 0x80;
            assert_eq!(aes_kwp_unwrap(&kek, &bad).unwrap_err(), AUTH_FAILED);
            assert_eq!(aes_kwp_unwrap(&[1u8; 24], &wrapped).unwrap_err(), AUTH_FAILED);
        }
        assert!(aes_kwp_unwrap(&kek, &[0u8; 12]).is_err());
        for len in 1..=40 {
            let plain: Vec<u8> = (0..len as u8).collect();
            assert_eq!(aes_kwp_unwrap(&kek, &aes_kwp_wrap(&kek, &plain).unwrap()).unwrap(), plain, "length {len}");
        }
    }

    #[test]
    fn rc4_matches_the_classic_vectors() {
        for (key, plain, expected) in [("Key", "Plaintext", "BBF316E8D940AF0AD3"), ("Wiki", "pedia", "1021BF0420"), ("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5")] {
            let mut data = plain.as_bytes().to_vec();
            rc4(key.as_bytes(), &mut data);
            assert_eq!(hex::encode_upper(&data), expected);
            rc4(key.as_bytes(), &mut data);
            assert_eq!(data, plain.as_bytes());
        }
    }
}
