//! Diffie-Hellman parameters (PKCS#3 `DHParameter`): the RFC 7919 FFDHE groups, or a freshly
//! generated safe prime p = 2q + 1 with generator 2.

use crate::ffdhe;
use crate::model::DhParamsResult;
use crate::util::*;
use num_bigint_dig::prime::probably_prime;
use num_bigint_dig::{BigUint, RandBigInt};

fn params_pem(p: &BigUint, g: u32) -> String {
    let der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_bigint_bytes(&p.to_bytes_be(), true);
            w.next().write_u32(g);
        })
    });
    to_pem("DH PARAMETERS", &der)
}

pub fn ffdhe(bits: u32) -> Res<DhParamsResult> {
    let hex = match bits {
        2048 => ffdhe::FFDHE2048,
        3072 => ffdhe::FFDHE3072,
        4096 => ffdhe::FFDHE4096,
        6144 => ffdhe::FFDHE6144,
        8192 => ffdhe::FFDHE8192,
        _ => return Err("RFC 7919 groups exist for 2048, 3072, 4096, 6144 and 8192 bits".into()),
    };
    let p = BigUint::parse_bytes(hex.as_bytes(), 16).ok_or("corrupt FFDHE constant")?;
    Ok(DhParamsResult {
        bit_size: bits,
        group: format!("ffdhe{bits}"),
        prime_hex: colon_hex(&p.to_bytes_be()),
        generator: 2,
        pem: params_pem(&p, 2),
        generated_at: fmt_ts(now_ts()),
    })
}

const SMALL_PRIMES: [u32; 54] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
];

/// Generates a `bits`-bit safe prime. Expect seconds for 1024 bits and up to a few minutes for
/// 2048 bits; larger sizes should use the RFC 7919 groups instead.
pub fn generate(bits: u32) -> Res<DhParamsResult> {
    if !(512..=2048).contains(&bits) {
        return Err("custom generation supports 512–2048 bits; use an RFC 7919 group for larger sizes".into());
    }
    let mut rng = rand::rngs::OsRng;
    let one = BigUint::from(1u32);
    loop {
        // q of bits-1 bits with the top two bits set (so p has exactly `bits` bits) and q ≡ 2 mod 3
        // is not required; the sieve below rejects q or 2q+1 with small factors.
        let mut q = rng.gen_biguint((bits - 1) as usize);
        let top = (BigUint::from(3u32)) << ((bits - 3) as usize);
        q |= top;
        q |= one.clone();
        let p = (&q << 1usize) + &one;
        if SMALL_PRIMES.iter().any(|&sp| {
            let sp = BigUint::from(sp);
            (&q % &sp).bits() == 0 || (&p % &sp).bits() == 0
        }) {
            continue;
        }
        if probably_prime(&q, 2) && probably_prime(&p, 20) && probably_prime(&q, 20) {
            return Ok(DhParamsResult {
                bit_size: bits,
                group: "custom".into(),
                prime_hex: colon_hex(&p.to_bytes_be()),
                generator: 2,
                pem: params_pem(&p, 2),
                generated_at: fmt_ts(now_ts()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffdhe_groups_have_the_right_size() {
        for bits in [2048, 3072, 4096, 6144, 8192] {
            let r = ffdhe(bits).unwrap();
            let p = BigUint::parse_bytes(r.prime_hex.replace(':', "").as_bytes(), 16).unwrap();
            assert_eq!(p.bits(), bits as usize);
        }
        assert!(ffdhe(1024).is_err());
    }

    #[test]
    fn generates_a_safe_prime() {
        let r = generate(512).unwrap();
        let p = BigUint::parse_bytes(r.prime_hex.replace(':', "").as_bytes(), 16).unwrap();
        assert_eq!(p.bits(), 512);
        let q = (&p - BigUint::from(1u32)) >> 1usize;
        assert!(probably_prime(&p, 10) && probably_prime(&q, 10));
    }
}
