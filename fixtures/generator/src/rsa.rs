//! RSA key material for the fixtures, prepared the way the circuits take it:
//! 120 bit limbs plus the Barrett reduction parameter.

use std::path::Path;

use crate::bigint::BigUint;
use crate::ec::run;

/// A modulus size the circuits are built for. Doc 9303 puts no upper bound
/// on the key a state signs with, and 4096 bit country signing keys are in
/// use, so the fixtures cover both sizes that have circuits.
#[derive(Clone, Copy)]
pub struct Size {
    pub bits: usize,
    pub limbs: usize,
}

/// 2048 bits in 120 bit limbs: 18 of them, with the top one partly used.
pub const RSA2048: Size = Size {
    bits: 2048,
    limbs: 18,
};

/// 3072 bits needs 26 limbs.
pub const RSA3072: Size = Size {
    bits: 3072,
    limbs: 26,
};

/// 4096 bits needs 35 limbs by the same arithmetic.
pub const RSA4096: Size = Size {
    bits: 4096,
    limbs: 35,
};

// The backend divides by the modulus using floor(2^(2 * MOD_BITS + 6) / n).
const BARRETT_OVERFLOW_BITS: usize = 6;

pub struct RsaKey {
    pem_path: std::path::PathBuf,
    pub modulus: BigUint,
    pub size: Size,
}

impl RsaKey {
    pub fn modulus_limbs(&self) -> Vec<u128> {
        self.modulus.to_limbs_120(self.size.limbs)
    }

    /// The reduction hint. A wrong value cannot make a bad signature verify,
    /// since the backend constrains multiplications against it, but a wrong
    /// value does make a good signature fail.
    pub fn redc_limbs(&self) -> Vec<u128> {
        let numerator = BigUint::power_of_two(2 * self.size.bits + BARRETT_OVERFLOW_BITS);

        numerator
            .divide(&self.modulus)
            .to_limbs_120(self.size.limbs)
    }
}

pub fn generate(pem_path: &Path) -> RsaKey {
    generate_sized(pem_path, RSA2048)
}

pub fn generate_sized(pem_path: &Path, size: Size) -> RsaKey {
    run(
        "openssl",
        &[
            "genrsa",
            "-out",
            pem_path.to_str().unwrap(),
            &size.bits.to_string(),
        ],
        None,
    );

    let text = String::from_utf8(run(
        "openssl",
        &["rsa", "-in", pem_path.to_str().unwrap(), "-noout", "-text"],
        None,
    ))
    .expect("openssl printed something that is not text");

    assert!(
        text.contains("publicExponent: 65537"),
        "rsa: only the exponent 65537 is supported, key reports something else"
    );

    let modulus_line = String::from_utf8(run(
        "openssl",
        &[
            "rsa",
            "-in",
            pem_path.to_str().unwrap(),
            "-noout",
            "-modulus",
        ],
        None,
    ))
    .expect("openssl printed something that is not text");

    let hex = modulus_line
        .trim()
        .strip_prefix("Modulus=")
        .expect("openssl did not print a modulus");

    let bytes = decode_hex(hex);

    assert_eq!(bytes.len() * 8, size.bits, "rsa: unexpected modulus size");

    RsaKey {
        pem_path: pem_path.to_path_buf(),
        modulus: BigUint::from_be_bytes(&bytes),
        size,
    }
}

pub fn sign_sha256(key: &RsaKey, message: &[u8]) -> Vec<u128> {
    let signature = run(
        "openssl",
        &["dgst", "-sha256", "-sign", key.pem_path.to_str().unwrap()],
        Some(message),
    );

    assert_eq!(
        signature.len() * 8,
        key.size.bits,
        "rsa: signature is not the modulus width"
    );

    BigUint::from_be_bytes(&signature).to_limbs_120(key.size.limbs)
}

fn decode_hex(text: &str) -> Vec<u8> {
    let cleaned: Vec<char> = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    assert!(cleaned.len().is_multiple_of(2), "rsa: odd hex length");

    cleaned
        .chunks(2)
        .map(|pair| {
            let high = pair[0].to_digit(16).unwrap() as u8;

            let low = pair[1].to_digit(16).unwrap() as u8;

            (high << 4) | low
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex() {
        assert_eq!(decode_hex("00FF10"), vec![0x00, 0xff, 0x10]);
    }

    #[test]
    fn generates_a_key_whose_limbs_round_trip() {
        let dir = crate::scratch::Scratch::new("rsa-test");

        let key = generate(&dir.join("k.pem"));

        assert_eq!(key.modulus_limbs().len(), RSA2048.limbs);

        assert_eq!(key.modulus.bit_length(), RSA2048.bits);

        // The reduction parameter is about 2^(2048 + 6) for a 2048 bit
        // modulus, so it must be wider than the modulus and fit the limbs.
        let redc = key.redc_limbs();

        assert_eq!(redc.len(), RSA2048.limbs);

        let signature = sign_sha256(&key, b"zkICAO");

        assert_eq!(signature.len(), RSA2048.limbs);
    }

    // The wider key is the one a state may sign with, and every derived
    // value has to widen with it: the limbs, the reduction parameter and
    // the signature.
    #[test]
    fn generates_a_four_thousand_ninety_six_bit_key() {
        let dir = crate::scratch::Scratch::new("rsa4096-test");

        let key = generate_sized(&dir.join("k.pem"), RSA4096);

        assert_eq!(key.modulus.bit_length(), RSA4096.bits);

        assert_eq!(key.modulus_limbs().len(), RSA4096.limbs);

        assert_eq!(key.redc_limbs().len(), RSA4096.limbs);

        assert_eq!(sign_sha256(&key, b"zkICAO").len(), RSA4096.limbs);
    }
}
