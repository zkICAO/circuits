//! RSA key material for the fixtures, prepared the way the circuits take it:
//! 120 bit limbs plus the Barrett reduction parameter.

use std::path::Path;

use crate::bigint::BigUint;
use crate::ec::run;

pub const MODULUS_BITS: usize = 2048;

pub const LIMBS: usize = 18;

// The backend divides by the modulus using floor(2^(2 * MOD_BITS + 6) / n).
const BARRETT_OVERFLOW_BITS: usize = 6;

pub struct RsaKey {
    pem_path: std::path::PathBuf,
    pub modulus: BigUint,
}

impl RsaKey {
    pub fn modulus_limbs(&self) -> Vec<u128> {
        self.modulus.to_limbs_120(LIMBS)
    }

    /// The reduction hint. A wrong value cannot make a bad signature verify,
    /// since the backend constrains multiplications against it, but a wrong
    /// value does make a good signature fail.
    pub fn redc_limbs(&self) -> Vec<u128> {
        let numerator = BigUint::power_of_two(2 * MODULUS_BITS + BARRETT_OVERFLOW_BITS);

        numerator.divide(&self.modulus).to_limbs_120(LIMBS)
    }
}

pub fn generate(pem_path: &Path) -> RsaKey {
    run(
        "openssl",
        &[
            "genrsa",
            "-out",
            pem_path.to_str().unwrap(),
            &MODULUS_BITS.to_string(),
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

    assert_eq!(
        bytes.len() * 8,
        MODULUS_BITS,
        "rsa: unexpected modulus size"
    );

    RsaKey {
        pem_path: pem_path.to_path_buf(),
        modulus: BigUint::from_be_bytes(&bytes),
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
        MODULUS_BITS,
        "rsa: signature is not the modulus width"
    );

    BigUint::from_be_bytes(&signature).to_limbs_120(LIMBS)
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
        let dir = std::env::temp_dir().join("zkicao-rsa-test");

        std::fs::create_dir_all(&dir).unwrap();

        let key = generate(&dir.join("k.pem"));

        assert_eq!(key.modulus_limbs().len(), LIMBS);

        assert_eq!(key.modulus.bit_length(), MODULUS_BITS);

        // The reduction parameter is about 2^(2048 + 6) for a 2048 bit
        // modulus, so it must be wider than the modulus and fit the limbs.
        let redc = key.redc_limbs();

        assert_eq!(redc.len(), LIMBS);

        let signature = sign_sha256(&key, b"zkICAO");

        assert_eq!(signature.len(), LIMBS);

        std::fs::remove_dir_all(&dir).ok();
    }
}
