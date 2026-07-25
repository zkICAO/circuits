//! RSA signature verification, PKCS#1 v1.5 with SHA-256.
//!
//! Most states sign with RSA rather than an elliptic curve, so this is what
//! a majority of real documents need. Verification recovers the encoded
//! message by raising the signature to the public exponent and then checks
//! that encoding byte for byte, which is what makes it a verification rather
//! than a comparison of two numbers.
//!
//! Only e = 65537 is accepted. It is what Doc 9303 infrastructure uses in
//! practice, and a small exponent path is the only one implemented here, so
//! a key with any other exponent must be rejected rather than silently
//! verified against the wrong arithmetic.
//!
//! The modulus is a runtime value because it differs per document. Its
//! Barrett reduction parameter comes in alongside it as a hint; the bignum
//! backend constrains every multiplication against it, so a wrong hint
//! cannot make a bad signature verify.

use bignum::params::BigNumParams;

use bignum::RuntimeBigNum;

/// The DigestInfo prefix for SHA-256: a DER SEQUENCE holding the algorithm
/// identifier with a NULL parameter, then the OCTET STRING header for a 32
/// byte digest.
pub global SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Raises the signature to 65537 as sixteen squarings and one multiply.
fn exponentiate<let N: u32, let MOD_BITS: u32>(
    signature: RuntimeBigNum<N, MOD_BITS>,
) -> RuntimeBigNum<N, MOD_BITS> {
    let mut squared = signature;

    for _ in 0..16 {
        squared = squared * squared;
    }

    squared * signature
}

/// Checks the recovered encoding against EMSA-PKCS1-v1_5 for SHA-256.
///
/// Every byte is constrained. The padding is not merely long enough, it is
/// exactly `00 01`, then `FF` up to a single `00` separator, then the digest
/// info and the digest. Accepting a shorter padding run would let a forger
/// place the digest info at another offset.
fn check_encoding<let EM: u32>(encoded: [u8; EM], digest: [u8; 32]) {
    // Two padding bytes, at least eight ones, a separator, then 51 bytes of
    // digest info and digest. Below that width the encoding cannot be built.
    assert(EM >= 62, "rsa: modulus is too small to hold the encoding");

    let digest_info_start = EM - 51;

    assert(encoded[0] == 0x00, "rsa: encoded message must start with zero");

    assert(encoded[1] == 0x01, "rsa: wrong block type");

    for i in 2..(digest_info_start - 1) {
        assert(encoded[i] == 0xff, "rsa: padding must be all ones");
    }

    assert(encoded[digest_info_start - 1] == 0x00, "rsa: missing padding separator");

    for i in 0..19 {
        assert(
            encoded[digest_info_start + i] == SHA256_DIGEST_INFO[i],
            "rsa: digest info does not describe sha-256",
        );
    }

    for i in 0..32 {
        assert(encoded[digest_info_start + 19 + i] == digest[i], "rsa: digest does not match");
    }
}

/// Verifies an RSA PKCS#1 v1.5 signature over a SHA-256 digest. The encoded
/// message spans the full modulus width, which the byte conversion derives
/// from `MOD_BITS`, so there is no separate length parameter that could
/// disagree with the modulus.
pub fn verify_pkcs1_v15_sha256<let N: u32, let MOD_BITS: u32>(
    modulus_limbs: [u128; N],
    redc_limbs: [u128; N],
    signature_limbs: [u128; N],
    digest: [u8; 32],
) {
    let params: BigNumParams<N, MOD_BITS> = BigNumParams::new(false, modulus_limbs, redc_limbs);

    let signature: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::from_array(params, signature_limbs);

    check_encoding(exponentiate(signature).to_be_bytes(), digest);
}

#[test]
fn accepts_a_well_formed_encoding() {
    let mut encoded: [u8; 256] = [0; 256];

    let mut digest: [u8; 32] = [0; 32];

    for i in 0..32 {
        digest[i] = (i as u8) + 7;
    }

    encoded[0] = 0x00;

    encoded[1] = 0x01;

    for i in 2..204 {
        encoded[i] = 0xff;
    }

    encoded[204] = 0x00;

    for i in 0..19 {
        encoded[205 + i] = SHA256_DIGEST_INFO[i];
    }

    for i in 0..32 {
        encoded[224 + i] = digest[i];
    }

    check_encoding(encoded, digest);
}

fn well_formed() -> ([u8; 256], [u8; 32]) {
    let mut encoded: [u8; 256] = [0; 256];

    let mut digest: [u8; 32] = [0; 32];

    for i in 0..32 {
        digest[i] = (i as u8) + 7;
    }

    encoded[1] = 0x01;

    for i in 2..204 {
        encoded[i] = 0xff;
    }

    for i in 0..19 {
        encoded[205 + i] = SHA256_DIGEST_INFO[i];
    }

    for i in 0..32 {
        encoded[224 + i] = digest[i];
    }

    (encoded, digest)
}

#[test(should_fail_with = "rsa: digest does not match")]
fn rejects_a_different_digest() {
    let (encoded, mut digest) = well_formed();

    digest[0] ^= 1;

    check_encoding(encoded, digest);
}

#[test(should_fail_with = "rsa: padding must be all ones")]
fn rejects_a_shortened_padding_run() {
    let (mut encoded, digest) = well_formed();

    encoded[100] = 0x00;

    check_encoding(encoded, digest);
}

#[test(should_fail_with = "rsa: wrong block type")]
fn rejects_a_different_block_type() {
    let (mut encoded, digest) = well_formed();

    encoded[1] = 0x02;

    check_encoding(encoded, digest);
}

#[test(should_fail_with = "rsa: digest info does not describe sha-256")]
fn rejects_another_digest_algorithm() {
    let (mut encoded, digest) = well_formed();

    encoded[205 + 18] = 0x14;

    check_encoding(encoded, digest);
}

#[test(should_fail_with = "rsa: missing padding separator")]
fn rejects_a_missing_separator() {
    let (mut encoded, digest) = well_formed();

    encoded[204] = 0xff;

    check_encoding(encoded, digest);
}

// The real check: a signature openssl produced with a generated RSA-2048
// key, verified against the modulus it was made with.
#[test]
fn verifies_a_real_signature() {
    verify_pkcs1_v15_sha256::<18, 2048>(
        testdata::RSA_MODULUS_LIMBS,
        testdata::RSA_REDC_LIMBS,
        testdata::RSA_SIGNATURE_LIMBS,
        testdata::RSA_DIGEST,
    );
}

#[test(should_fail_with = "rsa: digest does not match")]
fn rejects_a_real_signature_over_another_digest() {
    let mut digest = testdata::RSA_DIGEST;

    digest[0] ^= 1;

    verify_pkcs1_v15_sha256::<18, 2048>(
        testdata::RSA_MODULUS_LIMBS,
        testdata::RSA_REDC_LIMBS,
        testdata::RSA_SIGNATURE_LIMBS,
        digest,
    );
}
