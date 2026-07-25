//! Passive Authentication for a document whose Document Signer uses RSA-2048
//! with PKCS#1 v1.5 padding and SHA-256, with a Security Object of up to 512
//! bytes.
//!
//! Same chain as the elliptic curve variant. Only the signature check
//! differs, which is the point of keeping that step in the variant rather
//! than in the shared library.
//!
//! The document secret is derived from the signature, and an RSA signature is
//! a single number rather than a pair, so its limbs are split in half to fill
//! the two slots the derivation takes.

fn main(
    econtent: [u8; 512],
    econtent_len: u32,
    signed_attrs: [u8; 256],
    signed_attrs_len: u32,
    digest_offset: u32,
    modulus_limbs: [u128; 18],
    redc_limbs: [u128; 18],
    signature_limbs: [u128; 18],
    dsc_salt: Field,
    domain: pub Field,
    context: pub Field,
) -> pub (Field, Field, Field) {
    assert(context != 0, "sod: context must be set");

    let digests = sod::link(
        econtent,
        econtent_len,
        signed_attrs,
        signed_attrs_len,
        digest_offset,
    );

    rsa::verify_pkcs1_v15_sha256::<18, 2048>(
        modulus_limbs,
        redc_limbs,
        signature_limbs,
        digests.signed_attrs_hash,
    );

    let key_bytes = limbs_to_bytes(modulus_limbs);

    let signature_bytes = limbs_to_bytes(signature_limbs);

    let out = sod::outputs(
        digests.econtent_hash,
        key_bytes.0,
        key_bytes.1,
        signature_bytes.0,
        signature_bytes.1,
        dsc_salt,
        domain,
    );

    (out.econtent_binding, out.dsc_commitment, out.secret_binding)
}

/// Packs eighteen 120 bit limbs into two 32 byte halves, so a 2048 bit value
/// reaches the commitment helpers in the shape they take for a curve point.
/// Only the identity of the value matters here, not its numeric layout.
fn limbs_to_bytes(limbs: [u128; 18]) -> ([u8; 32], [u8; 32]) {
    let mut low: [u8; 32] = [0; 32];

    let mut high: [u8; 32] = [0; 32];

    for i in 0..9 {
        let low_bytes: [u8; 16] = (limbs[i] as Field).to_be_bytes();

        let high_bytes: [u8; 16] = (limbs[i + 9] as Field).to_be_bytes();

        for j in 0..3 {
            low[i * 3 + j] = low_bytes[13 + j];

            high[i * 3 + j] = high_bytes[13 + j];
        }
    }

    (low, high)
}

#[test]
fn verifies_a_document_signed_with_rsa() {
    let _ = main(
        testdata::RSA_ECONTENT,
        testdata::RSA_ECONTENT_LEN,
        testdata::RSA_SIGNED_ATTRS,
        testdata::RSA_SIGNED_ATTRS_LEN,
        testdata::RSA_DIGEST_OFFSET,
        testdata::RSA_MODULUS_LIMBS,
        testdata::RSA_REDC_LIMBS,
        testdata::RSA_SIGNATURE_LIMBS,
        11,
        42,
        7,
    );
}

#[test(should_fail_with = "rsa: digest does not match")]
fn rejects_a_signature_over_another_security_object() {
    let mut econtent = testdata::RSA_ECONTENT;

    econtent[testdata::RSA_DG2_OFFSET + 7] ^= 1;

    let mut signed_attrs = testdata::RSA_SIGNED_ATTRS;

    let digest = hash::sha256_bounded(econtent, testdata::RSA_ECONTENT_LEN);

    for i in 0..32 {
        signed_attrs[testdata::RSA_DIGEST_OFFSET + i] = digest[i];
    }

    let _ = main(
        econtent,
        testdata::RSA_ECONTENT_LEN,
        signed_attrs,
        testdata::RSA_SIGNED_ATTRS_LEN,
        testdata::RSA_DIGEST_OFFSET,
        testdata::RSA_MODULUS_LIMBS,
        testdata::RSA_REDC_LIMBS,
        testdata::RSA_SIGNATURE_LIMBS,
        11,
        42,
        7,
    );
}
