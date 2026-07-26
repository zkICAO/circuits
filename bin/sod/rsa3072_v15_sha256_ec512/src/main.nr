//! Passive Authentication for a document whose Document Signer uses RSA-3072
//! with PKCS#1 v1.5 padding and SHA-256, with a Security Object of up to 512
//! bytes.
//!
//! Same chain as the elliptic curve variant. Only the signature check
//! differs, which is the point of keeping that step in the variant rather
//! than in the shared library.
//!
//! The key and the signature are single numbers here rather than pairs, so
//! the commitment helpers that fold limbs are the right ones. Every limb
//! enters, which matters: an earlier version sampled a few bytes per limb and
//! so committed to 432 bits of a 2048 bit modulus.

fn main(
    econtent: [u8; 512],
    econtent_len: u32,
    signed_attrs: [u8; 256],
    signed_attrs_len: u32,
    digest_offset: u32,
    modulus_limbs: [u128; 26],
    redc_limbs: [u128; 26],
    signature_limbs: [u128; 26],
    dsc_salt: Field,
    domain: pub Field,
    context: pub Field,
) -> pub (Field, Field, Field) {
    assert(context != 0, "sod: context must be set");

    assert(domain != 0, "sod: domain must be set");

    let digests = sod::link(
        econtent,
        econtent_len,
        signed_attrs,
        signed_attrs_len,
        digest_offset,
    );

    rsa::verify_pkcs1_v15_sha256::<26, 3072>(
        modulus_limbs,
        redc_limbs,
        signature_limbs,
        digests.signed_attrs_hash,
    );

    let out = sod::outputs(
        digests.econtent_hash,
        commit::modulus_hash(modulus_limbs),
        commit::limbs_document_secret(signature_limbs),
        dsc_salt,
        domain,
    );

    (out.econtent_binding, out.dsc_commitment, out.secret_binding)
}

#[test]
fn verifies_a_document_signed_with_rsa() {
    let _ = main(
        testdata::RSA3072_ECONTENT,
        testdata::RSA3072_ECONTENT_LEN,
        testdata::RSA3072_SIGNED_ATTRS,
        testdata::RSA3072_SIGNED_ATTRS_LEN,
        testdata::RSA3072_DIGEST_OFFSET,
        testdata::RSA3072_MODULUS_LIMBS,
        testdata::RSA3072_REDC_LIMBS,
        testdata::RSA3072_SIGNATURE_LIMBS,
        11,
        42,
        7,
    );
}

#[test(should_fail_with = "rsa: digest does not match")]
fn rejects_a_signature_over_another_security_object() {
    let mut econtent = testdata::RSA3072_ECONTENT;

    econtent[testdata::RSA3072_DG2_OFFSET + 7] ^= 1;

    let mut signed_attrs = testdata::RSA3072_SIGNED_ATTRS;

    let digest = hash::sha256_bounded(econtent, testdata::RSA3072_ECONTENT_LEN);

    for i in 0..32 {
        signed_attrs[testdata::RSA3072_DIGEST_OFFSET + i] = digest[i];
    }

    let _ = main(
        econtent,
        testdata::RSA3072_ECONTENT_LEN,
        signed_attrs,
        testdata::RSA3072_SIGNED_ATTRS_LEN,
        testdata::RSA3072_DIGEST_OFFSET,
        testdata::RSA3072_MODULUS_LIMBS,
        testdata::RSA3072_REDC_LIMBS,
        testdata::RSA3072_SIGNATURE_LIMBS,
        11,
        42,
        7,
    );
}
