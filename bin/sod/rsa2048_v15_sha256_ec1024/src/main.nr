//! Passive Authentication for a document whose Document Signer uses RSA-2048
//! with PKCS#1 v1.5 padding and SHA-256, with a Security Object of up to 512
//! bytes.
//!
//! Doc 9303 allows sixteen data groups. Twelve fit a 512 byte Security
//! Object with SHA-256 hashes and thirteen do not, so a document carrying
//! more than twelve needs this variant. The fixtures build small documents,
//! so this variant compiles and measures here but is exercised by the tests
//! of the 512 byte one.
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
    econtent: [u8; 1024],
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

    assert(domain != 0, "sod: domain must be set");

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

    let out = sod::outputs(
        digests.econtent_hash,
        commit::modulus_hash(modulus_limbs),
        commit::limbs_document_secret(signature_limbs),
        dsc_salt,
        domain,
    );

    (out.econtent_binding, out.dsc_commitment, out.secret_binding)
}
