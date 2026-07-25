//! Passive Authentication, the part that establishes the issuing state
//! signed this document.
//!
//! The chain is: the Security Object content hashes to a digest, that
//! digest appears in the messageDigest signed attribute, and the Document
//! Signer signature covers those attributes. Checking all three links is
//! what makes the data group hashes inside the Security Object trustworthy;
//! reading those hashes out is a separate step.
//!
//! Generic over the buffer sizes so one implementation serves every size
//! variant. A circuit pays for the buffer, not for the actual document
//! length, which is why sizes are variants rather than one large buffer.
//!
//! Split in two so the signature check sits in the variant that knows its
//! own algorithm: `link` returns the digest the signature must cover, and
//! `outputs` derives the public values once that signature has verified.

use commit::{
    document_secret, dsc_commitment, econtent_binding, hash32_to_fields, pubkey_hash,
    secret_binding,
};

use hash::sha256_bounded;

pub struct SodOutput {
    pub econtent_binding: Field,
    pub dsc_commitment: Field,
    pub secret_binding: Field,
}

pub struct SodDigests {
    pub econtent_hash: [u8; 32],
    pub signed_attrs_hash: [u8; 32],
}

pub fn link<let EC: u32, let SA: u32>(
    econtent: [u8; EC],
    econtent_len: u32,
    signed_attrs: [u8; SA],
    signed_attrs_len: u32,
    digest_offset: u32,
) -> SodDigests {
    let econtent_hash = sha256_bounded(econtent, econtent_len);

    let attribute_digest =
        cms::message_digest_sha256(signed_attrs, signed_attrs_len, digest_offset);

    for i in 0..32 {
        assert(
            econtent_hash[i] == attribute_digest[i],
            "sod: security object digest does not match the signed attribute",
        );
    }

    SodDigests { econtent_hash, signed_attrs_hash: sha256_bounded(signed_attrs, signed_attrs_len) }
}

/// Publishes the secret as a domain scoped binding rather than directly, so
/// a nullifier circuit can prove it holds the same document without the
/// secret ever becoming public.
pub fn outputs<let K: u32>(
    econtent_hash: [u8; 32],
    pubkey_x: [u8; K],
    pubkey_y: [u8; K],
    signature_r: [u8; K],
    signature_s: [u8; K],
    dsc_salt: Field,
    domain: Field,
) -> SodOutput {
    SodOutput {
        econtent_binding: econtent_binding(hash32_to_fields(econtent_hash), domain),
        dsc_commitment: dsc_commitment(pubkey_hash(pubkey_x, pubkey_y), dsc_salt),
        secret_binding: secret_binding(document_secret(signature_r, signature_s), domain),
    }
}

#[test]
fn links_a_generated_document() {
    let digests = link(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_SIGNED_ATTRS,
        testdata::TD3_SIGNED_ATTRS_LEN,
        testdata::TD3_DIGEST_OFFSET,
    );

    let expected = sha256_bounded(testdata::TD3_ECONTENT, testdata::TD3_ECONTENT_LEN);

    for i in 0..32 {
        assert(digests.econtent_hash[i] == expected[i]);
    }
}

#[test(should_fail_with = "sod: security object digest does not match the signed attribute")]
fn rejects_a_tampered_security_object() {
    let mut econtent = testdata::TD3_ECONTENT;

    econtent[testdata::TD3_DG1_OFFSET + 7] ^= 1;

    let _ = link(
        econtent,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_SIGNED_ATTRS,
        testdata::TD3_SIGNED_ATTRS_LEN,
        testdata::TD3_DIGEST_OFFSET,
    );
}

#[test]
fn outputs_change_with_the_domain() {
    let digests = link(
        testdata::TD1_ECONTENT,
        testdata::TD1_ECONTENT_LEN,
        testdata::TD1_SIGNED_ATTRS,
        testdata::TD1_SIGNED_ATTRS_LEN,
        testdata::TD1_DIGEST_OFFSET,
    );

    let a = outputs(
        digests.econtent_hash,
        testdata::TD1_DSC_PUBKEY_X,
        testdata::TD1_DSC_PUBKEY_Y,
        testdata::TD1_SIGNATURE_R,
        testdata::TD1_SIGNATURE_S,
        7,
        1,
    );

    let b = outputs(
        digests.econtent_hash,
        testdata::TD1_DSC_PUBKEY_X,
        testdata::TD1_DSC_PUBKEY_Y,
        testdata::TD1_SIGNATURE_R,
        testdata::TD1_SIGNATURE_S,
        7,
        2,
    );

    assert(a.econtent_binding != b.econtent_binding);

    assert(a.dsc_commitment == b.dsc_commitment);

    assert(
        a.secret_binding != b.secret_binding,
        "the secret binding must differ between applications",
    );
}

#[test]
fn the_secret_binding_separates_documents() {
    let td3 = outputs(
        [0; 32],
        testdata::TD3_DSC_PUBKEY_X,
        testdata::TD3_DSC_PUBKEY_Y,
        testdata::TD3_SIGNATURE_R,
        testdata::TD3_SIGNATURE_S,
        0,
        1,
    );

    let td1 = outputs(
        [0; 32],
        testdata::TD1_DSC_PUBKEY_X,
        testdata::TD1_DSC_PUBKEY_Y,
        testdata::TD1_SIGNATURE_R,
        testdata::TD1_SIGNATURE_S,
        0,
        1,
    );

    assert(td3.secret_binding != td1.secret_binding);
}
