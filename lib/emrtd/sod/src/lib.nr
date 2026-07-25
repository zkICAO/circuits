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

use commit::{dsc_commitment, econtent_binding, hash32_to_fields, secret_binding};

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
///
/// The key and signature arrive already hashed. Their representation differs
/// by algorithm, a curve point against a modulus and its signature, and each
/// has a helper in `commit` that folds all of it. Taking the hashes here
/// rather than the raw values keeps that choice with the variant that knows
/// the algorithm, and leaves no room for one to pass a value in a shape that
/// silently drops part of it.
pub fn outputs(
    econtent_hash: [u8; 32],
    dsc_pubkey_hash: Field,
    document_secret: Field,
    dsc_salt: Field,
    domain: Field,
) -> SodOutput {
    SodOutput {
        econtent_binding: econtent_binding(hash32_to_fields(econtent_hash), domain),
        dsc_commitment: dsc_commitment(dsc_pubkey_hash, dsc_salt),
        secret_binding: secret_binding(document_secret, domain),
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

    let key = commit::pubkey_hash(testdata::TD1_DSC_PUBKEY_X, testdata::TD1_DSC_PUBKEY_Y);

    let secret = commit::document_secret(testdata::TD1_SIGNATURE_R, testdata::TD1_SIGNATURE_S);

    let a = outputs(digests.econtent_hash, key, secret, 7, 1);

    let b = outputs(digests.econtent_hash, key, secret, 7, 2);

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
        commit::pubkey_hash(testdata::TD3_DSC_PUBKEY_X, testdata::TD3_DSC_PUBKEY_Y),
        commit::document_secret(testdata::TD3_SIGNATURE_R, testdata::TD3_SIGNATURE_S),
        0,
        1,
    );

    let td1 = outputs(
        [0; 32],
        commit::pubkey_hash(testdata::TD1_DSC_PUBKEY_X, testdata::TD1_DSC_PUBKEY_Y),
        commit::document_secret(testdata::TD1_SIGNATURE_R, testdata::TD1_SIGNATURE_S),
        0,
        1,
    );

    assert(td3.secret_binding != td1.secret_binding);
}
