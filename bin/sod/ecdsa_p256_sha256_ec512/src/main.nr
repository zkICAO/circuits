//! Passive Authentication for a document whose Document Signer uses ECDSA
//! over P-256 with SHA-256, with a Security Object of up to 512 bytes.
//!
//! The public key is private here. What the verifier receives is a
//! commitment to it, which a trust circuit can match against a registry
//! without revealing which Document Signer, and therefore which issuing
//! state and batch, produced the document.

fn main(
    econtent: [u8; 512],
    econtent_len: u32,
    signed_attrs: [u8; 256],
    signed_attrs_len: u32,
    digest_offset: u32,
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    dsc_salt: Field,
    domain: pub Field,
    context: pub Field,
) -> pub (Field, Field, Field) {
    // Scopes the proof to one session so it cannot be replayed in another,
    // and stays out of every derived value so those remain stable across
    // sessions. Requiring it to be non-zero puts a real constraint on it,
    // rather than leaving it an input the circuit never reads.
    assert(context != 0, "sod: context must be set");

    assert(domain != 0, "sod: domain must be set");

    let digests = sod::link(
        econtent,
        econtent_len,
        signed_attrs,
        signed_attrs_len,
        digest_offset,
    );

    sig::verify_ecdsa_p256(
        pubkey_x,
        pubkey_y,
        digests.signed_attrs_hash,
        signature_r,
        signature_s,
    );

    let out = sod::outputs(
        digests.econtent_hash,
        commit::pubkey_hash(pubkey_x, pubkey_y),
        commit::document_secret(signature_r, signature_s),
        dsc_salt,
        domain,
    );

    (out.econtent_binding, out.dsc_commitment, out.secret_binding)
}

#[test]
fn verifies_the_generated_td3_document() {
    let _ = main(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_SIGNED_ATTRS,
        testdata::TD3_SIGNED_ATTRS_LEN,
        testdata::TD3_DIGEST_OFFSET,
        testdata::TD3_DSC_PUBKEY_X,
        testdata::TD3_DSC_PUBKEY_Y,
        testdata::TD3_SIGNATURE_R,
        testdata::TD3_SIGNATURE_S,
        11,
        22,
        33,
    );
}

#[test]
fn verifies_the_generated_td1_document() {
    let _ = main(
        testdata::TD1_ECONTENT,
        testdata::TD1_ECONTENT_LEN,
        testdata::TD1_SIGNED_ATTRS,
        testdata::TD1_SIGNED_ATTRS_LEN,
        testdata::TD1_DIGEST_OFFSET,
        testdata::TD1_DSC_PUBKEY_X,
        testdata::TD1_DSC_PUBKEY_Y,
        testdata::TD1_SIGNATURE_R,
        testdata::TD1_SIGNATURE_S,
        11,
        22,
        33,
    );
}

#[test(should_fail_with = "sig: ecdsa p256 verification failed")]
fn rejects_a_signature_from_another_document() {
    let _ = main(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_SIGNED_ATTRS,
        testdata::TD3_SIGNED_ATTRS_LEN,
        testdata::TD3_DIGEST_OFFSET,
        testdata::TD3_DSC_PUBKEY_X,
        testdata::TD3_DSC_PUBKEY_Y,
        testdata::TD1_SIGNATURE_R,
        testdata::TD1_SIGNATURE_S,
        11,
        22,
        33,
    );
}

#[test(should_fail_with = "sod: security object digest does not match the signed attribute")]
fn rejects_signed_attributes_from_another_document() {
    let _ = main(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD1_SIGNED_ATTRS,
        testdata::TD1_SIGNED_ATTRS_LEN,
        testdata::TD1_DIGEST_OFFSET,
        testdata::TD3_DSC_PUBKEY_X,
        testdata::TD3_DSC_PUBKEY_Y,
        testdata::TD3_SIGNATURE_R,
        testdata::TD3_SIGNATURE_S,
        11,
        22,
        33,
    );
}

#[test(should_fail_with = "sod: domain must be set")]
fn rejects_an_unset_domain() {
    let _ = main(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_SIGNED_ATTRS,
        testdata::TD3_SIGNED_ATTRS_LEN,
        testdata::TD3_DIGEST_OFFSET,
        testdata::TD3_DSC_PUBKEY_X,
        testdata::TD3_DSC_PUBKEY_Y,
        testdata::TD3_SIGNATURE_R,
        testdata::TD3_SIGNATURE_S,
        11,
        0,
        33,
    );
}
