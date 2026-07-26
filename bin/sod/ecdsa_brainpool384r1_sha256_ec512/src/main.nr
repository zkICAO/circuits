//! Passive Authentication for a document whose Document Signer uses ECDSA
//! over Brainpool P-384r1 with SHA-256, with a Security Object of up to 512 bytes.
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
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
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

    sig::verify_ecdsa_brainpool384r1(
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
        testdata::BRAINPOOL384_ECONTENT,
        testdata::BRAINPOOL384_ECONTENT_LEN,
        testdata::BRAINPOOL384_SIGNED_ATTRS,
        testdata::BRAINPOOL384_SIGNED_ATTRS_LEN,
        testdata::BRAINPOOL384_DIGEST_OFFSET,
        testdata::BRAINPOOL384_DSC_PUBKEY_X,
        testdata::BRAINPOOL384_DSC_PUBKEY_Y,
        testdata::BRAINPOOL384_SIGNATURE_R,
        testdata::BRAINPOOL384_SIGNATURE_S,
        11,
        22,
        33,
    );
}

#[test(should_fail_with = "sod: domain must be set")]
fn rejects_an_unset_domain() {
    let _ = main(
        testdata::BRAINPOOL384_ECONTENT,
        testdata::BRAINPOOL384_ECONTENT_LEN,
        testdata::BRAINPOOL384_SIGNED_ATTRS,
        testdata::BRAINPOOL384_SIGNED_ATTRS_LEN,
        testdata::BRAINPOOL384_DIGEST_OFFSET,
        testdata::BRAINPOOL384_DSC_PUBKEY_X,
        testdata::BRAINPOOL384_DSC_PUBKEY_Y,
        testdata::BRAINPOOL384_SIGNATURE_R,
        testdata::BRAINPOOL384_SIGNATURE_S,
        11,
        0,
        33,
    );
}

// A signature is over one Security Object. Changing the object after the
// fact leaves the digest link intact only if the signed attributes are
// changed too, and then the signature does not verify.
#[test(should_fail)]
fn rejects_a_signature_over_another_security_object() {
    let mut econtent = testdata::BRAINPOOL384_ECONTENT;

    econtent[testdata::BRAINPOOL384_DG2_OFFSET + 7] ^= 1;

    let _ = main(
        econtent,
        testdata::BRAINPOOL384_ECONTENT_LEN,
        testdata::BRAINPOOL384_SIGNED_ATTRS,
        testdata::BRAINPOOL384_SIGNED_ATTRS_LEN,
        testdata::BRAINPOOL384_DIGEST_OFFSET,
        testdata::BRAINPOOL384_DSC_PUBKEY_X,
        testdata::BRAINPOOL384_DSC_PUBKEY_Y,
        testdata::BRAINPOOL384_SIGNATURE_R,
        testdata::BRAINPOOL384_SIGNATURE_S,
        7,
        42,
        99,
    );
}
