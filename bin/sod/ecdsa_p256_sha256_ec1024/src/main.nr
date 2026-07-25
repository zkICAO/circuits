//! Passive Authentication for a document whose Document Signer uses ECDSA
//! over P-256 with SHA-256, with a Security Object of up to 1024 bytes.
//!
//! The public key is private here. What the verifier receives is a
//! commitment to it, which a trust circuit can match against a registry
//! without revealing which Document Signer, and therefore which issuing
//! state and batch, produced the document.

fn main(
    econtent: [u8; 1024],
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
