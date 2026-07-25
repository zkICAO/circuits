//! Proves the Document Signer that signed a document is one the verifier
//! trusts, against a published set of accepted signer keys.
//!
//! Depth sixteen holds 65536 keys, which is well above the number of
//! document signer certificates in circulation.
//!
//! The output is the same commitment Passive Authentication publishes. A
//! verifier requires the two to be equal, which is what makes this proof
//! about the key that actually signed the document rather than about some
//! other trusted key.

fn main(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    salt: Field,
    index: u32,
    siblings: [Field; 16],
    registry_root: pub Field,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(context != 0, "anchor: context must be set");

    assert(domain != 0, "anchor: domain must be set");

    anchor::prove_signer_is_trusted(pubkey_x, pubkey_y, salt, registry_root, index, siblings)
}

fn sample() -> ([u8; 32], [u8; 32], [Field; 16], Field) {
    let mut x: [u8; 32] = [0; 32];

    let mut y: [u8; 32] = [0; 32];

    for i in 0..32 {
        x[i] = (i as u8) + 1;

        y[i] = (i as u8) + 40;
    }

    let mut siblings: [Field; 16] = [0; 16];

    let mut current = commit::pubkey_hash(x, y);

    for level in 0..16 {
        siblings[level] = (level as Field) + 700;

        current = commit::hash_pair(current, siblings[level]);
    }

    (x, y, siblings, current)
}

#[test]
fn accepts_a_published_signer() {
    let (x, y, siblings, root) = sample();

    let commitment = main(x, y, 9, 0, siblings, root, 42, 7);

    assert(commitment == commit::dsc_commitment(commit::pubkey_hash(x, y), 9));
}

#[test(should_fail_with = "anchor: signer key is not in the published set")]
fn rejects_an_unpublished_signer() {
    let (x, mut y, siblings, root) = sample();

    y[31] ^= 1;

    let _ = main(x, y, 9, 0, siblings, root, 42, 7);
}

#[test(should_fail_with = "anchor: context must be set")]
fn rejects_an_unset_context() {
    let (x, y, siblings, root) = sample();

    let _ = main(x, y, 9, 0, siblings, root, 42, 0);
}
