//! Trust in the Document Signer.
//!
//! Passive Authentication proves a document was signed by some key. It says
//! nothing about whether that key belongs to a state, which is a separate
//! question and the one this answers.
//!
//! The mode here proves the signer key is in a set the verifier published,
//! which costs a Merkle path and no signature arithmetic. What it assumes is
//! that whoever built the set checked the certificates behind it. Verifying
//! the country signing certificate in circuit instead removes that
//! assumption and is not implemented.
//!
//! The proof does not reveal which signer. Both this circuit and Passive
//! Authentication publish a salted commitment to the key rather than the key
//! or its hash, so a verifier learns that the signer is trusted without
//! learning which state or which issuing batch produced the document, which
//! a bare key hash would give away and which would link two holders whose
//! documents share a signer.

use commit::{dsc_commitment, pubkey_hash, walk_path};

/// Proves the signer key sits in the published set and returns the same
/// commitment Passive Authentication publishes, so a verifier can require the
/// two to be equal.
pub fn prove_signer_is_trusted<let K: u32, let D: u32>(
    pubkey_x: [u8; K],
    pubkey_y: [u8; K],
    salt: Field,
    registry_root: Field,
    index: u32,
    siblings: [Field; D],
) -> Field {
    let leaf = pubkey_hash(pubkey_x, pubkey_y);

    assert(
        walk_path(leaf, index, siblings) == registry_root,
        "anchor: signer key is not in the published set",
    );

    dsc_commitment(leaf, salt)
}

fn sample_key() -> ([u8; 32], [u8; 32]) {
    let mut x: [u8; 32] = [0; 32];

    let mut y: [u8; 32] = [0; 32];

    for i in 0..32 {
        x[i] = (i as u8) + 1;

        y[i] = (i as u8) + 40;
    }

    (x, y)
}

// A set holding the key at index zero, padded out to the given depth.
fn registry_containing(leaf: Field) -> ([Field; 8], Field) {
    let mut siblings: [Field; 8] = [0; 8];

    let mut current = leaf;

    for level in 0..8 {
        siblings[level] = (level as Field) + 700;

        current = commit::hash_pair(current, siblings[level]);
    }

    (siblings, current)
}

#[test]
fn accepts_a_signer_in_the_set() {
    let (x, y) = sample_key();

    let (siblings, root) = registry_containing(pubkey_hash(x, y));

    let commitment = prove_signer_is_trusted(x, y, 5, root, 0, siblings);

    assert(commitment == dsc_commitment(pubkey_hash(x, y), 5));
}

#[test(should_fail_with = "anchor: signer key is not in the published set")]
fn rejects_a_signer_outside_the_set() {
    let (x, mut y) = sample_key();

    let (siblings, root) = registry_containing(pubkey_hash(x, y));

    y[0] ^= 1;

    let _ = prove_signer_is_trusted(x, y, 5, root, 0, siblings);
}

// The commitment is what ties this proof to Passive Authentication, so the
// same key under a different salt must not be mistaken for a match.
#[test]
fn the_salt_hides_which_signer_it_was() {
    let (x, y) = sample_key();

    let (siblings, root) = registry_containing(pubkey_hash(x, y));

    let a = prove_signer_is_trusted(x, y, 1, root, 0, siblings);

    let b = prove_signer_is_trusted(x, y, 2, root, 0, siblings);

    assert(a != b);
}

#[test(should_fail_with = "anchor: signer key is not in the published set")]
fn rejects_a_path_walked_from_the_wrong_position() {
    let (x, y) = sample_key();

    let (siblings, root) = registry_containing(pubkey_hash(x, y));

    let _ = prove_signer_is_trusted(x, y, 5, root, 1, siblings);
}
