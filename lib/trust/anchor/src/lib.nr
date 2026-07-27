//! Trust in the Document Signer.
//!
//! Passive Authentication proves a document was signed by some key. It says
//! nothing about whether that key belongs to a state, which is a separate
//! question and the one this answers.
//!
//! Two modes, differing in who checked what. `prove_signer_is_trusted`
//! proves the signer key is in a set the verifier published, which costs a
//! Merkle path and no signature arithmetic, and assumes whoever built the
//! set checked the certificates behind it. `prove_signer_is_certified`
//! removes that assumption by verifying the certificate in circuit, and
//! trusts only the published list of country signing keys.
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

/// Verifies the country signing key signed this Document Signer certificate,
/// that the certificate is valid on the given date, and that the country
/// signing key is one the verifier trusts.
///
/// This is the mode that removes the assumption the inclusion mode makes.
/// Nobody has to have checked a certificate off circuit: the signature over
/// it is checked here. What remains trusted is the list of country signing
/// keys, which is the trust anchor of the whole system and cannot be derived
/// from the document.
///
/// The key returned is read out of the signed certificate, so the commitment
/// it produces is a commitment to the key the authority actually certified.
pub fn prove_signer_is_certified<let N: u32, let LIMBS: u32, let MOD_BITS: u32, let D: u32>(
    tbs: [u8; N],
    tbs_len: u32,
    public_key_offset: u32,
    not_before_offset: u32,
    not_after_offset: u32,
    authority_modulus: [u128; LIMBS],
    authority_redc: [u128; LIMBS],
    authority_signature: [u128; LIMBS],
    authority_index: u32,
    authority_siblings: [Field; D],
    master_list_root: Field,
    current_yyyymmdd: u32,
    salt: Field,
) -> Field {
    rsa::verify_pkcs1_v15_sha256::<LIMBS, MOD_BITS>(
        authority_modulus,
        authority_redc,
        authority_signature,
        hash::sha256_bounded(tbs, tbs_len),
    );

    x509::assert_valid_at(
        tbs,
        tbs_len,
        not_before_offset,
        not_after_offset,
        current_yyyymmdd,
    );

    let authority_leaf = commit::modulus_hash(authority_modulus);

    assert(
        commit::walk_path(authority_leaf, authority_index, authority_siblings) == master_list_root,
        "anchor: country signing key is not in the published list",
    );

    let (x, y): ([u8; 32], [u8; 32]) = x509::ec_public_key(tbs, tbs_len, public_key_offset);

    dsc_commitment(pubkey_hash(x, y), salt)
}

fn chain_root(siblings: [Field; 4]) -> Field {
    let mut current = commit::modulus_hash(testdata::CHAIN_CSCA_MODULUS_LIMBS);

    for level in 0..4 {
        current = commit::hash_pair(current, siblings[level]);
    }

    current
}

fn chain_siblings() -> [Field; 4] {
    [11, 22, 33, 44]
}

#[test]
fn accepts_a_certificate_the_authority_signed() {
    let siblings = chain_siblings();

    let commitment = prove_signer_is_certified::<512, 18, 2048, 4>(
        testdata::CHAIN_TBS,
        testdata::CHAIN_TBS_LEN,
        testdata::CHAIN_PUBLIC_KEY_OFFSET,
        testdata::CHAIN_NOT_BEFORE_OFFSET,
        testdata::CHAIN_NOT_AFTER_OFFSET,
        testdata::CHAIN_CSCA_MODULUS_LIMBS,
        testdata::CHAIN_CSCA_REDC_LIMBS,
        testdata::CHAIN_CSCA_SIGNATURE_LIMBS,
        0,
        siblings,
        chain_root(siblings),
        20260725,
        3,
    );

    let expected = dsc_commitment(
        pubkey_hash(testdata::CHAIN_DSC_PUBKEY_X, testdata::CHAIN_DSC_PUBKEY_Y),
        3,
    );

    assert(commitment == expected, "the certified key must be the one committed to");
}

#[test(should_fail_with = "rsa: digest does not match")]
fn rejects_a_tampered_certificate() {
    let siblings = chain_siblings();

    let mut tbs = testdata::CHAIN_TBS;

    tbs[testdata::CHAIN_PUBLIC_KEY_OFFSET + 4] ^= 1;

    let _ = prove_signer_is_certified::<512, 18, 2048, 4>(
        tbs,
        testdata::CHAIN_TBS_LEN,
        testdata::CHAIN_PUBLIC_KEY_OFFSET,
        testdata::CHAIN_NOT_BEFORE_OFFSET,
        testdata::CHAIN_NOT_AFTER_OFFSET,
        testdata::CHAIN_CSCA_MODULUS_LIMBS,
        testdata::CHAIN_CSCA_REDC_LIMBS,
        testdata::CHAIN_CSCA_SIGNATURE_LIMBS,
        0,
        siblings,
        chain_root(siblings),
        20260725,
        3,
    );
}

#[test(should_fail_with = "x509: certificate has expired")]
fn rejects_an_expired_certificate() {
    let siblings = chain_siblings();

    let _ = prove_signer_is_certified::<512, 18, 2048, 4>(
        testdata::CHAIN_TBS,
        testdata::CHAIN_TBS_LEN,
        testdata::CHAIN_PUBLIC_KEY_OFFSET,
        testdata::CHAIN_NOT_BEFORE_OFFSET,
        testdata::CHAIN_NOT_AFTER_OFFSET,
        testdata::CHAIN_CSCA_MODULUS_LIMBS,
        testdata::CHAIN_CSCA_REDC_LIMBS,
        testdata::CHAIN_CSCA_SIGNATURE_LIMBS,
        0,
        siblings,
        chain_root(siblings),
        20310101,
        3,
    );
}

#[test(should_fail_with = "anchor: country signing key is not in the published list")]
fn rejects_an_authority_outside_the_list() {
    let siblings = chain_siblings();

    let _ = prove_signer_is_certified::<512, 18, 2048, 4>(
        testdata::CHAIN_TBS,
        testdata::CHAIN_TBS_LEN,
        testdata::CHAIN_PUBLIC_KEY_OFFSET,
        testdata::CHAIN_NOT_BEFORE_OFFSET,
        testdata::CHAIN_NOT_AFTER_OFFSET,
        testdata::CHAIN_CSCA_MODULUS_LIMBS,
        testdata::CHAIN_CSCA_REDC_LIMBS,
        testdata::CHAIN_CSCA_SIGNATURE_LIMBS,
        0,
        siblings,
        999,
        20260725,
        3,
    );
}
