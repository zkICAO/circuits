//! Nullifier policy identifiers.
//!
//! A policy fixes which document fields derive a holder's scoped
//! identifier, and therefore what uniqueness the resulting nullifier
//! actually guarantees. The identifier is a public input and is hashed
//! into the nullifier, so two policies can never produce the same value
//! for the same holder, and a verifier always knows which guarantee it
//! received.
//!
//! Identifiers encode a family and a version as `family * 1000 + version`.
//! A revision of a policy takes a new version and therefore a new
//! identifier: derived values from the old policy stay distinct.
//!
//! An application must fix exactly one policy per `domain`. Accepting two
//! policies within one domain lets one holder present two different
//! nullifiers, which defeats the uniqueness the nullifier exists to
//! provide.

pub global FAMILY_DOCUMENT_NUMBER: Field = 1;

pub global FAMILY_MRZ_STABLE: Field = 2;

pub global FAMILY_NATIONAL_IDENTIFIER: Field = 3;

// Document number and issuing state. Unique per document, but a holder
// who is issued a replacement document produces a different nullifier.
pub global DOCUMENT_NUMBER_V1: Field = 1001;

// Fields that survive reissue: birth date, primary and secondary
// identifiers, nationality. Stable across replacement documents, at the
// cost of a small collision probability between distinct holders who
// share all of those values.
pub global MRZ_STABLE_V1: Field = 2001;

// A persistent identifier assigned by the issuing state, where the
// document carries one. Strongest uniqueness, available only for
// documents whose profile exposes such a field.
pub global NATIONAL_IDENTIFIER_V1: Field = 3001;

pub fn assert_supported(policy_id: Field) {
    let known = (policy_id == DOCUMENT_NUMBER_V1)
        | (policy_id == MRZ_STABLE_V1)
        | (policy_id == NATIONAL_IDENTIFIER_V1);

    assert(known, "policy: unsupported policy identifier");
}

#[test]
fn accepts_shipped_policies() {
    assert_supported(DOCUMENT_NUMBER_V1);

    assert_supported(MRZ_STABLE_V1);

    assert_supported(NATIONAL_IDENTIFIER_V1);
}

#[test(should_fail_with = "policy: unsupported policy identifier")]
fn rejects_unknown_policy() {
    assert_supported(9999);
}

#[test(should_fail_with = "policy: unsupported policy identifier")]
fn rejects_family_without_version() {
    assert_supported(FAMILY_MRZ_STABLE);
}
