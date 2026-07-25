//! Scoped uniqueness: one value per holder per application, which an
//! application stores to recognise a repeat registration without learning
//! who registered.
//!
//! Three things go into it. The policy identifier says which fields were
//! used, and therefore what uniqueness the value actually carries. The
//! fields themselves come from the document, opened against the commitment
//! so they cannot be invented. The document secret makes the result
//! unguessable: without it the value would be a hash of public inputs and
//! printed fields, and anyone holding a copy of a document could compute
//! its holder's nullifier for any application and check whether that person
//! had registered.
//!
//! The secret is never an input a verifier sees. The Passive Authentication
//! circuit publishes a domain scoped binding to it, and this circuit proves
//! it holds the matching secret.

use commit::{nullifier as derive_nullifier, secret_binding};

use predicate::FieldOpening;

/// Uniqueness per document: the document number together with the issuing
/// state, which distinguishes documents that reuse a number across states.
///
/// A replacement document produces a different value, both because the
/// document number usually changes and because the secret is tied to the
/// signature on this document. An application that needs one value per
/// person across reissue needs a different policy and a secret that is not
/// chip bound.
pub fn document_number(
    issuing_state: FieldOpening,
    document_number_field: FieldOpening,
    expected_commitment: Field,
    secret: Field,
    expected_secret_binding: Field,
    domain: Field,
) -> Field {
    assert(issuing_state.field_id == 2, "nullifier: first opening must be the issuing state");

    assert(
        document_number_field.field_id == 3,
        "nullifier: second opening must be the document number",
    );

    predicate::open_field(issuing_state, expected_commitment, domain);

    predicate::open_field(document_number_field, expected_commitment, domain);

    assert(
        secret_binding(secret, domain) == expected_secret_binding,
        "nullifier: secret does not match the authenticated document",
    );

    let packed: [Field; 4] = [
        issuing_state.data[0],
        document_number_field.data[0],
        document_number_field.data[1],
        document_number_field.data[2],
    ];

    derive_nullifier(policy::DOCUMENT_NUMBER_V1, packed, secret, domain)
}

fn sample_document(domain: Field) -> ([Field; 16], Field) {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..16 {
        let id = (i as Field) + 1;

        let data: [Field; 4] = if i == 1 {
            [0x55544f, 0, 0, 0]
        } else if i == 2 {
            [0x4c383938393032433336, 0, 0, 0]
        } else {
            [0, 0, 0, 0]
        };

        let length: Field = if i == 1 {
            3
        } else if i == 2 {
            9
        } else {
            0
        };

        leaves[i] = commit::leaf(id, length, data, (i as Field) + 1000);
    }

    (leaves, commit::commitment(commit::root16(leaves), domain))
}

fn siblings_for(leaves: [Field; 16], index: u32) -> [Field; 4] {
    let mut level8: [Field; 8] = [0; 8];

    for i in 0..8 {
        level8[i] = commit::hash_pair(leaves[2 * i], leaves[2 * i + 1]);
    }

    let mut level4: [Field; 4] = [0; 4];

    for i in 0..4 {
        level4[i] = commit::hash_pair(level8[2 * i], level8[2 * i + 1]);
    }

    let mut level2: [Field; 2] = [0; 2];

    for i in 0..2 {
        level2[i] = commit::hash_pair(level4[2 * i], level4[2 * i + 1]);
    }

    [leaves[index ^ 1], level8[(index / 2) ^ 1], level4[(index / 4) ^ 1], level2[(index / 8) ^ 1]]
}

fn openings(leaves: [Field; 16]) -> (FieldOpening, FieldOpening) {
    (
        FieldOpening {
            field_id: 2,
            length: 3,
            data: [0x55544f, 0, 0, 0],
            entropy: 1001,
            siblings: siblings_for(leaves, 1),
        },
        FieldOpening {
            field_id: 3,
            length: 9,
            data: [0x4c383938393032433336, 0, 0, 0],
            entropy: 1002,
            siblings: siblings_for(leaves, 2),
        },
    )
}

#[test]
fn the_same_document_gives_the_same_value_within_an_application() {
    let domain = 42;

    let secret = 123456;

    let (leaves, c) = sample_document(domain);

    let (state, number) = openings(leaves);

    let binding = secret_binding(secret, domain);

    let a = document_number(state, number, c, secret, binding, domain);

    let b = document_number(state, number, c, secret, binding, domain);

    assert(a == b, "a nullifier must be deterministic");
}

#[test]
fn different_applications_give_unlinkable_values() {
    let secret = 123456;

    let (leaves_a, c_a) = sample_document(1);

    let (state_a, number_a) = openings(leaves_a);

    let a = document_number(state_a, number_a, c_a, secret, secret_binding(secret, 1), 1);

    let (leaves_b, c_b) = sample_document(2);

    let (state_b, number_b) = openings(leaves_b);

    let b = document_number(state_b, number_b, c_b, secret, secret_binding(secret, 2), 2);

    assert(a != b, "the same holder must be unlinkable across applications");
}

// The point of the secret: without a matching one, a party holding the
// printed fields still cannot produce the holder's nullifier.
#[test(should_fail_with = "nullifier: secret does not match the authenticated document")]
fn rejects_a_guessed_secret() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    let (state, number) = openings(leaves);

    let binding = secret_binding(123456, domain);

    let _ = document_number(state, number, c, 999999, binding, domain);
}

#[test]
fn a_different_secret_gives_a_different_value() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    let (state, number) = openings(leaves);

    let a = document_number(state, number, c, 111, secret_binding(111, domain), domain);

    let b = document_number(state, number, c, 222, secret_binding(222, domain), domain);

    assert(a != b);
}

#[test(should_fail_with = "nullifier: first opening must be the issuing state")]
fn rejects_openings_in_the_wrong_order() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    let (state, number) = openings(leaves);

    let secret = 123456;

    let _ = document_number(
        number,
        state,
        c,
        secret,
        secret_binding(secret, domain),
        domain,
    );
}

#[test(should_fail_with = "predicate: field is not part of the committed document")]
fn rejects_a_field_from_another_document() {
    let domain = 42;

    let (leaves, _) = sample_document(domain);

    let (_, other_commitment) = sample_document(43);

    let (state, number) = openings(leaves);

    let secret = 123456;

    let _ = document_number(
        state,
        number,
        other_commitment,
        secret,
        secret_binding(secret, domain),
        domain,
    );
}
