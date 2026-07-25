//! Statements about a single committed field.
//!
//! Each one rebuilds the field's leaf, walks it to the root, and checks that
//! root against the commitment the attribute circuit published. Only then
//! does it say anything about the value, so a statement always concerns a
//! field of the document it claims to be about.
//!
//! The field identifier is public. Without it a prover could prove a
//! statement about a convenient field and let the verifier believe it was
//! about the field it asked for.

use commit::{commitment, leaf, set_entry, walk_path};

pub use commit::FieldOpening;

/// Proves the opening really is a field of the committed document. Exposed
/// because the nullifier circuit needs the same guarantee before it uses a
/// field value.
pub fn open_field(opening: FieldOpening, expected_commitment: Field, domain: Field) {
    open(opening, expected_commitment, domain);
}

fn open(opening: FieldOpening, expected_commitment: Field, domain: Field) {
    assert(opening.field_id >= 1, "predicate: field identifier out of range");

    assert(opening.field_id <= 16, "predicate: field identifier out of range");

    let value = leaf(
        opening.field_id as Field,
        opening.length as Field,
        opening.data,
        opening.entropy,
    );

    let root = walk_path(value, opening.field_id - 1, opening.siblings);

    assert(
        commitment(root, domain) == expected_commitment,
        "predicate: field is not part of the committed document",
    );
}

/// Reads the numeric value of a field, refusing anything that does not fit
/// one element, since a comparison over a split value would be meaningless.
fn numeric_value(opening: FieldOpening) -> u64 {
    assert(opening.data[1] == 0, "predicate: value does not fit one element");

    assert(opening.data[2] == 0, "predicate: value does not fit one element");

    assert(opening.data[3] == 0, "predicate: value does not fit one element");

    let value = opening.data[0] as u64;

    assert(value as Field == opening.data[0], "predicate: value is not an integer");

    value
}

/// Proves the field is within an inclusive range. A one sided bound is a
/// range with the other end at its extreme, so this covers greater than,
/// less than and between with one circuit.
pub fn compare(
    opening: FieldOpening,
    expected_commitment: Field,
    domain: Field,
    minimum: u64,
    maximum: u64,
) {
    assert(minimum <= maximum, "predicate: empty range");

    open(opening, expected_commitment, domain);

    let value = numeric_value(opening);

    assert(value >= minimum, "predicate: value below the minimum");

    assert(value <= maximum, "predicate: value above the maximum");
}

/// Proves the field is one of a set, without saying which. The set is a
/// Merkle tree the verifier publishes, so a country list of any size costs
/// only its depth.
pub fn member<let D: u32>(
    opening: FieldOpening,
    expected_commitment: Field,
    domain: Field,
    set_root: Field,
    set_index: u32,
    set_siblings: [Field; D],
) {
    open(opening, expected_commitment, domain);

    assert(
        walk_path(set_entry(opening.data), set_index, set_siblings) == set_root,
        "predicate: value is not in the set",
    );
}

/// Discloses a field verbatim. The value becomes a public input, so this is
/// the one statement that gives the verifier the field itself.
pub fn reveal(
    opening: FieldOpening,
    expected_commitment: Field,
    domain: Field,
    revealed: [Field; 4],
    revealed_length: u32,
) {
    open(opening, expected_commitment, domain);

    assert(opening.length == revealed_length, "predicate: revealed length does not match");

    for i in 0..4 {
        assert(opening.data[i] == revealed[i], "predicate: revealed value does not match");
    }
}

// A document whose field 5 holds a birth date and field 4 a nationality,
// built the way an attribute circuit builds one.
fn sample_document(domain: Field) -> ([Field; 16], Field) {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..16 {
        let id = (i as Field) + 1;

        let data: [Field; 4] = if i == 4 {
            [19740812, 0, 0, 0]
        } else if i == 3 {
            [0x55544f, 0, 0, 0]
        } else {
            [0, 0, 0, 0]
        };

        let length: Field = if i == 4 {
            8
        } else if i == 3 {
            3
        } else {
            0
        };

        leaves[i] = leaf(id, length, data, (i as Field) + 1000);
    }

    (leaves, commitment(commit::root16(leaves), domain))
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

fn birth_date_opening(leaves: [Field; 16]) -> FieldOpening {
    FieldOpening {
        field_id: 5,
        length: 8,
        data: [19740812, 0, 0, 0],
        entropy: 1004,
        siblings: siblings_for(leaves, 4),
    }
}

#[test]
fn proves_a_birth_date_is_before_a_cutoff() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    compare(birth_date_opening(leaves), c, domain, 0, 20080725);
}

#[test(should_fail_with = "predicate: value above the maximum")]
fn rejects_a_birth_date_that_is_too_recent() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    compare(birth_date_opening(leaves), c, domain, 0, 19700101);
}

#[test(should_fail_with = "predicate: field is not part of the committed document")]
fn rejects_an_opening_from_another_document() {
    let domain = 42;

    let (leaves, _) = sample_document(domain);

    let (_, other) = sample_document(43);

    compare(birth_date_opening(leaves), other, domain, 0, 20080725);
}

#[test(should_fail_with = "predicate: field is not part of the committed document")]
fn rejects_a_field_claimed_under_another_identifier() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    let mut opening = birth_date_opening(leaves);

    opening.field_id = 7;

    compare(opening, c, domain, 0, 20080725);
}

#[test]
fn proves_membership_in_a_set_of_states() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    let opening = FieldOpening {
        field_id: 4,
        length: 3,
        data: [0x55544f, 0, 0, 0],
        entropy: 1003,
        siblings: siblings_for(leaves, 3),
    };

    let entry = set_entry([0x55544f, 0, 0, 0]);

    let other = set_entry([0x564e4d, 0, 0, 0]);

    let set_root = commit::hash_pair(entry, other);

    member(opening, c, domain, set_root, 0, [other]);
}

#[test]
fn reveals_a_field_verbatim() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    let opening = FieldOpening {
        field_id: 4,
        length: 3,
        data: [0x55544f, 0, 0, 0],
        entropy: 1003,
        siblings: siblings_for(leaves, 3),
    };

    reveal(opening, c, domain, [0x55544f, 0, 0, 0], 3);
}

#[test(should_fail_with = "predicate: revealed value does not match")]
fn rejects_revealing_a_different_value() {
    let domain = 42;

    let (leaves, c) = sample_document(domain);

    let opening = FieldOpening {
        field_id: 4,
        length: 3,
        data: [0x55544f, 0, 0, 0],
        entropy: 1003,
        siblings: siblings_for(leaves, 3),
    };

    reveal(opening, c, domain, [0x564e4d, 0, 0, 0], 3);
}
