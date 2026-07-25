//! Discloses one committed field verbatim.
//!
//! The value is a public input, so unlike the other predicates this one
//! hands the verifier the field itself. Everything else in the document
//! stays behind the commitment.

fn main(
    length: u32,
    data: [Field; 4],
    entropy: Field,
    siblings: [Field; 4],
    field_id: pub u32,
    commitment: pub Field,
    revealed: pub [Field; 4],
    revealed_length: pub u32,
    domain: pub Field,
    context: pub Field,
) {
    assert(context != 0, "predicate: context must be set");

    predicate::reveal(
        predicate::FieldOpening { field_id, length, data, entropy, siblings },
        commitment,
        domain,
        revealed,
        revealed_length,
    );
}

fn sample() -> ([Field; 4], Field, Field) {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..16 {
        let data: [Field; 4] = if i == 3 {
            [0x55544f, 0, 0, 0]
        } else {
            [0, 0, 0, 0]
        };

        let length: Field = if i == 3 { 3 } else { 0 };

        leaves[i] = commit::leaf((i as Field) + 1, length, data, (i as Field) + 1000);
    }

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

    let siblings: [Field; 4] = [leaves[2], level8[0], level4[1], level2[1]];

    (siblings, 1003, commit::commitment(commit::root16(leaves), 42))
}

#[test]
fn discloses_the_issuing_state() {
    let (siblings, entropy, commitment) = sample();

    main(
        3,
        [0x55544f, 0, 0, 0],
        entropy,
        siblings,
        4,
        commitment,
        [0x55544f, 0, 0, 0],
        3,
        42,
        7,
    );
}

#[test(should_fail_with = "predicate: revealed value does not match")]
fn rejects_disclosing_a_different_value() {
    let (siblings, entropy, commitment) = sample();

    main(
        3,
        [0x55544f, 0, 0, 0],
        entropy,
        siblings,
        4,
        commitment,
        [0x564e4d, 0, 0, 0],
        3,
        42,
        7,
    );
}
