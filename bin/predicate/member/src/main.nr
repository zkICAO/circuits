//! Proves a committed field is one of a set the verifier publishes, without
//! saying which one.
//!
//! The set is a Merkle tree of depth eight, which holds 256 entries and so
//! covers a list of issuing states or nationalities. Only its root is
//! public, so the verifier learns that the value is in the list and nothing
//! more.

fn main(
    length: u32,
    data: [Field; 4],
    entropy: Field,
    siblings: [Field; 4],
    set_index: u32,
    set_siblings: [Field; 8],
    field_id: pub u32,
    commitment: pub Field,
    set_root: pub Field,
    domain: pub Field,
    context: pub Field,
) {
    assert(context != 0, "predicate: context must be set");

    predicate::member(
        predicate::FieldOpening { field_id, length, data, entropy, siblings },
        commitment,
        domain,
        set_root,
        set_index,
        set_siblings,
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

/// A set holding the value at index zero, padded to depth eight.
fn set_with_the_value() -> ([Field; 8], Field) {
    let mut path: [Field; 8] = [0; 8];

    let mut current = commit::set_entry([0x55544f, 0, 0, 0]);

    path[0] = commit::set_entry([0x564e4d, 0, 0, 0]);

    current = commit::hash_pair(current, path[0]);

    for level in 1..8 {
        path[level] = (level as Field) + 500;

        current = commit::hash_pair(current, path[level]);
    }

    (path, current)
}

#[test]
fn proves_the_state_is_in_the_list() {
    let (siblings, entropy, commitment) = sample();

    let (set_siblings, set_root) = set_with_the_value();

    main(
        3,
        [0x55544f, 0, 0, 0],
        entropy,
        siblings,
        0,
        set_siblings,
        4,
        commitment,
        set_root,
        42,
        7,
    );
}

#[test(should_fail_with = "predicate: value is not in the set")]
fn rejects_a_state_outside_the_list() {
    let (siblings, entropy, commitment) = sample();

    let (set_siblings, _) = set_with_the_value();

    main(
        3,
        [0x55544f, 0, 0, 0],
        entropy,
        siblings,
        0,
        set_siblings,
        4,
        commitment,
        999,
        42,
        7,
    );
}
