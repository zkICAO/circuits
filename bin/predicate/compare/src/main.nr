//! Proves a committed numeric field lies within an inclusive range,
//! revealing only the range.
//!
//! One circuit covers over, under and between: a one sided bound is a range
//! whose other end sits at the extreme. An age check is a range on the birth
//! date, and an expiry check is a range on the expiry date.

fn main(
    length: u32,
    data: [Field; 4],
    entropy: Field,
    siblings: [Field; 4],
    field_id: pub u32,
    commitment: pub Field,
    minimum: pub u64,
    maximum: pub u64,
    domain: pub Field,
    context: pub Field,
) {
    assert(context != 0, "predicate: context must be set");

    assert(domain != 0, "predicate: domain must be set");

    predicate::compare(
        predicate::FieldOpening { field_id, length, data, entropy, siblings },
        commitment,
        domain,
        minimum,
        maximum,
    );
}

fn sample() -> ([Field; 4], Field, Field) {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..16 {
        let data: [Field; 4] = if i == 4 {
            [19740812, 0, 0, 0]
        } else {
            [0, 0, 0, 0]
        };

        let length: Field = if i == 4 { 8 } else { 0 };

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

    let siblings: [Field; 4] = [leaves[5], level8[3], level4[0], level2[1]];

    (siblings, 1004, commit::commitment(commit::root16(leaves), 42))
}

// Born on or before this date, which is how an application asks whether the
// holder is old enough without asking when they were born.
#[test]
fn proves_a_birth_date_is_before_a_cutoff() {
    let (siblings, entropy, commitment) = sample();

    main(
        8,
        [19740812, 0, 0, 0],
        entropy,
        siblings,
        5,
        commitment,
        0,
        20080725,
        42,
        7,
    );
}

#[test(should_fail_with = "predicate: value above the maximum")]
fn rejects_a_holder_who_is_too_young() {
    let (siblings, entropy, commitment) = sample();

    main(
        8,
        [19740812, 0, 0, 0],
        entropy,
        siblings,
        5,
        commitment,
        0,
        19700101,
        42,
        7,
    );
}

#[test(should_fail_with = "predicate: context must be set")]
fn rejects_an_unset_context() {
    let (siblings, entropy, commitment) = sample();

    main(
        8,
        [19740812, 0, 0, 0],
        entropy,
        siblings,
        5,
        commitment,
        0,
        20080725,
        42,
        0,
    );
}
