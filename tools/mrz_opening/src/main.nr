//! Produces the witness a predicate proof needs for one field.
//!
//! A predicate opens a field against the commitment an attribute proof
//! published, which needs that field's value, its blinding factor and its
//! Merkle path. All three come from the same derivation the attribute circuit
//! runs, so recomputing them outside would mean a second implementation that
//! could drift.
//!
//! This is a tool, not part of the protocol. It is executed to solve a
//! witness, never proved. Everything it returns is private material the
//! holder already holds, and a proof would publish it, which is exactly what
//! the commitment exists to prevent. Nothing should generate a verification
//! key for it, and it lives outside `bin/` so it is not mistaken for a
//! circuit. Noir requires the return of `main` to be public, which is why it
//! is marked so here and is not a statement about the protocol.

/// Which machine readable zone layout the data group holds, by the number
/// Doc 9303 gives it. The three profiles commit the same field identifiers
/// but read them at different offsets, so an opening has to be produced by
/// the profile that produced the commitment.
pub global LAYOUT_TD1: u32 = 1;

pub global LAYOUT_TD2: u32 = 2;

pub global LAYOUT_TD3: u32 = 3;

fn main(
    dg1: [u8; 128],
    dg1_len: u32,
    session_salt: Field,
    domain: Field,
    current_yyyymmdd: u32,
    field_id: u32,
    layout: u32,
) -> pub ([Field; 4], u32, Field, [Field; 4]) {
    assert(
        (layout == LAYOUT_TD1) | (layout == LAYOUT_TD2) | (layout == LAYOUT_TD3),
        "mrz_opening: unknown layout",
    );

    let opening = if layout == LAYOUT_TD3 {
        attributes::td3_opening(
            dg1,
            dg1_len,
            current_yyyymmdd,
            session_salt,
            domain,
            field_id,
        )
    } else if layout == LAYOUT_TD2 {
        attributes::td2_opening(
            dg1,
            dg1_len,
            current_yyyymmdd,
            session_salt,
            domain,
            field_id,
        )
    } else {
        attributes::td1_opening(
            dg1,
            dg1_len,
            current_yyyymmdd,
            session_salt,
            domain,
            field_id,
        )
    };

    (opening.data, opening.length, opening.entropy, opening.siblings)
}

// A branch that is not taken must not fire its layout's assertions, or a
// passport could never get an opening while the card branch exists. This is
// a property of how the compiler predicates conditionals, so it is checked
// rather than assumed, once per layout.
#[test]
fn each_layout_opens_its_own_document() {
    let td3 = main(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        123456789,
        42,
        20260725,
        4,
        LAYOUT_TD3,
    );

    assert(td3.1 == 3, "the nationality is three characters");

    let td2 = main(
        testdata::TD2_DG1,
        testdata::TD2_DG1_LEN,
        123456789,
        42,
        20260725,
        4,
        LAYOUT_TD2,
    );

    assert(td2.1 == 3);

    let td1 = main(
        testdata::TD1_DG1,
        testdata::TD1_DG1_LEN,
        123456789,
        42,
        20260725,
        4,
        LAYOUT_TD1,
    );

    assert(td1.1 == 3);

    // The same field of three different documents, so the openings differ.
    assert((td3.0[0] != td2.0[0]) | (td3.2 != td2.2));
}

#[test(should_fail_with = "mrz_opening: unknown layout")]
fn rejects_a_layout_that_does_not_exist() {
    let _ = main(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        123456789,
        42,
        20260725,
        4,
        9,
    );
}
