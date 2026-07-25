//! Commits the fields of an identity card machine readable zone, for a
//! document whose Security Object hashes data groups with SHA-256.
//!
//! Same shape as the passport profile; the layouts differ only in where the
//! standard puts each field.

fn main(
    dg1: [u8; 128],
    dg1_len: u32,
    session_salt: Field,
    dg_binding: pub Field,
    current_yyyymmdd: pub u32,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(context != 0, "attributes: context must be set");

    let out = attributes::td1(
        dg1,
        dg1_len,
        dg_binding,
        current_yyyymmdd,
        session_salt,
        domain,
    );

    out.commitment
}

#[test]
fn commits_the_generated_card() {
    let domain = 42;

    let binding = commit::dg_binding(
        commit::hash32_to_fields(
            hash::sha256_bounded(testdata::TD1_DG1, testdata::TD1_DG1_LEN),
        ),
        domain,
    );

    let commitment = main(
        testdata::TD1_DG1,
        testdata::TD1_DG1_LEN,
        1234,
        binding,
        20260725,
        domain,
        7,
    );

    assert(commitment != 0);
}

// The layouts must not be interchangeable: a card read as a passport, or the
// reverse, has to fail rather than produce a commitment over shifted fields.
#[test(should_fail_with = "attributes: unexpected dg1 length")]
fn rejects_a_passport_read_as_a_card() {
    let domain = 42;

    let binding = commit::dg_binding(
        commit::hash32_to_fields(
            hash::sha256_bounded(testdata::TD3_DG1, testdata::TD3_DG1_LEN),
        ),
        domain,
    );

    let _ = main(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        1234,
        binding,
        20260725,
        domain,
        7,
    );
}
