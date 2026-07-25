//! Commits the fields of a passport machine readable zone, for a document
//! whose Security Object hashes data groups with SHA-256.
//!
//! Dates are read here but not published. They go into the commitment, and
//! a predicate proof is what later says something about them, so the
//! verifier learns a statement rather than a birth date.
//!
//! `current_yyyymmdd` is public because it decides how a two digit year
//! resolves. A prover free to choose it could move a birth date by a
//! century.

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

    assert(domain != 0, "attributes: domain must be set");

    let out = attributes::td3(
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
fn commits_the_generated_passport() {
    let domain = 42;

    let binding = commit::dg_binding(
        commit::hash32_to_fields(
            hash::sha256_bounded(testdata::TD3_DG1, testdata::TD3_DG1_LEN),
        ),
        domain,
    );

    let a = main(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        1234,
        binding,
        20260725,
        domain,
        7,
    );

    let b = main(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        5678,
        binding,
        20260725,
        domain,
        7,
    );

    assert(a != b, "a fresh session salt must give a fresh commitment");
}

#[test(should_fail_with = "attributes: context must be set")]
fn rejects_an_unset_context() {
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
        0,
    );
}
