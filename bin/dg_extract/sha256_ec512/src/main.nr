//! Extracts one data group hash from a Security Object of up to 512 bytes
//! whose data group hashes are SHA-256.
//!
//! `dg_number` is public so a verifier states which data group the proof is
//! about, rather than trusting the prover to say afterwards.

fn main(
    econtent: [u8; 512],
    econtent_len: u32,
    oid_offset: u32,
    dg_offset: u32,
    dg_number: pub u8,
    econtent_binding: pub Field,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(context == context);

    dg_extract::extract_sha256(
        econtent,
        econtent_len,
        oid_offset,
        dg_offset,
        dg_number,
        econtent_binding,
        domain,
    )
}

#[test]
fn extracts_dg1_from_the_generated_document() {
    let domain = 42;

    let econtent_hash = hash::sha256_bounded(testdata::TD3_ECONTENT, testdata::TD3_ECONTENT_LEN);

    let binding = commit::econtent_binding(commit::hash32_to_fields(econtent_hash), domain);

    let dg_binding = main(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_OID_OFFSET,
        testdata::TD3_DG1_OFFSET,
        1,
        binding,
        domain,
        7,
    );

    let expected = commit::dg_binding(
        commit::hash32_to_fields(
            hash::sha256_bounded(testdata::TD3_DG1, testdata::TD3_DG1_LEN),
        ),
        domain,
    );

    assert(dg_binding == expected);
}
