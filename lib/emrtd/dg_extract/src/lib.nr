//! Reads one data group hash out of the Security Object.
//!
//! Kept apart from the signature check because a document usually needs
//! more than one data group, and repeating the signature check for each
//! would repeat the most expensive part of the proof. This circuit re-hashes
//! the Security Object and matches the binding the signature circuit
//! produced, which is what ties the two together without verifying the
//! signature again.

use commit::{dg_binding, econtent_binding, hash32_to_fields};

use hash::sha256_bounded;

pub fn extract_sha256<let EC: u32>(
    econtent: [u8; EC],
    econtent_len: u32,
    oid_offset: u32,
    dg_offset: u32,
    dg_number: u8,
    expected_econtent_binding: Field,
    domain: Field,
) -> Field {
    let econtent_hash = sha256_bounded(econtent, econtent_len);

    assert(
        econtent_binding(hash32_to_fields(econtent_hash), domain) == expected_econtent_binding,
        "dg_extract: security object does not match the authenticated one",
    );

    lds::check_sha256_oid(econtent, econtent_len, oid_offset);

    let dg_hash = lds::dg_entry_sha256(econtent, econtent_len, dg_offset, dg_number);

    dg_binding(hash32_to_fields(dg_hash), domain)
}

#[test]
fn extracts_two_data_groups_from_one_security_object() {
    let domain = 42;

    let binding = td3_binding(domain);

    let dg1 = extract_sha256(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_OID_OFFSET,
        testdata::TD3_DG1_OFFSET,
        1,
        binding,
        domain,
    );

    let dg2 = extract_sha256(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_OID_OFFSET,
        testdata::TD3_DG2_OFFSET,
        2,
        binding,
        domain,
    );

    assert(dg1 != dg2, "different data groups must bind differently");
}

#[test]
fn the_extracted_hash_is_the_hash_of_the_data_group() {
    let domain = 42;

    let expected = dg_binding(
        hash32_to_fields(sha256_bounded(testdata::TD3_DG1, testdata::TD3_DG1_LEN)),
        domain,
    );

    let actual = extract_sha256(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_OID_OFFSET,
        testdata::TD3_DG1_OFFSET,
        1,
        td3_binding(domain),
        domain,
    );

    assert(actual == expected);
}

#[test(should_fail_with = "dg_extract: security object does not match the authenticated one")]
fn rejects_a_security_object_that_was_not_authenticated() {
    let domain = 42;

    let mut econtent = testdata::TD3_ECONTENT;

    econtent[testdata::TD3_DG1_OFFSET + 7] ^= 1;

    let _ = extract_sha256(
        econtent,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_OID_OFFSET,
        testdata::TD3_DG1_OFFSET,
        1,
        td3_binding(domain),
        domain,
    );
}

#[test(should_fail_with = "lds: dg entry wrong dg number")]
fn rejects_reading_an_entry_as_the_wrong_data_group() {
    let domain = 42;

    let _ = extract_sha256(
        testdata::TD3_ECONTENT,
        testdata::TD3_ECONTENT_LEN,
        testdata::TD3_OID_OFFSET,
        testdata::TD3_DG1_OFFSET,
        2,
        td3_binding(domain),
        domain,
    );
}

// Helpers for the tests above. They read the generated fixtures, which is
// why this package depends on testdata at all, and they sit here so that
// every fixture reference in the file is below the first test.

fn td3_binding(domain: Field) -> Field {
    let econtent_hash = sha256_bounded(testdata::TD3_ECONTENT, testdata::TD3_ECONTENT_LEN);

    econtent_binding(hash32_to_fields(econtent_hash), domain)
}
