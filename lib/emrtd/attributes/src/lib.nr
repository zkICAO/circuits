//! Turns one data group into a commitment over its individual fields, so a
//! later proof can speak about a single field without revealing the rest.
//!
//! This is the machine readable zone profile. Doc 9303 requires DG1 on every
//! compliant document, and defines its layout in a small fixed set of forms,
//! so one profile covers documents from any issuing state. Fields a state
//! defines for itself live in other data groups and get their own profiles.
//!
//! Field identifiers are fixed here and shared with the predicate circuits,
//! which is what stops a proof about one field being replayed as a proof
//! about another.

use commit::{commitment, dg_binding, entropy_seed, field_entropy, hash32_to_fields, leaf, root16};

use hash::sha256_bounded;

pub global FIELD_DOCUMENT_CODE: u32 = 1;

pub global FIELD_ISSUING_STATE: u32 = 2;

pub global FIELD_DOCUMENT_NUMBER: u32 = 3;

pub global FIELD_NATIONALITY: u32 = 4;

pub global FIELD_BIRTH_DATE: u32 = 5;

pub global FIELD_SEX: u32 = 6;

pub global FIELD_EXPIRY_DATE: u32 = 7;

pub global FIELD_NAME: u32 = 8;

pub global FIELD_OPTIONAL_DATA: u32 = 9;

pub global FIELD_COUNT: u32 = 16;

// DG1 is the machine readable zone under two nested templates: `61 len`
// then `5F1F len`, so the characters start five bytes in for the lengths
// these documents use.
pub global DG1_MRZ_OFFSET: u32 = 5;

pub struct Attributes {
    pub dg_binding: Field,
    pub commitment: Field,
    pub birth_date: u32,
    pub expiry_date: u32,
}

struct FieldValue {
    id: u32,
    length: u32,
    data: [Field; 4],
}

fn empty_field(id: u32) -> FieldValue {
    FieldValue { id, length: 0, data: [0; 4] }
}

fn build_leaves(values: [FieldValue; 16], seed: Field) -> [Field; 16] {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..FIELD_COUNT {
        let value = values[i];

        leaves[i] = leaf(
            value.id as Field,
            value.length as Field,
            value.data,
            field_entropy(seed, value.id as Field),
        );
    }

    leaves
}

fn build_commitment(values: [FieldValue; 16], seed: Field, domain: Field) -> Field {
    commitment(root16(build_leaves(values, seed)), domain)
}

/// The opening for one field, derived from the same leaves the commitment is
/// built from. Used by the witness tool; a predicate takes this and proves it
/// against the commitment.
fn build_opening(values: [FieldValue; 16], seed: Field, field_id: u32) -> commit::FieldOpening {
    assert(field_id >= 1, "attributes: field identifier out of range");

    assert(field_id <= FIELD_COUNT, "attributes: field identifier out of range");

    let leaves = build_leaves(values, seed);

    let index = field_id - 1;

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

    let value = values[index];

    commit::FieldOpening {
        field_id,
        length: value.length,
        data: value.data,
        entropy: field_entropy(seed, value.id as Field),
        siblings: [
            leaves[index ^ 1],
            level8[(index / 2) ^ 1],
            level4[(index / 4) ^ 1],
            level2[(index / 8) ^ 1],
        ],
    }
}

fn check_dg1_template<let N: u32>(dg1: [u8; N], dg1_len: u32, mrz_len: u32) {
    assert(dg1_len <= N, "attributes: dg1 length exceeds buffer");

    assert(dg1_len == DG1_MRZ_OFFSET + mrz_len, "attributes: unexpected dg1 length");

    assert(dg1[0] == 0x61, "attributes: dg1 is missing its template tag");

    assert(dg1[1] as u32 == mrz_len + 3, "attributes: dg1 template length mismatch");

    assert(dg1[2] == 0x5f, "attributes: missing machine readable zone tag");

    assert(dg1[3] == 0x1f, "attributes: missing machine readable zone tag");

    assert(dg1[4] as u32 == mrz_len, "attributes: machine readable zone length mismatch");
}

struct Parsed {
    values: [FieldValue; 16],
    seed: Field,
    binding: Field,
    birth_date: u32,
    expiry_date: u32,
}

/// TD3 is the passport layout: two lines of 44 characters.
pub fn td3<let N: u32>(
    dg1: [u8; N],
    dg1_len: u32,
    expected_dg_binding: Field,
    current_yyyymmdd: u32,
    session_salt: Field,
    domain: Field,
) -> Attributes {
    let parsed = td3_parse(dg1, dg1_len, current_yyyymmdd, session_salt, domain);

    assert(
        parsed.binding == expected_dg_binding,
        "attributes: data group was not the authenticated one",
    );

    Attributes {
        dg_binding: parsed.binding,
        commitment: build_commitment(parsed.values, parsed.seed, domain),
        birth_date: parsed.birth_date,
        expiry_date: parsed.expiry_date,
    }
}

/// The opening for one field of a passport, for the witness tool. It runs the
/// same parse, so an opening cannot describe a field differently from the way
/// the commitment committed to it.
pub fn td3_opening<let N: u32>(
    dg1: [u8; N],
    dg1_len: u32,
    current_yyyymmdd: u32,
    session_salt: Field,
    domain: Field,
    field_id: u32,
) -> commit::FieldOpening {
    let parsed = td3_parse(dg1, dg1_len, current_yyyymmdd, session_salt, domain);

    build_opening(parsed.values, parsed.seed, field_id)
}

fn td3_parse<let N: u32>(
    dg1: [u8; N],
    dg1_len: u32,
    current_yyyymmdd: u32,
    session_salt: Field,
    domain: Field,
) -> Parsed {
    check_dg1_template(dg1, dg1_len, mrz::TD3_MRZ_BYTES);

    let dg_hash = sha256_bounded(dg1, dg1_len);

    let dg_hash_fields = hash32_to_fields(dg_hash);

    let binding = dg_binding(dg_hash_fields, domain);

    let mut characters: [u8; 88] = [0; 88];

    for i in 0..mrz::TD3_MRZ_BYTES {
        characters[i] = dg1[DG1_MRZ_OFFSET + i];
    }

    mrz::td3_validate(characters);

    let birth_date =
        mrz::birth_date_to_int(mrz::copy(characters, mrz::TD3_BIRTH_DATE), current_yyyymmdd);

    let expiry_date = mrz::expiry_date_to_int(mrz::copy(characters, mrz::TD3_EXPIRY_DATE));

    let mut values: [FieldValue; 16] = [empty_field(0); 16];

    for i in 0..FIELD_COUNT {
        values[i] = empty_field(i + 1);
    }

    values[FIELD_DOCUMENT_CODE - 1] = FieldValue {
        id: FIELD_DOCUMENT_CODE,
        length: 2,
        data: normalize::pack_to_4(characters, 0, 2),
    };

    values[FIELD_ISSUING_STATE - 1] = FieldValue {
        id: FIELD_ISSUING_STATE,
        length: 3,
        data: normalize::pack_to_4(characters, mrz::TD3_ISSUING_STATE, 3),
    };

    values[FIELD_DOCUMENT_NUMBER - 1] = FieldValue {
        id: FIELD_DOCUMENT_NUMBER,
        length: 9,
        data: normalize::pack_to_4(characters, mrz::TD3_DOC_NUMBER, 9),
    };

    values[FIELD_NATIONALITY - 1] = FieldValue {
        id: FIELD_NATIONALITY,
        length: 3,
        data: normalize::pack_to_4(characters, mrz::TD3_NATIONALITY, 3),
    };

    values[FIELD_BIRTH_DATE - 1] =
        FieldValue { id: FIELD_BIRTH_DATE, length: 8, data: [birth_date as Field, 0, 0, 0] };

    values[FIELD_SEX - 1] = FieldValue {
        id: FIELD_SEX,
        length: 1,
        data: normalize::pack_to_4(characters, mrz::TD3_SEX, 1),
    };

    values[FIELD_EXPIRY_DATE - 1] =
        FieldValue { id: FIELD_EXPIRY_DATE, length: 8, data: [expiry_date as Field, 0, 0, 0] };

    values[FIELD_NAME - 1] = FieldValue {
        id: FIELD_NAME,
        length: 39,
        data: normalize::pack_to_4(characters, mrz::TD3_NAME, 39),
    };

    values[FIELD_OPTIONAL_DATA - 1] = FieldValue {
        id: FIELD_OPTIONAL_DATA,
        length: 14,
        data: normalize::pack_to_4(characters, mrz::TD3_OPTIONAL, 14),
    };

    Parsed {
        values,
        seed: entropy_seed(dg_hash_fields, domain, session_salt),
        binding,
        birth_date,
        expiry_date,
    }
}

/// TD1 is the card layout: three lines of 30 characters.
pub fn td1<let N: u32>(
    dg1: [u8; N],
    dg1_len: u32,
    expected_dg_binding: Field,
    current_yyyymmdd: u32,
    session_salt: Field,
    domain: Field,
) -> Attributes {
    check_dg1_template(dg1, dg1_len, mrz::TD1_MRZ_BYTES);

    let dg_hash = sha256_bounded(dg1, dg1_len);

    let dg_hash_fields = hash32_to_fields(dg_hash);

    let binding = dg_binding(dg_hash_fields, domain);

    assert(binding == expected_dg_binding, "attributes: data group was not the authenticated one");

    let mut characters: [u8; 90] = [0; 90];

    for i in 0..mrz::TD1_MRZ_BYTES {
        characters[i] = dg1[DG1_MRZ_OFFSET + i];
    }

    mrz::td1_validate(characters);

    let birth_date =
        mrz::birth_date_to_int(mrz::copy(characters, mrz::TD1_BIRTH_DATE), current_yyyymmdd);

    let expiry_date = mrz::expiry_date_to_int(mrz::copy(characters, mrz::TD1_EXPIRY_DATE));

    let mut values: [FieldValue; 16] = [empty_field(0); 16];

    for i in 0..FIELD_COUNT {
        values[i] = empty_field(i + 1);
    }

    values[FIELD_DOCUMENT_CODE - 1] = FieldValue {
        id: FIELD_DOCUMENT_CODE,
        length: 2,
        data: normalize::pack_to_4(characters, 0, 2),
    };

    values[FIELD_ISSUING_STATE - 1] = FieldValue {
        id: FIELD_ISSUING_STATE,
        length: 3,
        data: normalize::pack_to_4(characters, mrz::TD1_ISSUING_STATE, 3),
    };

    values[FIELD_DOCUMENT_NUMBER - 1] = FieldValue {
        id: FIELD_DOCUMENT_NUMBER,
        length: 9,
        data: normalize::pack_to_4(characters, mrz::TD1_DOC_NUMBER, 9),
    };

    values[FIELD_NATIONALITY - 1] = FieldValue {
        id: FIELD_NATIONALITY,
        length: 3,
        data: normalize::pack_to_4(characters, mrz::TD1_NATIONALITY, 3),
    };

    values[FIELD_BIRTH_DATE - 1] =
        FieldValue { id: FIELD_BIRTH_DATE, length: 8, data: [birth_date as Field, 0, 0, 0] };

    values[FIELD_SEX - 1] = FieldValue {
        id: FIELD_SEX,
        length: 1,
        data: normalize::pack_to_4(characters, mrz::TD1_SEX, 1),
    };

    values[FIELD_EXPIRY_DATE - 1] =
        FieldValue { id: FIELD_EXPIRY_DATE, length: 8, data: [expiry_date as Field, 0, 0, 0] };

    values[FIELD_NAME - 1] = FieldValue {
        id: FIELD_NAME,
        length: 30,
        data: normalize::pack_to_4(characters, mrz::TD1_NAME, 30),
    };

    // TD1 carries two optional fields; the second is the one that follows
    // nationality and is where states put a personal number when they use one.
    values[FIELD_OPTIONAL_DATA - 1] = FieldValue {
        id: FIELD_OPTIONAL_DATA,
        length: 11,
        data: normalize::pack_to_4(characters, mrz::TD1_OPTIONAL2, 11),
    };

    let seed = entropy_seed(dg_hash_fields, domain, session_salt);

    Attributes {
        dg_binding: binding,
        commitment: build_commitment(values, seed, domain),
        birth_date,
        expiry_date,
    }
}

#[test]
fn reads_the_specimen_passport_dates() {
    let domain = 42;

    let out = td3(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        td3_expected_binding(domain),
        20260725,
        99,
        domain,
    );

    assert(out.birth_date == 19740812, "birth date");

    assert(out.expiry_date == 20120415, "expiry date");
}

#[test]
fn reads_the_specimen_card_dates() {
    let domain = 42;

    let out = td1(
        testdata::TD1_DG1,
        testdata::TD1_DG1_LEN,
        td1_expected_binding(domain),
        20260725,
        99,
        domain,
    );

    assert(out.birth_date == 19740812, "birth date");

    assert(out.expiry_date == 20120415, "expiry date");
}

#[test]
fn the_commitment_hides_behind_the_session_salt() {
    let domain = 42;

    let binding = td3_expected_binding(domain);

    let a = td3(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        binding,
        20260725,
        1,
        domain,
    );

    let b = td3(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        binding,
        20260725,
        2,
        domain,
    );

    assert(a.commitment != b.commitment, "a fresh salt must give a fresh commitment");

    assert(a.dg_binding == b.dg_binding, "the binding is independent of the salt");
}

#[test(should_fail_with = "attributes: data group was not the authenticated one")]
fn rejects_a_data_group_that_was_not_authenticated() {
    let domain = 42;

    let mut dg1 = testdata::TD3_DG1;

    dg1[DG1_MRZ_OFFSET] = 0x41;

    let _ = td3(
        dg1,
        testdata::TD3_DG1_LEN,
        td3_expected_binding(domain),
        20260725,
        99,
        domain,
    );
}

#[test(should_fail_with = "attributes: unexpected dg1 length")]
fn rejects_a_card_layout_read_as_a_passport() {
    let domain = 42;

    let _ = td3(
        testdata::TD1_DG1,
        testdata::TD1_DG1_LEN,
        td1_expected_binding(domain),
        20260725,
        99,
        domain,
    );
}

// The reason the opening and the commitment share one parse: an opening that
// described a field differently from the way it was committed would be
// undetectable here and would fail only inside a predicate proof.
#[test]
fn an_opening_proves_against_the_commitment_it_came_from() {
    let domain = 42;

    let salt = 8888;

    let today = 20260725;

    let out = td3(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        td3_expected_binding(domain),
        today,
        salt,
        domain,
    );

    for field_id in 1..10 {
        let opening = td3_opening(
            testdata::TD3_DG1,
            testdata::TD3_DG1_LEN,
            today,
            salt,
            domain,
            field_id,
        );

        predicate::open_field(opening, out.commitment, domain);
    }
}

#[test(should_fail_with = "attributes: field identifier out of range")]
fn refuses_an_opening_for_a_field_that_does_not_exist() {
    let _ = td3_opening(
        testdata::TD3_DG1,
        testdata::TD3_DG1_LEN,
        20260725,
        1,
        42,
        17,
    );
}

// Helpers for the tests above. They read the generated fixtures, which is
// why this package depends on testdata at all, and they sit here so that
// every fixture reference in the file is below the first test.

fn td3_expected_binding(domain: Field) -> Field {
    dg_binding(
        hash32_to_fields(sha256_bounded(testdata::TD3_DG1, testdata::TD3_DG1_LEN)),
        domain,
    )
}

fn td1_expected_binding(domain: Field) -> Field {
    dg_binding(
        hash32_to_fields(sha256_bounded(testdata::TD1_DG1, testdata::TD1_DG1_LEN)),
        domain,
    )
}
