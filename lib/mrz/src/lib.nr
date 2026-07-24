//! ICAO 9303 MRZ helpers for TD1 (id cards, 3 x 30) and TD3 (passports, 2 x 44).
//!
//! Field positions are fixed by the standard; check digits use the 7-3-1
//! weighting. Two digit years are resolved against a verifier supplied
//! current date (birth dates pivot on the current two digit year; expiry
//! dates on valid documents always fall in 2000..2099).

pub global TD3_MRZ_BYTES: u32 = 88;

pub global TD1_MRZ_BYTES: u32 = 90;

pub global TD3_ISSUING_STATE: u32 = 2;

pub global TD3_NAME: u32 = 5;

pub global TD3_DOC_NUMBER: u32 = 44;

pub global TD3_NATIONALITY: u32 = 54;

pub global TD3_BIRTH_DATE: u32 = 57;

pub global TD3_SEX: u32 = 64;

pub global TD3_EXPIRY_DATE: u32 = 65;

pub global TD3_OPTIONAL: u32 = 72;

pub global TD1_ISSUING_STATE: u32 = 2;

pub global TD1_DOC_NUMBER: u32 = 5;

pub global TD1_OPTIONAL1: u32 = 15;

pub global TD1_BIRTH_DATE: u32 = 30;

pub global TD1_SEX: u32 = 37;

pub global TD1_EXPIRY_DATE: u32 = 38;

pub global TD1_NATIONALITY: u32 = 45;

pub global TD1_OPTIONAL2: u32 = 48;

pub global TD1_NAME: u32 = 60;

pub fn char_value(c: u8) -> u32 {
    if c == 0x3C {
        0
    } else if (c >= 0x30) & (c <= 0x39) {
        (c - 0x30) as u32
    } else {
        assert((c >= 0x41) & (c <= 0x5A), "mrz: invalid character");

        (c - 0x37) as u32
    }
}

pub fn check_digit<let N: u32>(chars: [u8; N]) -> u8 {
    let weights: [u32; 3] = [7, 3, 1];

    let mut sum: u32 = 0;

    for i in 0..N {
        sum = sum + char_value(chars[i]) * weights[i % 3];
    }

    0x30 + (sum % 10) as u8
}

pub fn copy<let N: u32, let M: u32>(src: [u8; N], off: u32) -> [u8; M] {
    assert(off + M <= N, "mrz: copy out of bounds");

    let mut out: [u8; M] = [0; M];

    for i in 0..M {
        out[i] = src[off + i];
    }

    out
}

pub fn td3_validate(mrz: [u8; 88]) {
    let doc: [u8; 9] = copy(mrz, TD3_DOC_NUMBER);

    assert(check_digit(doc) == mrz[53], "mrz: td3 document number check digit");

    let dob: [u8; 6] = copy(mrz, TD3_BIRTH_DATE);

    assert(check_digit(dob) == mrz[63], "mrz: td3 birth date check digit");

    let exp: [u8; 6] = copy(mrz, TD3_EXPIRY_DATE);

    assert(check_digit(exp) == mrz[71], "mrz: td3 expiry date check digit");

    let opt: [u8; 14] = copy(mrz, TD3_OPTIONAL);

    assert(check_digit(opt) == mrz[86], "mrz: td3 optional data check digit");

    let mut comp: [u8; 39] = [0; 39];

    for i in 0..10 {
        comp[i] = mrz[44 + i];
    }

    for i in 0..7 {
        comp[10 + i] = mrz[57 + i];
    }

    for i in 0..22 {
        comp[17 + i] = mrz[65 + i];
    }

    assert(check_digit(comp) == mrz[87], "mrz: td3 composite check digit");
}

pub fn td1_validate(mrz: [u8; 90]) {
    let doc: [u8; 9] = copy(mrz, TD1_DOC_NUMBER);

    assert(check_digit(doc) == mrz[14], "mrz: td1 document number check digit");

    let dob: [u8; 6] = copy(mrz, TD1_BIRTH_DATE);

    assert(check_digit(dob) == mrz[36], "mrz: td1 birth date check digit");

    let exp: [u8; 6] = copy(mrz, TD1_EXPIRY_DATE);

    assert(check_digit(exp) == mrz[44], "mrz: td1 expiry date check digit");

    let mut comp: [u8; 50] = [0; 50];

    for i in 0..25 {
        comp[i] = mrz[5 + i];
    }

    for i in 0..7 {
        comp[25 + i] = mrz[30 + i];
    }

    for i in 0..7 {
        comp[32 + i] = mrz[38 + i];
    }

    for i in 0..11 {
        comp[39 + i] = mrz[48 + i];
    }

    assert(check_digit(comp) == mrz[59], "mrz: td1 composite check digit");
}

fn digit(c: u8) -> u32 {
    assert((c >= 0x30) & (c <= 0x39), "mrz: invalid date digit");

    (c - 0x30) as u32
}

fn parse_yymmdd(d: [u8; 6]) -> (u32, u32, u32) {
    let yy = digit(d[0]) * 10 + digit(d[1]);

    let mm = digit(d[2]) * 10 + digit(d[3]);

    let dd = digit(d[4]) * 10 + digit(d[5]);

    assert((mm >= 1) & (mm <= 12), "mrz: month out of range");

    assert((dd >= 1) & (dd <= 31), "mrz: day out of range");

    (yy, mm, dd)
}

pub fn birth_date_to_int(d: [u8; 6], current_yyyymmdd: u32) -> u32 {
    let (yy, mm, dd) = parse_yymmdd(d);

    let current_yy = (current_yyyymmdd / 10000) % 100;

    let century = if yy > current_yy { 1900 } else { 2000 };

    (century + yy) * 10000 + mm * 100 + dd
}

pub fn expiry_date_to_int(d: [u8; 6]) -> u32 {
    let (yy, mm, dd) = parse_yymmdd(d);

    (2000 + yy) * 10000 + mm * 100 + dd
}

fn td3_specimen() -> [u8; 88] {
    let line1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".as_bytes();

    let line2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10".as_bytes();

    let mut mrz: [u8; 88] = [0; 88];

    for i in 0..44 {
        mrz[i] = line1[i];

        mrz[44 + i] = line2[i];
    }

    mrz
}

fn td1_specimen() -> [u8; 90] {
    let line1 = "I<UTOD231458907<<<<<<<<<<<<<<<".as_bytes();

    let line2 = "7408122F1204159UTO<<<<<<<<<<<6".as_bytes();

    let line3 = "ERIKSSON<<ANNA<MARIA<<<<<<<<<<".as_bytes();

    let mut mrz: [u8; 90] = [0; 90];

    for i in 0..30 {
        mrz[i] = line1[i];

        mrz[30 + i] = line2[i];

        mrz[60 + i] = line3[i];
    }

    mrz
}

#[test]
fn td3_specimen_passes_all_check_digits() {
    td3_validate(td3_specimen());
}

#[test]
fn td1_specimen_passes_all_check_digits() {
    td1_validate(td1_specimen());
}

#[test(should_fail_with = "mrz: td3 document number check digit")]
fn td3_rejects_tampered_document_number() {
    let mut mrz = td3_specimen();

    mrz[44] = 0x4D;

    td3_validate(mrz);
}

#[test(should_fail_with = "mrz: td1 composite check digit")]
fn td1_rejects_tampered_optional_data() {
    let mut mrz = td1_specimen();

    mrz[48] = 0x42;

    td1_validate(mrz);
}

// The 7-3-1 check digit is taken modulo 10, so substituting a character
// whose value differs by a multiple of ten (A is 10, K is 20, U is 30,
// filler is 0) leaves the digit unchanged at every position. Check digits
// therefore detect transcription mistakes, not tampering: integrity of
// the MRZ rests entirely on the Security Object signature over DG1.
#[test]
fn check_digits_miss_multiple_of_ten_substitutions() {
    let mut mrz = td1_specimen();

    mrz[48] = 0x41;

    td1_validate(mrz);
}

#[test]
fn birth_date_century_pivot() {
    assert(birth_date_to_int("740812".as_bytes(), 20260723) == 19740812);

    assert(birth_date_to_int("120415".as_bytes(), 20260723) == 20120415);

    assert(birth_date_to_int("260101".as_bytes(), 20260723) == 20260101);

    assert(birth_date_to_int("270101".as_bytes(), 20260723) == 19270101);
}

#[test]
fn expiry_date_is_2000s() {
    assert(expiry_date_to_int("120415".as_bytes()) == 20120415);
}

#[test(should_fail_with = "mrz: month out of range")]
fn rejects_invalid_month() {
    let _ = expiry_date_to_int("121315".as_bytes());
}
