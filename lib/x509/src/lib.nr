//! Reading the parts of a certificate a trust chain depends on.
//!
//! Only two things are needed from a Document Signer certificate: the public
//! key it carries, which must be the key that signed the document, and the
//! period it is valid for. Everything else in the certificate is covered by
//! the issuer signature over the whole encoding, so it does not have to be
//! parsed to be trusted.
//!
//! Offsets are supplied rather than searched for. The structure at an offset
//! is constrained, so a wrong offset fails; what an offset cannot do is make
//! the circuit read bytes outside the signed encoding, since the signature
//! covers all of it.

/// An uncompressed elliptic curve point inside a SubjectPublicKeyInfo: a BIT
/// STRING with no unused bits, then the `04` marker, then the coordinates.
pub fn ec_public_key<let N: u32, let K: u32>(
    tbs: [u8; N],
    tbs_len: u32,
    offset: u32,
) -> ([u8; K], [u8; K]) {
    assert(tbs_len <= N, "x509: length exceeds buffer");

    let point_len = 1 + 2 * K;

    assert(offset + 3 + point_len <= tbs_len, "x509: public key runs past the certificate");

    assert(tbs[offset] == 0x03, "x509: public key is not a bit string");

    assert(tbs[offset + 1] as u32 == point_len + 1, "x509: wrong public key length");

    assert(tbs[offset + 2] == 0x00, "x509: bit string has unused bits");

    assert(tbs[offset + 3] == 0x04, "x509: point is not uncompressed");

    let mut x: [u8; K] = [0; K];

    let mut y: [u8; K] = [0; K];

    for i in 0..K {
        x[i] = tbs[offset + 4 + i];

        y[i] = tbs[offset + 4 + K + i];
    }

    (x, y)
}

fn digit(character: u8) -> u32 {
    assert((character >= 0x30) & (character <= 0x39), "x509: time digit expected");

    (character - 0x30) as u32
}

/// A UTCTime as certificates before 2050 use it: `YYMMDDHHMMSSZ`. Returned as
/// YYYYMMDD so it compares against the same form the rest of the system uses.
///
/// RFC 5280 requires UTCTime below 2050 and GeneralizedTime from 2050, so the
/// two digit year resolves without a pivot. GeneralizedTime is not handled,
/// and a certificate using it fails rather than being read as something else.
pub fn utc_time_to_int<let N: u32>(buf: [u8; N], tbs_len: u32, offset: u32) -> u32 {
    assert(tbs_len <= N, "x509: length exceeds buffer");

    assert(offset + 15 <= tbs_len, "x509: time runs past the certificate");

    assert(buf[offset] == 0x17, "x509: not a utc time");

    assert(buf[offset + 1] == 0x0d, "x509: wrong utc time length");

    assert(buf[offset + 14] == 0x5a, "x509: time is not in zulu");

    let start = offset + 2;

    let yy = digit(buf[start]) * 10 + digit(buf[start + 1]);

    let month = digit(buf[start + 2]) * 10 + digit(buf[start + 3]);

    let day = digit(buf[start + 4]) * 10 + digit(buf[start + 5]);

    assert((month >= 1) & (month <= 12), "x509: month out of range");

    assert((day >= 1) & (day <= 31), "x509: day out of range");

    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };

    year * 10000 + month * 100 + day
}

pub fn assert_valid_at<let N: u32>(
    tbs: [u8; N],
    tbs_len: u32,
    not_before_offset: u32,
    not_after_offset: u32,
    current_yyyymmdd: u32,
) {
    let not_before = utc_time_to_int(tbs, tbs_len, not_before_offset);

    let not_after = utc_time_to_int(tbs, tbs_len, not_after_offset);

    assert(not_before <= not_after, "x509: validity period is inverted");

    assert(current_yyyymmdd >= not_before, "x509: certificate is not yet valid");

    assert(current_yyyymmdd <= not_after, "x509: certificate has expired");
}

fn certificate_with_key_at(offset: u32) -> [u8; 256] {
    let mut buf: [u8; 256] = [0; 256];

    buf[offset] = 0x03;

    buf[offset + 1] = 66;

    buf[offset + 2] = 0x00;

    buf[offset + 3] = 0x04;

    for i in 0..32 {
        buf[offset + 4 + i] = (i as u8) + 1;

        buf[offset + 36 + i] = (i as u8) + 80;
    }

    buf
}

#[test]
fn reads_an_uncompressed_key() {
    let buf = certificate_with_key_at(10);

    let (x, y): ([u8; 32], [u8; 32]) = ec_public_key(buf, 256, 10);

    assert(x[0] == 1);

    assert(x[31] == 32);

    assert(y[0] == 80);

    assert(y[31] == 111);
}

#[test(should_fail_with = "x509: point is not uncompressed")]
fn rejects_a_compressed_point() {
    let mut buf = certificate_with_key_at(10);

    buf[13] = 0x02;

    let _: ([u8; 32], [u8; 32]) = ec_public_key(buf, 256, 10);
}

#[test(should_fail_with = "x509: public key is not a bit string")]
fn rejects_a_wrong_offset() {
    let buf = certificate_with_key_at(10);

    let _: ([u8; 32], [u8; 32]) = ec_public_key(buf, 256, 11);
}

fn certificate_with_times() -> [u8; 64] {
    let mut buf: [u8; 64] = [0; 64];

    let before = "170101000000Z".as_bytes();

    let after = "301231235959Z".as_bytes();

    buf[0] = 0x17;

    buf[1] = 0x0d;

    buf[16] = 0x17;

    buf[17] = 0x0d;

    for i in 0..13 {
        buf[2 + i] = before[i];

        buf[18 + i] = after[i];
    }

    buf
}

#[test]
fn reads_a_validity_period() {
    let buf = certificate_with_times();

    assert(utc_time_to_int(buf, 64, 0) == 20170101);

    assert(utc_time_to_int(buf, 64, 16) == 20301231);

    assert_valid_at(buf, 64, 0, 16, 20260725);
}

#[test(should_fail_with = "x509: certificate has expired")]
fn rejects_a_date_after_the_period() {
    let buf = certificate_with_times();

    assert_valid_at(buf, 64, 0, 16, 20310101);
}

#[test(should_fail_with = "x509: certificate is not yet valid")]
fn rejects_a_date_before_the_period() {
    let buf = certificate_with_times();

    assert_valid_at(buf, 64, 0, 16, 20160101);
}

// Years at or above fifty are the nineteen hundreds, which is what RFC 5280
// requires of a UTCTime and why no pivot on the current date is needed.
#[test]
fn resolves_the_century_by_the_rule_not_by_the_clock() {
    let mut buf: [u8; 64] = [0; 64];

    let text = "980101000000Z".as_bytes();

    buf[0] = 0x17;

    buf[1] = 0x0d;

    for i in 0..13 {
        buf[2 + i] = text[i];
    }

    assert(utc_time_to_int(buf, 64, 0) == 19980101);
}
