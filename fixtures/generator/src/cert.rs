//! Builds a Document Signer certificate so the trust chain can be exercised.
//!
//! Only the fields a verifier reads are filled in with care: the validity
//! period and the subject public key. The rest is present because a
//! certificate is not a certificate without it, and because the issuer
//! signature covers the whole encoding, so a fixture that skipped parts
//! would not exercise the same bytes a real one does.

use crate::der;

const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

const TAG_BIT_STRING: u8 = 0x03;

const TAG_UTC_TIME: u8 = 0x17;

const TAG_PRINTABLE_STRING: u8 = 0x13;

pub struct Certificate {
    pub tbs: Vec<u8>,
    pub public_key_offset: usize,
    pub not_before_offset: usize,
    pub not_after_offset: usize,
}

fn name(common_name: &str) -> Vec<u8> {
    let attribute = der::sequence(&[
        der::oid(OID_COMMON_NAME),
        der::tlv(TAG_PRINTABLE_STRING, common_name.as_bytes()),
    ]);

    der::sequence(&[der::set(&[attribute])])
}

fn utc_time(value: &str) -> Vec<u8> {
    assert_eq!(value.len(), 13, "cert: a utc time is thirteen characters");

    der::tlv(TAG_UTC_TIME, value.as_bytes())
}

/// `[0] EXPLICIT` wrapping of the version, which is how X.509 carries it.
fn version_v3() -> Vec<u8> {
    der::tlv(0xa0, &der::integer_u8(2))
}

/// A SubjectPublicKeyInfo over a P-256 point, the encoding both a
/// certificate and DG15 carry, and the offset of the key inside it.
pub fn subject_public_key_info(public_key_x: &[u8], public_key_y: &[u8]) -> Vec<u8> {
    let mut point = vec![0x00, 0x04];

    point.extend_from_slice(public_key_x);

    point.extend_from_slice(public_key_y);

    der::sequence(&[
        der::sequence(&[der::oid(OID_EC_PUBLIC_KEY), der::oid(OID_PRIME256V1)]),
        der::tlv(TAG_BIT_STRING, &point),
    ])
}

/// Where the bit string holding the point begins, measured from the start of
/// the SubjectPublicKeyInfo.
pub fn public_key_offset_in_spki(spki: &[u8]) -> usize {
    let algorithm_len =
        der::sequence(&[der::oid(OID_EC_PUBLIC_KEY), der::oid(OID_PRIME256V1)]).len();

    der::read(spki, 0).header_len + algorithm_len
}

pub fn build_dsc_tbs(
    public_key_x: &[u8],
    public_key_y: &[u8],
    not_before: &str,
    not_after: &str,
) -> Certificate {
    let mut point = vec![0x00, 0x04];

    point.extend_from_slice(public_key_x);

    point.extend_from_slice(public_key_y);

    let spki = subject_public_key_info(public_key_x, public_key_y);

    let validity = der::sequence(&[utc_time(not_before), utc_time(not_after)]);

    let parts = vec![
        version_v3(),
        der::integer_u8(3),
        der::sequence(&[der::oid(OID_SHA256_WITH_RSA), der::null()]),
        name("Test Country Signing CA"),
        validity.clone(),
        name("Test Document Signer"),
        spki.clone(),
    ];

    let tbs = der::sequence(&parts);

    let body_start = tbs.len() - parts.iter().map(Vec::len).sum::<usize>();

    let mut cursor = body_start;

    let mut validity_start = 0;

    let mut spki_start = 0;

    for (index, part) in parts.iter().enumerate() {
        if index == 4 {
            validity_start = cursor;
        }

        if index == 6 {
            spki_start = cursor;
        }

        cursor += part.len();
    }

    // Inside the validity SEQUENCE the two times follow its header.
    let not_before_offset = validity_start + der::read(&validity, 0).header_len;

    let not_after_offset = not_before_offset + utc_time(not_before).len();

    let public_key_offset = spki_start + public_key_offset_in_spki(&spki);

    let certificate = Certificate {
        tbs,
        public_key_offset,
        not_before_offset,
        not_after_offset,
    };

    check(
        &certificate,
        public_key_x,
        public_key_y,
        not_before,
        not_after,
    );

    certificate
}

/// Offsets are what the circuit trusts, so they are checked here rather than
/// left to a downstream failure that would be harder to read.
fn check(
    certificate: &Certificate,
    public_key_x: &[u8],
    public_key_y: &[u8],
    not_before: &str,
    not_after: &str,
) {
    let tbs = &certificate.tbs;

    let key = certificate.public_key_offset;

    assert_eq!(tbs[key], TAG_BIT_STRING, "cert: public key offset is wrong");

    assert_eq!(
        tbs[key + 1] as usize,
        2 + public_key_x.len() + public_key_y.len()
    );

    assert_eq!(
        tbs[key + 2],
        0x00,
        "cert: bit string should have no unused bits"
    );

    assert_eq!(tbs[key + 3], 0x04, "cert: point should be uncompressed");

    assert_eq!(&tbs[key + 4..key + 4 + public_key_x.len()], public_key_x);

    let y_start = key + 4 + public_key_x.len();

    assert_eq!(&tbs[y_start..y_start + public_key_y.len()], public_key_y);

    for (offset, expected) in [
        (certificate.not_before_offset, not_before),
        (certificate.not_after_offset, not_after),
    ] {
        assert_eq!(tbs[offset], TAG_UTC_TIME, "cert: time offset is wrong");

        assert_eq!(tbs[offset + 1], 13);

        assert_eq!(&tbs[offset + 2..offset + 15], expected.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_land_on_the_fields_a_verifier_reads() {
        let x: Vec<u8> = (0..32).map(|i| i as u8 + 1).collect();

        let y: Vec<u8> = (0..32).map(|i| i as u8 + 80).collect();

        // build_dsc_tbs checks its own offsets, so reaching this point is the
        // assertion; the explicit checks below guard against that being
        // weakened later.
        let certificate = build_dsc_tbs(&x, &y, "170101000000Z", "301231235959Z");

        assert_eq!(certificate.tbs[0], der::TAG_SEQUENCE);

        assert!(certificate.public_key_offset > certificate.not_after_offset);

        assert!(certificate.not_before_offset < certificate.not_after_offset);
    }
}
