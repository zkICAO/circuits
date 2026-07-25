//! CMS SignedData helpers.
//!
//! A Document Signer does not sign the Security Object directly. It signs
//! the signed attributes, one of which, messageDigest, holds the digest of
//! the Security Object. Tying the two together is what makes a signature
//! over the attributes also a signature over the document content, so the
//! attribute has to be located and its digest read out under constraint.

pub global OID_MESSAGE_DIGEST: [u8; 11] =
    [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

// Distance from the start of the digest back to the start of its attribute
// OID: the OCTET STRING header, the SET header, then the OID itself.
pub global DIGEST_HEADER_BYTES: u32 = 15;

pub global SHA256_DIGEST_BYTES: u32 = 32;

/// Reads the messageDigest attribute value at `digest_offset`, checking the
/// attribute really is messageDigest and really is a 32 byte octet string.
pub fn message_digest_sha256<let N: u32>(
    signed_attrs: [u8; N],
    len: u32,
    digest_offset: u32,
) -> [u8; 32] {
    assert(len <= N, "cms: len exceeds buffer");

    assert(digest_offset >= DIGEST_HEADER_BYTES, "cms: digest offset too small");

    assert(
        digest_offset + SHA256_DIGEST_BYTES <= len,
        "cms: digest runs past the signed attributes",
    );

    let oid_start = digest_offset - DIGEST_HEADER_BYTES;

    for i in 0..11 {
        assert(
            signed_attrs[oid_start + i] == OID_MESSAGE_DIGEST[i],
            "cms: attribute is not messageDigest",
        );
    }

    assert(signed_attrs[digest_offset - 4] == 0x31, "cms: attribute values are not a SET");

    assert(signed_attrs[digest_offset - 2] == 0x04, "cms: digest is not an OCTET STRING");

    assert(signed_attrs[digest_offset - 1] == 0x20, "cms: digest is not 32 bytes");

    let mut out: [u8; 32] = [0; 32];

    for i in 0..32 {
        out[i] = signed_attrs[digest_offset + i];
    }

    out
}

fn sample_attributes() -> ([u8; 64], u32) {
    let mut buf: [u8; 64] = [0; 64];

    let digest_offset: u32 = 20;

    let oid_start = digest_offset - DIGEST_HEADER_BYTES;

    for i in 0..11 {
        buf[oid_start + i] = OID_MESSAGE_DIGEST[i];
    }

    buf[digest_offset - 4] = 0x31;

    buf[digest_offset - 3] = 0x22;

    buf[digest_offset - 2] = 0x04;

    buf[digest_offset - 1] = 0x20;

    for i in 0..32 {
        buf[digest_offset + i] = (i as u8) + 1;
    }

    (buf, digest_offset)
}

#[test]
fn reads_the_digest() {
    let (buf, offset) = sample_attributes();

    let digest = message_digest_sha256(buf, 64, offset);

    for i in 0..32 {
        assert(digest[i] == (i as u8) + 1);
    }
}

#[test(should_fail_with = "cms: attribute is not messageDigest")]
fn rejects_a_different_attribute() {
    let (mut buf, offset) = sample_attributes();

    buf[offset - DIGEST_HEADER_BYTES + 10] = 0x03;

    let _ = message_digest_sha256(buf, 64, offset);
}

#[test(should_fail_with = "cms: digest is not 32 bytes")]
fn rejects_a_short_digest() {
    let (mut buf, offset) = sample_attributes();

    buf[offset - 1] = 0x14;

    let _ = message_digest_sha256(buf, 64, offset);
}

#[test(should_fail_with = "cms: digest runs past the signed attributes")]
fn rejects_a_digest_past_the_end() {
    let (buf, offset) = sample_attributes();

    let _ = message_digest_sha256(buf, 40, offset);
}
