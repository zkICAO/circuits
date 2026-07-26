//! Builds the Doc 9303 structures the circuits read: DG1, the Security
//! Object content, and the signed attributes a Document Signer signs.
//!
//! Offsets are returned alongside the bytes because a circuit is given the
//! position of each structure it inspects and constrains what it finds
//! there, rather than searching the buffer.

use crate::der;
use crate::ec;

pub const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

pub const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];

pub const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

pub const OID_LDS_SECURITY_OBJECT: &[u8] = &[0x67, 0x81, 0x08, 0x01, 0x01, 0x01];

pub const TAG_DG1: u8 = 0x61;

pub const TAG_MRZ_DATA: &[u8] = &[0x5f, 0x1f];

pub const MRZ_TD3: &str =
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

/// The card sized travel document layout, two lines of thirty six, built
/// from the same specimen holder as the other two with check digits computed
/// under the 7-3-1 weighting.
pub const MRZ_TD2: &str =
    "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6";

pub const MRZ_TD1: &str =
    "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

/// EF.DG1 is the MRZ wrapped in its own template: `61 len 5F1F len mrz`.
pub fn build_dg1(mrz: &str) -> Vec<u8> {
    let mut inner = TAG_MRZ_DATA.to_vec();

    inner.extend_from_slice(&der::encode_length(mrz.len()));

    inner.extend_from_slice(mrz.as_bytes());

    der::tlv(TAG_DG1, &inner)
}

pub struct DataGroup {
    pub number: u8,
    pub content: Vec<u8>,
}

pub struct SecurityObject {
    pub econtent: Vec<u8>,
    pub oid_offset: usize,
    pub dg_offsets: Vec<(u8, usize)>,
}

/// LDSSecurityObject: version, the digest algorithm, then one entry per data
/// group holding its hash.
pub fn build_security_object(groups: &[DataGroup]) -> SecurityObject {
    let version = der::integer_u8(0);

    let algorithm = der::sequence(&[der::oid(OID_SHA256), der::null()]);

    let mut entries: Vec<Vec<u8>> = Vec::new();

    for group in groups {
        let hash = ec::sha256(&group.content);

        entries.push(der::sequence(&[
            der::integer_u8(group.number),
            der::octet_string(&hash),
        ]));
    }

    let hash_values = der::sequence(&entries);

    let econtent = der::sequence(&[version.clone(), algorithm.clone(), hash_values.clone()]);

    let body_start = econtent.len() - (version.len() + algorithm.len() + hash_values.len());

    let algorithm_start = body_start + version.len();

    // The AlgorithmIdentifier SEQUENCE header precedes the OID it contains.
    let oid_offset = algorithm_start + der::read(&algorithm, 0).header_len;

    let entries_start = algorithm_start + algorithm.len() + der::read(&hash_values, 0).header_len;

    let mut dg_offsets = Vec::new();

    let mut cursor = entries_start;

    for (index, group) in groups.iter().enumerate() {
        dg_offsets.push((group.number, cursor));

        cursor += entries[index].len();
    }

    SecurityObject {
        econtent,
        oid_offset,
        dg_offsets,
    }
}

pub struct SignedAttributes {
    pub bytes: Vec<u8>,
    pub digest_offset: usize,
}

/// The signature covers the DER SET OF encoding of the signed attributes,
/// which is what this returns; inside a SignerInfo the same bytes appear
/// under an implicit context tag.
pub fn build_signed_attributes(econtent: &[u8]) -> SignedAttributes {
    let content_type = der::sequence(&[
        der::oid(OID_CONTENT_TYPE),
        der::set(&[der::oid(OID_LDS_SECURITY_OBJECT)]),
    ]);

    let digest = ec::sha256(econtent);

    let message_digest = der::sequence(&[
        der::oid(OID_MESSAGE_DIGEST),
        der::set(&[der::octet_string(&digest)]),
    ]);

    let bytes = der::set(&[content_type.clone(), message_digest.clone()]);

    let header = der::read(&bytes, 0).header_len;

    let message_digest_start = header + content_type.len();

    // Inside the attribute: SEQUENCE header, OID, SET header, OCTET STRING
    // header, then the digest itself.
    let digest_offset = message_digest_start
        + der::read(&message_digest, 0).header_len
        + der::oid(OID_MESSAGE_DIGEST).len()
        + 2
        + 2;

    assert_eq!(
        &bytes[digest_offset..digest_offset + 32],
        &digest[..],
        "icao: digest offset does not land on the digest"
    );

    SignedAttributes {
        bytes,
        digest_offset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dg1_wraps_the_mrz_in_its_template() {
        let dg1 = build_dg1(MRZ_TD3);

        assert_eq!(dg1[0], TAG_DG1);

        let outer = der::read(&dg1, 0);

        assert_eq!(&outer.content[0..2], TAG_MRZ_DATA);

        assert_eq!(outer.content[2] as usize, MRZ_TD3.len());

        assert_eq!(&outer.content[3..], MRZ_TD3.as_bytes());
    }

    #[test]
    fn security_object_offsets_point_at_the_right_bytes() {
        let groups = vec![
            DataGroup {
                number: 1,
                content: build_dg1(MRZ_TD3),
            },
            DataGroup {
                number: 2,
                content: vec![0xaa; 64],
            },
        ];

        let sod = build_security_object(&groups);

        assert_eq!(sod.econtent[sod.oid_offset], der::TAG_OID);

        assert_eq!(sod.econtent[sod.oid_offset + 1] as usize, OID_SHA256.len());

        assert_eq!(
            &sod.econtent[sod.oid_offset + 2..sod.oid_offset + 2 + OID_SHA256.len()],
            OID_SHA256
        );

        for (number, offset) in &sod.dg_offsets {
            assert_eq!(sod.econtent[*offset], der::TAG_SEQUENCE);

            assert_eq!(sod.econtent[*offset + 1], 0x25);

            assert_eq!(sod.econtent[*offset + 4], *number);

            assert_eq!(sod.econtent[*offset + 5], der::TAG_OCTET_STRING);

            assert_eq!(sod.econtent[*offset + 6], 0x20);
        }
    }

    #[test]
    fn signed_attributes_carry_the_econtent_digest() {
        let groups = vec![DataGroup {
            number: 1,
            content: build_dg1(MRZ_TD1),
        }];

        let sod = build_security_object(&groups);

        let attrs = build_signed_attributes(&sod.econtent);

        let expected = ec::sha256(&sod.econtent);

        assert_eq!(
            &attrs.bytes[attrs.digest_offset..attrs.digest_offset + 32],
            &expected[..]
        );
    }
}

#[cfg(test)]
mod sizing {
    use super::*;

    /// Builds a Security Object covering `count` data groups, which is what
    /// decides how large a buffer a circuit needs.
    fn econtent_len(count: u8, hash_len: usize) -> usize {
        let groups: Vec<DataGroup> = (1..=count)
            .map(|number| DataGroup {
                number,
                content: vec![number; 64],
            })
            .collect();

        assert_eq!(hash_len, 32, "only SHA-256 entries are built today");

        build_security_object(&groups).econtent.len()
    }

    // Doc 9303 allows sixteen data groups and requires two. The shipped
    // buffer is 512 bytes, so the number of groups a document carries decides
    // whether it can be proved at all.
    #[test]
    fn a_full_document_does_not_fit_the_512_byte_buffer() {
        assert!(econtent_len(2, 32) < 512, "the synthetic fixture fits");

        assert!(
            econtent_len(12, 32) < 512,
            "twelve groups still fit, which is why the shipped buffer is usable at all"
        );

        assert!(
            econtent_len(13, 32) > 512,
            "thirteen groups do not, so a document carrying them needs the larger variant"
        );

        assert!(
            econtent_len(16, 32) > 512,
            "a full document certainly does not"
        );
    }

    #[test]
    fn a_full_document_fits_1024() {
        assert!(econtent_len(16, 32) < 1024);
    }
}
