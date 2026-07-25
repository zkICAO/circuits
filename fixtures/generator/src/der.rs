//! Minimal DER writer. Only the definite length forms the circuits accept
//! are emitted, so a fixture can never carry an encoding the parser is not
//! expected to handle.

pub const TAG_INTEGER: u8 = 0x02;

pub const TAG_OCTET_STRING: u8 = 0x04;

pub const TAG_NULL: u8 = 0x05;

pub const TAG_OID: u8 = 0x06;

pub const TAG_SEQUENCE: u8 = 0x30;

pub const TAG_SET: u8 = 0x31;

pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        panic!("der: length {len} exceeds the two byte long form");
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];

    out.extend_from_slice(&encode_length(content.len()));

    out.extend_from_slice(content);

    out
}

pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &parts.concat())
}

pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SET, &parts.concat())
}

pub fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, content)
}

pub fn oid(encoded: &[u8]) -> Vec<u8> {
    tlv(TAG_OID, encoded)
}

pub fn null() -> Vec<u8> {
    vec![TAG_NULL, 0x00]
}

/// DER INTEGER of a small non-negative value, which is all the fixtures need
/// (version numbers and data group numbers).
pub fn integer_u8(value: u8) -> Vec<u8> {
    assert!(value < 0x80, "der: value {value} would need a padding byte");

    tlv(TAG_INTEGER, &[value])
}

/// Strips the leading zero DER adds to keep a big endian integer positive,
/// then left pads to `width` so the result is a fixed size scalar.
pub fn integer_to_fixed(content: &[u8], width: usize) -> Vec<u8> {
    let trimmed = if content.len() > 1 && content[0] == 0x00 {
        &content[1..]
    } else {
        content
    };

    assert!(
        trimmed.len() <= width,
        "der: integer of {} bytes does not fit {width}",
        trimmed.len()
    );

    let mut out = vec![0u8; width - trimmed.len()];

    out.extend_from_slice(trimmed);

    out
}

pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub total_len: usize,
    pub header_len: usize,
}

/// Reads one TLV at `offset`, used to walk signatures and certificates
/// produced by openssl.
pub fn read(buf: &[u8], offset: usize) -> Tlv<'_> {
    let tag = buf[offset];

    let first = buf[offset + 1];

    let (len, header_len) = if first < 0x80 {
        (first as usize, 2)
    } else if first == 0x81 {
        (buf[offset + 2] as usize, 3)
    } else if first == 0x82 {
        (
            ((buf[offset + 2] as usize) << 8) | buf[offset + 3] as usize,
            4,
        )
    } else {
        panic!("der: unsupported length form {first:#04x}");
    };

    Tlv {
        tag,
        content: &buf[offset + header_len..offset + header_len + len],
        total_len: header_len + len,
        header_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_use_the_shortest_form() {
        assert_eq!(encode_length(5), vec![5]);

        assert_eq!(encode_length(0x80), vec![0x81, 0x80]);

        assert_eq!(encode_length(300), vec![0x82, 0x01, 0x2c]);
    }

    #[test]
    fn reads_back_what_it_writes() {
        let encoded = sequence(&[integer_u8(1), octet_string(&[0xaa, 0xbb])]);

        let outer = read(&encoded, 0);

        assert_eq!(outer.tag, TAG_SEQUENCE);

        assert_eq!(outer.total_len, encoded.len());

        let inner = read(outer.content, 0);

        assert_eq!(inner.tag, TAG_INTEGER);

        assert_eq!(inner.content, &[1]);
    }

    #[test]
    fn fixed_width_integers_drop_the_sign_byte() {
        assert_eq!(integer_to_fixed(&[0x00, 0xff], 4), vec![0, 0, 0, 0xff]);

        assert_eq!(integer_to_fixed(&[0x7f], 2), vec![0, 0x7f]);
    }
}
