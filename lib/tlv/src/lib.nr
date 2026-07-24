//! Minimal DER TLV helpers: tag assertion and definite-length decoding
//! (short form and long form 0x81/0x82) with DER minimality checks.

pub struct Len {
    pub value: u32,
    pub header: u32,
}

pub fn expect_tag<let N: u32>(buf: [u8; N], off: u32, tag: u8) {
    assert(off < N, "tlv: offset out of bounds");

    assert(buf[off] == tag, "tlv: unexpected tag");
}

pub fn read_len<let N: u32>(buf: [u8; N], off: u32) -> Len {
    assert(off < N, "tlv: length offset out of bounds");

    let b0 = buf[off];

    if b0 < 0x80 {
        Len { value: b0 as u32, header: 1 }
    } else if b0 == 0x81 {
        assert(off + 1 < N, "tlv: truncated length");

        let v = buf[off + 1] as u32;

        assert(v >= 0x80, "tlv: non minimal length");

        Len { value: v, header: 2 }
    } else {
        assert(b0 == 0x82, "tlv: unsupported length form");

        assert(off + 2 < N, "tlv: truncated length");

        let v = (buf[off + 1] as u32) * 256 + (buf[off + 2] as u32);

        assert(v >= 0x100, "tlv: non minimal length");

        Len { value: v, header: 3 }
    }
}

#[test]
fn reads_short_form() {
    let buf: [u8; 4] = [0x30, 0x05, 0x00, 0x00];

    let l = read_len(buf, 1);

    assert(l.value == 5);

    assert(l.header == 1);
}

#[test]
fn reads_long_form_81() {
    let buf: [u8; 4] = [0x30, 0x81, 0x90, 0x00];

    let l = read_len(buf, 1);

    assert(l.value == 0x90);

    assert(l.header == 2);
}

#[test]
fn reads_long_form_82() {
    let buf: [u8; 5] = [0x30, 0x82, 0x01, 0x2c, 0x00];

    let l = read_len(buf, 1);

    assert(l.value == 300);

    assert(l.header == 3);
}

#[test(should_fail_with = "tlv: non minimal length")]
fn rejects_non_minimal_81() {
    let buf: [u8; 2] = [0x81, 0x05];

    let _ = read_len(buf, 0);
}

#[test(should_fail_with = "tlv: unexpected tag")]
fn rejects_wrong_tag() {
    let buf: [u8; 2] = [0x30, 0x00];

    expect_tag(buf, 0, 0x31);
}
