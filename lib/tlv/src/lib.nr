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

// `len` is the logical length of the encoded data, which is at most the
// buffer size. Checking the decoded content against it here means callers
// cannot forget to: a declared length that runs past the data would
// otherwise be returned intact and let a caller read whatever the buffer
// happens to hold beyond it.
pub fn read_len<let N: u32>(buf: [u8; N], off: u32, len: u32) -> Len {
    assert(len <= N, "tlv: len exceeds buffer");

    assert(off < len, "tlv: length offset out of bounds");

    let b0 = buf[off];

    let decoded = if b0 < 0x80 {
        Len { value: b0 as u32, header: 1 }
    } else if b0 == 0x81 {
        assert(off + 1 < len, "tlv: truncated length");

        let v = buf[off + 1] as u32;

        assert(v >= 0x80, "tlv: non minimal length");

        Len { value: v, header: 2 }
    } else {
        assert(b0 == 0x82, "tlv: unsupported length form");

        assert(off + 2 < len, "tlv: truncated length");

        let v = (buf[off + 1] as u32) * 256 + (buf[off + 2] as u32);

        assert(v >= 0x100, "tlv: non minimal length");

        Len { value: v, header: 3 }
    };

    assert(off + decoded.header + decoded.value <= len, "tlv: content exceeds data");

    decoded
}

#[test]
fn reads_short_form() {
    let buf: [u8; 8] = [0x30, 0x05, 0, 0, 0, 0, 0, 0];

    let l = read_len(buf, 1, 8);

    assert(l.value == 5);

    assert(l.header == 1);
}

#[test]
fn reads_long_form_81() {
    let mut buf: [u8; 160] = [0; 160];

    buf[0] = 0x30;

    buf[1] = 0x81;

    buf[2] = 0x90;

    let l = read_len(buf, 1, 160);

    assert(l.value == 0x90);

    assert(l.header == 2);
}

#[test]
fn reads_long_form_82() {
    let mut buf: [u8; 320] = [0; 320];

    buf[0] = 0x30;

    buf[1] = 0x82;

    buf[2] = 0x01;

    buf[3] = 0x2c;

    let l = read_len(buf, 1, 320);

    assert(l.value == 300);

    assert(l.header == 3);
}

#[test(should_fail_with = "tlv: non minimal length")]
fn rejects_non_minimal_81() {
    let buf: [u8; 8] = [0x81, 0x05, 0, 0, 0, 0, 0, 0];

    let _ = read_len(buf, 0, 8);
}

#[test(should_fail_with = "tlv: content exceeds data")]
fn rejects_length_running_past_the_data() {
    let buf: [u8; 8] = [0x30, 0x06, 0, 0, 0, 0, 0, 0];

    let _ = read_len(buf, 1, 5);
}

#[test(should_fail_with = "tlv: unexpected tag")]
fn rejects_wrong_tag() {
    let buf: [u8; 2] = [0x30, 0x00];

    expect_tag(buf, 0, 0x31);
}
