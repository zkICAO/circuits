//! Field normalization: raw document bytes into the canonical values that
//! predicates and nullifiers operate on. Dates become YYYYMMDD integers
//! (see mrz), country codes stay ISO 3166 alpha-3, byte fields pack big
//! endian into 4 Field elements of up to 31 bytes each.

pub global MAX_FIELD_BYTES: u32 = 124;

pub fn pack_to_4<let N: u32>(buf: [u8; N], off: u32, len: u32) -> [Field; 4] {
    assert(len <= MAX_FIELD_BYTES, "normalize: field too long");

    assert(off + len <= N, "normalize: field out of bounds");

    let mut out: [Field; 4] = [0; 4];

    for f in 0..4 {
        let mut felt: Field = 0;

        for b in 0..31 {
            let idx = f * 31 + b;

            if idx < len {
                felt = felt * 256 + buf[off + idx] as Field;
            }
        }

        out[f] = felt;
    }

    out
}

pub fn pack_alpha3(c: [u8; 3]) -> Field {
    for i in 0..3 {
        let ch = c[i];

        assert(
            ((ch >= 0x41) & (ch <= 0x5A)) | (ch == 0x3C),
            "normalize: invalid country character",
        );
    }

    (c[0] as Field) * 65536 + (c[1] as Field) * 256 + (c[2] as Field)
}

#[test]
fn packs_alpha3() {
    assert(pack_alpha3("VNM".as_bytes()) == 0x564E4D);

    assert(pack_alpha3("UTO".as_bytes()) == 0x55544F);
}

#[test(should_fail_with = "normalize: invalid country character")]
fn rejects_lowercase_country() {
    let _ = pack_alpha3("vnm".as_bytes());
}

#[test]
fn packs_short_field_into_first_element() {
    let buf: [u8; 8] = [0, 0, 0x41, 0x42, 0x43, 0, 0, 0];

    let out = pack_to_4(buf, 2, 3);

    assert(out[0] == 0x414243);

    assert(out[1] == 0);

    assert(out[2] == 0);

    assert(out[3] == 0);
}

#[test]
fn packs_across_element_boundary() {
    let mut buf: [u8; 40] = [0; 40];

    for i in 0..33 {
        buf[i] = 1;
    }

    let out = pack_to_4(buf, 0, 33);

    assert(out[0] != 0);

    assert(out[1] == 256 + 1);

    assert(out[2] == 0);
}
