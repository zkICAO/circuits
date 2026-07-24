//! LDSSecurityObject helpers (SHA-256 hash algorithm variant).
//!
//! The Security Object (SOD eContent) commits every data group hash. These
//! helpers assert its hash algorithm identifier and read one data group
//! entry.
//!
//! `dg_entry_sha256` checks the DER header sitting at the offset it is
//! given, and nothing about how that offset was reached: it does not walk
//! the Security Object from its start, so it cannot tell a genuine entry
//! from a byte sequence elsewhere in the buffer that happens to match the
//! same seven header bytes. A circuit that wants that guarantee has to
//! establish the offset itself. The hash read out is still covered by the
//! signature over the Security Object, so a match on arbitrary bytes only
//! yields data the issuer signed.

pub global SHA256_ALGORITHM_OID: [u8; 11] =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

pub global DG_ENTRY_SHA256_BYTES: u32 = 39;

pub fn check_sha256_oid<let N: u32>(buf: [u8; N], len: u32, off: u32) {
    assert(len <= N, "lds: len exceeds buffer");

    assert(off + 11 <= len, "lds: oid out of bounds");

    for i in 0..11 {
        assert(buf[off + i] == SHA256_ALGORITHM_OID[i], "lds: wrong hash algorithm oid");
    }
}

pub fn dg_entry_sha256<let N: u32>(buf: [u8; N], len: u32, off: u32, dg_number: u8) -> [u8; 32] {
    assert(len <= N, "lds: len exceeds buffer");

    assert(off + DG_ENTRY_SHA256_BYTES <= len, "lds: dg entry out of bounds");

    assert(dg_number >= 1, "lds: dg number must be >= 1");

    assert(dg_number <= 16, "lds: dg number must be <= 16");

    assert(buf[off] == 0x30, "lds: dg entry missing sequence");

    assert(buf[off + 1] == 0x25, "lds: dg entry wrong sequence length");

    assert(buf[off + 2] == 0x02, "lds: dg entry missing integer");

    assert(buf[off + 3] == 0x01, "lds: dg entry wrong integer length");

    assert(buf[off + 4] == dg_number, "lds: dg entry wrong dg number");

    assert(buf[off + 5] == 0x04, "lds: dg entry missing octet string");

    assert(buf[off + 6] == 0x20, "lds: dg entry wrong hash length");

    let mut out: [u8; 32] = [0; 32];

    for i in 0..32 {
        out[i] = buf[off + 7 + i];
    }

    out
}

fn sample_entry_at_5() -> [u8; 64] {
    let mut buf: [u8; 64] = [0; 64];

    buf[5] = 0x30;

    buf[6] = 0x25;

    buf[7] = 0x02;

    buf[8] = 0x01;

    buf[9] = 13;

    buf[10] = 0x04;

    buf[11] = 0x20;

    for i in 0..32 {
        buf[12 + i] = (i as u8) + 1;
    }

    buf
}

#[test]
fn extracts_dg13_entry() {
    let buf = sample_entry_at_5();

    let h = dg_entry_sha256(buf, 64, 5, 13);

    for i in 0..32 {
        assert(h[i] == (i as u8) + 1);
    }
}

#[test(should_fail_with = "lds: dg entry wrong dg number")]
fn rejects_wrong_dg_number() {
    let buf = sample_entry_at_5();

    let _ = dg_entry_sha256(buf, 64, 5, 14);
}

#[test(should_fail_with = "lds: dg entry out of bounds")]
fn rejects_out_of_bounds_entry() {
    let buf = sample_entry_at_5();

    let _ = dg_entry_sha256(buf, 30, 5, 13);
}

#[test]
fn accepts_sha256_oid() {
    let mut buf: [u8; 16] = [0; 16];

    for i in 0..11 {
        buf[2 + i] = SHA256_ALGORITHM_OID[i];
    }

    check_sha256_oid(buf, 16, 2);
}

#[test(should_fail_with = "lds: wrong hash algorithm oid")]
fn rejects_wrong_oid() {
    let mut buf: [u8; 16] = [0; 16];

    for i in 0..11 {
        buf[2 + i] = SHA256_ALGORITHM_OID[i];
    }

    buf[12] = 0xff;

    check_sha256_oid(buf, 16, 2);
}
