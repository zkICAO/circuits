//! Message digest entry points.
//!
//! ICAO 9303 documents carry two independent hash choices: the digest
//! algorithm of the CMS SignedData (used for the eContent digest and over
//! the signed attributes) and the algorithm the Security Object uses for
//! each data group hash. They are not required to be the same algorithm,
//! so circuits take them as separate variant dimensions and call the
//! matching entry point here.
//!
//! Only SHA-256 ships in the first circuit set. Further algorithms are
//! added alongside the circuit variants that need them, never earlier.

use sha256::sha256_var;

pub fn sha256_bounded<let N: u32>(msg: [u8; N], len: u32) -> [u8; 32] {
    assert(len <= N, "hash: length exceeds buffer");

    sha256_var(msg, len)
}

#[test]
fn sha256_matches_known_answer() {
    let mut msg: [u8; 8] = [0; 8];

    let abc = "abc".as_bytes();

    for i in 0..3 {
        msg[i] = abc[i];
    }

    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    let got = sha256_bounded(msg, 3);

    for i in 0..32 {
        assert(got[i] == expected[i], "sha256 mismatch");
    }
}

#[test(should_fail_with = "hash: length exceeds buffer")]
fn rejects_length_beyond_buffer() {
    let msg: [u8; 4] = [0; 4];

    let _ = sha256_bounded(msg, 5);
}
