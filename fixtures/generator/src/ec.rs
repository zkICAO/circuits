//! Elliptic curve key handling, delegated to the openssl command line tool.
//!
//! Signatures come back as DER `SEQUENCE { INTEGER r, INTEGER s }`. The
//! circuits require s at or below n/2, which certificate signatures do not
//! guarantee, so s is replaced by n - s when it is larger. Verification
//! accepts (r, s) exactly when it accepts (r, n - s), so this preserves what
//! the signature attests.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::der;

pub struct Curve {
    pub openssl_name: &'static str,
    pub scalar_bytes: usize,
    pub order: &'static [u8],
}

pub const P256: Curve = Curve {
    openssl_name: "prime256v1",
    scalar_bytes: 32,
    order: &[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ],
};

pub struct KeyPair {
    pub pem_path: std::path::PathBuf,
    pub public_x: Vec<u8>,
    pub public_y: Vec<u8>,
    pub curve: &'static Curve,
}

pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

fn run(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to start {program}: {e}"));

    if let Some(data) = stdin {
        child.stdin.as_mut().unwrap().write_all(data).unwrap();
    }

    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    out.stdout
}

pub fn generate(curve: &'static Curve, pem_path: &Path) -> KeyPair {
    run(
        "openssl",
        &[
            "ecparam",
            "-name",
            curve.openssl_name,
            "-genkey",
            "-noout",
            "-out",
            pem_path.to_str().unwrap(),
        ],
        None,
    );

    let spki = run(
        "openssl",
        &[
            "ec",
            "-in",
            pem_path.to_str().unwrap(),
            "-pubout",
            "-outform",
            "DER",
        ],
        None,
    );

    let (x, y) = uncompressed_point(&spki, curve.scalar_bytes);

    KeyPair {
        pem_path: pem_path.to_path_buf(),
        public_x: x,
        public_y: y,
        curve,
    }
}

/// SubjectPublicKeyInfo ends with a BIT STRING holding `04 || X || Y`.
fn uncompressed_point(spki: &[u8], scalar_bytes: usize) -> (Vec<u8>, Vec<u8>) {
    let point_len = 1 + 2 * scalar_bytes;

    let start = spki.len() - point_len;

    assert_eq!(
        spki[start], 0x04,
        "ec: public key point is not uncompressed"
    );

    let x = spki[start + 1..start + 1 + scalar_bytes].to_vec();

    let y = spki[start + 1 + scalar_bytes..start + point_len].to_vec();

    (x, y)
}

pub fn sign_sha256(key: &KeyPair, message: &[u8]) -> Signature {
    let der_sig = run(
        "openssl",
        &["dgst", "-sha256", "-sign", key.pem_path.to_str().unwrap()],
        Some(message),
    );

    let outer = der::read(&der_sig, 0);

    assert_eq!(
        outer.tag,
        der::TAG_SEQUENCE,
        "ec: signature is not a SEQUENCE"
    );

    let r_tlv = der::read(outer.content, 0);

    let s_tlv = der::read(outer.content, r_tlv.total_len);

    assert_eq!(
        r_tlv.tag,
        der::TAG_INTEGER,
        "ec: signature r is not an INTEGER"
    );

    assert_eq!(
        s_tlv.tag,
        der::TAG_INTEGER,
        "ec: signature s is not an INTEGER"
    );

    let r = der::integer_to_fixed(r_tlv.content, key.curve.scalar_bytes);

    let s = der::integer_to_fixed(s_tlv.content, key.curve.scalar_bytes);

    Signature {
        r,
        s: normalize_s(&s, key.curve.order),
    }
}

pub fn sha256(message: &[u8]) -> Vec<u8> {
    let out = run("openssl", &["dgst", "-sha256", "-binary"], Some(message));

    assert_eq!(out.len(), 32, "ec: unexpected digest length");

    out
}

fn is_greater_than_half(value: &[u8], order: &[u8]) -> bool {
    let half = shift_right_one(order);

    for i in 0..value.len() {
        if value[i] != half[i] {
            return value[i] > half[i];
        }
    }

    false
}

fn shift_right_one(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; value.len()];

    let mut carry = 0u8;

    for i in 0..value.len() {
        out[i] = (value[i] >> 1) | (carry << 7);

        carry = value[i] & 1;
    }

    out
}

fn subtract(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; a.len()];

    let mut borrow = 0i16;

    for i in (0..a.len()).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;

        if diff < 0 {
            out[i] = (diff + 256) as u8;

            borrow = 1;
        } else {
            out[i] = diff as u8;

            borrow = 0;
        }
    }

    assert_eq!(borrow, 0, "ec: subtraction underflowed");

    out
}

pub fn normalize_s(s: &[u8], order: &[u8]) -> Vec<u8> {
    if is_greater_than_half(s, order) {
        subtract(order, s)
    } else {
        s.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // n/2 for P-256 is
    // 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8.
    #[test]
    fn halving_the_order_matches_a_known_value() {
        let half = shift_right_one(P256.order);

        let expected: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61,
            0x7e, 0x31, 0x92, 0xa8,
        ];

        assert_eq!(half, expected);
    }

    #[test]
    fn low_s_is_left_alone_and_high_s_is_flipped() {
        let mut low = vec![0u8; 32];

        low[0] = 0x01;

        assert_eq!(normalize_s(&low, P256.order), low);

        let mut high = vec![0xffu8; 32];

        high[0] = 0xfe;

        let flipped = normalize_s(&high, P256.order);

        assert_ne!(flipped, high);

        assert!(!is_greater_than_half(&flipped, P256.order));
    }

    #[test]
    fn signing_produces_a_low_s_signature() {
        let dir = std::env::temp_dir().join("zkicao-ec-test");

        std::fs::create_dir_all(&dir).unwrap();

        let key = generate(&P256, &dir.join("k.pem"));

        let sig = sign_sha256(&key, b"zkICAO");

        assert_eq!(sig.r.len(), 32);

        assert!(!is_greater_than_half(&sig.s, P256.order));

        std::fs::remove_dir_all(&dir).ok();
    }
}
