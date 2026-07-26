//! Active Authentication: the chip itself answered, and it answered now.
//!
//! Passive Authentication proves a state signed the data. It cannot tell a
//! genuine chip from a copy of one, because everything it reads is static
//! and a copy carries the same bytes. Doc 9303 Part 11 closes that with a
//! key pair the chip holds: the private half never leaves it, the public
//! half is published in DG15 and therefore covered by the Security Object,
//! and a terminal sends a challenge the chip signs.
//!
//! What that adds is presence at a moment. A signature over a challenge the
//! verifier chose cannot be replayed from an earlier session and cannot be
//! produced from a copy of the data, because the copy does not have the
//! private key.
//!
//! The challenge is the session context, which every circuit already carries
//! and which the verifier already issues fresh per exchange. That is not a
//! coincidence to be tidied later: a value the verifier chooses per session
//! and that enters no derived value is exactly what a challenge is, so the
//! two are one field rather than two.
//!
//! What this does not do. It proves the chip that answered holds the private
//! key whose public half is in this document's DG15. A relay, a terminal
//! that forwards a challenge to a genuine chip elsewhere, is not addressed
//! here and cannot be: distinguishing that needs a distance bound, which is
//! a property of the reader's radio rather than of any proof.

use commit::{dg_binding, hash32_to_fields};

use hash::sha256_bounded;

/// DG15 is the public key wrapped in its own template, `6F <len> <SPKI>`,
/// so the key sits at a fixed distance from the start once the template is
/// read. Doc 9303 fixes the tag; the length is short form for the key sizes
/// this reads.
global DG15_TEMPLATE_TAG: u8 = 0x6F;

/// What a proof of chip presence establishes, for the caller to publish.
pub struct Presence {
    /// Binds this to the data group the Security Object committed to, which
    /// is what ties the key that answered to this document rather than to
    /// any document.
    pub dg_binding: Field,
}

/// Proves the chip holding the key in DG15 signed the challenge.
///
/// The data group is hashed and its binding checked against the one the
/// extraction proof published, so the key is the one the issuing state put
/// in this document. The key is then read out of the data group rather than
/// taken as an input, which is what makes it that key and not one the prover
/// chose.
/// The challenge the chip answered, as bytes. The verifier's session
/// context is the challenge, so this is that value big endian, and the
/// caller asserts the two are the same number: a signature over anything
/// else would prove presence at some moment other than this exchange.
pub fn prove_presence_p256<let N: u32>(
    dg15: [u8; N],
    dg15_len: u32,
    key_offset: u32,
    expected_dg_binding: Field,
    challenge: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    domain: Field,
) -> Presence {
    assert(dg15_len <= N, "chip: length exceeds the buffer");

    assert(dg15[0] == DG15_TEMPLATE_TAG, "chip: data group 15 template tag");

    assert(dg15[1] as u32 + 2 == dg15_len, "chip: data group 15 length");

    let binding = dg_binding(hash32_to_fields(sha256_bounded(dg15, dg15_len)), domain);

    assert(binding == expected_dg_binding, "chip: data group was not the authenticated one");

    // Read out of the signed data group, not supplied beside it.
    let (x, y): ([u8; 32], [u8; 32]) = x509::ec_public_key(dg15, dg15_len, key_offset);

    // The chip signs a digest of the challenge, not the challenge itself,
    // which is what the standard's elliptic curve variant does and what any
    // signing interface expects.
    let digest = sha256_bounded(challenge, 32);

    sig::verify_ecdsa_p256(x, y, digest, signature_r, signature_s);

    Presence { dg_binding: binding }
}

/// The challenge as a number, so a caller can require it to equal the
/// session context it published. Big endian, which is how every other byte
/// value in this protocol packs.
pub fn challenge_value(challenge: [u8; 32]) -> Field {
    let mut value: Field = 0;

    // The top byte is dropped: a 32 byte value can exceed the field, and a
    // session context is far smaller than 31 bytes.
    assert(challenge[0] == 0, "chip: challenge does not fit a field element");

    for i in 1..32 {
        value = value * 256 + challenge[i] as Field;
    }

    value
}
