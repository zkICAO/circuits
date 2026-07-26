//! Proves the chip answered, and answered this exchange.
//!
//! Every other proof in this protocol is over static data, so a copy of a
//! chip produces proofs indistinguishable from the original. This one is
//! not: the private key behind DG15 never leaves the chip, so a signature
//! over a challenge the verifier chose can only come from the chip itself,
//! and only during the exchange that challenge belongs to.
//!
//! It attaches to the rest by `dg_binding`, the same way an attribute proof
//! does, so the key that answered is the key the issuing state put in this
//! document rather than in some other one.
//!
//! What it does not rule out is a relay: a terminal that forwards the
//! challenge to a genuine chip somewhere else. Nothing in a proof can, since
//! ruling that out is a distance bound and therefore a property of the
//! reader's radio.

fn main(
    dg15: [u8; 128],
    dg15_len: u32,
    key_offset: u32,
    challenge: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    dg_binding: pub Field,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(domain != 0, "chip: domain must be set");

    assert(context != 0, "chip: context must be set");

    // The challenge is the context. Requiring them equal is what makes this
    // a proof about this exchange rather than about some earlier one whose
    // answer the prover kept.
    assert(
        chip::challenge_value(challenge) == context,
        "chip: the challenge is not this session's context",
    );

    let presence = chip::prove_presence_p256(
        dg15,
        dg15_len,
        key_offset,
        dg_binding,
        challenge,
        signature_r,
        signature_s,
        domain,
    );

    presence.dg_binding
}

// Helpers for the tests below read the generated fixtures, which is why this
// package depends on testdata.

#[test]
fn a_present_chip_answers_the_challenge() {
    let _ = main(
        testdata::DG15,
        testdata::DG15_LEN,
        testdata::DG15_KEY_OFFSET,
        testdata::DG15_CHALLENGE,
        testdata::DG15_SIGNATURE_R,
        testdata::DG15_SIGNATURE_S,
        expected_binding(42),
        42,
        99,
    );
}

// An answer kept from an earlier exchange is what this circuit exists to
// refuse, so the challenge has to be this session's.
#[test(should_fail_with = "chip: the challenge is not this session's context")]
fn rejects_an_answer_to_another_challenge() {
    let _ = main(
        testdata::DG15,
        testdata::DG15_LEN,
        testdata::DG15_KEY_OFFSET,
        testdata::DG15_CHALLENGE,
        testdata::DG15_SIGNATURE_R,
        testdata::DG15_SIGNATURE_S,
        expected_binding(42),
        42,
        100,
    );
}

// A copy of the data has the public key and no private key, so it can
// present DG15 and cannot produce an answer.
#[test(should_fail)]
fn rejects_an_invented_answer() {
    let mut r = testdata::DG15_SIGNATURE_R;

    r[31] ^= 1;

    let _ = main(
        testdata::DG15,
        testdata::DG15_LEN,
        testdata::DG15_KEY_OFFSET,
        testdata::DG15_CHALLENGE,
        r,
        testdata::DG15_SIGNATURE_S,
        expected_binding(42),
        42,
        99,
    );
}

#[test(should_fail_with = "chip: data group was not the authenticated one")]
fn rejects_a_key_from_another_document() {
    let _ = main(
        testdata::DG15,
        testdata::DG15_LEN,
        testdata::DG15_KEY_OFFSET,
        testdata::DG15_CHALLENGE,
        testdata::DG15_SIGNATURE_R,
        testdata::DG15_SIGNATURE_S,
        expected_binding(42) + 1,
        42,
        99,
    );
}

fn expected_binding(domain: Field) -> Field {
    commit::dg_binding(
        commit::hash32_to_fields(hash::sha256_bounded(testdata::DG15, testdata::DG15_LEN)),
        domain,
    )
}
