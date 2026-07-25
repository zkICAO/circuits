//! Extracts one data group hash from a Security Object of up to 1024 bytes
//! whose data group hashes are SHA-256.
//!
//! `dg_number` is public so a verifier states which data group the proof is
//! about, rather than trusting the prover to say afterwards.

fn main(
    econtent: [u8; 1024],
    econtent_len: u32,
    oid_offset: u32,
    dg_offset: u32,
    dg_number: pub u8,
    econtent_binding: pub Field,
    domain: pub Field,
    context: pub Field,
) -> pub Field {
    assert(context != 0, "dg_extract: context must be set");

    assert(domain != 0, "dg_extract: domain must be set");

    dg_extract::extract_sha256(
        econtent,
        econtent_len,
        oid_offset,
        dg_offset,
        dg_number,
        econtent_binding,
        domain,
    )
}
