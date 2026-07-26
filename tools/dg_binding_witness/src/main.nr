//! The binding of one data group, for a witness that needs it.
//!
//! A circuit that reads a data group checks its binding against the one the
//! extraction proof published, so a caller preparing that witness needs the
//! value. It is derived here with the library the circuits use rather than a
//! second time elsewhere. Executed to prepare a witness, never proved; a
//! data group hash is authenticated data, not a secret.

fn main(data: [u8; 128], len: u32, domain: Field) -> pub Field {
    commit::dg_binding(
        commit::hash32_to_fields(hash::sha256_bounded(data, len)),
        domain,
    )
}
