//! Produces the witness a predicate proof needs for one field.
//!
//! A predicate opens a field against the commitment an attribute proof
//! published, which needs that field's value, its blinding factor and its
//! Merkle path. All three come from the same derivation the attribute circuit
//! runs, so recomputing them outside would mean a second implementation that
//! could drift.
//!
//! This is a tool, not part of the protocol. It is executed to solve a
//! witness, never proved. Everything it returns is private material the
//! holder already holds, and a proof would publish it, which is exactly what
//! the commitment exists to prevent. Nothing should generate a verification
//! key for it, and it lives outside `bin/` so it is not mistaken for a
//! circuit. Noir requires the return of `main` to be public, which is why it
//! is marked so here and is not a statement about the protocol.

fn main(
    dg1: [u8; 128],
    dg1_len: u32,
    session_salt: Field,
    domain: Field,
    current_yyyymmdd: u32,
    field_id: u32,
) -> pub ([Field; 4], u32, Field, [Field; 4]) {
    let opening = attributes::td3_opening(
        dg1,
        dg1_len,
        current_yyyymmdd,
        session_salt,
        domain,
        field_id,
    );

    (opening.data, opening.length, opening.entropy, opening.siblings)
}
