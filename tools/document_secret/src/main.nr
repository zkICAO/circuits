//! Computes the document secret from a signature, for a nullifier witness.
//!
//! Passive Authentication publishes a domain scoped binding to this value
//! rather than the value itself, so a nullifier circuit has to be given the
//! secret to prove it holds the matching one. Deriving it here rather than
//! reimplementing the fold keeps one definition.
//!
//! Executed to prepare a witness, never proved. The output is private
//! material the holder already has: a proof of it would publish exactly what
//! the binding exists to keep back.

fn main(signature_r: [u8; 32], signature_s: [u8; 32]) -> pub Field {
    commit::document_secret(signature_r, signature_s)
}
