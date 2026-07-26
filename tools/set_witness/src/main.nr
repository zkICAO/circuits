//! Computes the root of a verifier published set for one packed value.
//!
//! A membership set is curated by the verifier, and its entries and nodes
//! are Poseidon2 hashes that have to match what the member predicate
//! recomputes. Deriving them here, with the same library the circuit uses,
//! keeps one implementation of the hashing.
//!
//! Executed to prepare a witness, never proved. It reveals nothing: a set
//! is published by the verifier anyway.

fn main(data: [Field; 4], set_siblings: [Field; 8]) -> pub Field {
    commit::walk_path(commit::set_entry(data), 0, set_siblings)
}
