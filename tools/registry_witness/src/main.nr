//! Computes a signer registry leaf and the root it sits under.
//!
//! A registry is published by whoever curates it, and its leaves and nodes
//! are Poseidon2 hashes that have to match what the anchor circuit
//! recomputes. Deriving them anywhere else would mean a second
//! implementation of the same hashing, and a divergence between the two
//! would show up as an inclusion proof that fails for a key that is really
//! in the set.
//!
//! Executed to prepare a witness, never proved. It reveals nothing: every
//! input is a public key that the registry publishes anyway.

fn main(pubkey_x: [u8; 32], pubkey_y: [u8; 32], siblings: [Field; 16]) -> pub (Field, Field) {
    let leaf = commit::pubkey_hash(pubkey_x, pubkey_y);

    (leaf, commit::walk_path(leaf, 0, siblings))
}
