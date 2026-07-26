//! The leaf an elliptic curve signer key takes in a published registry.
//!
//! A registry is built by whoever curates it, and its leaves are Poseidon2
//! hashes the anchor circuit recomputes, so they are derived here with the
//! library the circuit uses rather than a second time elsewhere. The tree
//! over these leaves is assembled by `merkle_path`.
//!
//! Executed to prepare a witness, never proved. It reveals nothing: every
//! input is a public key the registry publishes anyway.

fn main(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> pub Field {
    commit::pubkey_hash(pubkey_x, pubkey_y)
}
