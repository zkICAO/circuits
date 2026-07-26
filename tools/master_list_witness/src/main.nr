//! Computes a master list leaf and the root it sits under, for a country
//! signing key given as modulus limbs.
//!
//! The same single-implementation argument as the other witness tools: the
//! leaf and the nodes are Poseidon2 hashes the chain anchor recomputes, and
//! deriving them anywhere else would be a second implementation that can
//! drift. Executed to prepare a witness, never proved; a master list is
//! published anyway.

fn main(modulus_limbs: [u128; 18], siblings: [Field; 10]) -> pub (Field, Field) {
    let leaf = commit::modulus_hash(modulus_limbs);

    (leaf, commit::walk_path(leaf, 0, siblings))
}
