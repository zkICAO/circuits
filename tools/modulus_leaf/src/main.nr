//! The leaf a country signing key takes in a master list, given as modulus
//! limbs.
//!
//! Same argument as the other leaf tools: the hash is the one the chain
//! anchor recomputes, so it is derived with that library and not a second
//! implementation. Executed to prepare a witness, never proved; a master
//! list is published anyway.

fn main(modulus_limbs: [u128; 18]) -> pub Field {
    commit::modulus_hash(modulus_limbs)
}
