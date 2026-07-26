//! Prints the Poseidon2 values a second implementation has to reproduce.
//!
//! The Groth16 predicates are written in circom and open commitments the
//! Noir circuits made, so both stacks must compute one hash. Agreement
//! between two implementations of a hash cannot be assumed from matching
//! constants: it is checked against vectors, and this is where the vectors
//! come from. Every width the protocol uses appears, since the sponge
//! behaves differently at each: a width that divides into three element
//! chunks runs no final permutation, and one that does not runs one.
//!
//! Executed to produce values, never proved.

use poseidon::poseidon2::Poseidon2;

fn main(a: Field, b: Field, c: Field, d: Field) -> pub [Field; 6] {
    [
        Poseidon2::hash([a, b], 2),
        Poseidon2::hash([a, b, c], 3),
        Poseidon2::hash([a, b, c, d], 4),
        Poseidon2::hash([a, b, c, d, a], 5),
        Poseidon2::hash([a, b, c, d, a, b, c, d], 8),
        commit::hash_pair(a, b),
    ]
}
