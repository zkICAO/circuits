//! The leaf a packed value takes in a set the verifier publishes.
//!
//! Building a real set means hashing every entry the way the member
//! predicate hashes the one it opens, so this returns that leaf and
//! `merkle_path` assembles the tree over them. Executed to prepare a
//! witness, never proved.

fn main(data: [Field; 4]) -> pub Field {
    commit::set_entry(data)
}
