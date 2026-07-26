//! Builds the root and one sibling path of a tree the verifier publishes.
//!
//! The three trees a verifier maintains, the signer registry, the master
//! list and a membership set, differ only in depth, so one tool serves all
//! three. It takes up to sixteen real leaves and the depth the consuming
//! circuit was built for, and pads everything above the leaves with the
//! empty subtree convention in `commit`.
//!
//! The same single-implementation argument as the other witness tools: the
//! nodes are Poseidon2 hashes the circuits recompute, and building them
//! anywhere else would be a second implementation that can drift from this
//! one. Executed to prepare a witness, never proved; a published tree is
//! public by definition.
//!
//! Unused leaf slots are zero, which is the empty leaf of the convention, so
//! a tree of four entries and a tree of sixteen are the same construction.

fn main(leaves: [Field; 16], index: u32, depth: u32) -> pub (Field, [Field; 16]) {
    assert(index < 16, "merkle_path: index out of range");

    assert(depth >= 4, "merkle_path: depth must cover sixteen leaves");

    assert(depth <= 16, "merkle_path: depth out of range");

    let mut level8: [Field; 8] = [0; 8];

    for i in 0..8 {
        level8[i] = commit::hash_pair(leaves[2 * i], leaves[2 * i + 1]);
    }

    let mut level4: [Field; 4] = [0; 4];

    for i in 0..4 {
        level4[i] = commit::hash_pair(level8[2 * i], level8[2 * i + 1]);
    }

    let mut level2: [Field; 2] = [0; 2];

    for i in 0..2 {
        level2[i] = commit::hash_pair(level4[2 * i], level4[2 * i + 1]);
    }

    // The sibling at each of the four levels the leaves span is the node
    // beside the one the path passes through, which the index selects.
    let mut siblings: [Field; 16] = [0; 16];

    siblings[0] = leaves[index ^ 1];

    siblings[1] = level8[(index / 2) ^ 1];

    siblings[2] = level4[(index / 4) ^ 1];

    siblings[3] = level2[(index / 8) ^ 1];

    let mut root = commit::root16(leaves);

    // Above sixteen leaves the tree holds nothing, so each further level
    // pairs the root so far with an empty subtree of that height.
    for level in 4..16 {
        if level < depth {
            siblings[level] = commit::empty_subtree(level as u32);

            root = commit::hash_pair(root, siblings[level]);
        }
    }

    (root, siblings)
}

/// The first `D` levels of a path, which is what a circuit built for depth
/// `D` takes. The tool returns sixteen levels because one return type has to
/// serve every depth, and the levels above `depth` are zero.
fn prefix<let D: u32>(siblings: [Field; 16]) -> [Field; D] {
    assert(D <= 16, "merkle_path: prefix longer than the path");

    let mut out: [Field; D] = [0; D];

    for level in 0..D {
        out[level] = siblings[level];
    }

    out
}

fn sample_leaves() -> [Field; 16] {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..16 {
        leaves[i] = commit::set_entry([i as Field + 1, 0, 0, 0]);
    }

    leaves
}

// A path this tool produces has to verify under the walk the circuits use,
// at every index, at each of the three depths a circuit is built for.
#[test]
fn every_path_verifies_at_the_membership_depth() {
    let leaves = sample_leaves();

    for index in 0..16 {
        let (root, siblings) = main(leaves, index as u32, 8);

        let path: [Field; 8] = prefix(siblings);

        assert(commit::walk_path(leaves[index], index as u32, path) == root);
    }
}

#[test]
fn every_path_verifies_at_the_master_list_depth() {
    let leaves = sample_leaves();

    for index in 0..16 {
        let (root, siblings) = main(leaves, index as u32, 10);

        let path: [Field; 10] = prefix(siblings);

        assert(commit::walk_path(leaves[index], index as u32, path) == root);
    }
}

#[test]
fn every_path_verifies_at_the_signer_registry_depth() {
    let leaves = sample_leaves();

    for index in 0..16 {
        let (root, siblings) = main(leaves, index as u32, 16);

        let path: [Field; 16] = prefix(siblings);

        assert(commit::walk_path(leaves[index], index as u32, path) == root);
    }
}

// Depth changes the root, so a path proved against a tree of one depth does
// not verify against the same leaves published at another.
#[test]
fn a_deeper_tree_has_another_root() {
    let leaves = sample_leaves();

    let (shallow, _) = main(leaves, 0, 8);

    let (deep, _) = main(leaves, 0, 16);

    assert(shallow != deep);
}

// A tree that is mostly empty is the normal case: a registry of a few
// hundred keys in a depth sixteen tree is padding almost all the way up.
#[test]
fn a_partly_filled_tree_verifies() {
    let mut leaves: [Field; 16] = [0; 16];

    leaves[0] = commit::set_entry([0x55544f, 0, 0, 0]);

    leaves[1] = commit::set_entry([0x564e4d, 0, 0, 0]);

    let (root, siblings) = main(leaves, 1, 16);

    assert(commit::walk_path(leaves[1], 1, siblings) == root);
}

#[test(should_fail_with = "merkle_path: depth must cover sixteen leaves")]
fn rejects_a_depth_the_leaves_do_not_fit() {
    let _ = main([0; 16], 0, 3);
}
