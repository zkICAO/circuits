//! Single source of every binding value, leaf format and salt convention.
//! All circuits in this repository import these rather than re-deriving
//! them; the formulas they implement are specified in the zkICAO docs
//! repository.
//!
//! Every value here starts with a role tag, so a value produced for one
//! role cannot stand in for another. Merkle internal nodes are the one
//! untagged hash, and they are two wide while every tagged value is three
//! wide or more, which is what keeps a leaf or a seed from being passed
//! off as an internal node.
//!
//! `domain` enters every value a verifier stores or compares across
//! sessions. `context` enters none of them: it scopes a proof to one
//! session as a public input, and mixing it into a derived value would
//! change that value every session.
//!
//! Hiding is not automatic. Where a derived value is a function of
//! document data alone, anyone holding a copy of that data can recompute
//! it; see `entropy_seed`.

use poseidon::poseidon2::Poseidon2;

pub global TAG_ECONTENT: Field = 1;

pub global TAG_DG: Field = 2;

pub global TAG_DSC: Field = 3;

pub global TAG_LEAF: Field = 4;

pub global TAG_ENTROPY: Field = 5;

pub global TAG_COMMITMENT: Field = 6;

pub global TAG_NULLIFIER: Field = 7;

pub global TAG_FIELD_ENTROPY: Field = 8;

pub fn hash32_to_fields(h: [u8; 32]) -> [Field; 2] {
    let mut hi: Field = 0;

    let mut lo: Field = 0;

    for i in 0..16 {
        hi = hi * 256 + h[i] as Field;
    }

    for i in 16..32 {
        lo = lo * 256 + h[i] as Field;
    }

    [hi, lo]
}

pub fn econtent_binding(h: [Field; 2], domain: Field) -> Field {
    Poseidon2::hash([TAG_ECONTENT, h[0], h[1], domain], 4)
}

pub fn dg_binding(h: [Field; 2], domain: Field) -> Field {
    Poseidon2::hash([TAG_DG, h[0], h[1], domain], 4)
}

// dscSalt = 0 is the public registry convention: the verifier compares the
// commitment against a precomputed table. A random salt hides which DSC
// signed and is required when an anchor circuit proves trust in zero
// knowledge.
pub fn dsc_commitment(dsc_pubkey_hash: Field, salt: Field) -> Field {
    Poseidon2::hash([TAG_DSC, dsc_pubkey_hash, salt], 3)
}

// The session salt is the only hiding input in the commitment chain. Its
// absence does not merely link sessions, it removes hiding entirely:
// entropy_seed feeds every leaf, the root and the commitment, and for MRZ
// profiles dg_hash is SHA-256 over DG1, which is the printed machine
// readable zone wrapped in a TLV template. A party holding a photocopy of
// the data page could recompute the holder's commitment for a domain and
// test it against a registry. A zero salt is therefore rejected here; a
// persistent registry entry has to be built on a holder secret instead,
// not on a degenerate salt.
pub fn entropy_seed(dg_hash: [Field; 2], domain: Field, session_salt: Field) -> Field {
    assert(session_salt != 0, "commit: session salt must be non-zero");

    Poseidon2::hash(
        [TAG_ENTROPY, dg_hash[0], dg_hash[1], domain, session_salt],
        5,
    )
}

pub fn field_entropy(seed: Field, field_id: Field) -> Field {
    Poseidon2::hash([TAG_FIELD_ENTROPY, seed, field_id], 3)
}

pub fn leaf(field_id: Field, length: Field, data: [Field; 4], entropy: Field) -> Field {
    Poseidon2::hash(
        [TAG_LEAF, field_id, length, data[0], data[1], data[2], data[3], entropy],
        8,
    )
}

pub fn root16(leaves: [Field; 16]) -> Field {
    let mut l8: [Field; 8] = [0; 8];

    for i in 0..8 {
        l8[i] = Poseidon2::hash([leaves[2 * i], leaves[2 * i + 1]], 2);
    }

    let mut l4: [Field; 4] = [0; 4];

    for i in 0..4 {
        l4[i] = Poseidon2::hash([l8[2 * i], l8[2 * i + 1]], 2);
    }

    let mut l2: [Field; 2] = [0; 2];

    for i in 0..2 {
        l2[i] = Poseidon2::hash([l4[2 * i], l4[2 * i + 1]], 2);
    }

    Poseidon2::hash([l2[0], l2[1]], 2)
}

pub fn leaf_to_root16(leaf_value: Field, index: u32, siblings: [Field; 4]) -> Field {
    assert(index < 16, "commit: leaf index out of range");

    let mut current = leaf_value;

    for level in 0..4 {
        let bit = (index >> (level as u32)) & 1;

        let pair = if bit == 0 {
            [current, siblings[level]]
        } else {
            [siblings[level], current]
        };

        current = Poseidon2::hash(pair, 2);
    }

    current
}

pub fn commitment(root: Field, domain: Field) -> Field {
    Poseidon2::hash([TAG_COMMITMENT, root, domain], 3)
}

// `secret` carries whatever makes this value unguessable. Without it the
// nullifier would be a hash of a public policy identifier, a public
// domain and fields printed on the data page, so anyone holding a copy of
// a document could compute its owner's nullifier for any domain and test
// whether that person had registered: an enumeration oracle over the
// whole registered set.
//
// Two properties are required of `secret`, and both matter:
//   unguessable without access to the chip or to a keyed service, which
//   is what closes the oracle, and not chosen by the prover, since a
//   holder who can pick it can register twice and defeat the uniqueness
//   the nullifier exists to provide.
//
// Candidate sources differ in what they cost, and the choice is a
// protocol decision recorded in the specification, not here. Material
// read from the chip (for example the Security Object signature) needs no
// service but changes when a document is replaced, which is exactly the
// stability a reissue-stable policy promises. A verifiable oblivious
// pseudorandom function keyed by an independent service keeps that
// stability, at the cost of depending on the service.
pub fn nullifier(policy_id: Field, packed: [Field; 4], secret: Field, domain: Field) -> Field {
    assert(secret != 0, "commit: nullifier secret must be non-zero");

    Poseidon2::hash(
        [TAG_NULLIFIER, policy_id, packed[0], packed[1], packed[2], packed[3], secret, domain],
        8,
    )
}

#[test]
fn merkle_roundtrip_all_indices() {
    let mut leaves: [Field; 16] = [0; 16];

    for i in 0..16 {
        leaves[i] = (i as Field) + 100;
    }

    let root = root16(leaves);

    let mut l8: [Field; 8] = [0; 8];

    for i in 0..8 {
        l8[i] = Poseidon2::hash([leaves[2 * i], leaves[2 * i + 1]], 2);
    }

    let mut l4: [Field; 4] = [0; 4];

    for i in 0..4 {
        l4[i] = Poseidon2::hash([l8[2 * i], l8[2 * i + 1]], 2);
    }

    let mut l2: [Field; 2] = [0; 2];

    for i in 0..2 {
        l2[i] = Poseidon2::hash([l4[2 * i], l4[2 * i + 1]], 2);
    }

    for i in 0..16 {
        let siblings: [Field; 4] =
            [leaves[i ^ 1], l8[(i / 2) ^ 1], l4[(i / 4) ^ 1], l2[(i / 8) ^ 1]];

        assert(leaf_to_root16(leaves[i], i, siblings) == root, "roundtrip mismatch");
    }
}

#[test(should_fail_with = "commit: session salt must be non-zero")]
fn rejects_zero_session_salt() {
    let _ = entropy_seed([1, 2], 3, 0);
}

#[test(should_fail_with = "commit: nullifier secret must be non-zero")]
fn rejects_nullifier_without_secret() {
    let _ = nullifier(1001, [1, 2, 3, 4], 0, 7);
}

#[test]
fn nullifier_depends_on_secret() {
    let a = nullifier(1001, [1, 2, 3, 4], 111, 7);

    let b = nullifier(1001, [1, 2, 3, 4], 222, 7);

    assert(a != b);
}

#[test]
fn bindings_are_role_separated() {
    let h: [Field; 2] = [11, 22];

    assert(econtent_binding(h, 7) != dg_binding(h, 7));
}

#[test]
fn hash32_packs_big_endian() {
    let mut h: [u8; 32] = [0; 32];

    h[15] = 1;

    h[31] = 2;

    let f = hash32_to_fields(h);

    assert(f[0] == 1);

    assert(f[1] == 2);
}
