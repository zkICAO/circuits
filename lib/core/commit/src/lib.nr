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

pub global TAG_DSC_KEY: Field = 9;

pub global TAG_SET_ENTRY: Field = 10;

pub global TAG_DOCUMENT_SECRET: Field = 11;

pub global TAG_SECRET_BINDING: Field = 12;

/// An entry in a set the verifier publishes, such as a list of accepted
/// issuing states. Tagged like everything else so a set entry cannot be
/// mistaken for a document leaf.
pub fn set_entry(data: [Field; 4]) -> Field {
    Poseidon2::hash([TAG_SET_ENTRY, data[0], data[1], data[2], data[3]], 5)
}

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

/// Packs two equal length byte strings into four field elements, splitting
/// each in half so anything up to 62 bytes per string fits.
fn pack_pair<let K: u32>(a: [u8; K], b: [u8; K]) -> [Field; 4] {
    let half = K / 2;

    assert(half * 2 == K, "commit: length must be even");

    assert(half <= 31, "commit: half does not fit a field element");

    let mut packed: [Field; 4] = [0; 4];

    for i in 0..half {
        packed[0] = packed[0] * 256 + a[i] as Field;

        packed[1] = packed[1] * 256 + a[half + i] as Field;

        packed[2] = packed[2] * 256 + b[i] as Field;

        packed[3] = packed[3] * 256 + b[half + i] as Field;
    }

    packed
}

pub fn pubkey_hash<let K: u32>(x: [u8; K], y: [u8; K]) -> Field {
    let packed = pack_pair(x, y);

    Poseidon2::hash([TAG_DSC_KEY, packed[0], packed[1], packed[2], packed[3]], 5)
}

/// Folds a big number given as limbs, one limb at a time, so the same helper
/// serves any width. Every limb enters, which is what makes the result an
/// identifier for the whole number rather than for a sample of it.
///
/// The fold runs through two input hashes, which is the shape of a Merkle
/// internal node, so the accumulator alone would break the rule that only
/// nodes take that shape. The last step is three wide and carries both the
/// role tag and the limb count, which restores it and at the same time keeps
/// a narrow number from folding to the same value as a wider one whose
/// leading limbs are zero.
fn fold_limbs<let N: u32>(tag: Field, limbs: [u128; N]) -> Field {
    let mut accumulator: Field = 0;

    for i in 0..N {
        accumulator = Poseidon2::hash([accumulator, limbs[i] as Field], 2);
    }

    Poseidon2::hash([tag, N as Field, accumulator], 3)
}

/// An RSA key, hashed the way `pubkey_hash` hashes a curve point.
pub fn modulus_hash<let N: u32>(limbs: [u128; N]) -> Field {
    fold_limbs(TAG_DSC_KEY, limbs)
}

/// The document secret for a signature given as limbs, the RSA counterpart
/// of `document_secret`.
pub fn limbs_document_secret<let N: u32>(limbs: [u128; N]) -> Field {
    fold_limbs(TAG_DOCUMENT_SECRET, limbs)
}

/// Material that identifies one document and that only a party who read its
/// chip can produce. The signature over the Security Object serves: it is
/// fixed at issuance, so a prover cannot choose it, and it is not printed on
/// the data page, so it cannot be guessed from a photocopy.
///
/// It does not survive reissue. A replacement document carries a different
/// signature and therefore a different secret, which is why a policy that
/// promises stability across reissue cannot be built on this.
pub fn document_secret<let K: u32>(signature_r: [u8; K], signature_s: [u8; K]) -> Field {
    let packed = pack_pair(signature_r, signature_s);

    Poseidon2::hash(
        [TAG_DOCUMENT_SECRET, packed[0], packed[1], packed[2], packed[3]],
        5,
    )
}

/// Published so a later circuit can prove it holds the same secret without
/// revealing it. Scoped by domain, otherwise this value would itself be a
/// stable per document identifier visible to every application at once.
pub fn secret_binding(secret: Field, domain: Field) -> Field {
    Poseidon2::hash([TAG_SECRET_BINDING, secret, domain], 3)
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
// entropy_seed feeds every leaf, the root and the commitment, and a
// profile's content hash is often taken over data printed on the credential
// itself: in the machine readable zone profiles it is SHA-256 over DG1,
// which is that printed zone wrapped in a TLV template. A party holding a
// photocopy of the data page could then recompute the holder's commitment
// for a domain and test it against a registry. A zero salt is therefore rejected here; a
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

/// One field of a committed document, together with what is needed to show
/// it belongs there. Defined here because the leaf format is here: a
/// consumer that built its own version of this could drift from the format
/// the attribute circuits produce.
pub struct FieldOpening {
    pub field_id: u32,
    pub length: u32,
    pub data: [Field; 4],
    pub entropy: Field,
    pub siblings: [Field; 4],
}

pub fn leaf(field_id: Field, length: Field, data: [Field; 4], entropy: Field) -> Field {
    Poseidon2::hash(
        [TAG_LEAF, field_id, length, data[0], data[1], data[2], data[3], entropy],
        8,
    )
}

/// A Merkle internal node. Deliberately untagged and two wide: every value
/// with a role tag is wider, so a tagged value can never be read as a node.
pub fn hash_pair(left: Field, right: Field) -> Field {
    Poseidon2::hash([left, right], 2)
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

/// Walks a Merkle path of any depth. The index supplies one direction bit
/// per level, so a sibling can never be applied on the wrong side.
pub fn walk_path<let D: u32>(leaf_value: Field, index: u32, siblings: [Field; D]) -> Field {
    assert(D < 32, "commit: path depth out of range");

    let mut capacity: u32 = 1;

    for _ in 0..D {
        capacity = capacity * 2;
    }

    assert(index < capacity, "commit: leaf index out of range");

    let mut current = leaf_value;

    for level in 0..D {
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

        assert(walk_path(leaves[i], i, siblings) == root, "roundtrip mismatch");
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

// Every limb has to reach the result. An earlier RSA path sampled three
// bytes per limb, which committed to 432 bits of a 2048 bit modulus and so
// did not identify the key it claimed to.
#[test]
fn folding_limbs_depends_on_every_limb() {
    let mut limbs: [u128; 18] = [0; 18];

    for i in 0..18 {
        limbs[i] = (i as u128) + 1;
    }

    let baseline = modulus_hash(limbs);

    for position in 0..18 {
        let mut altered = limbs;

        altered[position] = altered[position] + 1;

        assert(modulus_hash(altered) != baseline, "a limb did not reach the hash");
    }
}

#[test]
fn a_key_and_a_secret_from_the_same_limbs_differ() {
    let mut limbs: [u128; 4] = [7, 8, 9, 10];

    assert(modulus_hash(limbs) != limbs_document_secret(limbs));
}

// A number is identified together with its width, so a narrower value cannot
// fold to the same result as a wider one whose leading limbs are zero.
#[test]
fn folding_separates_widths() {
    let short: [u128; 2] = [5, 6];

    let padded: [u128; 3] = [5, 6, 0];

    assert(modulus_hash(short) != modulus_hash(padded));
}
