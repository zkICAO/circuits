// The derived values of lib/core/commit, in circom.
//
// Every formula here has a counterpart in the Noir library, and the two must
// agree exactly: a predicate proved with this stack opens a commitment the
// Noir attribute circuit produced, so a difference of one field element in
// any of these means the predicate proves nothing about the document. The
// role tags are the same tags, taken from the same table, because a value
// produced for one role must not stand in for another in either stack.
//
// What is here is only what a predicate needs: the leaf, the path walk, the
// commitment and a set entry. The bindings a document proof produces are not
// here, because nothing on this side derives them.

pragma circom 2.1.6;

include "poseidon2.circom";

// The tags of lib/core/commit. Only the ones a predicate reaches.
function TAG_LEAF() { return 4; }

function TAG_COMMITMENT() { return 6; }

function TAG_SET_ENTRY() { return 10; }

// One committed field: identifier, length, the packed data and its blinding.
// Length is hashed because the packing is big endian with no length prefix,
// so two byte strings differing only in leading zeros pack identically.
template Leaf() {
    signal input fieldId;

    signal input length;

    signal input data[4];

    signal input entropy;

    signal output out;

    component h = Poseidon2(8);

    h.in[0] <== TAG_LEAF();

    h.in[1] <== fieldId;

    h.in[2] <== length;

    for (var i = 0; i < 4; i++) {
        h.in[3 + i] <== data[i];
    }

    h.in[7] <== entropy;

    out <== h.out;
}

template Commitment() {
    signal input root;

    signal input domain;

    signal output out;

    component h = Poseidon2(3);

    h.in[0] <== TAG_COMMITMENT();

    h.in[1] <== root;

    h.in[2] <== domain;

    out <== h.out;
}

// An entry in a set the verifier publishes. Note it hashes the data alone,
// not the length or the identifier, so membership is over packed values.
template SetEntry() {
    signal input data[4];

    signal output out;

    component h = Poseidon2(5);

    h.in[0] <== TAG_SET_ENTRY();

    for (var i = 0; i < 4; i++) {
        h.in[1 + i] <== data[i];
    }

    out <== h.out;
}

// The Merkle internal node: the one untagged two wide hash. Arity is what
// separates it from every tagged value, all of which are three wide or more.
template HashPair() {
    signal input left;

    signal input right;

    signal output out;

    component h = Poseidon2(2);

    h.in[0] <== left;

    h.in[1] <== right;

    out <== h.out;
}

// Walks a leaf to a root, taking one direction bit per level out of the
// index, so a sibling cannot be applied on the wrong side. The bits are
// constrained to be bits and to reconstruct the index, which is what stops a
// prover choosing a path that does not correspond to its stated position.
template WalkPath(depth) {
    signal input leaf;

    signal input index;

    signal input siblings[depth];

    signal output out;

    signal bits[depth];

    signal recomposed[depth + 1];

    recomposed[0] <== 0;

    var weight = 1;

    for (var level = 0; level < depth; level++) {
        bits[level] <-- (index >> level) & 1;

        bits[level] * (bits[level] - 1) === 0;

        recomposed[level + 1] <== recomposed[level] + bits[level] * weight;

        weight = weight * 2;
    }

    recomposed[depth] === index;

    signal current[depth + 1];

    current[0] <== leaf;

    component node[depth];

    // Selecting with the bit: when it is zero the current value is on the
    // left, when it is one it is on the right.
    signal swapped[depth][2];

    for (var level = 0; level < depth; level++) {
        swapped[level][0] <== current[level] + bits[level] * (siblings[level] - current[level]);

        swapped[level][1] <== siblings[level] + bits[level] * (current[level] - siblings[level]);

        node[level] = HashPair();

        node[level].left <== swapped[level][0];

        node[level].right <== swapped[level][1];

        current[level + 1] <== node[level].out;
    }

    out <== current[depth];
}
