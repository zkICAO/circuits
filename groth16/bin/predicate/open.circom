// Opening one field of a committed document, which every predicate does
// before it says anything about the value.
//
// The counterpart is `open` in lib/claims/predicate: rebuild the leaf from
// the opening, walk it to a root at the position the field identifier fixes,
// and require the commitment over that root to be the one the verifier was
// given. A statement proved about one field cannot be presented as a
// statement about another, because the identifier is inside the leaf and
// also fixes the position.

pragma circom 2.1.6;

include "../../poseidon2/commit.circom";

template OpenField() {
    signal input fieldId;

    signal input length;

    signal input data[4];

    signal input entropy;

    signal input siblings[4];

    signal input commitment;

    signal input domain;

    // The identifier names one of sixteen leaves. Range checking it is what
    // makes the position it selects meaningful.
    component range = Bits(5);

    range.in <== fieldId - 1;

    component leaf = Leaf();

    leaf.fieldId <== fieldId;

    leaf.length <== length;

    for (var i = 0; i < 4; i++) {
        leaf.data[i] <== data[i];
    }

    leaf.entropy <== entropy;

    component walk = WalkPath(4);

    walk.leaf <== leaf.out;

    walk.index <== fieldId - 1;

    for (var i = 0; i < 4; i++) {
        walk.siblings[i] <== siblings[i];
    }

    component expected = Commitment();

    expected.root <== walk.out;

    expected.domain <== domain;

    expected.out === commitment;
}

// Decomposes a value into `n` bits, which both range checks it and gives the
// bits to whatever needs them. A value that does not fit cannot satisfy the
// recomposition.
template Bits(n) {
    signal input in;

    signal output out[n];

    signal recomposed[n + 1];

    recomposed[0] <== 0;

    var weight = 1;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;

        out[i] * (out[i] - 1) === 0;

        recomposed[i + 1] <== recomposed[i] + out[i] * weight;

        weight = weight * 2;
    }

    recomposed[n] === in;
}
