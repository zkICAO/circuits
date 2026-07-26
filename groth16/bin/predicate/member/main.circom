// The Groth16 form of bin/predicate/member: a committed field is one of a
// set the verifier published, without saying which one.
//
// The set is a Merkle tree of depth eight, holding up to 256 entries, which
// covers a list of issuing states or nationalities. Only its root is public,
// so the verifier learns membership and nothing more, and the index is
// private for the same reason.

pragma circom 2.1.6;

include "../open.circom";

template Member() {
    // Public: which field, which document, which set.
    signal input fieldId;

    signal input commitment;

    signal input setRoot;

    signal input domain;

    // Private: the opening, and where in the set the value sits.
    signal input length;

    signal input data[4];

    signal input entropy;

    signal input siblings[4];

    signal input setIndex;

    signal input setSiblings[8];

    component opening = OpenField();

    opening.fieldId <== fieldId;

    opening.length <== length;

    for (var i = 0; i < 4; i++) {
        opening.data[i] <== data[i];
    }

    opening.entropy <== entropy;

    for (var i = 0; i < 4; i++) {
        opening.siblings[i] <== siblings[i];
    }

    opening.commitment <== commitment;

    opening.domain <== domain;

    // The set entry hashes the packed data alone, not the length and not the
    // identifier, so the verifier has to build its set with the same packing
    // and knows which field the proof is about from the public identifier.
    component entry = SetEntry();

    for (var i = 0; i < 4; i++) {
        entry.data[i] <== data[i];
    }

    component walk = WalkPath(8);

    walk.leaf <== entry.out;

    walk.index <== setIndex;

    for (var i = 0; i < 8; i++) {
        walk.siblings[i] <== setSiblings[i];
    }

    walk.out === setRoot;
}

component main {public [fieldId, commitment, setRoot, domain]} = Member();
