// The Groth16 form of bin/predicate/reveal: one committed field, disclosed.
//
// The disclosed value and its length are public and must equal the opening,
// which is what makes this a disclosure rather than an assertion. Note what
// it costs, the same as in the Noir circuit: a holder who reveals the same
// field to two applications links those sessions whatever the domain,
// because the value itself is not domain scoped.

pragma circom 2.1.6;

include "../open.circom";

template Reveal() {
    // Public: which field, which document, and what is being disclosed.
    signal input fieldId;

    signal input commitment;

    signal input revealed[4];

    signal input revealedLength;

    signal input domain;

    // Private: the blinding and the path, which stay private even here.
    signal input entropy;

    signal input siblings[4];

    component opening = OpenField();

    opening.fieldId <== fieldId;

    opening.length <== revealedLength;

    for (var i = 0; i < 4; i++) {
        opening.data[i] <== revealed[i];
    }

    opening.entropy <== entropy;

    for (var i = 0; i < 4; i++) {
        opening.siblings[i] <== siblings[i];
    }

    opening.commitment <== commitment;

    opening.domain <== domain;
}

component main {public [fieldId, commitment, revealed, revealedLength, domain]} = Reveal();
