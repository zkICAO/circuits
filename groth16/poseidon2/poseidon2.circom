// Poseidon2 over BN254 at width 4, matching the permutation Barretenberg
// implements and Noir exposes as std::hash::poseidon2_permutation.
//
// This exists because the two proving stacks have to agree on one hash. The
// Noir circuits commit a document's fields with Poseidon2, and a Groth16
// predicate that opened those commitments with any other hash, Poseidon v1
// from circomlib included, would compute a different root and prove nothing
// about the document. The constants come from the pinned Barretenberg
// revision rather than from a paper, and the agreement is checked against
// vectors the Noir side produced, not assumed.
//
// Structure, from the paper and the reference implementation: one external
// linear layer, four external rounds, fifty six internal rounds, four more
// external rounds. The S-box is x^5.

pragma circom 2.1.6;

include "constants.circom";

// x^5, as three constraints rather than five multiplications.
template SBox() {
    signal input in;

    signal output out;

    signal square;

    signal quad;

    square <== in * in;

    quad <== square * square;

    out <== quad * in;
}

// The external MDS layer. The matrix is
//
//     5 7 1 3
//     4 6 1 1
//     1 3 5 7
//     1 1 4 6
//
// evaluated by the addition chain the reference implementation uses, which
// is linear so it costs no constraints.
template ExternalLayer() {
    signal input in[4];

    signal output out[4];

    signal t0;

    signal t1;

    signal t2;

    signal t3;

    signal t4;

    signal t5;

    t0 <== in[0] + in[1];

    t1 <== in[2] + in[3];

    t2 <== in[1] + in[1] + t1;

    t3 <== in[3] + in[3] + t0;

    t4 <== t1 + t1 + t1 + t1 + t3;

    t5 <== t0 + t0 + t0 + t0 + t2;

    out[0] <== t3 + t5;

    out[1] <== t5;

    out[2] <== t2 + t4;

    out[3] <== t4;
}

// The internal layer multiplies by the identity plus a diagonal, so each
// output is the whole sum plus that position's own scaled contribution.
template InternalLayer() {
    signal input in[4];

    signal output out[4];

    var diagonal[4] = POSEIDON2_INTERNAL_DIAGONAL_MINUS_ONE();

    signal sum;

    sum <== in[0] + in[1] + in[2] + in[3];

    for (var i = 0; i < 4; i++) {
        out[i] <== diagonal[i] * in[i] + sum;
    }
}

template Poseidon2Permutation() {
    signal input in[4];

    signal output out[4];

    var rc[64][4] = POSEIDON2_ROUND_CONSTANTS();

    component initial = ExternalLayer();

    for (var i = 0; i < 4; i++) {
        initial.in[i] <== in[i];
    }

    // Every round's state, so each stage reads the one before it.
    signal state[65][4];

    for (var i = 0; i < 4; i++) {
        state[0][i] <== initial.out[i];
    }

    component firstSbox[4][4];

    component firstLayer[4];

    for (var r = 0; r < 4; r++) {
        firstLayer[r] = ExternalLayer();

        for (var i = 0; i < 4; i++) {
            firstSbox[r][i] = SBox();

            firstSbox[r][i].in <== state[r][i] + rc[r][i];

            firstLayer[r].in[i] <== firstSbox[r][i].out;
        }

        for (var i = 0; i < 4; i++) {
            state[r + 1][i] <== firstLayer[r].out[i];
        }
    }

    // The internal rounds add a constant to the first element only and put
    // the S-box on that element alone, which is what makes them cheap.
    component middleSbox[56];

    component middleLayer[56];

    for (var r = 0; r < 56; r++) {
        middleSbox[r] = SBox();

        middleSbox[r].in <== state[4 + r][0] + rc[4 + r][0];

        middleLayer[r] = InternalLayer();

        middleLayer[r].in[0] <== middleSbox[r].out;

        for (var i = 1; i < 4; i++) {
            middleLayer[r].in[i] <== state[4 + r][i];
        }

        for (var i = 0; i < 4; i++) {
            state[5 + r][i] <== middleLayer[r].out[i];
        }
    }

    component lastSbox[4][4];

    component lastLayer[4];

    for (var r = 0; r < 4; r++) {
        lastLayer[r] = ExternalLayer();

        for (var i = 0; i < 4; i++) {
            lastSbox[r][i] = SBox();

            lastSbox[r][i].in <== state[60 + r][i] + rc[60 + r][i];

            lastLayer[r].in[i] <== lastSbox[r][i].out;
        }

        for (var i = 0; i < 4; i++) {
            state[61 + r][i] <== lastLayer[r].out[i];
        }
    }

    for (var i = 0; i < 4; i++) {
        out[i] <== state[64][i];
    }
}

// The sponge Noir's Poseidon2::hash runs, at a fixed input length.
//
// The initial value is the length shifted left by 64 bits, sitting in the
// capacity element. Absorbing takes three elements at a time; a final
// permutation runs unless the input divided evenly into chunks, which is
// the one case where the last chunk's permutation already ran.
template Poseidon2(N) {
    signal input in[N];

    signal output out;

    var chunks = N \ 3;

    var remainder = N % 3;

    // Number of permutations: one per full chunk, plus one for a partial
    // tail or for the empty input.
    var permutations = chunks + ((remainder != 0 || N == 0) ? 1 : 0);

    signal state[permutations + 1][4];

    state[0][0] <== 0;

    state[0][1] <== 0;

    state[0][2] <== 0;

    state[0][3] <== N * 18446744073709551616;

    component permutation[permutations];

    var applied = 0;

    for (var c = 0; c < chunks; c++) {
        permutation[applied] = Poseidon2Permutation();

        for (var i = 0; i < 3; i++) {
            permutation[applied].in[i] <== state[applied][i] + in[c * 3 + i];
        }

        permutation[applied].in[3] <== state[applied][3];

        for (var i = 0; i < 4; i++) {
            state[applied + 1][i] <== permutation[applied].out[i];
        }

        applied++;
    }

    if (remainder != 0 || N == 0) {
        permutation[applied] = Poseidon2Permutation();

        for (var i = 0; i < 3; i++) {
            if (i < remainder) {
                permutation[applied].in[i] <== state[applied][i] + in[chunks * 3 + i];
            } else {
                permutation[applied].in[i] <== state[applied][i];
            }
        }

        permutation[applied].in[3] <== state[applied][3];

        for (var i = 0; i < 4; i++) {
            state[applied + 1][i] <== permutation[applied].out[i];
        }

        applied++;
    }

    out <== state[permutations][0];
}
