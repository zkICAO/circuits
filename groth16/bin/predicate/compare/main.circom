// The Groth16 form of bin/predicate/compare: a committed field lies within a
// range the verifier published, without disclosing the value.
//
// Same statement, same commitment format and same field identifiers as the
// Noir circuit of that name. What differs is the proving system, which is
// the point: a Groth16 proof is a few hundred bytes and its on chain
// verification is a fixed pairing check, where the recursive stack pays for
// a much larger verifier.
//
// One bound comparison covers over, under and between, since a one sided
// bound is a range with the other end at its extreme.

pragma circom 2.1.6;

include "../open.circom";

template Compare() {
    // Public: what the verifier asked and which document it asked of.
    signal input fieldId;

    signal input commitment;

    signal input minimum;

    signal input maximum;

    signal input domain;

    // Private: the opening the holder derived with the witness tool.
    signal input length;

    signal input data[4];

    signal input entropy;

    signal input siblings[4];

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

    // The value has to fit one element, as it does in the Noir circuit, so
    // the comparison is over an integer rather than over packed text.
    data[1] === 0;

    data[2] === 0;

    data[3] === 0;

    // Bounds and value are 64 bit, matching the widths the Noir circuit
    // takes. Comparing at 64 bits in a field this size is exact: the
    // difference of two 64 bit values cannot wrap.
    component valueBits = Bits(64);

    valueBits.in <== data[0];

    component minimumBits = Bits(64);

    minimumBits.in <== minimum;

    component maximumBits = Bits(64);

    maximumBits.in <== maximum;

    // minimum <= value <= maximum, each as a 65 bit non negative difference.
    component aboveMinimum = Bits(65);

    aboveMinimum.in <== data[0] - minimum;

    component belowMaximum = Bits(65);

    belowMaximum.in <== maximum - data[0];

    // An empty range would let the two checks above pass vacuously for no
    // value at all, so it is refused as the Noir circuit refuses it.
    component orderedBounds = Bits(65);

    orderedBounds.in <== maximum - minimum;
}

component main {public [fieldId, commitment, minimum, maximum, domain]} = Compare();
