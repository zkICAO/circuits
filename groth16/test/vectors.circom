pragma circom 2.1.6;

include "../poseidon2/poseidon2.circom";

// Every width the protocol uses, so the sponge is checked at a chunk
// boundary and either side of one.
template Vectors() {
    signal input a;

    signal input b;

    signal input c;

    signal input d;

    signal output two;

    signal output three;

    signal output four;

    signal output five;

    signal output eight;

    component h2 = Poseidon2(2);

    h2.in[0] <== a;

    h2.in[1] <== b;

    two <== h2.out;

    component h3 = Poseidon2(3);

    h3.in[0] <== a;

    h3.in[1] <== b;

    h3.in[2] <== c;

    three <== h3.out;

    component h4 = Poseidon2(4);

    h4.in[0] <== a;

    h4.in[1] <== b;

    h4.in[2] <== c;

    h4.in[3] <== d;

    four <== h4.out;

    component h5 = Poseidon2(5);

    h5.in[0] <== a;

    h5.in[1] <== b;

    h5.in[2] <== c;

    h5.in[3] <== d;

    h5.in[4] <== a;

    five <== h5.out;

    component h8 = Poseidon2(8);

    h8.in[0] <== a;

    h8.in[1] <== b;

    h8.in[2] <== c;

    h8.in[3] <== d;

    h8.in[4] <== a;

    h8.in[5] <== b;

    h8.in[6] <== c;

    h8.in[7] <== d;

    eight <== h8.out;
}

component main = Vectors();
