pragma circom 2.0.3;

include "../snark-jwt-verify/circomlib/circuits/comparators.circom";
include "../snark-jwt-verify/circomlib/circuits/gates.circom";

template BinAdd(nbits) {
    signal input op1[nbits];
    signal input op2[nbits];
    signal output out[nbits + 1];
    
    signal register[nbits];
    signal carry[nbits + 1];
    
    component lt2[nbits];
    component gt1[nbits];
    component eq3[nbits];

    carry[0] <== 0;
    for (var i = 0; i < nbits; i++) {
        register[i] <== op1[i] + op2[i] + carry[i];
        
        lt2[i] = LessThan(2);
        lt2[i].in[0] <== register[i];
        lt2[i].in[1] <== 2;

        gt1[i] = NOT();
        gt1[i].in <== lt2[i].out;

        carry[i + 1] <== gt1[i].out;

        eq3[i] = IsZero();
        eq3[i].in <== register[i] - 3;

        out[i] <== lt2[i].out * register[i] + eq3[i].out;
    }
    out[nbits] <== carry[nbits];
}
