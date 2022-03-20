const chai = require("chai");
const { wasm: wasm_tester } = require("circom_tester");
const {bitArrayToNum, bufferToBitArray} = require('./helpers/utils.js');
const { assert } = chai;


describe("BinAdd", function () {
    let cir1
    let cir2
    let cir3
    let cir4
    let cir496
    before(async () => {
        cir1 = await wasm_tester(`${__dirname}/circuits/binadd1_test.circom`);
        cir2 = await wasm_tester(`${__dirname}/circuits/binadd2_test.circom`);
        cir3 = await wasm_tester(`${__dirname}/circuits/binadd3_test.circom`);
        cir4 = await wasm_tester(`${__dirname}/circuits/binadd4_test.circom`);
        cir496 = await wasm_tester(`${__dirname}/circuits/binadd496_test.circom`);
    })
    it ("BinAdd(1) exhaustively", async () => {
        for (var i = 0; i < 2; i++) {
            for (var j = 0; j < 2; j++) {
                const op1 = [i]
                const op2 = [j]
                const witness = await cir1.calculateWitness({ op1, op2 }, true);
                const out = witness.slice(1,3);
                // console.log(bitArrayToNum(out))
                assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(out));            
            }
        }
    });
    it ("BinAdd(2) exhaustively", async () => {
        for (var i = 0; i < 2; i++) {
            for (var j = 0; j < 2; j++) {
                for (var x = 0; x < 2; x++) {
                    for (var y = 0; y < 2; y++) {
                        const op1 = [i, x]
                        const op2 = [j, y]
                        const witness = await cir2.calculateWitness({ op1, op2 }, true);
                        const out = witness.slice(1,4);
                        // console.log(bitArrayToNum(out))
                        assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(out));            
                    }
                }
            }
        }
    });
    it ("BinAdd(3) exhaustively", async () => {
        for (var i = 0; i < 2; i++) {
            for (var j = 0; j < 2; j++) {
                for (var x = 0; x < 2; x++) {
                    for (var y = 0; y < 2; y++) {
                        for (var r = 0; r < 2; r++) {
                            for (var s = 0; s < 2; s++) {
                                const op1 = [i, x, r]
                                const op2 = [j, y, s]
                                const witness = await cir3.calculateWitness({ op1, op2 }, true);
                                const out = witness.slice(1, 5);
                                // console.log(bitArrayToNum(out))
                                assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(out));            
                            }
                        }
                    }
                }
            }
        }
    });
    it ("BinAdd(4) exhaustively", async () => {
        for (var i = 0; i < 2; i++) {
            for (var j = 0; j < 2; j++) {
                for (var x = 0; x < 2; x++) {
                    for (var y = 0; y < 2; y++) {
                        for (var r = 0; r < 2; r++) {
                            for (var s = 0; s < 2; s++) {
                                for (var k = 0; k < 2; k++) {
                                    for (var l = 0; l < 2; l++) {
                                        const op1 = [i, x, r, k]
                                        const op2 = [j, y, s, l]
                                        const witness = await cir4.calculateWitness({ op1, op2 }, true);
                                        const out = witness.slice(1, 6);
                                        // console.log(bitArrayToNum(out))
                                        assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(out));            
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    it ("BinAdd(496) 0 test", async () => {
        const zero = new Uint8Array(Array(62).fill(0x00))
        const op1 = bufferToBitArray(zero);
        const op2 = bufferToBitArray(zero)
        const witness = await cir496.calculateWitness({ op1, op2 }, true);
        const outFull = witness.slice(1, 496+1+1);
        assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(outFull));            
    });
    it ("BinAdd(496) a number", async () => {
        const num = new Uint8Array(Array(62).fill().map((_, i) => i))
        const op1 = bufferToBitArray(num);
        const op2 = bufferToBitArray(num)
        const witness = await cir496.calculateWitness({ op1, op2 }, true);
        const outFull = witness.slice(1, 496+1+1);
        assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(outFull));            
    });
    it ("BinAdd(496) overflow test", async () => {
        const limit = new Uint8Array(Array(62).fill(0xFF))
        const one = new Uint8Array([0x80, ...Array(61).fill(0x00)])
        const op1 = bufferToBitArray(limit);
        const op2 = bufferToBitArray(one)
        console.log('op1', op1.join(""), op1.length);
        console.log('op2', op2.join(""), op2.length);
        const witness = await cir496.calculateWitness({ op1, op2 }, true);
        const outFull = witness.slice(1, 496+1+1);
        const outCropped = witness.slice(1, 496+1);
        console.log('out', outCropped.join(""), outCropped.length)
        assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(outFull));            
        assert.equal(0, bitArrayToNum(outCropped));            
    });
});
