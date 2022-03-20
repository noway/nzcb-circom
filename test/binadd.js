const chai = require("chai");
const { wasm: wasm_tester } = require("circom_tester");
const chaiAsPromised = require("chai-as-promised");
const {bitArrayToNum} = require('./helpers/utils.js');
chai.use(chaiAsPromised);
const { assert } = chai;


describe("BinAdd", function () {
    let cir1
    let cir2
    let cir3
    let cir4
    before(async () => {
        cir1 = await wasm_tester(`${__dirname}/circuits/binadd1_test.circom`);
        cir2 = await wasm_tester(`${__dirname}/circuits/binadd2_test.circom`);
        cir3 = await wasm_tester(`${__dirname}/circuits/binadd3_test.circom`);
        cir4 = await wasm_tester(`${__dirname}/circuits/binadd4_test.circom`);
    })
    it ("BinAdd(1) exhaustively", async () => {
        for (var i = 0; i < 2; i++) {
            for (var j = 0; j < 2; j++) {
                const op1 = [i]
                const op2 = [j]
                const witness = await cir1.calculateWitness({ op1, op2 }, true);
                const out = witness.slice(1,3);
                console.log(bitArrayToNum(out))
                assert.equal(bitArrayToNum(op1) + bitArrayToNum(op2), bitArrayToNum(out));            
            }
        }
    });
});
