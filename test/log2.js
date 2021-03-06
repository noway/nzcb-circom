const { assert } = require("chai");
const { wasm: wasm_tester } = require("circom_tester");

describe("log2 function", function () {
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/log2_test.circom`);
    })
    it ("log2 works", async () => {
        const witness = await cir.calculateWitness({}, true);
    });
});