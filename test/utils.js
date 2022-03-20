const { assert } = require("chai");
const { bitArrayToBuffer, chunksToBits, fitBytes, toHexString } = require("./helpers/utils");

describe("chunksToBytes function", function () {
    it ("chunksToBytes works", async () => {

        const example1Chunks = [
            332803489704591243828114355286261993890678185647226483553216796488284950010n,
            213n
        ]
        const example2Chunks = [
            366677313775235426412199931337625106565467678080892143469223808086055532772n,
            119n
        ]

        const example1 = '5fb355822221720ea4ce6734e5a09e459d452574a19310c0cea7c141f43a3dab';
        const example2 = '271ce33d671a2d3b816d788135f4343e14bc66802f8cd841faac939e8c11f3ee';

        assert.equal(toHexString(fitBytes(bitArrayToBuffer(chunksToBits(example1Chunks, 248)), 32)), example1)
        assert.equal(toHexString(fitBytes(bitArrayToBuffer(chunksToBits(example2Chunks, 248)), 32)), example2)
    });
});