const crypto = require("crypto");
const { assert } = require("chai");
const { wasm: wasm_tester } = require("circom_tester");
const { verifyPassURIOffline, DID_DOCUMENTS } = require("@vaxxnz/nzcp");
const { bufferToBitArray, bitArrayToBuffer, bufferToBytes, chunksToBits, bitArrayToNum, fitBytes, toHexString } = require("./helpers/utils");
const { getCOSE, encodeToBeSigned } = require('./helpers/nzcp');
const { encodeUint, padArray, stringToArray } = require('./helpers/cbor');
const buildPedersenHash = require("circomlibjs").buildPedersenHash;
const buildBabyJub = require("circomlibjs").buildBabyjub;
const Scalar = require("ffjavascript").Scalar;
const F1Field = require("ffjavascript").F1Field;

require('dotenv').config()


// get a well distributed random field element in the domain of Z/pZ
// this might return not perfectly well distributed random values, but it's within 1 bit of being well-distributed
function getRandomFieldElement() {
    const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    const Fr = new F1Field(p);
    const randomBytes32 = crypto.randomBytes(32)
    const randomBits = bufferToBitArray(randomBytes32);
    // log2(p) is 253.596691355002 so we need at least 254 bits
    const randomBits254 = randomBits.slice(0, 254);
    const r = bitArrayToNum(randomBits254)
    const s = Fr.e(r)
    return s
}


async function getNZCPPubIdentity(passURI, secretIndex, isLive) {
    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const { givenName, familyName, dob } = verificationResult.credentialSubject;
    const credSubjConcat = `${givenName},${familyName},${dob}` // TODO: rename to nullifier
    const cose = getCOSE(passURI);
    const toBeSigned = encodeToBeSigned(cose.bodyProtected, cose.payload);
    const babyJub = await buildBabyJub();
    const F = babyJub.F;
    const pedersen = await buildPedersenHash();
    const nullifier = fitBytes(new TextEncoder().encode(credSubjConcat), 64);
    const h = pedersen.hash(nullifier);
    const hP = babyJub.unpackPoint(h);
    const nullifierHash = [F.toObject(hP[0]), F.toObject(hP[1])]
    const nullififerRange = [nullifierHash[0], nullifierHash[1] + secretIndex]
    const toBeSignedHash = crypto.createHash('sha256').update(toBeSigned).digest('hex')
    const nbf = verificationResult.raw.nbf
    const exp = verificationResult.raw.exp
    const pubIdentity = { nullififerRange, toBeSignedHash, nbf, exp };
    console.log('credSubjConcat', credSubjConcat);
    console.log('pubIdentity', pubIdentity);
    return pubIdentity;
}

async function testNZCPPubIdentity(cir, passURI, isLive, maxLen) {
    const SHA256_BYTES = 32;
    const TIMESTAMP_BITS = 8 * 4;

    const secretIndex = getRandomFieldElement();
    const expected = await getNZCPPubIdentity(passURI, secretIndex, isLive);

    const passThruData = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
    const cose = getCOSE(passURI);
    const toBeSigned = encodeToBeSigned(cose.bodyProtected, cose.payload);
    const fittedToBeSigned = fitBytes(toBeSigned, maxLen);
    const input = { toBeSigned: bufferToBitArray(fittedToBeSigned), toBeSignedLen: toBeSigned.length, data: bufferToBitArray(passThruData), secretIndex }
    const witness = await cir.calculateWitness(input, true);

    const out = witness.slice(1, 5);
    const nullifierRange = out.slice(0, 2);

    const bits = chunksToBits(out.slice(2), 248);

    const toBeSignedHashBits = bits.slice(0, SHA256_BYTES * 8);
    const nbfBits = bits.slice(SHA256_BYTES * 8, SHA256_BYTES * 8 + TIMESTAMP_BITS);
    const expBits = bits.slice(SHA256_BYTES * 8 + TIMESTAMP_BITS, SHA256_BYTES * 8 + 2 * TIMESTAMP_BITS);
    const dataBits = bits.slice(SHA256_BYTES * 8 + 2 * TIMESTAMP_BITS);
    

    const toBeSignedHash = bitArrayToBuffer(toBeSignedHashBits)
    const toBeSignedHashHex = toHexString(toBeSignedHash);

    assert.equal(nullifierRange[0], expected.nullififerRange[0]);
    assert.equal(nullifierRange[1], expected.nullififerRange[1]);
    assert.equal(toBeSignedHashHex, expected.toBeSignedHash);

    const nbf = bitArrayToNum(nbfBits);
    assert.equal(nbf, expected.nbf)

    const exp = bitArrayToNum(expBits);
    assert.equal(exp, expected.exp)

    const actualPassThruData = bitArrayToBuffer(dataBits)
    assert.deepEqual(actualPassThruData, passThruData);
}

const EXAMPLE_PASS_URI = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";

const LIVE_PASS_URI_1 = process.env.LIVE_PASS_URI_1;
const LIVE_PASS_URI_2 = process.env.LIVE_PASS_URI_2;
const LIVE_PASS_URI_3 = process.env.LIVE_PASS_URI_3;
const LIVE_PASS_URI_4 = process.env.LIVE_PASS_URI_4;

async function testFindCWTClaims(cir, passURI, isLive, pos, maxLen, expectedVCPos, expectedNbfPos, expectedExpPos) {

    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const exp = verificationResult.raw.exp
    const nbf = verificationResult.raw.nbf

    const mapLen = 5;
    const cose = getCOSE(passURI);
    const toBeSigned = encodeToBeSigned(cose.bodyProtected, cose.payload);
    const fittedToBeSigned = fitBytes(toBeSigned, maxLen);
    const bytes = bufferToBytes(fittedToBeSigned)
    const witness = await cir.calculateWitness({ mapLen, bytes, pos }, true);

    const actualVCPos = Number(witness[1]);
    assert.equal(actualVCPos, expectedVCPos);

    const actualNbfPos = Number(witness[2]);
    assert.equal(actualNbfPos, expectedNbfPos);

    const actualExpPos = Number(witness[3]);
    assert.equal(actualExpPos, expectedExpPos);

    // assert that expiry date is at the right position
    const actualNbf = bufferToBytes(fittedToBeSigned.slice(actualNbfPos, actualNbfPos + 5));
    assert.deepEqual(actualNbf, encodeUint(nbf));

    // assert that expiry date is at the right position
    const actualExp = bufferToBytes(fittedToBeSigned.slice(actualExpPos, actualExpPos + 5));
    assert.deepEqual(actualExp, encodeUint(exp));

}
describe("NZCP find CWT claims - example pass", function () {
    this.timeout(100000);

    const maxLen = 314;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findCWTClaims_exampleTest.circom`);
    })

    it ("Should find CWT claims of EXAMPLE_PASS_URI", async () => {
        await testFindCWTClaims(cir, EXAMPLE_PASS_URI, false, 28, maxLen, 76, 62, 68);
    });
});

describe("NZCP find CWT claims - live pass", function () {
    this.timeout(100000);

    const maxLen = 355;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findCWTClaims_liveTest.circom`);
    })

    it ("Should find CWT claims of LIVE_PASS_URI_1", async () => {
        await testFindCWTClaims(cir, LIVE_PASS_URI_1, true, 31, maxLen, 80, 66, 72);
    });
    if (LIVE_PASS_URI_2) {
        it ("Should find CWT claims of LIVE_PASS_URI_2", async () => {
            await testFindCWTClaims(cir, LIVE_PASS_URI_2, true, 31, maxLen, 80, 66, 72);
        });
    }
    if (LIVE_PASS_URI_3) {
        it ("Should find CWT claims of LIVE_PASS_URI_3", async () => {
            await testFindCWTClaims(cir, LIVE_PASS_URI_3, true, 31, maxLen, 80, 66, 72);
        });
    }
    if (LIVE_PASS_URI_4) {
        it ("Should find CWT claims of LIVE_PASS_URI_4", async () => {
            await testFindCWTClaims(cir, LIVE_PASS_URI_4, true, 31, maxLen, 80, 66, 72);
        });
    }
});


async function testFindCredSubj(cir, passURI, pos, maxLen, expectedCredSubjPos) {

    const mapLen = 4;
    const cose = getCOSE(passURI);
    const toBeSigned = encodeToBeSigned(cose.bodyProtected, cose.payload);
    const fittedToBeSigned = fitBytes(toBeSigned, maxLen);
    const bytes = bufferToBytes(fittedToBeSigned)
    const witness = await cir.calculateWitness({ mapLen, bytes, pos }, true);

    const actualCredSubjPos = Number(witness[1]);
    assert.equal(actualCredSubjPos, expectedCredSubjPos);
}

describe("NZCP find credential subject - example pass", function () {
    this.timeout(100000);

    const maxLen = 314;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findCredSubj_exampleTest.circom`);
    })

    it ("Should find credential subject of EXAMPLE_PASS_URI", async () => {
        await testFindCredSubj(cir, EXAMPLE_PASS_URI, 77, maxLen, 246);
    });
});

describe("NZCP find credential subject - live pass", function () {
    this.timeout(100000);

    const maxLen = 355;
    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/findCredSubj_liveTest.circom`);
    })

    it ("Should find credential subject of LIVE_PASS_URI_1", async () => {
        await testFindCredSubj(cir, LIVE_PASS_URI_1, 81, maxLen, 250);
    });

    if (LIVE_PASS_URI_2) {
        it ("Should find credential subject of LIVE_PASS_URI_2", async () => {
            await testFindCredSubj(cir, LIVE_PASS_URI_2, 81, maxLen, 250);
        });
    }

    if (LIVE_PASS_URI_3) {
        it ("Should find credential subject of LIVE_PASS_URI_3", async () => {
            await testFindCredSubj(cir, LIVE_PASS_URI_3, 81, maxLen, 250);
        });
    }

    if (LIVE_PASS_URI_4) {
        it ("Should find credential subject of LIVE_PASS_URI_4", async () => {
            await testFindCredSubj(cir, LIVE_PASS_URI_4, 81, maxLen, 250);
        });
    }
});

async function testReadCredSubj(cir, passURI, isLive, pos, maxLen, maxBufferLen) {

    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const { givenName, familyName, dob } = verificationResult.credentialSubject;

    const mapLen = 3;
    const cose = getCOSE(passURI);
    const toBeSigned = encodeToBeSigned(cose.bodyProtected, cose.payload);
    const fittedToBeSigned = fitBytes(toBeSigned, maxLen);
    const bytes = bufferToBytes(fittedToBeSigned)
    const witness = await cir.calculateWitness({ mapLen, bytes, pos }, true);

    const actualGivenName = witness.slice(1, 1 + maxBufferLen).map(e => Number(e));
    const actualGivenNameLen = witness[1 + maxBufferLen];

    const actualFamilyName = witness.slice(2 + maxBufferLen, 2 + 2 * maxBufferLen).map(e => Number(e));
    const actualFamilyNameLen = witness[2 + 2 * maxBufferLen];

    const actualDob = witness.slice(3 + 2 * maxBufferLen, 3 + 3 * maxBufferLen).map(e => Number(e));
    const actualDobLen = witness[3 + 3 * maxBufferLen];

    assert.deepEqual(actualGivenName, padArray(stringToArray(givenName), maxBufferLen));
    assert.equal(actualGivenNameLen, givenName.length);

    assert.deepEqual(actualFamilyName, padArray(stringToArray(familyName), maxBufferLen));
    assert.equal(actualFamilyNameLen, familyName.length);

    assert.deepEqual(actualDob, padArray(stringToArray(dob), maxBufferLen));
    assert.equal(actualDobLen, dob.length);
}
describe("NZCP read credential subject - example pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/readCredSubj_exampleTest.circom`);
    })

    it ("Should read credential subject of EXAMPLE_PASS_URI", async () => {
        await testReadCredSubj(cir, EXAMPLE_PASS_URI, false, 247, 314, 32);
    });
});

describe("NZCP read credential subject - live pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/readCredSubj_liveTest.circom`);
    })

    it ("Should read credential subject of LIVE_PASS_URI_1", async () => {
        await testReadCredSubj(cir, LIVE_PASS_URI_1, true, 251, 355, 64);
    });
    if (LIVE_PASS_URI_2) {
        it ("Should read credential subject of LIVE_PASS_URI_2", async () => {
            await testReadCredSubj(cir, LIVE_PASS_URI_2, true, 251, 355, 64);
        });
    }
    if (LIVE_PASS_URI_3) {
        it ("Should read credential subject of LIVE_PASS_URI_3", async () => {
            await testReadCredSubj(cir, LIVE_PASS_URI_3, true, 251, 355, 64);
        });
    }
    if (LIVE_PASS_URI_4) {
        it ("Should read credential subject of LIVE_PASS_URI_4", async () => {
            await testReadCredSubj(cir, LIVE_PASS_URI_4, true, 251, 355, 64);
        });
    }
});

async function testCredSubjConcat(cir, passURI, isLive) {
    const maxBufferLen = 64;

    const verificationResult = verifyPassURIOffline(passURI, { didDocument: isLive ? DID_DOCUMENTS.MOH_LIVE : DID_DOCUMENTS.MOH_EXAMPLE })
    const { givenName, familyName, dob } = verificationResult.credentialSubject;

    const expectedResult = `${givenName},${familyName},${dob}`

    const witness = await cir.calculateWitness({ 
        givenName: padArray(stringToArray(givenName), maxBufferLen),
        givenNameLen: givenName.length,
        familyName: padArray(stringToArray(familyName), maxBufferLen),
        familyNameLen: familyName.length,
        dob: padArray(stringToArray(dob), maxBufferLen),
        dobLen: dob.length,
     }, true);


     const actualResult = witness.slice(1, 1 + maxBufferLen).map(e => Number(e));
     const actualResultLen = witness[1 + maxBufferLen];

     assert.deepEqual(actualResult, padArray(stringToArray(expectedResult), maxBufferLen));
     assert.equal(actualResultLen, expectedResult.length);
}

describe("NZCP credential subject concat - example pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/concatCredSubj_test.circom`);
    })

    it ("Should concat credential subject for EXAMPLE_PASS_URI", async () => {
        await testCredSubjConcat(cir, EXAMPLE_PASS_URI, false, 64);
    });

    it ("Should concat credential subject for LIVE_PASS_URI_1", async () => {
        await testCredSubjConcat(cir, LIVE_PASS_URI_1, true, 64);
    });
    if (LIVE_PASS_URI_2) {
        it ("Should concat credential subject for LIVE_PASS_URI_2", async () => {
            await testCredSubjConcat(cir, LIVE_PASS_URI_2, true, 64);
        });
    }
    if (LIVE_PASS_URI_3) {
        it ("Should concat credential subject for LIVE_PASS_URI_3", async () => {
            await testCredSubjConcat(cir, LIVE_PASS_URI_3, true, 64);
        });
    }
    if (LIVE_PASS_URI_4) {
        it ("Should concat credential subject for LIVE_PASS_URI_4", async () => {
            await testCredSubjConcat(cir, LIVE_PASS_URI_4, true, 64);
        });
    }
});
describe("NZCP public identity - example pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/nzcp_exampleTest.circom`);
    })

    it ("Should output pub identity for EXAMPLE_PASS_URI", async () => {
        await testNZCPPubIdentity(cir, EXAMPLE_PASS_URI, false, 314);
    });
});


describe("NZCP public identity - live pass", function () {
    this.timeout(100000);

    let cir
    before(async () => {
        cir = await wasm_tester(`${__dirname}/../circuits/nzcp_liveTest.circom`);
    })

    it ("Should output pub identity for LIVE_PASS_URI_1", async () => {
        await testNZCPPubIdentity(cir, LIVE_PASS_URI_1, true, 355);
    });
    if (LIVE_PASS_URI_2) {
        it ("Should output pub identity for LIVE_PASS_URI_2", async () => {
            await testNZCPPubIdentity(cir, LIVE_PASS_URI_2, true, 355);
        });
    }
    if (LIVE_PASS_URI_3) {
        it ("Should output pub identity for LIVE_PASS_URI_3", async () => {
            await testNZCPPubIdentity(cir, LIVE_PASS_URI_3, true, 355);
        });
    }
    if (LIVE_PASS_URI_4) {
        it ("Should output pub identity for LIVE_PASS_URI_4", async () => {
            await testNZCPPubIdentity(cir, LIVE_PASS_URI_4, true, 355);
        });
    }
});

