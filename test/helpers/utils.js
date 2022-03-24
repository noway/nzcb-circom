
function bufferToBitArray(b) {
    const res = [];
    for (let i = 0; i < b.length; i++) {
        for (let j = 0; j < 8; j++) {
            res.push(b[i] >> (7 - j) & 1);
        }
    }
    return res;
}

function bitArrayToBuffer(a) {
    const len = Math.floor((a.length - 1) / 8) + 1;
    const b = new Uint8Array(len);

    for (let i = 0; i < a.length; i++) {
        const p = Math.floor(i / 8);
        b[p] = b[p] | (Number(a[i]) << (7 - (i % 8)));
    }
    return b;
}

function bufferToBytes(b) {
    const res = [];
    for (let i = 0; i < b.length; i++) {
        res.push(b[i]);
    }
    return res;
}

function chunksToBits(chunks, chunkSize) {
    let bits = [];
    for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        bits = [...bits, ...chunkToBits(chunk, chunkSize)]
    }
    return new Uint8Array(bits);
}

function chunkToBits(chunk, chunkSize) {
    const bits = [];
    for (let j = 0; j < chunkSize; j++) {
        const byte = (chunk >> BigInt(j)) & 1n;
        bits.push(Number(byte));
    }
    return bits
}

function fitBytes(input, maxLen) {
    const bytes = new Uint8Array(maxLen);
    for (let i = 0; i < input.length; i++) {
        bytes[i] = input[i];
    }
    return bytes;
}

function bitArrayToNum(a) {
    let num = 0n;
    for(let i = 0; i < a.length; i++) {
        num |= BigInt(a[i]) << BigInt(i);
    }
    return num
}

function toHexString(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

function evmRearrangeBits(bitArray) {
    const res = []
    const BYTE_LEN = 8;
    for (let k = 0; k < bitArray.length / BYTE_LEN; k++) {
        const b = bitArray.length / BYTE_LEN - 1 - k;
        for (let i = 0; i < BYTE_LEN; i++) {
            res[b * BYTE_LEN + (7 - i)] = bitArray[k * BYTE_LEN + i];
        }
    }
    return res;
}

function evmBytesToNum(bytes) {
    return bitArrayToNum(bufferToBitArray(bitArrayToBuffer(evmRearrangeBits(bufferToBitArray(bytes)))))
}

function evmRearrangeBytes(bytes) {
    return bitArrayToBuffer(evmRearrangeBits(bufferToBitArray(bytes)))   
}

module.exports = {
    bufferToBitArray,
    bitArrayToBuffer,
    bufferToBytes,
    chunksToBits,
    chunkToBits,
    fitBytes,
    bitArrayToNum,
    toHexString,
    evmRearrangeBits,
    evmBytesToNum,
    evmRearrangeBytes,
}