
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
    const b = new Buffer.alloc(len);

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
    const bits = new Uint8Array(chunks.length * chunkSize);
    for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        for (let j = 0; j < chunkSize; j++) {
            const bitIdx = i * chunkSize + j;
            const byte = (chunk >> BigInt(j)) & 1n;
            bits[bitIdx] = Number(byte);
        }
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

module.exports = {
    bufferToBitArray,
    bitArrayToBuffer,
    bufferToBytes,
    chunksToBits,
    fitBytes,
}