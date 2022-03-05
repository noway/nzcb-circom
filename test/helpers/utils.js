
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

function bufferToChunks(bytes, chunkSize) {
    const len = Math.floor((bytes.length - 1) / chunkSize) + 1;
    const chunks = new Array(len).fill().map(() => 0n);
    console.log(chunks)

    for (let i = 0; i < bytes.length; i++) {
        const currentChunkIdx = Math.floor(i / chunkSize);
        const chunkBitIdx = i % chunkSize;
        const additive = BigInt(bytes[i]) << BigInt(8 * chunkBitIdx);
        console.log('a[i]', bytes[i], 'additive',additive)
        chunks[currentChunkIdx] = chunks[currentChunkIdx] | additive;
    }
    return chunks
}


module.exports = {
    bufferToBitArray,
    bitArrayToBuffer,
    bufferToBytes,
    bufferToChunks,
}