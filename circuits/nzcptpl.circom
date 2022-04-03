pragma circom 2.0.3;

include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/gates.circom";
include "../sha256-var-circom-main/snark-jwt-verify/circomlib/circuits/comparators.circom";
include "../sha256-var-circom-main/circuits/sha256Var.circom";
include "../sha512-master/circuits/sha512/sha512.circom";
include "./cbor.circom";

/* CBOR types */
#define MAJOR_TYPE_INT 0
#define MAJOR_TYPE_NEGATIVE_INT 1
#define MAJOR_TYPE_BYTES 2
#define MAJOR_TYPE_STRING 3
#define MAJOR_TYPE_ARRAY 4
#define MAJOR_TYPE_MAP 5
#define MAJOR_TYPE_TAG 6
#define MAJOR_TYPE_CONTENT_FREE 7

/* check through constraint and assert */
#define hardcore_assert(a, b) a === b; assert(a == b)

/* assign bytes to a signal in one go */
#define copyBytes(b, a, c) for(var z = 0; z < c; z++) { a[z] <== b[z]; }

/* from https://github.com/iden3/circomlib/blob/master/circuits/gates.circom#L45 */
#define NOT(in) (1 + in - 2*in)


// @dev find verifiable credential position, expiry date position and not before position
// @param BytesLen - max bytes length of the cbor buffer
// @param MaxCborArrayLen - maximum number of elements in the CBOR array
// @param MaxCborMapLen - maximum number of elements in the CBOR map
template FindCWTClaims(BytesLen, MaxCborArrayLen, MaxCborMapLen) {
    // constants
    var ConstBytesLen = 2;
    var ConstBytes[ConstBytesLen] = [118, 99];

    // i/o signals
    signal input mapLen;
    signal input bytes[BytesLen];
    signal input pos;

    signal output vcPos;
    signal output exp;

    // signals
    signal v[MaxCborMapLen];
    signal type[MaxCborMapLen];
    signal value[MaxCborMapLen];
    signal isNeedle[MaxCborMapLen];
    signal isExp[MaxCborMapLen];
    signal isAccepted[MaxCborMapLen];
    signal isExpAccepted[MaxCborMapLen];

    component readType[MaxCborMapLen];
    component decodeUint[MaxCborMapLen];
    component decodeUintValue[MaxCborMapLen];
    component skipValue[MaxCborMapLen];
    component isString[MaxCborMapLen];
    component isInt[MaxCborMapLen];
    component isNeedleString[MaxCborMapLen];
    component is4Int[MaxCborMapLen];
    component withinMapLen[MaxCborMapLen];

    component foundPosTally = CalculateTotal(MaxCborMapLen);
    component expPosTally = CalculateTotal(MaxCborMapLen);

    for (var k = 0; k < MaxCborMapLen; k++) { 

        // read type
        readType[k] = ReadType(BytesLen);
        copyBytes(bytes, readType[k].bytes, BytesLen)
        readType[k].pos <== k == 0 ? pos : skipValue[k - 1].nextPos;
        v[k] <== readType[k].v;
        type[k] <== readType[k].type;

        // decode uint
        decodeUint[k] = DecodeUint(BytesLen);
        decodeUint[k].v <== v[k];
        copyBytes(bytes, decodeUint[k].bytes, BytesLen)
        decodeUint[k].pos <== readType[k].nextPos;
        value[k] <== decodeUint[k].value;

        // is current value a string?
        isString[k] = IsEqual();
        isString[k].in[0] <== type[k];
        isString[k].in[1] <== MAJOR_TYPE_STRING;

        // is current value an integer?
        isInt[k] = IsEqual();
        isInt[k].in[0] <== type[k];
        isInt[k].in[1] <== MAJOR_TYPE_INT;

        // skip value for next iteration
        skipValue[k] = SkipValue(BytesLen, MaxCborArrayLen);
        skipValue[k].pos <== decodeUint[k].nextPos + (value[k] * isString[k].out);
        copyBytes(bytes, skipValue[k].bytes, BytesLen)

        // is current value interpreted as a string is a "vc" string?
        isNeedleString[k] = StringEquals(BytesLen, ConstBytes, ConstBytesLen);
        copyBytes(bytes, isNeedleString[k].bytes, BytesLen)
        isNeedleString[k].pos <== decodeUint[k].nextPos; // pos before skipping
        isNeedleString[k].len <== value[k];

        // is current value interpreted as an integer is a 4 number?
        is4Int[k] = IsEqual();
        is4Int[k].in[0] <== 4;
        is4Int[k].in[1] <== value[k]; // pos before skipping

        // are we within map bounds?
        withinMapLen[k] = LessThan(8);
        withinMapLen[k].in[0] <== k;
        withinMapLen[k].in[1] <== mapLen;

        // is current value a "vc" string?
        isNeedle[k] <== isString[k].out * isNeedleString[k].out;

        // is current value a 4 int?
        isExp[k] <== isInt[k].out * is4Int[k].out;

        // should we select this vc pos candidate?
        isAccepted[k] <== isNeedle[k] * withinMapLen[k].out;

        // should we select this exp candidate?
        isExpAccepted[k] <== isExp[k] * withinMapLen[k].out;

        // put a vc pos candidate into CalculateTotal to be able to get vc pos outside of the loop
        foundPosTally.nums[k] <== isAccepted[k] * (decodeUint[k].nextPos + value[k]);
        
        // put a expPos candidate into CalculateTotal to be able to get exp pos outside of the loop
        expPosTally.nums[k] <== isExpAccepted[k] * decodeUint[k].nextPos;
    }

    vcPos <== foundPosTally.sum;

    // read exp field in the map
    component expReadType = ReadType(BytesLen);
    copyBytes(bytes, expReadType.bytes, BytesLen)
    expReadType.pos <== expPosTally.sum;
    component expDecodeUint = DecodeUint(BytesLen);
    expDecodeUint.v <== expReadType.v;
    copyBytes(bytes, expDecodeUint.bytes, BytesLen)
    expDecodeUint.pos <== expReadType.nextPos;
    exp <== expDecodeUint.value;
}

// @dev find credential subject position
// @param BytesLen - max bytes length of the cbor buffer
// @param MaxCborArrayLen - maximum number of elements in the CBOR array
// @param MaxCborMapLen - maximum number of elements in the CBOR map
template FindCredSubj(BytesLen, MaxCborArrayLen, MaxCborMapLen) {
    // constants
    var ConstBytesLen = 17;
    var ConstBytes[ConstBytesLen] = [99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 83, 117, 98, 106, 101, 99, 116];

    // i/o signals
    signal input mapLen;
    signal input bytes[BytesLen];
    signal input pos;

    signal output needlePos;

    // signals
    signal v[MaxCborMapLen];
    signal type[MaxCborMapLen];
    signal value[MaxCborMapLen];
    signal isNeedle[MaxCborMapLen];
    signal isAccepted[MaxCborMapLen];

    component readType[MaxCborMapLen];
    component decodeUint[MaxCborMapLen];
    component skipValue[MaxCborMapLen];
    component isString[MaxCborMapLen];
    component isNeedleString[MaxCborMapLen];
    component withinMapLen[MaxCborMapLen];

    component foundPosTally = CalculateTotal(MaxCborMapLen);

    for (var k = 0; k < MaxCborMapLen; k++) { 

        // read type
        readType[k] = ReadType(BytesLen);
        copyBytes(bytes, readType[k].bytes, BytesLen)
        readType[k].pos <== k == 0 ? pos : skipValue[k - 1].nextPos;
        v[k] <== readType[k].v;
        type[k] <== readType[k].type;

        // decode uint
        decodeUint[k] = DecodeUint(BytesLen);
        decodeUint[k].v <== v[k];
        copyBytes(bytes, decodeUint[k].bytes, BytesLen)
        decodeUint[k].pos <== readType[k].nextPos;
        value[k] <== decodeUint[k].value;

        // is current value a string?
        isString[k] = IsEqual();
        isString[k].in[0] <== type[k];
        isString[k].in[1] <== MAJOR_TYPE_STRING;

        // skip value for next iteration
        skipValue[k] = SkipValue(BytesLen, MaxCborArrayLen);
        skipValue[k].pos <== decodeUint[k].nextPos + (value[k] * isString[k].out);
        copyBytes(bytes, skipValue[k].bytes, BytesLen)

        // is current value interpreted as a string is a "vc" string?
        isNeedleString[k] = StringEquals(BytesLen, ConstBytes, ConstBytesLen);
        copyBytes(bytes, isNeedleString[k].bytes, BytesLen)
        isNeedleString[k].pos <== decodeUint[k].nextPos; // pos before skipping
        isNeedleString[k].len <== value[k];

        withinMapLen[k] = LessThan(8);
        withinMapLen[k].in[0] <== k;
        withinMapLen[k].in[1] <== mapLen;

        // is current value a "vc" string?
        isNeedle[k] <== isString[k].out * isNeedleString[k].out;

        // should we select this vc pos candidate?
        isAccepted[k] <== isNeedle[k] * withinMapLen[k].out;

        // put a vc pos candidate into CalculateTotal to be able to get vc pos outside of the loop
        foundPosTally.nums[k] <== isAccepted[k] * (decodeUint[k].nextPos + value[k]);
    }

    needlePos <== foundPosTally.sum;
}

// @dev read credential subject
// @param BytesLen - max bytes length of the cbor buffer
// @param MaxBufferLen - max buffer length of every piece of credential subject (e.g. givenName, familyName, dob)
template ReadCredSubj(BytesLen, MaxBufferLen) {

    // constants
    var CREDENTIAL_SUBJECT_MAP_LEN = 3;
    var MaxStringLen = MaxBufferLen \ CREDENTIAL_SUBJECT_MAP_LEN;

    // strings
    var GIVEN_NAME_LEN = 9;
    var GIVEN_NAME_STR[GIVEN_NAME_LEN] = [103, 105, 118, 101, 110, 78, 97, 109, 101];
    var FAMILY_NAME_LEN = 10;
    var FAMILY_NAME_STR[FAMILY_NAME_LEN] = [102, 97, 109, 105, 108, 121, 78, 97, 109, 101];
    var DOB_LEN = 3;
    var DOB_STR[DOB_LEN] = [100, 111, 98];

    // i/o signals
    signal input mapLen;
    signal input bytes[BytesLen];
    signal input pos;

    signal output givenName[MaxBufferLen];
    signal output givenNameLen;
    signal output familyName[MaxBufferLen];
    signal output familyNameLen;
    signal output dob[MaxBufferLen];
    signal output dobLen;



    // check that map length is exactly as per NZCP spec
    hardcore_assert(mapLen, CREDENTIAL_SUBJECT_MAP_LEN);


    component readStringLength[CREDENTIAL_SUBJECT_MAP_LEN];

    component isGivenName[CREDENTIAL_SUBJECT_MAP_LEN];
    component isFamilyName[CREDENTIAL_SUBJECT_MAP_LEN];
    component isDOB[CREDENTIAL_SUBJECT_MAP_LEN];
    component copyString[CREDENTIAL_SUBJECT_MAP_LEN];

    for(var k = 0; k < CREDENTIAL_SUBJECT_MAP_LEN; k++) {

        readStringLength[k] = ReadStringLength(BytesLen);
        copyBytes(bytes, readStringLength[k].bytes, BytesLen)
        readStringLength[k].pos <== k == 0 ? pos : copyString[k - 1].nextPos;

        isGivenName[k] = StringEquals(BytesLen, GIVEN_NAME_STR, GIVEN_NAME_LEN);
        copyBytes(bytes, isGivenName[k].bytes, BytesLen)
        isGivenName[k].pos <== readStringLength[k].nextPos; // pos before skipping
        isGivenName[k].len <== readStringLength[k].len;

        isFamilyName[k] = StringEquals(BytesLen, FAMILY_NAME_STR, FAMILY_NAME_LEN);
        copyBytes(bytes, isFamilyName[k].bytes, BytesLen)
        isFamilyName[k].pos <== readStringLength[k].nextPos; // pos before skipping
        isFamilyName[k].len <== readStringLength[k].len;

        isDOB[k] = StringEquals(BytesLen, DOB_STR, DOB_LEN);
        copyBytes(bytes, isDOB[k].bytes, BytesLen)
        isDOB[k].pos <== readStringLength[k].nextPos; // pos before skipping
        isDOB[k].len <== readStringLength[k].len;

        copyString[k] = CopyString(BytesLen, MaxStringLen);
        copyBytes(bytes, copyString[k].bytes, BytesLen)
        copyString[k].pos <== readStringLength[k].nextPos + readStringLength[k].len;

    }


    // assign givenName
    component givenNameCharTally[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        givenNameCharTally[h] = CalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            givenNameCharTally[h].nums[i] <== isGivenName[i].out * copyString[i].outbytes[h];
        }
        givenName[h] <== givenNameCharTally[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { givenName[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component givenNameLenTally;
    givenNameLenTally = CalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        givenNameLenTally.nums[i] <== isGivenName[i].out * copyString[i].len;
    }
    givenNameLen <== givenNameLenTally.sum;


    // assign familyName
    component familyNameCharTally[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        familyNameCharTally[h] = CalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            familyNameCharTally[h].nums[i] <== isFamilyName[i].out * copyString[i].outbytes[h];
        }
        familyName[h] <== familyNameCharTally[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { familyName[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component familyNameLenTally;
    familyNameLenTally = CalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        familyNameLenTally.nums[i] <== isFamilyName[i].out * copyString[i].len;
    }
    familyNameLen <== familyNameLenTally.sum;


    // assign dob
    component dobCharTally[MaxStringLen];
    for(var h = 0; h<MaxStringLen; h++) {
        dobCharTally[h] = CalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
        for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
            dobCharTally[h].nums[i] <== isDOB[i].out * copyString[i].outbytes[h];
        }
        dob[h] <== dobCharTally[h].sum;
    }
    for(var h = MaxStringLen; h < MaxBufferLen; h++) { dob[h] <== 0; } // pad out the rest of the string with zeros to avoid invalid access
    component dobLenTally;
    dobLenTally = CalculateTotal(CREDENTIAL_SUBJECT_MAP_LEN);
    for(var i = 0; i < CREDENTIAL_SUBJECT_MAP_LEN; i++) {
        dobLenTally.nums[i] <== isDOB[i].out * copyString[i].len;
    }
    dobLen <== dobLenTally.sum;

}

// @dev concat givenName, familyName and dob with comma as separator
// @param MaxBufferLen - max length of the buffer
template ConstructNullifier(MaxBufferLen) {
    var COMMA_CHAR = 44;
    var ConcatSizeBits = log2(MaxBufferLen) + 1;

    signal input givenName[MaxBufferLen];
    signal input givenNameLen;
    signal input familyName[MaxBufferLen];
    signal input familyNameLen;
    signal input dob[MaxBufferLen];
    signal input dobLen;
    signal output result[MaxBufferLen];
    signal output resultLen;

    component isGivenName[MaxBufferLen];
    component isUnderSep1[MaxBufferLen];
    component isUnderFamilyName[MaxBufferLen];
    component isUnderSep2[MaxBufferLen];

    component givenNameSelector[MaxBufferLen];
    component familyNameSelector[MaxBufferLen];
    component dobSelector[MaxBufferLen];

    signal notGivenName[MaxBufferLen];
    signal isSep1[MaxBufferLen];
    signal isFamilyName[MaxBufferLen];
    signal isSep2[MaxBufferLen];
    signal isDOB[MaxBufferLen];

    signal givenNameChar[MaxBufferLen];
    signal sep1Char[MaxBufferLen];
    signal familyNameChar[MaxBufferLen];
    signal sep2Char[MaxBufferLen];
    signal dobChar[MaxBufferLen];
    
    for(var k = 0; k < MaxBufferLen; k++) {
        isGivenName[k] = LessThan(ConcatSizeBits);
        isGivenName[k].in[0] <== k;
        isGivenName[k].in[1] <== givenNameLen;

        isUnderSep1[k] = LessThan(ConcatSizeBits);
        isUnderSep1[k].in[0] <== k;
        isUnderSep1[k].in[1] <== givenNameLen + 1;

        isUnderFamilyName[k] = LessThan(ConcatSizeBits);
        isUnderFamilyName[k].in[0] <== k;
        isUnderFamilyName[k].in[1] <== givenNameLen + 1 + familyNameLen;

        isUnderSep2[k] = LessThan(ConcatSizeBits);
        isUnderSep2[k].in[0] <== k;
        isUnderSep2[k].in[1] <== givenNameLen + 1 + familyNameLen + 1;

        givenNameSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z < MaxBufferLen; z++) { givenNameSelector[k].in[z] <== givenName[z]; }
        givenNameSelector[k].index <== k;

        familyNameSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z < MaxBufferLen; z++) { familyNameSelector[k].in[z] <== familyName[z]; }
        familyNameSelector[k].index <== k - givenNameLen - 1;

        dobSelector[k] = QuinSelector(MaxBufferLen);
        for(var z = 0; z < MaxBufferLen; z++) { dobSelector[k].in[z] <== dob[z]; }
        dobSelector[k].index <== k - givenNameLen - 1 - familyNameLen - 1;
        
        notGivenName[k] <== NOT(isGivenName[k].out);
        isSep1[k] <== isUnderSep1[k].out * notGivenName[k];
        isFamilyName[k] <== isUnderFamilyName[k].out * NOT(isUnderSep1[k].out);
        isSep2[k] <== isUnderSep2[k].out * NOT(isUnderFamilyName[k].out);
        isDOB[k] <== NOT(isUnderSep2[k].out);

        givenNameChar[k] <== isGivenName[k].out * givenNameSelector[k].out;
        sep1Char[k] <== isSep1[k] * COMMA_CHAR;
        familyNameChar[k] <== isFamilyName[k] * familyNameSelector[k].out;
        sep2Char[k] <== isSep2[k] * COMMA_CHAR;
        dobChar[k] <== isDOB[k] * dobSelector[k].out;

        result[k] <== givenNameChar[k] + sep1Char[k] + familyNameChar[k] + sep2Char[k] + dobChar[k];
    }
    resultLen <== givenNameLen + 1 + familyNameLen + 1 + dobLen;
}

// @dev get NZCP public identity based on ToBeSigned
// @dev only 64 bytes is used for nullifier `${givenName},${familyName},${dob}`
// @param IsLive - are we to use live or example NZCP?
// @param MaxToBeSignedBytes - maximum number of bytes in ToBeSigned
// @param MaxCborArrayLenVC - maximum number of elements in the CBOR array for verifiable credential
// @param MaxCborMapLenVC - maximum number of elements in the CBOR map for verifiable credential
// @param MaxCborArrayLenCredSubj - maximum number of elements in the CBOR array for credential subject
// @param MaxCborMapLenCredSubj - maximum number of elements in the CBOR map for credential subject
template NZCPPubIdentity(IsLive, MaxToBeSignedBytes, MaxCborArrayLenVC, MaxCborMapLenVC, MaxCborArrayLenCredSubj, MaxCborMapLenCredSubj) {
    // constants
    var HASHPART_BITS = 256;
    var SHA256_BITS = 256;
    var BLOCK_SIZE = 512;
    var CLAIMS_SKIP_EXAMPLE = 27;
    var CLAIMS_SKIP_LIVE = 30;
    var CHUNK_BITS = 248;
    var OUT_SIGNALS = 3;
    var BYTE_BITS = 8;
    var TIMESTAMP_BYTES = 4;
    var TIMESTAMP_BITS = BYTE_BITS * TIMESTAMP_BYTES;
    var CHUNK_BYTES = CHUNK_BITS / BYTE_BITS;

    // concat string aka the nullifier
    // Only 64 character latin strings are supported.
    var NULLIFIFER_BYTES = 64;
    var NULLIFIFER_BITS = NULLIFIFER_BYTES * 8;

    // half of the nullifier hash that is going to be scrambled to produce nullifierRange
    var NULLIFIFER_HASH_HALF_BITS = 256;

    // compile time parameters
    var DataLen = CHUNK_BITS * OUT_SIGNALS - HASHPART_BITS - SHA256_BITS - TIMESTAMP_BITS;
    var ClaimsSkip = IsLive ? CLAIMS_SKIP_LIVE : CLAIMS_SKIP_EXAMPLE;

    // ToBeSigned hash
    var MaxToBeSignedBits = MaxToBeSignedBytes * 8;

    var ToBeSignedBlockSpace = 3; // max 503 characters
    var ToBeSignedBlockCount = pow(2, ToBeSignedBlockSpace);
    var ToBeSignedMaxBits = BLOCK_SIZE * ToBeSignedBlockCount;

    assert(MaxToBeSignedBits <= ToBeSignedMaxBits); // compile time check

    // i/o signals
    signal input toBeSigned[MaxToBeSignedBits]; // gets zero-outted beyond length
    signal input toBeSignedLen; // length of toBeSigned in bytes
    signal input data[DataLen]; // extra pass-thru data for various purposes, fill with 0s of not needed
    signal output out[OUT_SIGNALS];


    // check that input is only bits (0 or 1) (hardcore assert)
    for (var i = 0; i < MaxToBeSignedBits; i++ ) {
        toBeSigned[i] * (toBeSigned[i] - 1) === 0;
        assert(toBeSigned[i] == 0 || toBeSigned[i] == 1);
    }


    // hardcore assert that toBeSignedLen is less than MaxToBeSignedBytes
    var MaxToBeSignedBytesPlusOne = MaxToBeSignedBytes + 1;
    component lteMaxToBeSignedBytes = LessThan(log2(MaxToBeSignedBytesPlusOne) + 1);
    lteMaxToBeSignedBytes.in[0] <== toBeSignedLen;
    lteMaxToBeSignedBytes.in[1] <== MaxToBeSignedBytesPlusOne;
    assert(toBeSignedLen < MaxToBeSignedBytesPlusOne);
    lteMaxToBeSignedBytes.out === 1;


    // calculate ToBeSigned sha256 hash
    component tbsSha256 = Sha256Var(ToBeSignedBlockSpace);
    tbsSha256.len <== toBeSignedLen * 8;
    for (var i = 0; i < MaxToBeSignedBits; i++) {
        tbsSha256.in[i] <== toBeSigned[i];
    }
    for (var i = MaxToBeSignedBits; i < ToBeSignedMaxBits; i++) {
        tbsSha256.in[i] <== 0;
    }


    // convert ToBeSigned bits to bytes
    // zero-out everything after the length
    signal ToBeSigned[MaxToBeSignedBytes];
    component b2n[MaxToBeSignedBytes];
    component ltLen[MaxToBeSignedBytes];
    for (var k = 0; k < MaxToBeSignedBytes; k++) {
        b2n[k] = Bits2Num(8);
        for (var i = 0; i < 8; i++) {
            b2n[k].in[i] <== toBeSigned[k * 8 + (7 - i)];
        }
        ltLen[k] = LessThan(log2(MaxToBeSignedBytes) + 1);
        ltLen[k].in[0] <== k;
        ltLen[k].in[1] <== toBeSignedLen;
        ToBeSigned[k] <== b2n[k].out * ltLen[k].out;
    }

    component readMapLengthClaims = ReadMapLength(MaxToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLengthClaims.bytes, MaxToBeSignedBytes)
    readMapLengthClaims.pos <== ClaimsSkip;

    // find "vc" key pos in the map
    signal exp;
    component findVC = FindCWTClaims(MaxToBeSignedBytes, MaxCborArrayLenVC, MaxCborMapLenVC);
    copyBytes(ToBeSigned, findVC.bytes, MaxToBeSignedBytes)
    findVC.pos <== readMapLengthClaims.nextPos;
    findVC.mapLen <== readMapLengthClaims.len;
    exp <== findVC.exp;


    // find credential subject
    component readMapLengthVC = ReadMapLength(MaxToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLengthVC.bytes, MaxToBeSignedBytes)
    readMapLengthVC.pos <== findVC.vcPos;

    signal credSubjPos;
    component findCredSubj = FindCredSubj(MaxToBeSignedBytes, MaxCborArrayLenCredSubj, MaxCborMapLenCredSubj);
    copyBytes(ToBeSigned, findCredSubj.bytes, MaxToBeSignedBytes)
    findCredSubj.pos <== readMapLengthVC.nextPos;
    findCredSubj.mapLen <== readMapLengthVC.len;
    credSubjPos <== findCredSubj.needlePos;

    // read credential subject map length
    component readMapLengthCredSubj = ReadMapLength(MaxToBeSignedBytes);
    copyBytes(ToBeSigned, readMapLengthCredSubj.bytes, MaxToBeSignedBytes)
    readMapLengthCredSubj.pos <== credSubjPos;


    // read credential subject map
    component readCredSubj = ReadCredSubj(MaxToBeSignedBytes, NULLIFIFER_BYTES);
    copyBytes(ToBeSigned, readCredSubj.bytes, MaxToBeSignedBytes)
    readCredSubj.pos <== readMapLengthCredSubj.nextPos;
    readCredSubj.mapLen <== readMapLengthCredSubj.len;

    // concat given name, family name and dob
    component nullifier = ConstructNullifier(NULLIFIFER_BYTES);
    nullifier.givenNameLen <== readCredSubj.givenNameLen;
    nullifier.familyNameLen <== readCredSubj.familyNameLen;
    nullifier.dobLen <== readCredSubj.dobLen;
    for (var i = 0; i < NULLIFIFER_BYTES; i++) { nullifier.givenName[i] <== readCredSubj.givenName[i]; }
    for (var i = 0; i < NULLIFIFER_BYTES; i++) { nullifier.familyName[i] <== readCredSubj.familyName[i]; }
    for (var i = 0; i < NULLIFIFER_BYTES; i++) { nullifier.dob[i] <== readCredSubj.dob[i]; }
    
    // convert concat string into bits
    component n2bNullifier[NULLIFIFER_BYTES];
    signal nullifierBits[NULLIFIFER_BITS];
    for(var k = 0; k < NULLIFIFER_BYTES; k++) {
        n2bNullifier[k] = Num2Bits(8);
        n2bNullifier[k].in <== nullifier.result[k];
        for (var j = 0; j < 8; j++) {
            nullifierBits[k*8 + (7 - j)] <== n2bNullifier[k].out[j];
        }
    }

    // calculate nullifierHash of the nullifer using pedersen hash
    // nullifier = `${givenName},${familyName},${dob}`
    // nullifierHash = Sha512(nullifier)
    // we only export 256 first bits of nullifier hash thus protecting nullifier privacy
    component nullifierSha512 = Sha512(NULLIFIFER_BITS);
    for (var i = 0; i < NULLIFIFER_BITS; i++) {
        nullifierSha512.in[i] <== nullifierBits[i];
    }

    // export
    component n2bExp = Num2Bits(TIMESTAMP_BITS);
    n2bExp.in <== exp;

    component outB2n[3];
    outB2n[0] = Bits2Num(CHUNK_BITS);
    outB2n[1] = Bits2Num(CHUNK_BITS);
    outB2n[2] = Bits2Num(CHUNK_BITS);


    // pack nullifier hash part
    // here and below:
    // rearrange bits so it is cheaper to read in solidity
    for(var k = 0; k < CHUNK_BYTES; k++) {
        var b = CHUNK_BYTES - 1 - k;
        for (var i = 0; i < BYTE_BITS; i++) {
            outB2n[0].in[b * BYTE_BITS + (7 - i)] <== nullifierSha512.out[k * BYTE_BITS + i];
        }
    }
    for(var k = 0; k < 8 / BYTE_BITS; k++) {
        var b = CHUNK_BYTES - 1 - k;
        for (var i = 0; i < BYTE_BITS; i++) {
            outB2n[1].in[b * BYTE_BITS + (7 - i)] <== nullifierSha512.out[CHUNK_BITS + (k * BYTE_BITS + i)];
        }
    }

    // pack ToBeSigned sha256
    for(var k = 1; k < CHUNK_BYTES; k++) {
        var b = CHUNK_BYTES - 1 - k;
        for (var i = 0; i < BYTE_BITS; i++) {
            outB2n[1].in[b * BYTE_BITS + (7 - i)] <== tbsSha256.out[(k * BYTE_BITS + i) - 8];
        }
    }
    for(var k = 0; k < 16 / BYTE_BITS; k++) {
        var b = CHUNK_BYTES - 1 - k;
        for (var i = 0; i < BYTE_BITS; i++) {
            outB2n[2].in[b * BYTE_BITS + (7 - i)] <== tbsSha256.out[CHUNK_BITS + (k * BYTE_BITS + i) - 8];
        }
    }

    var c;
    var idx;

    // Pack exp
    c = 0;
    idx = 0;
    for(var k = 2; k < 2 + TIMESTAMP_BYTES; k++) {
        var b = CHUNK_BYTES - 1 - k;
        var d = TIMESTAMP_BYTES - 1 - idx;
        for (var i = 0; i < BYTE_BITS; i++) {
            outB2n[2].in[b * BYTE_BITS + i] <== n2bExp.out[d * BYTE_BITS + i];
            c++;
        }
        idx++;
    }

    // Pack the pass-thru data
    c = 0;
    idx = 0;
    for(var k = 2 + TIMESTAMP_BYTES; k < CHUNK_BYTES; k++) {
        var b = CHUNK_BYTES - 1 - k;
        var d = (DataLen / BYTE_BITS) - 1 - idx;
        for (var i = 0; i < BYTE_BITS; i++) {
            outB2n[2].in[b * BYTE_BITS + i] <== data[d * BYTE_BITS + i];
            c++;
        }
        idx++;
    }

    out[0] <== outB2n[0].out;
    out[1] <== outB2n[1].out;
    out[2] <== outB2n[2].out;
}


