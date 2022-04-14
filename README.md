# NZ COVID Badge - ZK-SNARK repo

## Info & FAQ
Read [the website](https://nzcb.netlify.app/) for more info.

## Technical info
Based on [NZCP.circom](https://github.com/noway/nzcp-circom)


## How it works

The circuit takes in the following private inputs:
- `toBeSigned` - the `ToBeSigned` value of NZ COVID Pass as per https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
- `toBeSignedLen` - the length of `toBeSigned`


The circuit outputs the following public inputs:
- `nullifierHashPart` - the blinded sha512 hash of the credential subject of the NZ COVID Pass. That is your given name, family name and date of birth delimited by comma. The blinding is done by taking 256 bits of the 512 bit hash, therefore one blinded hash can represent 2<sup>256</sup> identities.
- `toBeSignedSha256` - the SHA256 hash of the `toBeSigned` value.
- `exp` - the expiry date of the NZ COVID Pass.
- `data` - 20 bytes of pass-through data that is used for the receiving address (MEV protection)

## NZ COVID Pass verification
The circuit does not verify the signature of the NZ COVID Pass. It merely proves that an identity is associated with the NZ COVID Pass, be it signed or unsigned. The user may not be in a possession of a valid signature for the `ToBeSigned` value that is provided.

The signature is verified in the solidity contract.

## Limitations
For live passes:
- The length of the `ToBeSigned` value is limited to 351 bytes.
- The length of the credential subject string (defined as `${familyName},${givenName},${dob}`) is limited to 64 bytes.

## Tests
- Create `.env` file in the root directory of the project
- Populate it with at least 1 live pass URI. 
    - Use `.env.example` as a reference.
- Run `make test`

## Related repos
- [NZ COVID Badge - Dapp repo](https://github.com/noway/nzcb-dapp)
- [NZ COVID Badge - Contract repo](https://github.com/noway/nzcb)
- [NZ COVID Badge - ZK-SNARK repo](https://github.com/noway/nzcb-circom)

## License
MIT License
