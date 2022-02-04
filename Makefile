.PHONY: nzcp/nzcp.wasm circuits/nzcp.circom circuits/cbor.circom

public.json: nzcp/nzcp.wasm
	cd nzcp_js && node generate_witness.js nzcp.wasm ../input.json witness.wtns
	snarkjs groth16 prove nzcp_0001.zkey nzcp_js/witness.wtns proof.json public.json

nzcp/nzcp.wasm: circomlib-master
	circom circuits/nzcp.circom --wasm --sym

circom.zip:
	curl -Lo circomlib.zip https://github.com/iden3/circomlib/archive/refs/heads/master.zip

circomlib-master/: circom.zip
	unzip circomlib.zip


circuits/nzcp.circom: circuits/cbor.circom
	cpp -P circuits/nzcptpl.circom | sed 's/##//g' > circuits/nzcp.circom

circuits/cbor.circom: 
	cpp -P circuits/cbortpl.circom | sed 's/##//g' > circuits/cbor.circom