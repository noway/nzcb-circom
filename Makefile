.PHONY: circuits/nzcp.circom circuits/cbor.circom test clean ceremony

all: node_modules circuits/nzcp.circom circuits/nzcp_example.wasm circuits/nzcp_live.wasm

circuits/nzcp_exampleTest.wasm:
	circom circuits/nzcp_exampleTest.circom --r1cs --wasm

circuits/nzcp_liveTest.wasm:
	circom circuits/nzcp_liveTest.circom --r1cs --wasm

circuits/nzcp_example.wasm:
	circom circuits/nzcp_example.circom --r1cs --wasm

circuits/nzcp_live.wasm:
	circom circuits/nzcp_live.circom --r1cs --wasm

test: node_modules circuits/nzcp.circom
	yarn exec mocha

sha256-var-circom.zip:
	curl -Lo $@ https://github.com/noway/sha256-var-circom/archive/refs/heads/main.zip
	
sha256-var-circom-main/: sha256-var-circom.zip
	unzip $<
	cd $@ && make

circuits/nzcp.circom: circuits/cbor.circom sha256-var-circom-main
	cpp -P circuits/nzcptpl.circom > $@

circuits/cbor.circom: sha256-var-circom-main
	cpp -P circuits/cbortpl.circom > $@

node_modules/:
	yarn

plonk:
	snarkjs plonk setup nzcp_exampleTest.r1cs powersOfTau28_hez_final_22.ptau nzcp_exampleTest_final.zkey
	snarkjs zkey export verificationkey nzcp_exampleTest_final.zkey verification_key.json
	snarkjs zkey export solidityverifier nzcp_exampleTest_final.zkey contracts/VerifierExample.sol

ceremony:
	snarkjs powersoftau new bn128 21 pot21_0000.ptau -v
	snarkjs powersoftau contribute pot21_0000.ptau pot21_0001.ptau --name="First contribution" -v
	snarkjs powersoftau prepare phase2 pot21_0001.ptau pot21_final.ptau -v
	snarkjs groth16 setup nzcp_example.r1cs pot21_final.ptau nzcp_example_0000.zkey
	snarkjs zkey contribute nzcp_example_0000.zkey nzcp_example_0001.zkey --name="1st Contributor Name" -v
	snarkjs zkey export verificationkey nzcp_example_0001.zkey verification_key.json





clean:
	rm -rf sha256-var-circom.zip
	rm -rf sha256-var-circom-main
	rm -rf node_modules