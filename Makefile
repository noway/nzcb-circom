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

sha512.zip:
	curl -Lo $@ https://github.com/noway/sha512/archive/refs/heads/master.zip

sha512-master/: sha512.zip
	unzip $<
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(ShR)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(SigmaPlus)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(SmallSigma)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(BigSigma)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(RotR)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(Xor3)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(T2)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(Maj_t)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(T1)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(Ch_t)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(H)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom
	cd $@/circuits/sha512 && sed -i '' -E 's/([^[:alnum:]_])(K)([^[:alnum:]_])/\1Sha512_\2\3/g' *.circom

circuits/nzcp.circom: circuits/cbor.circom sha256-var-circom-main sha512-master
	cpp -P circuits/nzcptpl.circom > $@

circuits/cbor.circom: sha256-var-circom-main
	cpp -P circuits/cbortpl.circom > $@

node_modules/:
	yarn

plonk:
	snarkjs plonk setup nzcp_exampleTest.r1cs powersOfTau28_hez_final_22.ptau nzcp_exampleTest_final.zkey
	snarkjs zkey export verificationkey nzcp_exampleTest_final.zkey verification_key.json
	snarkjs zkey export solidityverifier nzcp_exampleTest_final.zkey contracts/VerifierExample.sol

phase1:
	snarkjs powersoftau new bn128 21 pot21_0000.ptau -v
	snarkjs powersoftau contribute pot21_0000.ptau pot21_0001.ptau --name="First contribution" -v
	snarkjs powersoftau prepare phase2 pot21_0001.ptau pot21_final.ptau -v

phase2:
	snarkjs groth16 setup nzcp_example.r1cs pot21_final.ptau nzcp_example_0000.zkey
	snarkjs zkey contribute nzcp_example_0000.zkey nzcp_example_0001.zkey --name="1st Contributor Name" -v
	snarkjs zkey export verificationkey nzcp_example_0001.zkey verification_key.json
	snarkjs zkey export solidityverifier nzcp_example_0001.zkey contracts/VerifierExample.sol





clean:
	rm -rf sha256-var-circom.zip
	rm -rf sha256-var-circom-main
	rm -rf sha512.zip
	rm -rf sha512-master
	rm -rf node_modules