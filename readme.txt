Steps to run this project on your end

Dependencies
- install rust
- install nodejs
- install circom
- install snarkjs


- nodejs dependencies - crypto path express body-parser fs merkletreejs

Run logging API to generate logs to be used as input to our circuit

node server.js

- make POST API calls to generate access logs with the correct api endpoint /logs/generate

Build merkletrees from the logs

node buildmerkletree.js

Generate circom inputs for the logs

node generateCircomInputs.js

Compile circom circuit

circom circuits/logProof.circom --r1cs --wasm --sym -o circuits


Trusted setup with tau

snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v


generate witnesses for the logs

node circuits/logProof_js/generate_witness.js circuits/logProof_js/logProof.wasm circom_inputs/input_all.json circuits/witness.wtns


generate LogProof

snarkjs groth16 prove circuits/logProof.zkey circuits/witness.wtns circuits/proof.json circuits/public.json

Verify proof

snarkjs groth16 verify circuits/verification_key.json circuits/public.json circuits/proof.json
