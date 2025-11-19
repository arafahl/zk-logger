pragma circom 2.0.0;

// We installed circomlib with: npm install circomlib
// logProof.circom is inside the "circuits" folder, so we go up one level ("..")
// and then into node_modules/circomlib/...
include "../node_modules/circomlib/circuits/sha256/sha256.circom";

//
// Simple placeholder Merkle inclusion gadget.
// NOTE: This is NOT a cryptographically correct SHA256 Merkle tree.
// It just gives you a consistent "root" based on leaf + siblings + path positions
// so the circuit compiles and runs end-to-end for learning / demo purposes.
//
template MerkleTreeInclusion(depth) {
    // Inputs
    signal input leaf;                  // starting leaf
    signal input siblings[depth];       // siblings along the path
    signal input pathPositions[depth];  // 0 = leaf is left, 1 = leaf is right

    // Output
    signal output root;

    // Current value as we walk up the tree
    signal current[depth + 1];
    signal left[depth];
    signal right[depth];

    // start from the leaf
    current[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Enforce that pathPositions[i] is 0 or 1 (boolean)
        pathPositions[i] * (pathPositions[i] - 1) === 0;

        // If pathPositions[i] == 0 → current is left, sibling is right
        // If pathPositions[i] == 1 → sibling is left, current is right
        //
        // This form keeps each constraint quadratic:
        //   left  = current + p * (sibling - current)
        //   right = sibling + p * (current - sibling)
        left[i]  <== current[i]  + pathPositions[i] * (siblings[i] - current[i]);
        right[i] <== siblings[i] + pathPositions[i] * (current[i]  - siblings[i]);

        // Very simple "combine" – this is NOT real SHA256.
        // It's just some arithmetic so we have constraints.
        current[i + 1] <== left[i] + right[i];
    }

    root <== current[depth];
}

template LogProof(depth) {
    // -------- Private inputs --------
    signal input log_timestamp; // SHA256-decimal (or however you encode it)
    signal input log_userId;    // SHA256-decimal
    signal input log_action;    // SHA256-decimal
    signal input log_status;    // numeric (e.g. 200, 401, etc.)
    signal input log_ip;        // SHA256-decimal

    // Leaf = SHA256(log fields) as decimal (must match what you hashed in JS)
    signal input leaf;

    // Merkle proof inputs
    signal input siblings[depth];       // Merkle siblings as decimals
    signal input pathPositions[depth];  // 0 = current leaf is left, 1 = right

    // -------- Public output --------
    signal output root;                 // Merkle root that will be public

    // -------- Step 1: recompute leaf hash from fields --------
    // This assumes Sha256(5) from circomlib is compatible with however
    // you encode the 5 fields in generateCircomInputs.js.
    component hasher = Sha256(5);
    hasher.in[0] <== log_timestamp;
    hasher.in[1] <== log_userId;
    hasher.in[2] <== log_action;
    hasher.in[3] <== log_status;
    hasher.in[4] <== log_ip;

    // Ensure that the computed hash equals the provided leaf
    // hasher.out is an array; we simply compare against its first element for now.
    leaf === hasher.out[0];

    // -------- Step 2: Merkle inclusion proof (toy) --------
    component merkleCheck = MerkleTreeInclusion(depth);

    merkleCheck.leaf <== leaf;

    for (var i = 0; i < depth; i++) {
        merkleCheck.siblings[i]      <== siblings[i];
        merkleCheck.pathPositions[i] <== pathPositions[i];
    }

    // Public root
    root <== merkleCheck.root;
}

// Adjust depth to log2(number_of_leaves) in your Merkle tree.
component main = LogProof(3);
