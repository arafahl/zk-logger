pragma circom 2.0.0;

include "circomlib/sha256.circom";
include "circomlib/merkle.circom";

template LogProof(depth) {
    // Private inputs
    signal input log_timestamp; // SHA256-decimal
    signal input log_userId;    // SHA256-decimal
    signal input log_action;    // SHA256-decimal
    signal input log_status;    // numeric
    signal input log_ip;        // SHA256-decimal
    signal input leaf;          // SHA256 of full log as decimal
    signal input siblings[depth];  // Merkle siblings as decimals
    signal input pathPositions[depth]; // 0=left, 1=right

    // Public input
    signal output root;

    // --- Step 1: Recompute hash of log ---
    component hasher = Sha256(5); // 5 fields
    hasher.in[0] <== log_timestamp;
    hasher.in[1] <== log_userId;
    hasher.in[2] <== log_action;
    hasher.in[3] <== log_status;
    hasher.in[4] <== log_ip;

    // Assert recomputed hash equals the leaf
    leaf === hasher.out;

    // --- Step 2: Merkle Tree Inclusion ---
    component merkleCheck = MerkleTreeInclusion(depth);
    merkleCheck.leaf <== leaf;
    for (var i = 0; i < depth; i++) {
        merkleCheck.siblings[i] <== siblings[i];
        merkleCheck.pathPositions[i] <== pathPositions[i];
    }

    root <== merkleCheck.root;
}

component main = LogProof(3); // change depth = log2(number of leaves)