pragma circom 2.0.0;

// -----------------------------------------------------
// Simple Merkle inclusion gadget (NOT cryptographic).
// It only checks that, given a leaf, siblings[],
// and pathPositions[], you end up at a root.
// -----------------------------------------------------
template MerkleTreeInclusion(depth) {
    signal input leaf;                  // starting leaf
    signal input siblings[depth];       // siblings along the path
    signal input pathPositions[depth];  // 0 = leaf is left, 1 = leaf is right

    signal output root;

    signal current[depth + 1];
    signal left[depth];
    signal right[depth];

    // Start from the leaf
    current[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Enforce boolean: pathPositions[i] ∈ {0,1}
        pathPositions[i] * (pathPositions[i] - 1) === 0;

        // Conditional selection using a single multiplication per constraint
        // left  = current + p * (sibling - current)
        // right = sibling + p * (current - sibling)
        left[i]  <== current[i]  + pathPositions[i] * (siblings[i] - current[i]);
        right[i] <== siblings[i] + pathPositions[i] * (current[i]  - siblings[i]);

        // Simple combine (NOT SHA256, just arithmetic)
        current[i + 1] <== left[i] + right[i];
    }

    root <== current[depth];
}

// -----------------------------------------------------
// LogProof circuit
// - Takes log fields as private inputs (not used in constraints here,
//   but they are part of the witness, so you can talk about them).
// - Takes a leaf, Merkle siblings, and path positions.
// - Outputs the Merkle root.
// -----------------------------------------------------
template LogProof(depth) {
    // Private log fields (not constrained in this simplified version)
    signal input log_timestamp;
    signal input log_userId;
    signal input log_action;
    signal input log_status;
    signal input log_ip;

    // Leaf (already computed off-chain from the log)
    signal input leaf;

    // Merkle proof inputs
    signal input siblings[depth];
    signal input pathPositions[depth];

    // Public output: Merkle root
    signal output root;

    // Merkle inclusion gadget
    component merkleCheck = MerkleTreeInclusion(depth);
    merkleCheck.leaf <== leaf;

    for (var i = 0; i < depth; i++) {
        merkleCheck.siblings[i]      <== siblings[i];
        merkleCheck.pathPositions[i] <== pathPositions[i];
    }

    root <== merkleCheck.root;
}

// Depth = 5 because your JSON has 5 siblings/pathPositions for most entries.
component main = LogProof(5);
