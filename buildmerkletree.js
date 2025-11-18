const fs = require("fs");
const path = require("path");
const { MerkleTree } = require("merkletreejs");
const crypto = require("crypto");

// Paths
const LOG_FILE = "inputs/logs.json";
const OUTPUT_DIR = "merkle_outputs";

// SHA256 hashing for tree leaves
function sha256(data) {
    return crypto.createHash("sha256").update(data).digest();
}

// Load logs
function loadLogs() {
    if (!fs.existsSync(LOG_FILE)) {
        console.error("No logs found! Generate some logs first.");
        process.exit(1);
    }
    return JSON.parse(fs.readFileSync(LOG_FILE));
}

// Save output files
function saveFile(name, content) {
    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }
    fs.writeFileSync(path.join(OUTPUT_DIR, name), content);
}

function main() {
    const logs = loadLogs();

    // Extract only the stored hashes
    const leafHashes = logs.map(entry => Buffer.from(entry.hash, "hex"));

    // Build Merkle tree
    const merkleTree = new MerkleTree(leafHashes, sha256, { sortPairs: true });

    const root = merkleTree.getRoot().toString("hex");

    console.log("🌳 Merkle Root:", root);

    // Save outputs
    saveFile("leafHashes.json", JSON.stringify(leafHashes.map(h => h.toString("hex")), null, 2));
    saveFile("root.txt", root);

    // Save a Merkle path for each leaf
    const proofs = logs.map((entry, index) => {
        return {
            id: entry.id,
            hash: entry.hash,
            proof: merkleTree.getProof(leafHashes[index]).map(x => x.data.toString("hex"))
        };
    });

    saveFile("proofs.json", JSON.stringify(proofs, null, 2));

    console.log("✔ Merkle tree construction complete.");
    console.log("Files saved in:", OUTPUT_DIR);
}

main();
