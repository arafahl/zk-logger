const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const LOG_FILE = "inputs/logs.json";
const PROOFS_FILE = "merkle_outputs/proofs.json";
const ROOT_FILE = "merkle_outputs/root.txt";

const OUTPUT_DIR = "circom_inputs";
const OUTPUT_FILE = "input_all.json"; // single file for all logs

// SHA256 → decimal string for Circom input
function sha256Decimal(str) {
    const hash = crypto.createHash("sha256").update(str).digest("hex");
    return BigInt("0x" + hash).toString();
}

function loadJSON(file) {
    return JSON.parse(fs.readFileSync(file));
}

function saveJSON(name, data) {
    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }
    fs.writeFileSync(path.join(OUTPUT_DIR, name), JSON.stringify(data, null, 2));
}

function main() {
    const logs = loadJSON(LOG_FILE);
    const proofs = loadJSON(PROOFS_FILE);
    const merkleRoot = fs.readFileSync(ROOT_FILE, "utf8").trim();

    const allInputs = logs.map(entry => {
        const proofEntry = proofs.find(p => p.id === entry.id);
        if (!proofEntry) {
            console.error(`No Merkle proof found for log ID ${entry.id}`);
            return null;
        }

        const { log } = entry;
        const leafHashHex = entry.hash;

        // Convert Merkle siblings to decimal for Circom
        const siblingsDecimal = proofEntry.proof.map(h => BigInt("0x" + h).toString());

        // Determine path positions (left/right)
        const pathPositions = siblingsDecimal.map((_, i) => 0); 
        // NOTE: merkletreejs with sortPairs = true, all positions = 0

        return {
            id: entry.id,
            log: {
                timestamp: sha256Decimal(log.timestamp),
                userId: sha256Decimal(log.userId),
                action: sha256Decimal(log.action),
                status: log.status,
                ip: sha256Decimal(log.ip)
            },
            leaf: BigInt("0x" + leafHashHex).toString(),
            siblings: siblingsDecimal,
            pathPositions: pathPositions
        };
    }).filter(Boolean);

    const circomInputAll = {
        root: BigInt("0x" + merkleRoot).toString(),
        entries: allInputs
    };

    saveJSON(OUTPUT_FILE, circomInputAll);
    console.log(`✔ Circom input for all logs generated: ${OUTPUT_FILE}`);
}

main();
