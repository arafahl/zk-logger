const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const app = express();

app.use(express.json());

const LOG_FILE = "inputs/logs.json";

// Load logs from file
function loadLogs() {
    if (!fs.existsSync(LOG_FILE)) {
        return [];
    }
    const data = fs.readFileSync(LOG_FILE);
    return JSON.parse(data);
}

// Save logs to file
function saveLogs(logs) {
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
}

// Generate SHA256 hash for a log entry
function hashLog(log) {
    const logString = JSON.stringify(log);
    return crypto.createHash("sha256").update(logString).digest("hex");
}

// Generate random cloud-like access log
function generateAccessLog() {
    const actions = ["LOGIN", "UPLOAD", "DELETE", "READ", "MODIFY"];
    const statuses = [200, 401, 403, 500];

    return {
        timestamp: new Date().toISOString(),
        userId: `user_${Math.floor(Math.random() * 1000)}`,
        action: actions[Math.floor(Math.random() * actions.length)],
        status: statuses[Math.floor(Math.random() * statuses.length)],
        ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
    };
}

/* --------------------- ROUTES --------------------- */

// Generate a new log and store it
app.post("/logs/generate", (req, res) => {
    let logs = loadLogs();
    
    const newLog = generateAccessLog();
    const hash = hashLog(newLog);

    const logEntry = {
        id: logs.length + 1,
        log: newLog,
        hash: hash
    };

    logs.push(logEntry);
    saveLogs(logs);

    return res.json({
        message: "Log generated and hashed successfully",
        log: logEntry
    });
});

// Return all stored logs
app.get("/logs", (req, res) => {
    const logs = loadLogs();
    return res.json(logs);
});

// Get a specific log by ID
app.get("/logs/:id", (req, res) => {
    const logs = loadLogs();
    const log = logs.find(l => l.id == req.params.id);

    if (!log) {
        return res.status(404).json({ error: "Log not found" });
    }

    return res.json(log);
});

// Verify if a log's hash is correct
app.get("/logs/:id/verify", (req, res) => {
    const logs = loadLogs();
    const entry = logs.find(l => l.id == req.params.id);

    if (!entry) {
        return res.status(404).json({ error: "Log not found" });
    }

    const computedHash = hashLog(entry.log);

    return res.json({
        id: entry.id,
        storedHash: entry.hash,
        computedHash: computedHash,
        valid: computedHash === entry.hash
    });
});

/* --------------------- START SERVER --------------------- */

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`ZK Logging API running on http://localhost:${PORT}`);
});