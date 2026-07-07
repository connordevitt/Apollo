// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import express from "express";
import { existsSync, readFileSync } from "node:fs";
import type { Request, Response } from "express";

const PORT = 3000;
const FINDINGS_FILE = "findings.jsonl";
const app = express();

app.get("/findings", (req: Request, res: Response) =>  { 
    if (!existsSync(FINDINGS_FILE)) {
        res.status(404).send("Findings file not found");
        return;
    }
    const findings = readFileSync(FINDINGS_FILE, "utf8");
    const splitFindings = findings.split("\n").filter(finding => finding.trim() !== "");
    const findingsArray = splitFindings.map(finding => JSON.parse(finding));
    res.json(findingsArray);
}); 

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
