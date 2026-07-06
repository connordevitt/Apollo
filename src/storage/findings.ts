// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import type { Finding } from '../types.js';

const FINDINGS_FILE = 'findings.jsonl'

export function saveFindings(findings: Finding[]) {
     
    if (!existsSync(FINDINGS_FILE)) {
        appendFileSync(FINDINGS_FILE, '');
    }
    const existingFindings = readFileSync(FINDINGS_FILE, 'utf8').split('\n').filter(line => line.trim() !== '').map(line => JSON.parse(line));
    const newFindings = findings.filter(finding => !existingFindings.some(existing => existing.hook === finding.hook && finding.pattern === existing.pattern));
    appendFileSync(FINDINGS_FILE, newFindings.map(finding => JSON.stringify(finding) + '\n').join(''));
}