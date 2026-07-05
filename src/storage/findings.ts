// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import fs, { existsSync, mkdirSync, writeFileSync } from 'fs';
import path from 'path';
import type { Finding } from '../types.js';

const FINDINGS_FILE = 'findings.json'

export function saveFindings(findings: Finding[]) {
    if (!existsSync(path.dirname(FINDINGS_FILE))) {
        mkdirSync(path.dirname(FINDINGS_FILE), { recursive: true });
    }
    writeFileSync(FINDINGS_FILE, JSON.stringify(findings, null, 2));
}
