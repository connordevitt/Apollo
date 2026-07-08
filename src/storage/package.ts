// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.

import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import type { PackageRecord } from '../types.js';

const PACKAGE_FILE = 'packages.jsonl';

export function savePackages(packages: PackageRecord[]) {
    if (!existsSync(PACKAGE_FILE)) {
        appendFileSync(PACKAGE_FILE, '');
    }
    const existingRecords = readFileSync(PACKAGE_FILE, 'utf8').split('\n').filter(line => line.trim() !== '').map(line => JSON.parse(line));
    const newRecords = packages.filter(pkg => !existingRecords.some(existing =>
        existing.package === pkg.package && 
        existing.version === pkg.version
    ))
    appendFileSync(PACKAGE_FILE, newRecords.map(record => JSON.stringify(record) + '\n').join(''));
}