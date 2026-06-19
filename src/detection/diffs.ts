// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import type { Finding } from "../types.js";

export function findPreviousVersion(
    versions: Record<string, unknown>,
    time: Record<string, string>,
    latest: string,
): string | null {
    const published = Object.keys(versions)
          .filter(v => time[v])
          .sort((a, b) => (time[a] ?? "").localeCompare(time[b] ?? ""));

    const latestIdx = published.indexOf(latest);
    if (latestIdx <= 0) return null;
    return published[latestIdx - 1] ?? null;
}

const INSTALL_HOOKS = ["preinstall", "install", "postinstall"];

export function diffInstallScripts (
    previousScripts: Record<string, string>, 
    currentScripts: Record<string, string>,
): Finding[] {
    const findings: Finding[] = [];

    for (const hook of INSTALL_HOOKS) {
        const before = previousScripts[hook];
        const after = currentScripts[hook];

        if (!after) continue;

        if (!before) {
            findings.push({
                hook,
                pattern: `New ${hook} script added`,
                snippet: after, 
                severity: "high",
                confidence: "medium",
            });
        } else if (before !== after) {
            findings.push({
                hook, 
                pattern: `${hook} hook has changed`,
                snippet: after,
                severity: "medium",
                confidence: "medium",
            });
        }
    }
    return findings;
}