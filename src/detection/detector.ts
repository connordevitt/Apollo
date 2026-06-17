// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import type { PackageInfo, Finding, Rule } from "../types.js";

const SCRIPT_RULES: Rule[] = [
    { id: "install-curl", pattern: "curl", severity: "high", confidence: "high", test: s => s.includes("curl")},
    { id: "install-wget", pattern: "wget", severity: "high", confidence: "high", test: s => s.includes("wget")},
    { id: "pipe-sh", pattern: "| sh", severity: "critical", confidence: "high", test: s => /\|\s*(ba)?sh/.test(s)},
    { id: "node-eval", pattern: "node -e", severity: "medium", confidence: "medium", test: s => s.includes("node -e")},
];

export function analyzePackage(pkg: PackageInfo): Finding[] {
    const findings: Finding[] = [];

    const installHooks = ["preinstall", "install", "postinstall"];

    for (const hook of installHooks) {
        const script = pkg.scripts[hook];
        if (!script) continue;

       for (const rule of SCRIPT_RULES) {
        if (rule.test(script)) {
            findings.push({
                hook, 
                pattern: rule.pattern,
                snippet: script, 
                severity: rule.severity,
                confidence: rule.confidence,
            });
        }
       }
    }
    return findings;
}

