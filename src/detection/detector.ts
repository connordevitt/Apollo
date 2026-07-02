// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import type { PackageInfo, Finding, Rule } from "../types.js";

const SCRIPT_RULES: Rule[] = [
    { id: "install-curl", pattern: "curl", severity: "high", confidence: "high", test: s => s.includes("curl")},
    { id: "install-wget", pattern: "wget", severity: "high", confidence: "high", test: s => s.includes("wget")},
    { id: "pipe-sh", pattern: "| sh", severity: "critical", confidence: "high", test: s => /\|\s*(ba)?sh/.test(s)},
    { id: "node-eval", pattern: "node -e", severity: "medium", confidence: "medium", test: s => s.includes("node -e")},
    { id: "raw-ip-url", pattern: "http(s)://", severity: "high", confidence: "high", test: s => /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s)},
    { id: "base64-decode", pattern: "base64 decode", severity: "high", confidence: "high", test: s => /Buffer\.from\([^)]*base64/.test(s) || s.includes("atob(")},
    { id: "inline-eval", pattern: "eval(", severity: "high", confidence: "high", test: s => s.includes("eval(")},
    { id: "webhook-exfil", pattern: "exfil endpoint", severity: "critical", confidence: "high", test: s => /discord(app)?\.com\/api\/webhooks|api\.telegram\.org|webhook\.site|requestbin|pipedream\.net|burpcollaborator\.net|oastify\.com|interact\.sh/i.test(s)},
    { id: "win-cradle", pattern: "certutil/bitsadmin", severity: "high", confidence: "high", test: s => /certutil|bitsadmin/i.test(s)},

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

const SOURCE_RULES: Rule[] = [
    { id: "inline-eval", pattern: "eval(", severity: "low", confidence: "low", test: s => s.includes("eval(")},
];

export function analyzeSourceFiles(files: Map<string, string>): Finding[] {
    const findings: Finding[] = [];

    for (const [file, content] of files.entries()) {
        if (file.endsWith(".js") || file.endsWith(".ts")) {
        for (const rule of SOURCE_RULES) {
            if (rule.test(content)) {
                findings.push({
                    hook: file,
                    pattern: rule.pattern,
                    snippet: content.slice(0, 200),
                    severity: rule.severity,
                    confidence: rule.confidence,
                });
                }
            }
        }
    }
    return findings;
}