// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import type { PackageInfo, Finding, Rule } from "../types.js";

const TOKEN_NAMES = "NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN";

const envTokenAccess = new RegExp(`process\\.env(\\.|\\[\\s*['"\`])(${TOKEN_NAMES})\\b`);
const envTokenDestructure = new RegExp(`\\{[^}]*\\b(${TOKEN_NAMES})\\b[^}]*\\}\\s*=\\s*process\\.env`);
const envDump = /JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|keys|values)\(\s*process\.env\s*\)/;

// Known exfil endpoints 
const WEBHOOK = /discord(app)?\.com\/api\/webhooks|api\.telegram\.org|webhook\.site|requestbin|pipedream\.net|burpcollaborator\.net|oastify\.com|interact\.sh/i;

const ENV_RULES: Rule[] = [
    { id: "env-token-read", pattern: "credential env var read", severity: "low", confidence: "low", test: s => envTokenAccess.test(s) || envTokenDestructure.test(s)},
    { id: "env-dump", pattern: "full process.env dump", severity: "critical", confidence: "high", test: s => envDump.test(s)},
];

const SCRIPT_RULES: Rule[] = [
    { id: "install-curl", pattern: "curl", severity: "high", confidence: "high", test: s => s.includes("curl")},
    { id: "install-wget", pattern: "wget", severity: "high", confidence: "high", test: s => s.includes("wget")},
    { id: "pipe-sh", pattern: "| sh", severity: "critical", confidence: "high", test: s => /\|\s*(ba)?sh/.test(s)},
    { id: "node-eval", pattern: "node -e", severity: "medium", confidence: "medium", test: s => s.includes("node -e")},
    { id: "raw-ip-url", pattern: "http(s)://", severity: "high", confidence: "high", test: s => /http(s)?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s)},
    { id: "base64-decode", pattern: "base64 decode", severity: "high", confidence: "high", test: s => /Buffer\.from\([^)]*base64/.test(s) || s.includes("atob(")},
    { id: "inline-eval", pattern: "eval(", severity: "high", confidence: "high", test: s => s.includes("eval(")},
    { id: "webhook-exfil", pattern: "exfil endpoint", severity: "critical", confidence: "high", test: s => WEBHOOK.test(s)},
    { id: "win-cradle", pattern: "certutil/bitsadmin", severity: "high", confidence: "high", test: s => /certutil|bitsadmin/i.test(s)},
    { id: "env-exfil", pattern: "env-exfil", severity: "critical", confidence: "high", test: s => envTokenAccess.test(s) && (s.includes("curl") || s.includes("wget") || s.includes("https://"))},
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
                package: pkg.name,
                version: pkg.version,
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
    ...ENV_RULES,
    
    { id: "npmrc-read", pattern: ".npmrc read", severity: "high", confidence: "medium", test: s => /\.npmrc/.test(s) && /readFile|createReadStream/.test(s)},
    { id: "ssh-key-read", pattern: "ssh key access", severity: "high", confidence: "medium", test: s => /\.ssh[\/\\]|id_rsa|id_ed25519/.test(s)},
    { id: "cred-exfil-webhook", pattern: "credential exfil to webhook", severity: "critical", confidence: "high", test: s => envTokenAccess.test(s) && WEBHOOK.test(s)},

];


export function analyzeSourceFiles(pkg: PackageInfo, files: Map<string, string>): Finding[] {
    const findings: Finding[] = [];

    for (const [file, content] of files.entries()) {
        if (file.endsWith(".js") || file.endsWith(".ts")) {
        for (const rule of SOURCE_RULES) {
            if (rule.test(content)) {
                findings.push({
                    package: pkg.name,
                    version: pkg.version,
                    hook: file.replace("package/", ""),
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