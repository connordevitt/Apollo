// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import type { PackageInfo, Finding, Rule } from "../types.js";

const TOKEN_NAMES = "NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN";

const envTokenAccess = new RegExp(`process\\.env(\\.|\\[\\s*['"\`])(${TOKEN_NAMES})\\b`);
const envTokenDestructure = new RegExp(`\\{[^}]*\\b(${TOKEN_NAMES})\\b[^}]*\\}\\s*=\\s*process\\.env`);
const envDump = /JSON\.stringify\(\s*process\.env\b|Object\.(entries|keys|values)\(\s*process\.env\s*\)|\{\s*\.\.\.\s*process\.env\s*\}/;

// Known exfil endpoints
const WEBHOOK = /discord(app)?\.com\/api\/webhooks|api\.telegram\.org|webhook\.site|requestbin|pipedream\.net|burpcollaborator\.net|oastify\.com|interact\.sh/i;

const NETWORK_SINK = /\bfetch\s*\(|\b(https?|http2)\.(request|get)\b|\bXMLHttpRequest\b|\baxios\b|\bgot\s*\(|\bnode-fetch\b|\bundici\b|\bfollow-redirects\b|\bsuperagent\b|\bneedle\b|\bWebSocket\s*\(|net\.(connect|createConnection)|dns\.(promises\.)?(lookup|resolve)|(require|import)\s*\(\s*['"`](node:)?(https?|http2|dns|net|undici|follow-redirects|ws|superagent|needle|request)['"`]\s*\)|\bcurl\b|\bwget\b|\bnslookup\b|\bdig\s|\bnc\s/i;
const FS_READ = /readFileSync|readFile|createReadStream|openSync|\.open\(|readdirSync|readdir/;
const SSH_PATH = /\.ssh[\/\\]|id_rsa|id_ed25519|id_ecdsa|authorized_keys/;
const NPMRC_PATH = /\.npmrc/;
const FIRST_PARTY = /(^|\.)(github|githubusercontent|npmjs|yarnpkg|gitlab|bitbucket|amazonaws|googleapis|azure)\.(com|org|net|io)$/i;
const URL_LITERAL = /https?:\/\/[^\s'"`)]+/i;

// Stop at $ and { too, so a template-literal URL like `https://api.github.com${path}`
// yields the host "api.github.com", not "api.github.com${path}".
function hostOf(url: string): string | null {
    const m = /^https?:\/\/([^\/?#:\s'"`)${]+)/i.exec(url);
    return m ? m[1]! : null;
}

function isInternalHost(host: string): boolean {
    if (host === "localhost" || host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")) {
        return true;
    }
    const parts = host.split(".");
    const second = Number(parts[1]);
    if (host.startsWith("172.") && second >= 16 && second <= 31) {
        return true;
    }
    return false;
}
const B64_DECODE = /Buffer\.from\([^)]*['"`]base64['"`]|atob\s*\(|base64\s+(-d|--decode)/i;
const HOST_RECON = /\bwhoami\b|\bhostname\b|\buname\b|\bid\s+-u\b|os\.(hostname|userInfo)\s*\(/i;

function positions(re: RegExp, s: string): number[] {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    const out: number[] = [];
    let m: RegExpExecArray | null;
    while ((m = g.exec(s)) !== null) {
        out.push(m.index);
        if (m.index === g.lastIndex) g.lastIndex++; // guard against zero-width loops
    }
    return out;
}

function near(s: string, a: RegExp, b: RegExp, window = 400): boolean {
    const pa = positions(a, s);
    if (pa.length === 0) return false;
    const pb = positions(b, s);
    if (pb.length === 0) return false;
    return pa.some(i => pb.some(j => Math.abs(i - j) <= window));
}


function credExfil(s: string, creds: RegExp, window = 600): boolean {
    const cred = positions(creds, s);
    if (cred.length === 0) return false;
    const sinks = positions(NETWORK_SINK, s).filter(j => cred.some(i => Math.abs(i - j) <= window));
    if (sinks.length === 0) return false;
    const urls = positions(URL_LITERAL, s).filter(j => cred.some(i => Math.abs(i - j) <= window));
  
    if (urls.length === 0) return true;
    return !urls.every(j => {
        const host = hostOf(s.slice(j, j + 200));
        return host !== null && (FIRST_PARTY.test(host) || isInternalHost(host));
    });
}

// ── Install-script rules ────────────────────────────────────────────────────
const SCRIPT_RULES: Rule[] = [
    { id: "install-curl", pattern: "curl", severity: "high", confidence: "high", test: s => /\bcurl\b/.test(s) },
    { id: "install-wget", pattern: "wget", severity: "high", confidence: "high", test: s => /\bwget\b/.test(s) },
    { id: "pipe-sh", pattern: "pipe to interpreter", severity: "critical", confidence: "high", test: s => /(?<!\|)\|\s*((ba)?sh|node|python3?|perl|ruby)\b/.test(s) },
    { id: "download-exec", pattern: "download + execute", severity: "critical", confidence: "high", test: s => /\b(curl|wget)\b/.test(s) && /(\||&&|;)\s*(node|python3?|perl|ruby|sh|bash|\.\/)/.test(s) },
    { id: "raw-ip-url", pattern: "http(s)://<ip>", severity: "high", confidence: "high", test: s => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s) },
    { id: "inline-eval", pattern: "eval(", severity: "high", confidence: "medium", test: s => /\beval\s*\(/.test(s) },
    { id: "webhook-exfil", pattern: "exfil endpoint", severity: "critical", confidence: "high", test: s => WEBHOOK.test(s) },
    { id: "win-cradle", pattern: "certutil/bitsadmin", severity: "high", confidence: "high", test: s => /\b(certutil|bitsadmin)\b/i.test(s) },
    { id: "recon-exfil", pattern: "host recon + network exfil", severity: "critical", confidence: "high", test: s => near(s, HOST_RECON, NETWORK_SINK, 300) },
    { id: "node-e-payload", pattern: "node -e payload", severity: "high", confidence: "high", test: s => /node\s+-e\b/.test(s) && (/\beval\s*\(/.test(s) || B64_DECODE.test(s) || NETWORK_SINK.test(s)) },
    { id: "env-exfil", pattern: "env-exfil", severity: "critical", confidence: "high", test: s => (envTokenAccess.test(s) || envTokenDestructure.test(s)) && NETWORK_SINK.test(s) },
];

export function analyzePackage(pkg: PackageInfo): Finding[] {
    const findings: Finding[] = [];

    const installHooks = ["preinstall", "install", "postinstall", "prepare"];

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


function extractEvidence(
    source: string,
    evidence?: RegExp,
): { snippet: string; line?: number } {
    if (!evidence) return { snippet: source.slice(0, 200) };
    const index = source.search(evidence);
    if (index < 0) return { snippet: source.slice(0, 200) };
    const start = source.lastIndexOf("\n", Math.max(0, index - 150));
    const end = source.indexOf("\n", index + 250);
    const line = source.slice(0, index).split("\n").length;
    return {
        snippet: source.slice(
            start < 0 ? 0 : start + 1,
            end < 0 ? source.length : end,
        ),
        line,
    };
}

// ── Source-file rules ───────────────────────────────────────────────────────
const SOURCE_RULES: Rule[] = [
    // Compound / high-confidence — real exfil shapes.
    { id: "cred-exfil", pattern: "credential read + network sink", severity: "critical", confidence: "high", test: s => credExfil(s, new RegExp(`${envTokenAccess.source}|${envTokenDestructure.source}`)), evidence: new RegExp(`${envTokenAccess.source}|${envTokenDestructure.source}`) },
    { id: "envdump-exfil", pattern: "process.env dump + network sink", severity: "critical", confidence: "high", test: s => near(s, envDump, NETWORK_SINK, 400), evidence: envDump },
    { id: "ssh-exfil", pattern: "ssh key read + network sink", severity: "critical", confidence: "high", test: s => near(s, SSH_PATH, FS_READ, 200) && NETWORK_SINK.test(s), evidence: SSH_PATH },
    { id: "npmrc-exfil", pattern: ".npmrc read + network sink", severity: "critical", confidence: "high", test: s => near(s, NPMRC_PATH, NETWORK_SINK, 400), evidence: NPMRC_PATH },
    { id: "eval-payload", pattern: "eval of decoded payload", severity: "high", confidence: "high", test: s => near(s, /\beval\s*\(/, B64_DECODE, 200), evidence: new RegExp(`${B64_DECODE.source}|\\beval\\s*\\(`, "i") },
    { id: "env-dump", pattern: "process.env dump", severity: "low", confidence: "low", test: s => envDump.test(s), evidence: envDump },
    { id: "env-token-read", pattern: "credential env var read", severity: "low", confidence: "low", test: s => envTokenAccess.test(s) || envTokenDestructure.test(s), evidence: new RegExp(`${envTokenAccess.source}|${envTokenDestructure.source}`) },
    { id: "ssh-key-read", pattern: "ssh key file read", severity: "medium", confidence: "low", test: s => near(s, SSH_PATH, FS_READ, 200), evidence: SSH_PATH },
    { id: "npmrc-read", pattern: ".npmrc read", severity: "medium", confidence: "low", test: s => near(s, NPMRC_PATH, FS_READ, 200), evidence: NPMRC_PATH },
    { id: "webhook-exfil", pattern: "webhook exfil", severity: "critical", confidence: "medium", test: s => WEBHOOK.test(s), evidence: WEBHOOK },
];

const SOURCE_EXTENSIONS = [".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"];

export function analyzeSourceFiles(pkg: PackageInfo, files: Map<string, string>): Finding[] {
    const findings: Finding[] = [];
    const seenPatterns = new Set<string>();
    

    for (const [file, content] of files.entries()) {
        if (!SOURCE_EXTENSIONS.some(ext => file.endsWith(ext))) continue;
        for (const rule of SOURCE_RULES) {
            if (seenPatterns.has(rule.id)) continue;
            if (rule.test(content)) {
                const evidence = extractEvidence(content, rule.evidence)
                seenPatterns.add(rule.id);
                findings.push({
                    package: pkg.name,
                    version: pkg.version,
                    hook: file.replace("package/", ""),
                    pattern: rule.pattern,
                    snippet: evidence.snippet,
                    line: evidence.line,
                    severity: rule.severity,
                    confidence: rule.confidence,
                });
            }
        }
    }
    return findings;
}
