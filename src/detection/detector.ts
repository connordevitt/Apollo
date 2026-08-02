// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import type { PackageInfo, Finding, Severity, Confidence } from "../types.js";

// ── Scan primitives ─────────────────────────────────────────────────────────

/** Sentinel for `match`: rule fired but can't pin an offset. */
const HIT = -1;

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

class Scan {
    private readonly cache = new Map<string, number[]>();
    constructor(readonly text: string) {}

    at(re: RegExp): number[] {
        const key = `${re.source} ${re.flags.replace("g", "")}`;
        let p = this.cache.get(key);
        if (p === undefined) {
            p = positions(re, this.text);
            this.cache.set(key, p);
        }
        return p;
    }

    has(re: RegExp): boolean {
        return this.at(re).length > 0;
    }

    first(re: RegExp): number | null {
        return this.at(re)[0] ?? null;
    }

    near(a: RegExp, b: RegExp, window = 400): number | null {
        const pb = this.at(b);
        if (pb.length === 0) return null;
        for (const i of this.at(a)) {
            if (pb.some(j => Math.abs(i - j) <= window)) return i;
        }
        return null;
    }

    /** Offset of the first `anchor` match with every regex in `all` within `window` chars. */
    cluster(anchor: RegExp, all: RegExp[], window = 400): number | null {
        for (const i of this.at(anchor)) {
            if (all.every(re => this.at(re).some(j => Math.abs(i - j) <= window))) return i;
        }
        return null;
    }

    window(i: number, radius: number): string {
        return this.text.slice(Math.max(0, i - radius), i + radius);
    }
}

interface Rule {
    id: string;
    pattern: string;
    severity: Severity;
    confidence: Confidence;
    match: (sc: Scan) => number | null;
    /** Leans on offset proximity, so it degrades on single-line bundles. */
    proximity?: boolean;
    /** Rule ids suppressed when this one fires on the same text. */
    supersedes?: readonly string[];
}

// ── Vocabulary: credentials & secret material ───────────────────────────────

const TOKEN_NAMES = "NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN";

const envTokenAccess = new RegExp(`process\\.env(\\.|\\[\\s*['"\`])(${TOKEN_NAMES})\\b`);
const envTokenDestructure = new RegExp(`\\{[^}]*\\b(${TOKEN_NAMES})\\b[^}]*\\}\\s*=\\s*process\\.env`);
const ENV_TOKEN = new RegExp(`${envTokenAccess.source}|${envTokenDestructure.source}`);
const envDump = /JSON\.stringify\(\s*process\.env(?![\w.\[])|Object\.(entries|keys|values)\(\s*process\.env\s*\)|\{\s*\.\.\.\s*process\.env\s*\}/;
const HARDCODED_CRED = new RegExp(
    `process\\.env(?:\\.|\\[\\s*['"\`])(?:${TOKEN_NAMES})\\b[\\s\\]'"\`]*(?:\\?\\?|\\|\\|)\\s*['"\`](?=[A-Za-z0-9_\\-]*[0-9])[A-Za-z0-9_\\-]{12,}['"\`]`,
);

const SSH_PATH = /\.ssh[\/\\](?![\w./\\-]*\.pub\b)|id_rsa(?!\.pub)|id_ed25519(?!\.pub)|id_ecdsa(?!\.pub)|authorized_keys/;
const NPMRC_PATH = /\.npmrc/;
// The dotenv arm requires the literal to *be* a path so `process.env.X` can't satisfy it.
const CRED_FILE_PATH = /['"`](?:[^'"`\n]{0,80}[\/\\])?\.env(?:\.[\w-]+)?['"`]|\.aws[\/\\]credentials|\.config[\/\\]gcloud|\.netrc\b|\.git-credentials|\.docker[\/\\]config\.json|\.kube[\/\\]config|\.gnupg[\/\\]|Keychains?[\/\\]|login\.keychain/i;
const SECRET_MATERIAL = new RegExp(
    `${ENV_TOKEN.source}|${envDump.source}|${SSH_PATH.source}|${NPMRC_PATH.source}|${CRED_FILE_PATH.source}`,
    "i",
);

const FS_READ = /readFileSync|readFile|createReadStream|openSync|\.open\(|readdirSync|readdir|copyFileSync|globSync|\bglob\s*\(/;
const FS_WRITE = /writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync|renameSync/;

// ── Vocabulary: sinks ───────────────────────────────────────────────────────

const NETWORK_SINK = /\bfetch\s*\(|\b(https?|http2)\.(request|get)\b|\bXMLHttpRequest\b|\baxios\b|\bgot\s*\(|\bnode-fetch\b|\bundici\b|\bfollow-redirects\b|\bsuperagent\b|\bneedle\b|\bWebSocket\s*\(|net\.(connect|createConnection)|dns\.(promises\.)?(lookup|resolve)|(require|import)\s*\(\s*['"`](node:)?(https?|http2|dns|net|undici|follow-redirects|ws|superagent|needle|request)['"`]\s*\)|\bcurl\b|\bwget\b|\bnslookup\b|\bdig\s|\bnc\s/i;
// `exec` must be unqualified: `RE.exec(str)` is a RegExp match, not a subprocess. Dotted
// `cp.exec(...)` is covered by the `child_process` arm instead. Compound rules only.
const EXEC_SINK = /\b(?:execSync|execFile|execFileSync|spawnSync|spawn)\s*\(|(?<![.\w])exec\s*\(|child_process/;
const CODE_SINK = /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]|vm\.(?:runIn\w+|compileFunction)\s*\(|process\.binding\s*\(/;
const SOCKET_OPEN = /net\.(?:connect|createConnection)\s*\(|new\s+net\.Socket\s*\(|new\s+WebSocket\s*\(|tls\.connect\s*\(/;
const DNS_LOOKUP = /dns\.(?:promises\.)?(?:resolve\w*|lookup)\s*\(|\bnslookup\b|\bdig\s+/;
const URL_LITERAL = /https?:\/\/[^\s'"`)]+/i;

const WEBHOOK_EXFIL = /discord(app)?\.com\/api\/webhooks|webhook\.site|requestbin\.(com|net)|requestb\.in|pipedream\.net|burpcollaborator\.net|oastify\.com|interact\.sh|\.ngrok(-free)?\.(io|app)|trycloudflare\.com|\.serveo\.net/i;
const WEBHOOK_DUAL = /api\.telegram\.org|hooks\.slack\.com|api\.pastebin\.com|\bpaste\.ee\b|transfer\.sh|file\.io\b|0x0\.st/i;
const WEBHOOK = new RegExp(`${WEBHOOK_EXFIL.source}|${WEBHOOK_DUAL.source}`, "i");

// ── Vocabulary: obfuscation & staging ───────────────────────────────────────

const B64_DECODE = /Buffer\.from\([^)]*['"`]base64['"`]|atob\s*\(|base64\s+(-d|--decode)|Buffer\.from\([^)]*['"`]hex['"`]/i;
const HEX_IDENT = /\b_0x[a-f0-9]{4,8}\b/; // javascript-obfuscator signature
const HEX_ESCAPE_RUN = /(?:\\x[0-9a-f]{2}){8,}|(?:\\u00[0-9a-f]{2}){8,}/i;
const CHARCODE_CHAIN = /String\.fromCharCode\(\s*(?:0x[0-9a-f]+|\d+)\s*(?:,\s*(?:0x[0-9a-f]+|\d+)\s*){7,}\)/i;
const DECODE_ANY = new RegExp(`${B64_DECODE.source}|${HEX_ESCAPE_RUN.source}|${CHARCODE_CHAIN.source}`, "i");

const TMP_WRITE = /os\.tmpdir\s*\(\)|['"`]\/tmp\/|%TEMP%|process\.env\.(?:TEMP|TMPDIR)\b|\/var\/tmp\//i;
const CHMOD_EXEC = /chmod\s+(?:\+x|[0-7]*[1357][0-7]*)\b|chmodSync?\s*\([^)]*0o?[0-7]*[1357]/;
const HOST_RECON = /\bwhoami\b|\bhostname\b|\buname\b|\bid\s+-u\b|os\.(hostname|userInfo|networkInterfaces)\s*\(/i;
const SANDBOX_CHECK = /\/\.dockerenv|\bisDocker\s*\(|VirtualBox|VMware|\bqemu\b|SbieDll|wine_get_version/i;
const TLS_DISABLE = /NODE_TLS_REJECT_UNAUTHORIZED['"`\]\s]*=\s*['"`]?0|rejectUnauthorized\s*:\s*false|strictSSL\s*:\s*false|(?:curl|wget)\s[^\n]*(?:-k\b|--insecure|--no-check-certificate)/;

// ── Vocabulary: theft targets ───────────────────────────────────────────────

const BROWSER_PROFILE = /User Data[\/\\]Default|Google[\/\\]Chrome[\/\\]|BraveSoftware[\/\\]|Microsoft[\/\\]Edge[\/\\]|Mozilla[\/\\]Firefox[\/\\]|\bLogin Data\b|Local Storage[\/\\]leveldb|\bmoz_cookies\b|\bcookies\.sqlite\b|\bLocal State\b/i;
const WALLET_TARGET = /nkbihfbeogaeaoehlefnkodbefgpgknn|ejbalbakoplchlghecdalmeeeajnimhm|fhbohimaelbohpjbbldcngcnapndodjp|hnfanknocfeofbddgcijnmhnfnkdnaad|Exodus[\/\\]exodus\.wallet|Electrum[\/\\]wallets|\.ethereum[\/\\]keystore|\bwallet\.dat\b|Ledger Live|seed[\s_-]?phrase|mnemonic/i;
const CRYPTO_ADDR = /\b(?:0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}|T[A-Za-z1-9]{33})\b/;
const CLIPBOARD = /\bclipboardy\b|navigator\.clipboard|\bpbpaste\b|\bpbcopy\b|\bxclip\b|clipboard\.(?:read|write)Text/i;
const SECRET_SCANNER_TOOL = /\btrufflehog\b|\bgitleaks\b|\bnosey ?parker\b|\bdetect-secrets\b/i;
const NPM_PUBLISH = /npm\s+(?:--?\S+\s+)*publish\b|npm-registry-fetch|registry\.npmjs\.org\/-\/package/;
const WORKFLOW_PATH = /\.github[\/\\]workflows/;

// ── Host allowlists ─────────────────────────────────────────────────────────

const FIRST_PARTY = /(^|\.)(github|githubusercontent|npmjs|yarnpkg|gitlab|bitbucket|amazonaws|googleapis|azure)\.(com|org|net|io)$/i;
const FIRST_PARTY_CLIENT = /@?octokit\b|\bOctokit\b|api\.github\.com|githubusercontent\.com|api\.gitlab\.com|\bgoogleapis\b|@?aws-sdk\b/i;
const FIRST_PARTY_HOST = /\b(amazonaws\.com|googleapis\.com|github(usercontent)?\.com|gitlab\.com|npmjs\.(org|com)|yarnpkg\.com|bitbucket\.org|core\.windows\.net)\b/i;
const BINARY_HOST = /(^|\.)(github\.com|githubusercontent\.com|registry\.npmjs\.org|npmjs\.com|nodejs\.org|storage\.googleapis\.com|jsdelivr\.net|unpkg\.com|pypi\.org|files\.pythonhosted\.org|sourceforge\.net|gitlab\.com|bitbucket\.org|chromium\.org|playwright\.azureedge\.net)$|\.s3[.-][\w-]*\.amazonaws\.com$|\.blob\.core\.windows\.net$|\.r2\.cloudflarestorage\.com$/i;

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

function isAllowedHost(host: string): boolean {
    return FIRST_PARTY.test(host) || BINARY_HOST.test(host) || isInternalHost(host);
}

function untrustedUrlNear(sc: Scan, anchor: number, radius: number): boolean {
    return sc.at(URL_LITERAL).some(j => {
        if (Math.abs(j - anchor) > radius) return false;
        const host = hostOf(sc.text.slice(j, j + 200));
        return host !== null && !isAllowedHost(host);
    });
}

function allUrlsTrusted(sc: Scan): boolean {
    return sc.at(URL_LITERAL).every(j => {
        const host = hostOf(sc.text.slice(j, j + 200));
        return host === null || isAllowedHost(host);
    });
}

// ── Credential-flow analysis ────────────────────────────────────────────────

// A credential read that is returned, used as a ??/|| fallback, or an `if (...)` existence
// guard is being *resolved*, not sent — the token flows out to the caller, not into a sink.
// Real exfil keeps the credential as an argument/value (`body: process.env.X`), which stays active.
function isPassiveCredRead(s: string, pos: number): boolean {
    const before = s.slice(Math.max(0, pos - 24), pos);
    if (/(?:return|=>|\?\?|\|\|)\s*$/.test(before)) return true; // returned / fallback operand
    if (/\bif\s*\(\s*$/.test(before)) return true;                // existence guard
    const after = s.slice(pos, pos + 96);
    if (/^process\.env(?:\.\w+|\[\s*['"`][^'"`]+['"`]\s*\])\s*(?:\?\?|\|\|)/.test(after)) return true; // left of a fallback
    return false;
}

// First-party checks are scoped per read rather than per file: one that talks to both GitHub
// and an attacker host must not be exonerated by the GitHub call.
function credExfil(sc: Scan, creds: RegExp, radius = 600): number | null {
    const reads = sc.at(creds).filter(i => !isPassiveCredRead(sc.text, i));
    if (reads.length === 0) return null;
    const sinks = sc.at(NETWORK_SINK);
    if (sinks.length === 0) return null;

    for (const i of reads) {
        if (!sinks.some(j => Math.abs(i - j) <= radius)) continue;
        const urls = sc.at(URL_LITERAL).filter(j => Math.abs(i - j) <= radius);
        if (urls.length === 0) {
            // Destination is a variable; fall back to whether the window looks first-party.
            const view = sc.window(i, radius);
            if (!FIRST_PARTY_CLIENT.test(view) && !FIRST_PARTY_HOST.test(view)) return i;
            continue;
        }
        if (untrustedUrlNear(sc, i, radius)) return i;
    }
    return null;
}

// ── File context & confidence adjustment ────────────────────────────────────

const META_VOCAB = /\bremediation\b|\bblock ?list\b|\ballow ?list\b|false[\s_-]?positive|\bseverity\b|\bdetectors?\b|\bheuristics?\b|\bIOC\b|threat[\s_-]?(pattern|model|intel|feed)|exfiltrat|malicious|\bCVE-|\bscanner\b|\bSAST\b|supply[\s-]?chain/gi;
const SSH_CLIENT_LIB = /\bssh2\b|node-ssh|ssh2-sftp-client|\bsimple-git\b|nodegit|ssh-config/i;
// `(?<!\w)` on .env keeps `process.env.HOME` from counting as a dotenv reference — otherwise
// two env reads next to an ssh path look like a blocklist and downgrade real exfil.
const SECRET_FILE_TOKEN = /id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.pem\b|\.key\b|\.secret\b|(?<!\w)\.env\b|\.npmrc\b|credentials/gi;

function isMinified(s: string): boolean {
    if (s.length < 2000) return false;
    let max = 0, run = 0, lines = 1;
    for (let i = 0; i < s.length; i++) {
        if (s[i] === "\n") { if (run > max) max = run; run = 0; lines++; }
        else run++;
    }
    if (run > max) max = run;
    return max > 1000 || s.length / lines > 300;
}

function obfuscationSignals(sc: Scan): number {
    let n = 0;
    if (sc.at(HEX_IDENT).length >= 5) n++;
    if (sc.has(HEX_ESCAPE_RUN)) n++;
    if (sc.has(CHARCODE_CHAIN)) n++;
    if (sc.has(B64_DECODE)) n++;
    return n;
}

function secretFamilyCount(sc: Scan): number {
    let n = 0;
    if (sc.has(SSH_PATH)) n++;
    if (sc.has(NPMRC_PATH)) n++;
    if (sc.has(WEBHOOK)) n++;
    if (sc.has(ENV_TOKEN)) n++;
    if (sc.has(B64_DECODE)) n++;
    if (sc.has(CRED_FILE_PATH)) n++;
    return n;
}

// Other scanners and IOC feeds carry the vocabulary we hunt for. Requiring unobfuscated,
// unminified code means the exemption can't be bought by sprinkling "severity" into a payload.
function isAnalysisTooling(sc: Scan, minified: boolean): boolean {
    if (minified) return false;
    if (sc.at(META_VOCAB).length < 3) return false;
    if (secretFamilyCount(sc) < 2) return false;
    if (obfuscationSignals(sc) > 0) return false;
    return true;
}

/** A file listing >=3 secret-file families within 120 chars is a blocklist, not a thief. */
function isSecretBlocklist(sc: Scan): boolean {
    const p = sc.at(SECRET_FILE_TOKEN);
    for (let i = 0; i + 2 < p.length; i++) {
        if (p[i + 2]! - p[i]! <= 120) return true;
    }
    return false;
}

interface FileContext {
    minified: boolean;
    tooling: boolean;
    sshClient: boolean;
    secretBlocklist: boolean;
    lowTrust: boolean;
    installReachable: boolean;
}

const CONFIDENCE_ORDER: Confidence[] = ["low", "medium", "high"];
const SECRET_PATH_RULES = new Set(["ssh-exfil", "ssh-key-read", "npmrc-exfil", "npmrc-read", "credfile-exfil"]);

function step<T>(order: T[], value: T, by: number): T {
    const i = order.indexOf(value);
    return order[Math.min(order.length - 1, Math.max(0, i + by))]!;
}

function contextAdjust(rule: Rule, ctx: FileContext): { severity: Severity; confidence: Confidence } {
    if (ctx.tooling && (rule.proximity === true || rule.id === "webhook-endpoint")) {
        return { severity: "low", confidence: "low" };
    }

    let confidence = rule.confidence;
    if (ctx.minified && rule.proximity === true) confidence = "low";
    if (ctx.sshClient && (rule.id === "ssh-exfil" || rule.id === "ssh-key-read")) confidence = "low";
    if (ctx.secretBlocklist && SECRET_PATH_RULES.has(rule.id)) confidence = "low";
    if (ctx.lowTrust) confidence = step(CONFIDENCE_ORDER, confidence, -1);
    // Code npm runs unattended on install is worse than the same code in a library file.
    if (ctx.installReachable && !ctx.lowTrust) confidence = step(CONFIDENCE_ORDER, confidence, 1);

    return { severity: rule.severity, confidence };
}

// ── Install-script rules ────────────────────────────────────────────────────
// Also applied to shell files and to any file an install hook executes.

const SCRIPT_RULES: Rule[] = [
    {
        id: "download-exec", pattern: "download + execute", severity: "critical", confidence: "high",
        supersedes: ["install-curl", "install-wget", "pipe-sh"],
        // `\.?\/[\w.\/-]+` catches the drop-then-run shape (`... && /tmp/p`). `chmod` is
        // deliberately absent: `curl -o bin/tool && chmod +x bin/tool` is honest packaging.
        match: sc => (sc.has(/\b(curl|wget)\b/) && sc.has(/(\||&&|;)\s*(?:sudo\s+)?(node|python3?|perl|ruby|sh|bash|\.?\/[\w.\/-]+)/))
            ? (sc.first(/\b(curl|wget)\b/) ?? HIT) : null,
    },
    {
        id: "pipe-sh", pattern: "pipe to interpreter", severity: "critical", confidence: "high",
        supersedes: ["install-curl", "install-wget"],
        match: sc => sc.first(/(?<!\|)\|\s*((ba)?sh|node|python3?|perl|ruby)\b/),
    },
    {
        id: "env-exfil", pattern: "env-exfil", severity: "critical", confidence: "high",
        match: sc => sc.has(ENV_TOKEN) && sc.has(NETWORK_SINK) ? sc.first(ENV_TOKEN) : null,
    },
    {
        id: "webhook-exfil", pattern: "exfil endpoint", severity: "critical", confidence: "high",
        match: sc => sc.first(WEBHOOK),
    },
    {
        id: "recon-exfil", pattern: "host recon + network exfil", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.near(HOST_RECON, NETWORK_SINK, 300),
    },
    {
        id: "raw-ip-url", pattern: "http(s)://<ip>", severity: "high", confidence: "high",
        match: sc => sc.first(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/),
    },
    {
        id: "win-cradle", pattern: "certutil/bitsadmin", severity: "high", confidence: "high",
        match: sc => sc.first(/\b(certutil|bitsadmin)\b/i),
    },
    {
        id: "node-e-payload", pattern: "node -e payload", severity: "high", confidence: "high",
        match: sc => sc.has(/node\s+-e\b/) && (sc.has(CODE_SINK) || sc.has(DECODE_ANY) || sc.has(NETWORK_SINK))
            ? sc.first(/node\s+-e\b/) : null,
    },
    {
        id: "obfuscated-script", pattern: "obfuscated install script", severity: "high", confidence: "high",
        match: sc => sc.has(HEX_ESCAPE_RUN) || sc.has(CHARCODE_CHAIN)
            ? (sc.first(HEX_ESCAPE_RUN) ?? sc.first(CHARCODE_CHAIN)) : null,
    },
    {
        id: "b64-exec", pattern: "base64 decode + execute", severity: "high", confidence: "high",
        proximity: true,
        match: sc => sc.near(B64_DECODE, /\||\b(sh|bash|node|eval)\b/, 200),
    },
    {
        id: "inline-eval", pattern: "eval(", severity: "high", confidence: "medium",
        match: sc => sc.first(/\beval\s*\(/),
    },
    {
        id: "install-curl", pattern: "curl", severity: "high", confidence: "high",
        match: sc => sc.first(/\bcurl\b/),
    },
    {
        id: "install-wget", pattern: "wget", severity: "high", confidence: "high",
        match: sc => sc.first(/\bwget\b/),
    },
];

const BARE_FETCH_RULES = new Set(["install-curl", "install-wget"]);

// `curl https://github.com/.../release.tar.gz -o x` is what thousands of honest packages do
// to fetch a prebuilt binary. The compound rules above still fire on everything else.
function scriptAdjust(rule: Rule, sc: Scan): { severity: Severity; confidence: Confidence } {
    if (BARE_FETCH_RULES.has(rule.id) && sc.has(URL_LITERAL) && allUrlsTrusted(sc)) {
        return { severity: "low", confidence: "low" };
    }
    return { severity: rule.severity, confidence: rule.confidence };
}

// ── Source-file rules ───────────────────────────────────────────────────────

const SOURCE_RULES: Rule[] = [
    // Credential theft.
    {
        id: "cred-exfil", pattern: "credential read + network sink", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => credExfil(sc, ENV_TOKEN),
    },
    {
        id: "hardcoded-cred", pattern: "hardcoded credential fallback", severity: "critical", confidence: "high",
        match: sc => sc.first(HARDCODED_CRED),
    },
    {
        id: "envdump-exfil", pattern: "process.env dump + network sink", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.near(envDump, NETWORK_SINK, 400),
    },
    {
        id: "ssh-exfil", pattern: "ssh key read + network sink", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.has(NETWORK_SINK) ? sc.near(SSH_PATH, FS_READ, 200) : null,
    },
    {
        id: "npmrc-exfil", pattern: ".npmrc read + network sink", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.has(NETWORK_SINK) ? sc.near(NPMRC_PATH, FS_READ, 200) : null,
    },
    {
        id: "credfile-exfil", pattern: "credential file read + network sink", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => {
            const anchor = sc.near(CRED_FILE_PATH, FS_READ, 200);
            if (anchor === null || !sc.has(NETWORK_SINK)) return null;
            // dotenv/aws-sdk read these files for a living; they just don't ship them anywhere odd.
            if (FIRST_PARTY_CLIENT.test(sc.window(anchor, 600))) return null;
            return untrustedUrlNear(sc, anchor, 600) || !sc.has(URL_LITERAL) ? anchor : null;
        },
    },

    // Remote / obfuscated code execution.
    {
        id: "remote-code-exec", pattern: "remote payload + execute", severity: "critical", confidence: "high",
        proximity: true,
        // Only CODE_SINK, not EXEC_SINK: "fetch, then spawn a subprocess" describes half the
        // CLI tools on the registry. Fetch-then-decode-then-exec is `exec-obfuscated` instead.
        match: sc => {
            const anchor = sc.near(NETWORK_SINK, CODE_SINK, 300);
            return anchor !== null && untrustedUrlNear(sc, anchor, 600) ? anchor : null;
        },
    },
    {
        id: "exec-obfuscated", pattern: "obfuscated command execution", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.near(EXEC_SINK, DECODE_ANY, 200),
    },
    {
        id: "eval-payload", pattern: "eval of decoded payload", severity: "high", confidence: "high",
        proximity: true,
        match: sc => sc.near(CODE_SINK, DECODE_ANY, 200),
    },
    {
        id: "reverse-shell", pattern: "socket + shell spawn", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.cluster(SOCKET_OPEN, [EXEC_SINK, /['"`](?:\/bin\/)?(?:ba|z|k)?sh['"`]|cmd\.exe|powershell|\.stdin\b|\bstdio\b/i], 400),
    },
    {
        id: "tmp-drop-exec", pattern: "temp file drop + chmod + execute", severity: "high", confidence: "high",
        proximity: true,
        match: sc => sc.cluster(TMP_WRITE, [FS_WRITE, CHMOD_EXEC, EXEC_SINK], 500),
    },

    // Worm / CI persistence.
    {
        // `npm publish` beside a registry token is also just a release tool (np, release-it).
        // What separates a worm is that it's packed, or fetched the payload it republishes.
        id: "self-propagation", pattern: "npm publish + stolen token", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => {
            const anchor = sc.near(NPM_PUBLISH, new RegExp(`${ENV_TOKEN.source}|${NPMRC_PATH.source}|_authToken`), 600);
            if (anchor === null) return null;
            if (obfuscationSignals(sc) >= 2) return anchor;
            return untrustedUrlNear(sc, anchor, 800) ? anchor : null;
        },
    },
    {
        // Scaffolders (create-*, plop, yeoman) legitimately emit workflow files, so the write
        // alone means nothing; it's a worm signal only alongside credentials or a publish.
        id: "workflow-drop", pattern: "writes .github/workflows + credential context", severity: "high", confidence: "medium",
        proximity: true,
        match: sc => {
            const anchor = sc.near(WORKFLOW_PATH, FS_WRITE, 300);
            if (anchor === null) return null;
            const context = new RegExp(`${SECRET_MATERIAL.source}|${NPM_PUBLISH.source}|${WEBHOOK.source}`, "i");
            return sc.at(context).some(j => Math.abs(j - anchor) <= 800) ? anchor : null;
        },
    },
    {
        id: "secret-scanner-drop", pattern: "bundled secret scanner", severity: "high", confidence: "high",
        proximity: true,
        match: sc => sc.near(SECRET_SCANNER_TOOL, new RegExp(`${EXEC_SINK.source}|${NETWORK_SINK.source}`, "i"), 400),
    },
    {
        id: "npmrc-token-write", pattern: "writes registry auth token", severity: "high", confidence: "medium",
        proximity: true,
        match: sc => sc.near(/_authToken/, FS_WRITE, 300),
    },

    // Local data theft.
    {
        id: "browser-cred-theft", pattern: "browser profile read + network sink", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.has(NETWORK_SINK) ? sc.near(BROWSER_PROFILE, FS_READ, 300) : null,
    },
    {
        id: "wallet-theft", pattern: "crypto wallet read + network sink", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.has(NETWORK_SINK) ? sc.near(WALLET_TARGET, FS_READ, 300) : null,
    },
    {
        id: "clipboard-hijack", pattern: "clipboard + hardcoded wallet address", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.near(CLIPBOARD, CRYPTO_ADDR, 400),
    },
    {
        id: "browser-profile-read", pattern: "browser profile read", severity: "medium", confidence: "low",
        proximity: true,
        match: sc => sc.near(BROWSER_PROFILE, FS_READ, 300),
    },
    {
        id: "wallet-path-read", pattern: "crypto wallet path read", severity: "medium", confidence: "low",
        proximity: true,
        match: sc => sc.near(WALLET_TARGET, FS_READ, 300),
    },

    // Exfil channels.
    {
        id: "webhook-exfil", pattern: "webhook exfil", severity: "critical", confidence: "high",
        proximity: true,
        match: sc => sc.near(WEBHOOK_EXFIL, new RegExp(`${NETWORK_SINK.source}|${SECRET_MATERIAL.source}`, "i"), 400),
    },
    {
        id: "webhook-exfil-secret", pattern: "webhook exfil (secret nearby)", severity: "critical", confidence: "medium",
        proximity: true,
        match: sc => sc.near(WEBHOOK_DUAL, SECRET_MATERIAL, 400),
    },
    {
        id: "dns-exfil", pattern: "dns lookup + secret material", severity: "high", confidence: "medium",
        proximity: true,
        match: sc => sc.near(DNS_LOOKUP, new RegExp(`${SECRET_MATERIAL.source}|${B64_DECODE.source}`, "i"), 300),
    },
    {
        id: "webhook-endpoint", pattern: "exfil-capable endpoint referenced", severity: "low", confidence: "low",
        match: sc => sc.first(WEBHOOK_EXFIL),
    },

    // Weak signals — cheap on their own, useful when they stack.
    {
        id: "obfuscated-network", pattern: "obfuscated code + network sink", severity: "high", confidence: "medium",
        match: sc => obfuscationSignals(sc) >= 2 && sc.has(NETWORK_SINK)
            ? (sc.first(HEX_ESCAPE_RUN) ?? sc.first(CHARCODE_CHAIN) ?? sc.first(HEX_IDENT) ?? HIT) : null,
    },
    {
        id: "sandbox-evasion", pattern: "vm/sandbox check + payload", severity: "medium", confidence: "medium",
        proximity: true,
        match: sc => sc.near(SANDBOX_CHECK, new RegExp(`${CODE_SINK.source}|${EXEC_SINK.source}|${NETWORK_SINK.source}`, "i"), 400),
    },
    {
        id: "tls-disabled", pattern: "TLS verification disabled", severity: "medium", confidence: "low",
        proximity: true,
        match: sc => sc.near(TLS_DISABLE, NETWORK_SINK, 400),
    },
    {
        id: "obfuscated-code", pattern: "obfuscated code", severity: "low", confidence: "medium",
        match: sc => obfuscationSignals(sc) >= 2
            ? (sc.first(HEX_ESCAPE_RUN) ?? sc.first(CHARCODE_CHAIN) ?? sc.first(HEX_IDENT) ?? HIT) : null,
    },
    {
        id: "ssh-key-read", pattern: "ssh key file read", severity: "medium", confidence: "low",
        proximity: true,
        match: sc => sc.near(SSH_PATH, FS_READ, 200),
    },
    {
        id: "npmrc-read", pattern: ".npmrc read", severity: "medium", confidence: "low",
        proximity: true,
        match: sc => sc.near(NPMRC_PATH, FS_READ, 200),
    },
    {
        id: "env-dump", pattern: "process.env dump", severity: "low", confidence: "low",
        match: sc => sc.first(envDump),
    },
    {
        id: "env-token-read", pattern: "credential env var read", severity: "low", confidence: "low",
        match: sc => sc.first(ENV_TOKEN),
    },
];

// Weak rules fire on the same evidence as the compound ones, so one payload would otherwise
// be counted several times by the scorer.
const SOURCE_SUPERSEDES: Record<string, readonly string[]> = {
    "cred-exfil": ["env-token-read", "env-dump"],
    "envdump-exfil": ["env-dump", "env-token-read"],
    "hardcoded-cred": ["env-token-read"],
    "ssh-exfil": ["ssh-key-read"],
    "npmrc-exfil": ["npmrc-read"],
    "self-propagation": ["npmrc-read", "env-token-read", "npmrc-token-write"],
    "webhook-exfil": ["webhook-endpoint"],
    "exec-obfuscated": ["obfuscated-code", "obfuscated-network", "eval-payload"],
    "remote-code-exec": ["obfuscated-code", "obfuscated-network"],
    "eval-payload": ["obfuscated-code"],
    "obfuscated-network": ["obfuscated-code"],
    "browser-cred-theft": ["browser-profile-read"],
    "wallet-theft": ["wallet-path-read"],
    "credfile-exfil": ["env-token-read"],
};
for (const rule of SOURCE_RULES) {
    rule.supersedes = SOURCE_SUPERSEDES[rule.id];
}

// ── Evidence extraction ─────────────────────────────────────────────────────

function extractEvidence(source: string, index: number): { snippet: string; line?: number } {
    if (index < 0) return { snippet: source.slice(0, 200) };

    const lineStart = source.lastIndexOf("\n", index) + 1;
    const nl = source.indexOf("\n", index);
    const lineEnd = nl < 0 ? source.length : nl;
    const line = source.slice(0, index).split("\n").length;

    // Bundles are one enormous line; show the neighbourhood of the match, not its head.
    if (lineEnd - lineStart > 300) {
        const from = Math.max(lineStart, index - 100);
        const to = Math.min(lineEnd, from + 280);
        return {
            snippet: `${from > lineStart ? "…" : ""}${source.slice(from, to).trim()}${to < lineEnd ? "…" : ""}`,
            line,
        };
    }
    return { snippet: source.slice(lineStart, lineEnd).trim().slice(0, 300), line };
}

// ── Package-manifest analysis ───────────────────────────────────────────────

const INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare"];
// `prepublish` still runs on install under npm <5, and the pack/publish hooks execute for
// anyone installing from a git ref, so all of them are attacker-reachable.
const RUN_HOOKS = [...INSTALL_HOOKS, "preprepare", "postprepare", "prepack", "postpack", "prepublish", "prepublishOnly"];

export function analyzePackage(pkg: PackageInfo): Finding[] {
    const findings: Finding[] = [];

    for (const hook of RUN_HOOKS) {
        const script = pkg.scripts[hook];
        if (!script) continue;
        findings.push(...runScriptRules(pkg, hook, script));
    }
    return findings;
}

function runScriptRules(pkg: PackageInfo, hook: string, script: string): Finding[] {
    const sc = new Scan(script);
    const hits: Rule[] = [];
    const superseded = new Set<string>();

    for (const rule of SCRIPT_RULES) {
        if (rule.match(sc) === null) continue;
        hits.push(rule);
        for (const id of rule.supersedes ?? []) superseded.add(id);
    }

    return hits
        .filter(rule => !superseded.has(rule.id))
        .map(rule => {
            const { severity, confidence } = scriptAdjust(rule, sc);
            return {
                package: pkg.name,
                version: pkg.version,
                hook,
                pattern: rule.pattern,
                snippet: script.slice(0, 300),
                severity,
                confidence,
            } satisfies Finding;
        });
}

// ── Source-file analysis ────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = [".js", ".ts", ".mjs", ".cjs", ".mts", ".cts", ".jsx", ".tsx"];
// Install hooks routinely delegate to these; scanning only JS leaves the payload unread.
const SHELL_EXTENSIONS = [".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".py", ".rb", ".pl"];
const SKIP_FILE = /\.d\.[cm]?ts$|\.(map|md|json|lock|txt|yml|yaml)$/i;
// Not skipped outright — an attacker would just move the payload here. Downgraded instead.
const LOW_TRUST_PATH = /(?:^|\/)(?:__tests__|tests?|fixtures?|examples?|docs?|benchmarks?|samples?|node_modules)\//i;
const LOW_TRUST_FILE = /\.(test|spec)\./i;

const MAX_SCANNED_FILES = 500;

const LOCAL_SCRIPT_REF = /(?:^|[\s;&|'"(])\.?\/?((?:[\w.@-]+\/)*[\w.@-]+\.(?:js|cjs|mjs|ts|sh|bash|py|rb|bat|cmd|ps1))\b/g;

/** Paths the install hooks hand to an interpreter, e.g. `node scripts/install.js`. */
function installReachablePaths(scripts: Record<string, string>): string[] {
    const refs: string[] = [];
    for (const hook of RUN_HOOKS) {
        const script = scripts[hook];
        if (!script) continue;
        for (const m of script.matchAll(LOCAL_SCRIPT_REF)) {
            refs.push(m[1]!.replace(/^\.\//, ""));
        }
    }
    return refs;
}

function isInstallReachable(file: string, refs: string[]): boolean {
    const path = file.replace(/^[^/]+\//, ""); // tarballs are rooted at `package/`
    return refs.some(ref => path === ref || path.endsWith(`/${ref}`));
}

export function analyzeSourceFiles(pkg: PackageInfo, files: Map<string, string>): Finding[] {
    const findings: Finding[] = [];
    const seenPatterns = new Set<string>();
    const seenLines = new Set<string>();
    const refs = installReachablePaths(pkg.scripts);

    // Rules dedupe to one finding per package, so the highest-value files must be read first.
    const ordered = [...files.entries()]
        .filter(([file]) => !SKIP_FILE.test(file) && classify(file) !== null)
        .sort((a, b) => rank(a[0], refs) - rank(b[0], refs))
        .slice(0, MAX_SCANNED_FILES);

    for (const [file, content] of ordered) {
        const kind = classify(file)!;
        const installReachable = isInstallReachable(file, refs);
        const lowTrust = !installReachable && (LOW_TRUST_PATH.test(file) || LOW_TRUST_FILE.test(file));

        const sc = new Scan(content);
        const minified = isMinified(content);
        const ctx: FileContext = {
            minified,
            tooling: isAnalysisTooling(sc, minified),
            sshClient: sc.has(SSH_CLIENT_LIB),
            secretBlocklist: isSecretBlocklist(sc),
            lowTrust,
            installReachable,
        };

        const rules = kind === "shell"
            ? SCRIPT_RULES
            : installReachable ? [...SOURCE_RULES, ...SCRIPT_RULES] : SOURCE_RULES;

        const hits: { rule: Rule; index: number }[] = [];
        const superseded = new Set<string>();
        for (const rule of rules) {
            if (seenPatterns.has(rule.id)) continue;
            const index = rule.match(sc);
            if (index === null) continue;
            // In tests/fixtures/bundled deps, only unambiguous findings are worth the noise.
            if (lowTrust && rule.severity !== "critical" && rule.severity !== "high") continue;
            hits.push({ rule, index });
            for (const id of rule.supersedes ?? []) superseded.add(id);
        }

        for (const { rule, index } of hits) {
            if (superseded.has(rule.id)) continue;
            const evidence = extractEvidence(content, index);
            if (evidence.line !== undefined) {
                const key = `${file}:${evidence.line}`;
                if (seenLines.has(key)) continue;
                seenLines.add(key);
            }
            seenPatterns.add(rule.id);
            const { severity, confidence } = contextAdjust(rule, ctx);
            findings.push({
                package: pkg.name,
                version: pkg.version,
                hook: file.replace("package/", ""),
                pattern: rule.pattern,
                snippet: evidence.snippet,
                line: evidence.line,
                severity,
                confidence,
            });
        }
    }
    return findings;
}

function classify(file: string): "source" | "shell" | null {
    if (SOURCE_EXTENSIONS.some(ext => file.endsWith(ext))) return "source";
    if (SHELL_EXTENSIONS.some(ext => file.endsWith(ext))) return "shell";
    return null;
}

function rank(file: string, refs: string[]): number {
    if (isInstallReachable(file, refs)) return 0;
    if (LOW_TRUST_PATH.test(file) || LOW_TRUST_FILE.test(file)) return 2;
    return 1;
}
