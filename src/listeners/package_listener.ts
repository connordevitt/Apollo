// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import { analyzePackage, analyzeSourceFiles } from "../detection/detector.js";
import { diffInstallScripts, findPreviousVersion } from "../detection/diffs.js";
import { scorePackage } from "../detection/score.js";
import { fetchTarballFiles } from "./tarball.js";
import type { Finding } from "../types.js";
import { loadCursor, saveCursor } from "../storage/cursor.js";

const FETCH_TIMEOUT_MS = 30_000;

const HEARTBEAT_INTERVAL = 100;
// skip tarballs whose unpacked size exceeds this — nobody feeds us a 500 MB blob
const MAX_TARBALL_UNPACKED_BYTES = 10_000_000; // 10 MB
let scannedCount = 0;


const seenVersions = new Map<string, Set<string>>();

export async function listenToChanges() {
    console.log("Starting package listener...");
    const initResponse = await fetch("https://replicate.npmjs.com/", { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)});
    if (!initResponse.ok) {
        throw new Error(`Failed to get initial seq: ${initResponse.status}`);
    }
    const initData = await initResponse.json() as { update_seq: number };
    const currentSeq: number = initData.update_seq;

    // fresh machine: start at the live head; resume: rewind 500 seqs for overlap
    const saved = loadCursor();
    let cursor = saved === null ? currentSeq : Math.max(0, saved - 500);

    console.log(`Watching from seq: ${cursor} (current: ${currentSeq})`);
    
    while (true) {
        try {
            const response = await fetch(
                `https://replicate.npmjs.com/registry/_changes?since=${cursor}&limit=100`
                , { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)}
            );

            if (!response.ok) {
                console.log(`failed HTTP request. Error: ${response.status}`);
                await sleep(5000);
                continue;
            }

            const data = await response.json() as {
                results: { id: string; seq: number }[];
                last_seq: number;
            };

            const CONCURRENCY = 8;
            for (let i = 0; i < data.results.length; i += CONCURRENCY) {
                const batch = data.results.slice(i, i + CONCURRENCY);
                await Promise.all(batch.map(processChange));
            }
            cursor = data.last_seq;
            saveCursor(cursor);
            if (data.results.length === 0) {
                console.log("No new changes found, sleeping for 5 seconds");
                await sleep(5000);
            }
        } catch (err) {
            console.error(`Error polling changes feed:`, (err as Error).message);
            await sleep(5000);
        }
    }
}

async function processChange(change: { id: string }): Promise<void> {
    if (change.id.startsWith("_design")) return;

    try {
        const encodedName = change.id.replace("/", "%2F");
        const pkgResponse = await fetch(`https://registry.npmjs.org/${encodedName}`
            , { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)}
        );
        
        if (!pkgResponse.ok) {
            // 404 = deleted/unpublished package; anything else worth surfacing
            if (pkgResponse.status !== 404) {
                console.warn(`${pkgResponse.status} on ${change.id}`);
            }
            return;
        }

        const pkg = await pkgResponse.json() as {
            name: string;
            "dist-tags"?: Record<string, string>;
            versions?: Record<string, {
                scripts?: Record<string, string>;
                dependencies?: Record<string, string>;
                dist?: { tarball: string; unpackedSize?: number };
            }>;
            time?: Record<string, string>;
        };

        const distTags = pkg["dist-tags"] ?? {};
        const seen = seenVersions.get(pkg.name);
        const allVersions = Object.keys(pkg.versions ?? {});

        // first sight: analyze dist-tag targets only; later: any version we haven't seen yet
        const toAnalyze = seen
            ? allVersions.filter(v => !seen.has(v))
            : Object.values(distTags).filter(v => allVersions.includes(v));

        // mark everything (analyzed + skipped) as seen, before the early return
        seenVersions.set(pkg.name, new Set(allVersions));

        if (toAnalyze.length === 0) return;

        for (const version of toAnalyze) {
            const versionData = pkg.versions?.[version];
            if (!versionData) continue;
            const dependencies = Object.keys(versionData.dependencies || {});

            const staticFindings = analyzePackage({
                name: pkg.name,
                version,
                scripts: versionData.scripts ?? {},
                dependencies,
            });

            const previous = findPreviousVersion(pkg.versions ?? {}, pkg.time ?? {}, version);
            const diffFindings = previous
                ? diffInstallScripts(
                    pkg.versions?.[previous]?.scripts ?? {},
                    versionData.scripts ?? {},
                )
                : [];

            // own try/catch: a dead tarball degrades to manifest-only scan, never skips the package
            let sourceFindings: Finding[] = [];
            const dist = versionData.dist;
            if (dist?.tarball && (dist.unpackedSize ?? 0) <= MAX_TARBALL_UNPACKED_BYTES) {
                try {
                    const files = await fetchTarballFiles(dist.tarball);
                    sourceFindings = analyzeSourceFiles(files);
                } catch (err) {
                    console.warn(`tarball scan failed for ${pkg.name}@${version}:`, (err as Error).message);
                }
            }

            const findings = [...staticFindings, ...diffFindings, ...sourceFindings];

            scannedCount++;
            if (scannedCount % HEARTBEAT_INTERVAL === 0) {
                console.log(`[heartbeat] scanned ${scannedCount} versions`);
            }

            const scoreResult = scorePackage(findings);
            if (scoreResult.verdict !== 'quiet') {
                console.log(`\n  SUSPICIOUS: ${pkg.name}@${version}`);
                for (const finding of scoreResult.findings) {
                    console.log(`   [${finding.hook}] matched "${finding.pattern}"`);
                    console.log(`     ${finding.snippet}`);
                }
                console.log(`\n  SCORE: ${scoreResult.score} (${scoreResult.verdict})`);
            }
        }
    } catch (err) {
        console.warn(`Failed to process ${change.id}:`, (err as Error).message);
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
