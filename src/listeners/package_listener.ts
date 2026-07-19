// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import { analyzePackage, analyzeSourceFiles } from "../detection/detector.js";
import { diffInstallScripts, findPreviousVersion } from "../detection/diffs.js";
import { scorePackage } from "../detection/score.js";
import { fetchTarballFiles } from "./tarball.js";
import type { Finding } from "../types.js";
import { loadCursor, saveCursor } from "../storage/cursor.js";
import { saveFindings } from "../storage/findings.js";
import { savePackages } from "../storage/package.js";

const FETCH_TIMEOUT_MS = 30_000;

const HEARTBEAT_INTERVAL = 100;
// skip tarballs whose unpacked size exceeds this, nobody feeds us a 500 MB blob
const MAX_TARBALL_UNPACKED_BYTES = 10_000_000; 
let scannedCount = 0;

interface RegistryChange {
    id: string;
    seq: number;
}
let rewindTarget: number | null = null;     
let watermark = 0;
const pending: number[] = [];
const completed = new Set<number>();

const seenVersions = new Map<string, Set<string>>();
async function* produceChanges(cursor: number): AsyncGenerator<RegistryChange, never, void> {
    while (true) {
        try {
             const response = await fetch(
            `https://replicate.npmjs.com/registry/_changes?since=${cursor}&limit=100`
            , { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)}
        );

        if (!response.ok) {
            console.log(`failed http request. Error: ${response.status}`);
            await sleep(5000);
            continue;
        }
        const data = await response.json() as {
            results: RegistryChange[];
            last_seq: number;
        };

        if (data.results.length === 0) {
            console.log("No new changes were found. To sleep we go...")
            await sleep(5000);
        }
        for (const res of data.results) {
            markDispatched(res.seq);
            yield res;
        }

        cursor = data.last_seq;
        } catch (err) {
            console.error(`Error polling changes feed:`, (err as Error).message);
            await sleep(5000);
        }
    } 
}

function markDispatched(seq: number): void {
    pending.push(seq);
}

function markCompleted(seq: number): void {
    const before = watermark;
    completed.add(seq);
    while (pending.length > 0 && completed.has(pending[0]!)) {
        const done = pending.shift()!;
        completed.delete(done);
        watermark = done;
    }

    if (watermark !== before) {
        saveCursor(watermark);
        if (rewindTarget !== null && watermark >= rewindTarget) {
            console.log(`[catch-up] replayed the 500-seq rewind overlap (passed ${rewindTarget})`);
            rewindTarget = null;
        }
    }
}

async function worker(results: AsyncGenerator<RegistryChange>): Promise<void> {
    for await (const res of results) {
        await processChange(res);
        markCompleted(res.seq);
    }
}

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
    rewindTarget = saved;
    let cursor = saved === null ? currentSeq : Math.max(0, saved - 500);
    watermark = cursor;

    console.log(`Watching from seq: ${cursor} (current: ${currentSeq})`);

    const changes = produceChanges(cursor);
    const CONCURRENCY = 8;
    const workers = Array.from({ length: CONCURRENCY}, () => worker(changes))
    await Promise.all(workers);
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

        // mark everything analyzed & skipped
        seenVersions.set(pkg.name, new Set(allVersions));

        if (toAnalyze.length === 0) return;

        for (const version of toAnalyze) {
            const versionData = pkg.versions?.[version];
            if (!versionData) continue;
            const dependencies = Object.keys(versionData.dependencies || {});

            const pkgInfo = {
                name: pkg.name,
                version,
                scripts: versionData.scripts ?? {},
                dependencies,
            };

            const staticFindings = analyzePackage(pkgInfo);

            const previous = findPreviousVersion(pkg.versions ?? {}, pkg.time ?? {}, version);
            const diffFindings = previous
                ? diffInstallScripts(
                    pkgInfo,
                    pkg.versions?.[previous]?.scripts ?? {},
                    versionData.scripts ?? {},
                )
                : [];

            
            let sourceFindings: Finding[] = [];
            const dist = versionData.dist;
            if (dist?.tarball && (dist.unpackedSize ?? 0) <= MAX_TARBALL_UNPACKED_BYTES) {
                try {
                    const files = await fetchTarballFiles(dist.tarball);
                    sourceFindings = analyzeSourceFiles(pkgInfo, files);
                } catch (err) {
                    console.warn(`tarball scan failed for ${pkg.name}@${version}:`, (err as Error).message);
                }
            }

            const findings = [...staticFindings, ...diffFindings, ...sourceFindings];

            scannedCount++;
            if (scannedCount % HEARTBEAT_INTERVAL === 0) {
                console.log(`[heartbeat] scanned ${scannedCount} versions (watermark: ${watermark})`);
            }

            const scoreResult = scorePackage(findings);
            if (scoreResult.verdict !== 'quiet') {
                console.log(`\n  SUSPICIOUS: ${pkg.name}@${version}{${pkg.time?.["modified"]}}`);
                for (const finding of scoreResult.findings) {
                    console.log(
                        ` [${finding.hook}${finding.line != null ? `:${finding.line}` : ""}] matched "${finding.pattern}"`
                    );
                    console.log(`     ${finding.snippet}`);
                }
                console.log(`\n  SCORE: ${scoreResult.score} (${scoreResult.verdict})`);
            } 
            if (scoreResult.score >= 7) {
                saveFindings(findings);
                savePackages([{
                    package: pkg.name,
                    version,
                    score: scoreResult.score,
                    verdict: scoreResult.verdict,
                }]);
            }
        }
    } catch (err) {
        console.warn(`Failed to process ${change.id}:`, (err as Error).message);
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
