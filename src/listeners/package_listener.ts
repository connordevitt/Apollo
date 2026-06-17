// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import { analyzePackage } from "../detection/detector.js";
import { diffInstallScripts, findPreviousVersion } from "../detection/diffs.js";
import { scorePackage } from "../detection/score.js";

const HEARTBEAT_INTERVAL = 100;
let scannedCount = 0;

export async function listenToChanges() {
    console.log("Starting package listener...");
    
   
    const initResponse = await fetch("https://replicate.npmjs.com/");
    if (!initResponse.ok) {
        throw new Error(`Failed to get initial seq: ${initResponse.status}`);
    }
    const initData = await initResponse.json() as { update_seq: number };
    
    const currentSeq = initData.update_seq;
    let since = String(Math.max(0, currentSeq - 500));
    
    console.log(`Watching from seq: ${since} (current: ${currentSeq})`);
    
    while (true) {
        try {
            const response = await fetch(
                `https://replicate.npmjs.com/registry/_changes?since=${since}&limit=100`
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
            since = String(data.last_seq);
            if (data.results.length === 0) {
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
        const pkgResponse = await fetch(`https://registry.npmjs.org/${encodedName}`);
        if (!pkgResponse.ok) {
            // 404 = deleted/unpublished package; anything else worth surfacing
            if (pkgResponse.status !== 404) {
                console.warn(`${pkgResponse.status} on ${change.id}`);
            }
            return;
        }

        const pkg = await pkgResponse.json() as {
            name: string;
            "dist-tags"?: { latest?: string };
            versions?: Record<string, {
                scripts?: Record<string, string>;
                dependencies?: Record<string, string>;
            }>;
                time?: Record<string, string>;
        };

        const latest = pkg["dist-tags"]?.latest;
        if (latest && pkg.versions?.[latest]) {
            const versionData = pkg.versions[latest];
            const dependencies = Object.keys(versionData?.dependencies || {});

            const staticFindings = analyzePackage({
                name: pkg.name,
                version: latest,
                scripts: versionData?.scripts ?? {},
                dependencies,
            });

            const previous = findPreviousVersion(pkg.versions, pkg.time ?? {}, latest);
            const diffFindings = previous
                ? diffInstallScripts(
                    pkg.versions[previous]?.scripts ?? {},
                    versionData.scripts ?? {},
                )
                : [];

            const findings = [...staticFindings, ...diffFindings];

            scannedCount++;
            if (scannedCount % HEARTBEAT_INTERVAL === 0) {
                console.log(`[heartbeat] scanned ${scannedCount} packages`);
            }

            const scoreResult = scorePackage(findings);
            if (scoreResult.verdict !== 'quiet') {
                console.log(`\n  SUSPICIOUS: ${pkg.name}@${latest}`);
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
