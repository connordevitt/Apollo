// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import type { Finding, PackageScore, Severity, Confidence } from "../types.js";

const SEVERITY_POINTS: Record<Severity, number> = {
    low: 1,
    medium: 3,
    high: 6,
    critical: 10,
};


const FACTOR: Record<Confidence, number> = {
    low: 0.3,
    medium: 0.6,
    high: 1.0,
};

export function scorePackage(findings: Finding[]): PackageScore {
     let total = 0;
     for (const f of findings) {
        total += (SEVERITY_POINTS[f.severity] ?? 0) * (FACTOR[f.confidence] ?? 0);
     }
     const verdict = total === 0 ? 'quiet' : total < 4 ? 'watch' : 'alert';
     return {
        score: total,
        verdict,
        findings,
     };
}
