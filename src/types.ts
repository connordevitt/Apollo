// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
export interface PackageInfo {
    name: string;
    version: string;
    scripts: Record<string, string>;
    dependencies: string[];
}

export interface Finding {
    package: string;
    version: string;
    hook: string;
    score?: number;
    pattern: string;
    snippet: string;
    severity: Severity;
    confidence: Confidence;
}


export interface Rule {
    id: string;
    pattern: string;
    severity: Severity;
    confidence: Confidence;
    test: (script: string) => boolean;
}


export interface PackageScore {
    score: number;
    verdict: Verdict;
    findings: Finding[];
}


export interface PackageRecord { 
    package: string;
    version: string;
    score: number;
    verdict: Verdict;
}

export type Severity = "low" | "medium" | "high" | "critical";

export type Confidence = "low" | "medium" | "high";

export type Verdict = "quiet" | "watch" | "alert";