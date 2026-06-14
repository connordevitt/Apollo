export interface PackageInfo {
    name: string;
    version: string;
    scripts: Record<string, string>;
    dependencies: string[];
}

export interface Finding {
    hook: string;
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


export type Severity = "low" | "medium" | "high" | "critical";

export type Confidence = "low" | "medium" | "high";