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
}
