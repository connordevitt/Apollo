import type { PackageInfo, Finding } from "../types.js";

export function analyzePackage(pkg: PackageInfo): Finding[] {
    const findings: Finding[] = [];

    const installHooks = ["preinstall", "install", "postinstall"];

    for (const hook of installHooks) {
        const script = pkg.scripts[hook];
        if (!script) continue;

        if (script.includes("curl")) {
            findings.push({
                hook,
                pattern: "curl",
                snippet: script
            });
        }
    }
    return findings;
}

