export async function listenToChanges() {
    console.log("Starting package listener...");
    
    // The registry info endpoint reports the true latest sequence (update_seq).
    // NOTE: _changes?limit=1 returns the OLDEST change, not the newest, so it
    // can't be used to find the current position.
    const initResponse = await fetch("https://replicate.npmjs.com/");
    if (!initResponse.ok) {
        throw new Error(`Failed to get initial seq: ${initResponse.status}`);
    }
    const initData = await initResponse.json() as { update_seq: number };
    
    const currentSeq = initData.update_seq;
    let since = String(Math.max(0, currentSeq - 500));
    
    console.log(`Watching from seq: ${since} (current: ${currentSeq})`);
    
    while (true) {
        const response = await fetch(
            `https://replicate.npmjs.com/registry/_changes?since=${since}&limit=100`
        );

        if (!response.ok) {
            console.error(`HTTP error: ${response.status}`);
            await sleep(5000);
            continue;
        }

        const data = await response.json() as { 
            results: { id: string; seq: string }[]; 
            last_seq: string 
        };
        
        for (const change of data.results) {
            if (change.id.startsWith("_design")) continue;
            
            const encodedName = change.id.replace("/", "%2F");
            const pkgResponse = await fetch(`https://registry.npmjs.org/${encodedName}`);
            if (!pkgResponse.ok) continue;

            const pkg = await pkgResponse.json() as {
                name: string;
                "dist-tags"?: { latest?: string };
                versions?: Record<string, {
                    scripts?: Record<string, string>;
                    dependencies?: Record<string, string>;
                }>;
            };
            
            const latest = pkg["dist-tags"]?.latest;
            if (latest && pkg.versions?.[latest]) {
                const versionData = pkg.versions[latest];

                const dependencies = Object.keys(versionData?.dependencies || {});
                // TODO: Pass to detection module pkg name, version, script, dependencies, etc
                console.log(JSON.stringify({
                    name: pkg.name,
                    version: latest,
                    scripts: versionData.scripts ?? {},
                    dependencies
                }, null, 2));

            }
        }
        
        since = data.last_seq;
        
        if (data.results.length === 0) {
            await sleep(5000);
        }
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
