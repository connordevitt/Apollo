// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import { extract } from "tar-stream";
import { gunzipSync } from "node:zlib";

// Skip files bigger than this so one huge blob can't balloon memory.
const MAX_FILE_BYTES = 1_000_000; // 1 MB


export async function fetchTarballFiles(tarballUrl: string): Promise<Map<string, string>> {
    const res = await fetch(tarballUrl);
    if (!res.ok) throw new Error(`tarball download failed: ${res.status}`);
    const gzippedBytes = Buffer.from(await res.arrayBuffer()); 
    const tarBytes = gunzipSync(gzippedBytes);

    const files = new Map<string, string>();
    const untar = extract();

    untar.on("entry", (header, stream, next) => {
        const isFile = header.type === "file";
        const tooBig = (header.size ?? 0) > MAX_FILE_BYTES;

        if (!isFile || tooBig) {
            stream.on("end", next); 
            stream.resume();
            return;
        }

        const chunks: Buffer[] = [];
        stream.on("data", (chunk: Buffer) => chunks.push(chunk));
        stream.on("end", () => {
            files.set(header.name, Buffer.concat(chunks).toString("utf8"));
            next(); // tar-stream is paused until we ask for the next entry
        });
    });

    await new Promise<void>((resolve, reject) => {
        untar.on("finish", resolve);
        untar.on("error", reject);
        untar.end(tarBytes);
    });

    return files;
}
