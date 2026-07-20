// cursor.ts to remember the spot we left off in a scan for index.ts

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { logger } from "../logger.js";

const CURSOR_FILE = "cursor.json";
const MAX_ATTEMPTS = 5;

function sleepSync(ms: number): void {
    const end = Date.now() + ms;
    while (Date.now() < end) {
    }
}

const saveCursor = (cursor: number): void => {
    const payload = JSON.stringify({ cursor }, null, 2);

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        try {
            // Direct write is more reliable on Windows than temp+rename under load.
            writeFileSync(CURSOR_FILE, payload);
            if (attempt === 1) {
                console.log(`Cursor saved successfully: ${cursor}`);
            } else {
                console.log(`Cursor saved successfully: ${cursor} (attempt ${attempt})`);
            }
            return;
        } catch (error) {
            const code = (error as NodeJS.ErrnoException).code;
            if ((code === "EPERM" || code === "EBUSY") && attempt < MAX_ATTEMPTS) {
                sleepSync(20 * attempt);
                continue;
            }
            logger.error({ err: error, cursor }, "Failed to save cursor");
            return;
        }
    }
};
 
// null = no usable saved cursor (missing, corrupt, or not a number);
// callers decide the fallback, returning 0 here would mean "start of npm history"
const loadCursor = (): number | null => {
    if (!existsSync(CURSOR_FILE)) {
        return null;
    }
    try {
        const data = readFileSync(CURSOR_FILE, "utf8");
        const cursor = JSON.parse(data).cursor;
        return typeof cursor === "number" ? cursor : null;
    } catch (error) {
        console.error("Failed to load cursor:", error);
        return null;
    }
};




export { saveCursor, loadCursor};
