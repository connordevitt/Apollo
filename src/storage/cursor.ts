// cursor.ts to remember the spot we left off in a scan for index.ts

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";

const CURSOR_FILE = "cursor.json";
const saveCursor = (cursor: number): void => {
    if (!existsSync(CURSOR_FILE)) {
        mkdirSync(path.dirname(CURSOR_FILE), { recursive: true });
    }
    try {
        writeFileSync(CURSOR_FILE, JSON.stringify({ cursor }, null, 2));
    } catch (error) {
        console.error("Failed to save cursor:", error);
    }
};

// null = no usable saved cursor (missing, corrupt, or not a number);
// callers decide the fallback — returning 0 here would mean "start of npm history"
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

export { saveCursor, loadCursor };