// cursor.ts to remember the spot we left off in a scan for index.ts

import { node:fs, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
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

const loadCursor = (): number => {
    if (!existsSync(CURSOR_FILE)) {
        return 0;
    }
    try {
        const data = readFileSync(CURSOR_FILE, "utf8");
        return JSON.parse(data).cursor;
    } catch (error) {
        console.error("Failed to load cursor:", error);
        return 0;
    }
};

export { saveCursor, loadCursor };