// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.

import { createWriteStream } from "fs";
import { pino, type Logger } from "pino";

interface LoggerOptions {
    level?: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
    name?: string;
    output?: "console" | "file";
    file?: string;
    timestamp?: boolean;
}

export function createLogger(options: LoggerOptions = {}): Logger {
    const {
        level = "info",
        name = "Apollo",
        output = "console",
        file = "apollo.log",
    } = options;

    const stream = output === "file"
        ? createWriteStream(file, { flags: "a" })
        : process.stdout;

    return pino({
        level,
        name,
        formatters: { level(label: string) { return { level: label }; } },
        timestamp: pino.stdTimeFunctions.isoTime,
    }, stream);
}

export const logger = createLogger();