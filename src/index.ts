#!/usr/bin/env node
// Copyright (C) 2026 Connor Devitt. Licensed under AGPL-3.0-only.
import { listenToChanges } from "./listeners/package_listener.js";

const helloWorld = () => {
    console.log("Hello World Apollo has arrived!");
}

helloWorld();
listenToChanges().catch(error => {
    console.error("Apollo had a fatal error on startup:", error);
    process.exit(1);
})