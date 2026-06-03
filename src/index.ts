#!/usr/bin/env node
import { listenToChanges } from "./listeners/package_listener.js";

const helloWorld = () => {
    console.log("Hello World Apollo has arrived!");
}

helloWorld();
listenToChanges();