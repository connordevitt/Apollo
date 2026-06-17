# Apollo

Apollo watches the npm registry for malicious packages. It listens to the npm change feed in real time, runs each new publish through a set of detection rules, and scores it for suspicious behavior — things like curl/wget in install hooks, piping to shell, newly added postinstall scripts, or changes to existing ones.

It's early. The detection is basic right now but the foundation is there.

## How it works

1. Connects to the npm CouchDB change feed
2. Fetches full package metadata for each new publish
3. Runs static analysis on install scripts (`preinstall`, `install`, `postinstall`)
4. Diffs the current version's scripts against the previous version
5. Scores the findings and flags anything above a threshold

## Running it

```bash
npm install
npm run dev
```

Output looks like this:

```
Watching from seq: 115259798 (current: 115260298)
[heartbeat] scanned 100 packages

  SUSPICIOUS: rea1ity-tool@1.0.5
   [postinstall] matched "curl"
     curl --connect-timeout 5 -i -k 10.100.52.96:8443/api >> good 2>&1

  SCORE: 7.8 (alert)
```

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).
