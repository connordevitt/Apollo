# Apollo

Apollo watches the npm registry for malicious packages. It polls the npm change feed, runs each new publish through a set of detection rules, and scores it for suspicious behavior. Examples of suspicious behavior include curl/wget in install hooks, piping to shell, newly added postinstall scripts, or changes to existing ones.

It's early. The detection is basic right now but the foundation is there.

## How it works

1. Gets the current `update_seq` from the npm CouchDB registry, then starts ~500 changes back
2. Polls the `_changes` feed in batches (`since`/`limit=100`), sleeping 5s when there's nothing new
3. Fetches full package metadata for each changed package with 8 workers. Watermark is used to track the last completed sequence number.
4. Runs static analysis on install scripts (`preinstall`, `install`, `postinstall`)
5. Diffs the current version's scripts against the previous version
6. Scores the findings and flags anything above a threshold

## Running it

```bash
npm ci
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

## Storage: 

Findings are stored in `findings.jsonl`. It's a newline-delimited JSON file.

```json
{
  "hook": "package/dist/index.js",
  "pattern": "full process.env dump",
  "snippet": "console.log(process.env);"
  "severity": "critical",
  "confidence": "high"
}
```

Cursor is used to store the sequence last seen and pick up where it left off.

```json
{
  "sequence": 115260298
}
```

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).
