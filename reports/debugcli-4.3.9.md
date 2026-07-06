# Malware Triage Report: `debugcli@4.3.9`

- **Status:** Suspected malicious.
- **Date:** 2026-07-05
- **Source:** Apollo scanner (`findings.jsonl`), corroborated with npm registry metadata only (no tarball downloaded or executed)
- **Verdict:** Suspected supply-chain attack — combosquat/brand impersonation of `debug` (name + `-cli`) delivering a credential-accessing `postinstall` hook. Flagged by Socket; not yet confirmed by source review.

## Summary

`debugcli` presents itself as "A tiny, fast debugging utility". The real `debug` package's tagline nearly verbatim, while shipping a 12.6KB `install.js` that runs
automatically on install via a `postinstall` hook. Apollo flagged that file for
both a full `process.env` dump and a `~/.npmrc` read. Combined with its imports
(`https`, `crypto`, `zlib`, `os`), this matches the standard profile of an
npm-token/CI-secret exfiltration payload, not a debugging library.

## Package details


| Field            | Value                                                                           |
| ---------------- | ------------------------------------------------------------------------------- |
| Package          | `debugcli`                                                                      |
| Flagged version  | `4.3.9` (latest)                                                                |
| First published  | 2026-07-03                                                                      |
| Versions         | 5 (`4.3.4`–`4.3.9`) in ~2 days                                                  |
| Maintainer       | `romanspon` [spontanat@gmail.com](mailto:spontanat@gmail.com) (sole maintainer) |
| Weekly downloads | ~535                                                                            |
| Repository       | None linked                                                                     |
| README           | None                                                                            |
| Files            | 3 — `index.js` (35 B stub), `install.js` (12.6 KB), `package.json`              |
| Install hook     | `"postinstall": "node install.js"`                                              |
| Dependency       | `debug@^4.3.4` (likely camouflage)                                              |




## Indicators of compromise / suspicion

1. **Auto-executing installer.** `postinstall` runs `install.js` on every
  `npm install`, including transitive installs.
2. **Credential access.** Apollo pattern hits in `install.js`:
  - `full process.env dump` (severity: critical, confidence: high) harvests  CI secrets, API keys, tokens from the environment.
  - `.npmrc read` (severity: high, confidence: medium) the classic npm auth-token theft signature.
3. **Exfiltration-shaped imports.** `https`, `crypto`, `zlib`, `os`, `path`, `fs`
  in a package whose stated purpose needs none of them.
4. **Impersonation.** Description copied from `debug`; depends on `debug`;
  version numbers (`4.3.x`) mimic `debug`'s real version range. Notably,
   `debug` itself was compromised in Sept 2025 (CVE-2025-59144), giving the
   name recognition/phishing value.
5. **Empty facade.** The actual module (`index.js`) is 35 bytes — the package
  has no real functionality; the installer is the product.
6. **Fresh account behavior.** Brand-new package, rapid-fire versions, no repo,
  no README, single maintainer.
7. **No existing advisory.** No GHSA/OSV/NVD entry or public report found for
  `debugcli` as of this writing it appears unreported.



## What was NOT done

- The tarball was not downloaded, extracted, or executed.
- `install.js` contents beyond Apollo's captured snippet were not reviewed.  
Full payload confirmation should happen only in an isolated sandbox  
(throwaway VM/container, no credentials or tokens mounted).

