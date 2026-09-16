# AGC-052 — DNS Beacon (High-Entropy Subdomains)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-052` |
| Category | `08-command-control` — Command & Control |
| MITRE Technique | `T1071.004` Application Layer Protocol: DNS |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | DNS log analysis — high volume of distinct subdomains under one base domain, queried by a single host, directed at a specific authoritative server |
| Time to Triage | 05:00 (assess subdomain entropy; verify destination is not a legitimate dynamic-subdomain service like CDN or DDNS) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as beacon source; `EXT-ATTACKER-SIM` (10.10.40.10) as C2 DNS server |
| Chain | ◀ [AGC-051](../AGC-051-https-beacon/README.md) · next [AGC-053](../AGC-053-uncommon-port-c2/README.md) ▶ |
| One-line Summary | DNS beacon from COMPROMISED-HOST-01 to attacker-controlled DNS server at 10.10.40.10. 10 TXT queries with unique high-entropy random subdomains under `agc052lab.local` (e.g., `1549336820-beacon.agc052lab.local`). All resolved to 10.10.40.10 (wildcard A record). 10 Sysmon EID 22 DNS Query events captured. The subdomain uniqueness (10/10 distinct) combined with numeric-random entropy is the key detection signal — no legitimate application generates this pattern. |

## Attacker Perspective

### Tradecraft

**What:** The attacker runs C2 over DNS instead of a direct HTTPS session, packing data into queries and commands into responses:
1. **Outbound data:** Encoded into subdomain labels (e.g., `<base64-encoded-data>.c2domain.com`)
2. **Inbound commands:** Encoded into DNS response records (TXT, CNAME, A records)
3. **Each query uses a unique subdomain:** Resolvers cache answers, so a repeated subdomain would be served from cache and never reach the attacker's server

**Why DNS is harder to block than HTTPS:**
- Nearly everything on the network needs DNS, so nobody blocks it outright
- Queries often leave the perimeter to external resolvers with no inspection
- Query volume is high, so one malicious lookup hides in the noise

**Why subdomain uniqueness is the key signal:** What gives DNS C2 away is not query count but the number of distinct subdomains under one base domain. Legitimate services reuse the same hostnames; DNS C2 mints a new subdomain per query because each one carries different encoded data.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `EXT-ATTACKER-SIM` (10.10.40.10) running a DNS server (responding with wildcard A record).

**DNS query timeline (all timestamps UTC):**

| Query | Timestamp | Subdomain | Response |
|---|---|---|---|
| 1 | 21:51:23.370 | 1549336820-beacon | A: 10.10.40.10 |
| 2 | 21:51:38.852 | 342146600-beacon | A: 10.10.40.10 |
| 3 | 21:51:53.875 | 411229632-beacon | A: 10.10.40.10 |
| 4 | 21:52:08.897 | 1930557100-beacon | A: 10.10.40.10 |
| 5 | 21:52:23.922 | 1880935480-beacon | A: 10.10.40.10 |
| 6 | 21:52:38.947 | 1596787465-beacon | A: 10.10.40.10 |
| 7 | 21:52:53.966 | 521848668-beacon | A: 10.10.40.10 |
| 8 | 21:53:08.991 | 1597286771-beacon | A: 10.10.40.10 |
| 9 | 21:53:24.017 | 131276789-beacon | A: 10.10.40.10 |
| 10 | 21:53:39.055 | 1160479175-beacon | A: 10.10.40.10 |

**Uniqueness:** 10/10 subdomains are distinct (100% unique).

## SOC Perspective

### Detection

**Sysmon EID 22 — DNS Query (10 events, one per beacon cycle):**

**Representative event (Query 1):**
```
Dns query:
UtcTime: 2026-09-15 21:51:23.832
ProcessGuid: {eb65e329-bdda-6aa9-2d04-000000001400}
ProcessId: 5492
QueryName: 1549336820-beacon.agc052lab.local
QueryStatus: 0
QueryResults: 10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

**Representative event (Query 10):**
```
Dns query:
UtcTime: 2026-09-15 21:53:39.068
ProcessId: 5492
QueryName: 1160479175-beacon.agc052lab.local
QueryStatus: 0
QueryResults: 10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

**Detection indicators:**
1. **Subdomain uniqueness:** 10 queries, 10 distinct subdomains under `agc052lab.local`
2. **High-entropy subdomain labels:** Numeric random strings (e.g., `1549336820`) are not human-readable hostnames
3. **Single authoritative server:** All queries directed to 10.10.40.10
4. **Same process:** All from PID 5492 (powershell.exe)
5. **QueryStatus: 0:** Resolution succeeded — the C2 DNS server is answering

### Investigation

**Step 1 — Quantify subdomain cardinality:**
For each base domain the host queries, count distinct subdomains within a time window:
- Extract base domain from QueryName (strip the leftmost label)
- Count distinct leftmost labels per base domain per source host
- Threshold: 5+ unique subdomains under one base domain within 1 hour

Here: 10 unique subdomains under `agc052lab.local` in ~2.5 minutes.

**Step 2 — Assess subdomain entropy:**
Calculate Shannon entropy of the subdomain labels:
- `1549336820-beacon` — numeric prefix with fixed suffix, high entropy for the numeric portion
- Compare against known patterns: CDN hashes (hex), load-balancer IDs, human-readable hostnames

**Step 3 — Check destination legitimacy:**
- `agc052lab.local` is not in the organization's approved domain list
- `.local` TLD is typically internal mDNS, not authoritative DNS
- Queries went straight to an external server (10.10.40.10), bypassing the organizational resolver

**Step 4 — Correlate with other C2 indicators:**
Cross-reference with AGC-051 (HTTPS beacon to same destination 10.10.40.10):
- Both channels terminate at the same external IP
- That is dual-channel C2: block HTTPS and the DNS channel keeps running

### Report

**Verdict: True Positive** — DNS-based C2 beaconing using high-entropy unique subdomains.

**Confidence: High** — on five points:
1. 10 unique subdomains under one base domain in 2.5 minutes — no legitimate application generates this cardinality.
2. Subdomain labels are numeric-random, the shape of algorithmic C2 encoding.
3. Queries went to an external server (10.10.40.10) rather than the organizational resolver.
4. `agc052lab.local` is not a known legitimate domain.
5. Same destination as the HTTPS beacon in AGC-051 — one set of infrastructure runs both channels.

**Response recommendation:**
1. **Block the C2 domain** at the resolver — sinkhole `agc052lab.local` — and block 10.10.40.10 at the firewall.
2. **Isolate the beaconing host** — COMPROMISED-HOST-01 is under remote control over the DNS channel.
3. **Deploy DNS entropy alerting:** Alert on base domains that combine high subdomain cardinality with high label entropy.
4. **Note on blocking difficulty:** DNS C2 outlives a domain block — the attacker registers a new domain and re-encodes the beacon. Entropy-based detection at the resolver holds up where a blocklist does not.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Command and Control (TA0011) | T1071.004 | Application Layer Protocol: DNS | 10 Sysmon EID 22: unique high-entropy subdomains under `agc052lab.local` queried to 10.10.40.10. All resolved (wildcard A). powershell.exe PID 5492. 100% subdomain uniqueness. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### DNS beacon summary

```
Base domain:   agc052lab.local
DNS server:    10.10.40.10 (EXT-ATTACKER-SIM)
Queries:       10
Unique subs:   10 (100%)
Duration:      ~2.5 minutes (21:51:23 to 21:53:39 UTC)
Response:      All resolved to 10.10.40.10 (wildcard A record)
```

### Subdomain list (all unique)

```
1549336820-beacon.agc052lab.local
342146600-beacon.agc052lab.local
411229632-beacon.agc052lab.local
1930557100-beacon.agc052lab.local
1880935480-beacon.agc052lab.local
1596787465-beacon.agc052lab.local
521848668-beacon.agc052lab.local
1597286771-beacon.agc052lab.local
131276789-beacon.agc052lab.local
1160479175-beacon.agc052lab.local
```

### Raw Sysmon EID 22 (Query 1)

```
Dns query:
UtcTime: 2026-09-15 21:51:23.832
ProcessId: 5492
QueryName: 1549336820-beacon.agc052lab.local
QueryStatus: 0
QueryResults: 10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

### Raw Sysmon EID 22 (Query 10)

```
Dns query:
UtcTime: 2026-09-15 21:53:39.068
ProcessId: 5492
QueryName: 1160479175-beacon.agc052lab.local
QueryStatus: 0
QueryResults: 10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```
