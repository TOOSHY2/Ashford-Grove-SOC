# AGC-052 -- DNS Beacon (High-Entropy Subdomains)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-052` |
| Category | `08-command-control` -- Command & Control |
| MITRE Technique | `T1071.004` Application Layer Protocol: DNS |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | DNS log analysis -- high volume of distinct subdomains under one base domain, queried by a single host, directed at a specific authoritative server |
| Time to Triage | 05:00 (assess subdomain entropy; verify destination is not a legitimate dynamic-subdomain service like CDN or DDNS) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as beacon source; `EXT-ATTACKER-SIM` (10.10.40.10) as C2 DNS server |
| Chain | < AGC-051 . next AGC-053 > |
| One-line Summary | DNS beacon from COMPROMISED-HOST-01 to attacker-controlled DNS server at 10.10.40.10. 10 TXT queries with unique high-entropy random subdomains under `agc052lab.local` (e.g., `1549336820-beacon.agc052lab.local`). All resolved to 10.10.40.10 (wildcard A record). 10 Sysmon EID 22 DNS Query events captured. The subdomain uniqueness (10/10 distinct) combined with numeric-random entropy is the key detection signal -- no legitimate application generates this pattern. |

## Attacker Perspective

### Tradecraft

**What:** DNS beaconing uses the DNS protocol as a covert C2 channel. Instead of connecting directly to a C2 server over HTTPS, the attacker encodes commands and data into DNS queries and responses:
1. **Outbound data:** Encoded into subdomain labels (e.g., `<base64-encoded-data>.c2domain.com`)
2. **Inbound commands:** Encoded into DNS response records (TXT, CNAME, A records)
3. **Each query uses a unique subdomain:** DNS resolvers cache responses -- same subdomain would return cached answer without reaching the attacker's server

**Why DNS is harder to block than HTTPS:**
- DNS is required for virtually all network operations -- blocking it breaks everything
- DNS queries often traverse the firewall to external resolvers without inspection
- DNS traffic volume is high, making individual malicious queries hard to spot

**Why subdomain uniqueness is the key signal:** The distinguishing characteristic of DNS C2 is NOT the number of queries but the number of UNIQUE subdomains under a single base domain. Legitimate services reuse the same hostnames; DNS C2 generates a unique subdomain for every query because each carries different encoded data.

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

**Sysmon EID 22 -- DNS Query (10 events, one per beacon cycle):**

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
5. **QueryStatus: 0:** Successful resolution -- the C2 DNS server is responding

### Investigation

**Step 1 -- Quantify subdomain cardinality:**
For each base domain queried by the host, count the number of UNIQUE subdomains within a time window:
- Extract base domain from QueryName (strip the leftmost label)
- Count distinct leftmost labels per base domain per source host
- Threshold: 5+ unique subdomains under one base domain within 1 hour

In this case: 10 unique subdomains under `agc052lab.local` in ~2.5 minutes.

**Step 2 -- Assess subdomain entropy:**
Calculate Shannon entropy of the subdomain labels:
- `1549336820-beacon` -- numeric prefix with fixed suffix, high entropy for the numeric portion
- Compare against known patterns: CDN hashes (hex), load-balancer IDs, human-readable hostnames

**Step 3 -- Check destination legitimacy:**
- `agc052lab.local` is not in the organization's approved domain list
- `.local` TLD is typically internal mDNS, not authoritative DNS
- Queries directed to specific external server (10.10.40.10), bypassing organizational DNS resolver

**Step 4 -- Correlate with other C2 indicators:**
Cross-reference with AGC-051 (HTTPS beacon to same destination 10.10.40.10):
- Both scenarios show C2 communication to the same external IP
- Dual-channel C2: HTTPS + DNS -- if one is blocked, the other continues

### Report

**Verdict: True Positive** -- DNS-based C2 beaconing using high-entropy unique subdomains.

**Confidence: High** -- Calibrated assessment:
1. 10 unique subdomains under one base domain in 2.5 minutes -- no legitimate application generates this cardinality.
2. Subdomain labels are numeric-random -- consistent with algorithmic C2 encoding.
3. Queries directed to specific external server (10.10.40.10), bypassing organizational DNS.
4. `agc052lab.local` is not a known legitimate domain.
5. Same destination as HTTPS beacon (AGC-051) -- confirms dual-channel C2 infrastructure.

**Response recommendation:**
1. **Block the C2 domain** at DNS resolver level -- sinkhole `agc052lab.local`. Block 10.10.40.10 at firewall.
2. **Isolate the beaconing host** -- active remote control via DNS channel.
3. **Deploy DNS entropy alerting:** Monitor for base domains with high subdomain cardinality + high entropy.
4. **Note on blocking difficulty:** DNS C2 is harder to fully block than HTTPS C2 -- attacker can register a new domain and re-encode the beacon. Best defense is entropy-based detection at the DNS resolver.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Command and Control (TA0011) | T1071.004 | Application Layer Protocol: DNS | 10 Sysmon EID 22: unique high-entropy subdomains under `agc052lab.local` queried to 10.10.40.10. All resolved (wildcard A). powershell.exe PID 5492. 100% subdomain uniqueness. | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

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
