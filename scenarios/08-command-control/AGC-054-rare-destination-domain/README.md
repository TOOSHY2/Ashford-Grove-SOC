# AGC-054 — Rare / First-Seen Destination Domain

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-054` |
| Category | `08-command-control` — Command & Control |
| MITRE Technique | `T1071` Application Layer Protocol (domain rarity as supporting signal) |
| Verdict | True Positive (conditional) |
| Confidence | Medium (domain rarity alone); elevated to High when combined with behavioral C2 indicators from AGC-051/052/053 |
| Time to Detect | Historical DNS log comparison — query "have we ever seen this domain before" across all hosts and all available log history |
| Time to Triage | 05:00 (search DNS history for prior occurrences; check domain age/reputation if WHOIS available; correlate with other C2 indicators) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103); `EXT-ATTACKER-SIM` (10.10.40.10) as authoritative DNS |
| Chain | ◀ [AGC-053](../AGC-053-uncommon-port-c2/README.md) · next [AGC-055](../AGC-055-powershell-outbound/README.md) ▶ |
| One-line Summary | COMPROMISED-HOST-01 resolved 4 never-before-seen domains (`agc054-c2drop.xyz`, `agc054-payload-drop.net`, `agc054-exfil-relay.org`, `agc054-c2-backup.io`), all resolving to 10.10.40.10 (attacker infrastructure). 4 Sysmon EID 22 events captured. HTTPS connection attempted to the C2 domain (SSL/TLS trust failure). Domain rarity alone is Medium confidence — many legitimate new services produce first-seen domains. Combined with AGC-051 beacon timing + AGC-053 uncommon port, confidence elevates to High. |

## Attacker Perspective

### Tradecraft

**What:** Attackers register new domains for C2 infrastructure shortly before use. These domains have no prior history in the target organization's DNS logs, making them "first-seen" or "rare" destinations. The attacker benefits because:
1. No reputation data exists — the domain has never been flagged as malicious
2. No prior association with the organization — it won't appear on any whitelist
3. Short-lived domains can be registered, used for a campaign, and abandoned

**Why domain rarity is a supporting signal, not a standalone verdict:**
Many legitimate activities produce first-seen domains:
- New SaaS tool adoption (a user signs up for a new service)
- Partner integrations (first API call to a new vendor)
- Software updates from new CDN endpoints
- Marketing/analytics tracking domains

This means first-seen domain alone cannot drive a high-confidence verdict. It becomes high-confidence only when combined with a behavioral C2 indicator (beacon timing, uncommon port, high-entropy DNS).

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `EXT-ATTACKER-SIM` (10.10.40.10) running DNS server with wildcard responses.

**Steps executed (all timestamps UTC):**

| Step | Time | Action | Domain | Result |
|---|---|---|---|---|
| 1 | 22:03:11 | DNS resolve | agc054-c2drop.xyz | A: 10.10.40.10 |
| 2 | 22:03:12 | HTTPS connect | agc054-c2drop.xyz (via IP) | SSL/TLS trust failure |
| 3 | 22:03:12 | DNS resolve | agc054-payload-drop.net | A: 10.10.40.10 |
| 4 | 22:03:12 | DNS resolve | agc054-exfil-relay.org | A: 10.10.40.10 |
| 5 | 22:03:12 | DNS resolve | agc054-c2-backup.io | A: 10.10.40.10 |

**Key observations:**
- All 4 domains resolve to the same IP (10.10.40.10) — multiple domains pointing to single infrastructure is a known C2 pattern
- Domain names contain operational terms (`c2drop`, `payload-drop`, `exfil-relay`, `c2-backup`) — in real attacks these would be less obvious
- All domains are genuinely first-seen — zero prior occurrences in the lab's DNS history

## SOC Perspective

### Detection

**Sysmon EID 22 — DNS Query (4 events):**

**Event 1: agc054-c2drop.xyz**
```
Dns query:
UtcTime: 2026-09-15 22:03:12.032
ProcessId: 3396
QueryName: agc054-c2drop.xyz
QueryStatus: 0
QueryResults: 10.10.40.10;::ffff:10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

**Event 2: agc054-payload-drop.net**
```
Dns query:
UtcTime: 2026-09-15 22:03:12.144
QueryName: agc054-payload-drop.net
QueryStatus: 0
QueryResults: 10.10.40.10;::ffff:10.10.40.10;
```

**Event 3: agc054-exfil-relay.org**
```
Dns query:
UtcTime: 2026-09-15 22:03:12.158
QueryName: agc054-exfil-relay.org
QueryStatus: 0
QueryResults: 10.10.40.10;::ffff:10.10.40.10;
```

**Event 4: agc054-c2-backup.io**
```
Dns query:
UtcTime: 2026-09-15 22:03:12.166
QueryName: agc054-c2-backup.io
QueryStatus: 0
QueryResults: 10.10.40.10;::ffff:10.10.40.10;
```

**Sysmon EID 3 — Network Connection (1 event):**
```
Network connection detected:
UtcTime: 2026-09-15 22:03:12.089
ProcessId: 3396
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Protocol: tcp
SourceIp: 10.10.10.103
SourcePort: 64762
DestinationIp: 10.10.40.10
DestinationPort: 443
```

### Investigation

**Step 1 — Historical DNS search ("have we ever seen this?"):**
Query the SIEM's full DNS history for each domain:
- `agc054-c2drop.xyz`: 0 prior occurrences (first-seen confirmed)
- `agc054-payload-drop.net`: 0 prior occurrences
- `agc054-exfil-relay.org`: 0 prior occurrences
- `agc054-c2-backup.io`: 0 prior occurrences

All 4 domains are genuinely first-seen — zero prior DNS queries from any host in the environment.

**Step 2 — Domain age and reputation (enrichment):**
In a production SOC, this step would include:
- WHOIS lookup for registration date (newly registered domains are higher risk)
- Threat intelligence feed correlation (known C2 infrastructure)
- Domain categorization services (uncategorized = suspicious)

In this lab: the domains are synthetic and would show as unregistered/uncategorized.

**Step 3 — Correlate with behavioral C2 indicators:**
Domain rarity alone is Medium confidence. Combine with:
- AGC-051: Same destination IP (10.10.40.10) with periodic HTTPS beacon timing
- AGC-052: Same destination IP with DNS beacon pattern
- AGC-053: Same destination IP with non-standard port C2

Combined signal: first-seen domain + beacon timing + same C2 infrastructure = **High confidence** lateral C2.

**Step 4 — Multi-domain convergence:**
4 distinct first-seen domains all resolving to the same IP (10.10.40.10) is itself a significant indicator:
- Legitimate services rarely have multiple unrelated domains pointing to the same IP
- C2 infrastructure commonly uses multiple domains for redundancy (domain fronting, failover)

### Report

**Verdict: True Positive (conditional)** — First-seen domains resolving to confirmed C2 infrastructure.

**Confidence: Medium** (domain rarity alone) / **High** (combined with AGC-051/052/053 behavioral indicators):
1. 4 domains with zero prior DNS history in the environment — genuinely first-seen.
2. All resolve to 10.10.40.10 — confirmed C2 IP from AGC-051/052/053.
3. Multiple first-seen domains to same IP = C2 domain rotation/redundancy pattern.
4. Standalone domain rarity is NOT sufficient for high-confidence verdict — many legitimate new services produce first-seen domains weekly.
5. Combined with behavioral C2 indicators (beacon timing, DNS tunneling, uncommon port), confidence rises to High.

**Response recommendation:**
1. **Flag for monitoring** rather than immediate block if domain rarity is the ONLY indicator. Investigate further before escalating.
2. **Elevate to High and block** when combined with a second C2 indicator (beacon timing, uncommon port, DNS entropy).
3. **Block the IP** (10.10.40.10) rather than individual domains — domain rotation makes per-domain blocking a losing game.
4. **WHOIS enrichment:** In production, add domain age/registration date to the investigation. Domains registered within days of first use are significantly more suspicious.
5. **Implement first-seen alerting:** SIEM rule that flags domains with zero prior history. Use as a triage accelerator, not an automatic block.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Command and Control (TA0011) | T1071 | Application Layer Protocol | 4 Sysmon EID 22: first-seen domains (`agc054-c2drop.xyz`, `agc054-payload-drop.net`, `agc054-exfil-relay.org`, `agc054-c2-backup.io`) all resolving to 10.10.40.10. 1 EID 3: HTTPS to 10.10.40.10:443. Zero prior DNS history. Multi-domain convergence to single C2 IP. | Medium (High combined) |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### First-seen domain resolution summary

```
Domain                       | Resolution     | Prior History
-----------------------------|----------------|---------------
agc054-c2drop.xyz            | 10.10.40.10    | 0 occurrences
agc054-payload-drop.net      | 10.10.40.10    | 0 occurrences
agc054-exfil-relay.org       | 10.10.40.10    | 0 occurrences
agc054-c2-backup.io          | 10.10.40.10    | 0 occurrences

All 4 domains -> same IP: C2 domain rotation pattern
```

### Raw Sysmon EID 22 (agc054-c2drop.xyz)

```
Dns query:
UtcTime: 2026-09-15 22:03:12.032
ProcessId: 3396
QueryName: agc054-c2drop.xyz
QueryStatus: 0
QueryResults: 10.10.40.10;::ffff:10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

### Raw Sysmon EID 3 (HTTPS to C2 IP)

```
Network connection detected:
UtcTime: 2026-09-15 22:03:12.089
ProcessId: 3396
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Protocol: tcp
SourceIp: 10.10.10.103
SourcePort: 64762
DestinationIp: 10.10.40.10
DestinationPort: 443
```
