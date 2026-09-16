# AGC-051 — HTTPS Beacon (Periodic C2)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-051` |
| Category | `08-command-control` — Command & Control |
| MITRE Technique | `T1071.001` Application Layer Protocol: Web Protocols |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Network-flow analysis — recurring connections to same external destination with consistent low-variance timing interval |
| Time to Triage | 05:00 (compute inter-connection deltas; verify destination is not a known legitimate polling service) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as beacon source; `EXT-ATTACKER-SIM` (10.10.40.10) as C2 destination |
| Chain | ◀ [AGC-050](../../07-lateral-movement/AGC-050-east-west-port-scan/README.md) (Lateral Movement category) · next [AGC-052](../AGC-052-dns-beacon/README.md) ▶ |
| One-line Summary | Periodic HTTPS beacon from COMPROMISED-HOST-01 to external IP 10.10.40.10 every ~30 seconds. 10 connection cycles over ~5 minutes with extremely low timing variance (30.018-30.135s delta). 10 Sysmon EID 3 events captured TCP connections from powershell.exe to 10.10.40.10. SSL/TLS handshake failed (no valid cert on C2). The consistent low-variance interval is the core detection signal — human browsing produces irregular, high-variance connection patterns; automated C2 beaconing produces metronomic regularity. |

## Attacker Perspective

### Tradecraft

**What:** The compromised host contacts an attacker-controlled server over HTTPS (port 443) on a fixed timer to:
1. Check in and report status
2. Receive new commands or tasks
3. Exfiltrate collected data
4. Download additional payloads

The attacker picks HTTPS because:
- Port 443 is allowed outbound through almost every firewall
- TLS hides the request body from inline inspection
- The traffic sits inside the normal volume of web browsing

**Why timing regularity is the key signal:** Timing is what separates a beacon from browsing. A person reading pages produces gaps of 5 seconds, then 30 seconds, then 2 minutes. A beacon fires on a programmatic timer, so its gaps barely move. Mature C2 frameworks add "jitter" (random variance) to the interval, but even a jittered beacon stays far more regular than a human.

**Why at this lifecycle stage:** With persistence set (AGC-019-024) and lateral movement done (AGC-043-050), the attacker needs a channel to keep issuing commands and pull data out. Every later stage of this chain runs over it.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `EXT-ATTACKER-SIM` (10.10.40.10) running as C2 destination.
- PowerShell `Invoke-WebRequest` in a loop as the beacon mechanism.

**Beacon parameters:**
- **URL:** `https://10.10.40.10/beacon`
- **Interval:** 30 seconds (shortened from a typical 60s to keep the run brief)
- **Cycles:** 10
- **Duration:** ~5 minutes (21:43:43 to 21:48:13 UTC)
- **Timeout:** 3 seconds per request

**Beacon timeline (all timestamps UTC):**

| Cycle | Timestamp | Delta (s) | Result |
|---|---|---|---|
| 1 | 21:43:43.232 | — | SSL/TLS trust failure |
| 2 | 21:44:13.367 | 30.135 | SSL/TLS trust failure |
| 3 | 21:44:43.391 | 30.024 | SSL/TLS trust failure |
| 4 | 21:45:13.409 | 30.018 | SSL/TLS trust failure |
| 5 | 21:45:43.440 | 30.031 | SSL/TLS trust failure |
| 6 | 21:46:13.465 | 30.025 | SSL/TLS trust failure |
| 7 | 21:46:43.501 | 30.036 | SSL/TLS trust failure |
| 8 | 21:47:13.539 | 30.038 | SSL/TLS trust failure |
| 9 | 21:47:43.580 | 30.041 | SSL/TLS trust failure |
| 10 | 21:48:13.606 | 30.026 | SSL/TLS trust failure |

**Timing statistics:**
- Mean delta: 30.042 seconds
- Standard deviation: 0.034 seconds
- Variance coefficient: 0.11%
- No human browsing pattern comes close to that spread

## SOC Perspective

### Detection

**Sysmon EID 3 — Network Connection (10 events, one per beacon cycle):**

All 10 events share the same process (PID 2676, powershell.exe) and destination (10.10.40.10); only the source port changes:

**Representative event (Cycle 10):**
```
Network connection detected:
RuleName: -
UtcTime: 2026-09-15 21:48:13.608
ProcessGuid: {eb65e329-bc0e-6aa9-2204-000000001400}
ProcessId: 2676
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64723
DestinationIp: 10.10.40.10
DestinationPort: 443
```

**Source port progression (monotonically increasing):**
```
Cycle  1: 64704
Cycle  2: 64706
Cycle  3: 64709
Cycle  4: 64711
Cycle  5: 64713
Cycle  6: 64715
Cycle  7: 64717
Cycle  8: 64718
Cycle  9: 64721
Cycle 10: 64723
```

**Detection indicators:**
1. **Low-variance timing:** 10 connections with mean interval 30.042s and 0.034s standard deviation
2. **Same destination:** All 10 connections target 10.10.40.10:443
3. **Same process:** All from PID 2676 (powershell.exe) — one long-running process, not ten separate launches
4. **External IP:** 10.10.40.10 is in the External zone, not a known business service
5. **No DNS resolution:** Destination reached by raw IP, not hostname (no Sysmon EID 22 DNS events)

### Investigation

**Step 1 — Compute inter-connection timing deltas:**
Pull every connection from COMPROMISED-HOST-01 to 10.10.40.10 and compute the gap between consecutive ones. The signal is:
- Low standard deviation relative to mean (coefficient of variation < 5% indicates automated beaconing)
- Here: CV = 0.11% — a metronome

For comparison, a user revisiting the same site would show deltas like 3s, 45s, 120s, 8s — high variance, no pattern.

**Step 2 — Check destination reputation and rarity:**
- Is 10.10.40.10 a known business service or CDN? No — it's in the lab's External zone.
- Has any other host in the lab connected to this IP? A destination only one host talks to raises suspicion.
- Domain reputation (if a domain were used): check against threat intelligence feeds.

**Step 3 — Exclude legitimate polling applications:**
Some legitimate applications produce regular-interval connections:
- Windows Update check (irregular, not fixed interval)
- Antivirus definition updates (typically hourly, not every 30s)
- Monitoring agents (known destinations, documented in asset inventory)
- Chat/messaging keepalives (known service IPs)

powershell.exe hitting a raw external IP every 30s matches none of them.

**Step 4 — Correlate with host indicators:**
Cross-reference the beaconing host with other alerts:
- COMPROMISED-HOST-01 has had alerts fire against it across the whole chain (AGC-001 through AGC-050)
- The beacon destination (10.10.40.10) sits in the External zone, where C2 infrastructure would be

### Report

**Verdict: True Positive** — Periodic HTTPS beaconing to external C2 infrastructure.

**Confidence: High** — on five points:
1. 10 connections with 0.11% timing variance is statistically incompatible with human-driven traffic.
2. Destination (10.10.40.10) is an external IP tied to no known business service.
3. The connecting process is powershell.exe, a scripting engine, not a browser or updater.
4. Raw IP access with no DNS lookup fits C2 that sidesteps DNS-based detection.
5. The pattern matches the default beacon behavior of Cobalt Strike and Metasploit.

**Response recommendation:**
1. **Block the C2 destination** (10.10.40.10) at the firewall now, before the attacker issues the next command.
2. **Isolate the beaconing host** — COMPROMISED-HOST-01 is under active remote control.
3. **Preserve connection logs** before retention expires — the beacon timeline dates how long the attacker held the channel.
4. **SIEM detection rule:** For each source-destination pair, compute the standard deviation of inter-connection deltas over a sliding window. Alert when CV < 5% AND connection count > 5 AND the destination is not allowlisted. The rule ignores the interval itself, so a beacon on any timer fires it.
5. **Hunt for additional beacons:** The attacker may hold a backup channel on another port or destination. Run the same delta analysis from COMPROMISED-HOST-01 and from every host it moved to in AGC-043-050.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Command and Control (TA0011) | T1071.001 | Application Layer Protocol: Web Protocols | 10 Sysmon EID 3: powershell.exe TCP to 10.10.40.10:443 at 30.042s mean interval (SD=0.034s, CV=0.11%). HTTPS beacon pattern over ~5 minutes. SSL/TLS handshake attempted (trust failure). Raw IP, no DNS. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Beacon timing analysis

```
Cycle  1: 21:43:43.232  delta: --
Cycle  2: 21:44:13.367  delta: 30.135s
Cycle  3: 21:44:43.391  delta: 30.024s
Cycle  4: 21:45:13.409  delta: 30.018s
Cycle  5: 21:45:43.440  delta: 30.031s
Cycle  6: 21:46:13.465  delta: 30.025s
Cycle  7: 21:46:43.501  delta: 30.036s
Cycle  8: 21:47:13.539  delta: 30.038s
Cycle  9: 21:47:43.580  delta: 30.041s
Cycle 10: 21:48:13.606  delta: 30.026s

Mean: 30.042s | SD: 0.034s | CV: 0.11%
```

### Raw Sysmon EID 3 (representative — Cycle 1)

```
Network connection detected:
UtcTime: 2026-09-15 21:43:43.302
ProcessGuid: {eb65e329-bc0e-6aa9-2204-000000001400}
ProcessId: 2676
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64704
DestinationIp: 10.10.40.10
DestinationPort: 443
```

### Raw Sysmon EID 3 (representative — Cycle 10)

```
Network connection detected:
UtcTime: 2026-09-15 21:48:13.608
ProcessGuid: {eb65e329-bc0e-6aa9-2204-000000001400}
ProcessId: 2676
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64723
DestinationIp: 10.10.40.10
DestinationPort: 443
```
