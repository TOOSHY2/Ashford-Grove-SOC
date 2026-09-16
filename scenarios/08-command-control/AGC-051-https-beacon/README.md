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

**What:** HTTPS beaconing is the most common C2 communication pattern. A compromised host periodically contacts an external server controlled by the attacker over HTTPS (port 443) to:
1. Check in and report status
2. Receive new commands or tasks
3. Exfiltrate collected data
4. Download additional payloads

The attacker uses HTTPS specifically because:
- Port 443 is almost universally allowed through firewalls
- TLS encryption prevents content inspection by network security tools
- HTTPS traffic blends with legitimate web browsing volume

**Why timing regularity is the key signal:** The critical difference between C2 beaconing and legitimate web traffic is the timing pattern. Human web browsing produces connections with highly variable intervals (reading a page for 5 seconds, then 30 seconds, then 2 minutes). Automated C2 beaconing produces connections with consistent, low-variance intervals because the beacon timer is programmatic. Sophisticated C2 frameworks add "jitter" (random variance) to the interval, but even jittered beacons show statistically distinguishable regularity compared to human browsing.

**Why at this lifecycle stage:** After establishing persistence (AGC-019-024) and performing lateral movement (AGC-043-050), the attacker needs a reliable communication channel to maintain access, receive instructions, and exfiltrate data. C2 is the backbone of any sustained intrusion.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `EXT-ATTACKER-SIM` (10.10.40.10) running as C2 destination.
- PowerShell `Invoke-WebRequest` used as beacon mechanism.

**Beacon parameters:**
- **URL:** `https://10.10.40.10/beacon`
- **Interval:** 30 seconds (compressed from typical 60s for lab efficiency)
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
- This is extremely low variance — far below any human browsing pattern

## SOC Perspective

### Detection

**Sysmon EID 3 — Network Connection (10 events, one per beacon cycle):**

All 10 events share identical structure — same process (PID 2676, powershell.exe), same destination (10.10.40.10), incrementing source ports:

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
3. **Same process:** All from PID 2676 (powershell.exe) — a single long-running process making periodic connections
4. **External IP:** 10.10.40.10 is in the External zone, not a known business service
5. **No DNS resolution:** Destination accessed by raw IP, not hostname (no EID 22 DNS events)

### Investigation

**Step 1 — Compute inter-connection timing deltas:**
Pull all connections from the source host to the destination and calculate the time delta between consecutive connections. The core signal is:
- Low standard deviation relative to mean (coefficient of variation < 5% indicates automated beaconing)
- In this case: CV = 0.11% — essentially a metronome

Human browsing comparison: a user visiting the same site repeatedly would show deltas like 3s, 45s, 120s, 8s — high variance, no regular pattern.

**Step 2 — Check destination reputation and rarity:**
- Is 10.10.40.10 a known business service or CDN? No — it's in the lab's External zone.
- Has any other host in the environment connected to this IP? If not, it's a rare/unique destination, which increases suspicion.
- Domain reputation (if a domain were used): check against threat intelligence feeds.

**Step 3 — Exclude legitimate polling applications:**
Some legitimate applications produce regular-interval connections:
- Windows Update check (irregular, not fixed interval)
- Antivirus definition updates (typically hourly, not every 30s)
- Monitoring agents (known destinations, documented in asset inventory)
- Chat/messaging keepalives (known service IPs)

In this case: powershell.exe connecting to a raw external IP every 30s matches none of these legitimate patterns.

**Step 4 — Correlate with host indicators:**
Cross-reference the beaconing host with other alerts:
- COMPROMISED-HOST-01 has triggered alerts across the entire attack chain (AGC-001 through AGC-050)
- The beacon destination (10.10.40.10) is in the External zone — consistent with C2 infrastructure outside the organization's network

### Report

**Verdict: True Positive** — Periodic HTTPS beaconing to external C2 infrastructure.

**Confidence: High** — Calibrated assessment:
1. 10 connections with 0.11% timing variance is statistically incompatible with human-driven traffic.
2. Destination (10.10.40.10) is an external IP not associated with any known business service.
3. Connection source (powershell.exe) is a scripting engine, not a legitimate application.
4. Raw IP access (no DNS resolution) is consistent with C2 infrastructure that avoids DNS-based detection.
5. The pattern matches known C2 framework behavior (Cobalt Strike, Metasploit, etc.).

**Response recommendation:**
1. **Block the C2 destination** at the firewall immediately (10.10.40.10) — sever the communication channel before the attacker can issue commands.
2. **Isolate the beaconing host** — COMPROMISED-HOST-01 is under active remote control.
3. **Preserve connection logs** as evidence before log retention expires — the beacon timeline is forensic evidence of the intrusion duration.
4. **SIEM detection rule:** For each source-destination pair, compute the standard deviation of inter-connection deltas over a sliding window. Alert when CV < 5% AND connection count > 5 AND destination is not whitelisted. This catches beaconing regardless of the specific interval.
5. **Hunt for additional beacons:** The attacker may have established backup C2 channels on other ports or to other destinations. Search for any other low-variance connection patterns from this host or from hosts it laterally moved to.

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
