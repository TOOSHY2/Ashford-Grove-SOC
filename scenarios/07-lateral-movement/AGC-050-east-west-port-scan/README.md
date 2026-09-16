# AGC-050 — East-West Internal Port Scan

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-050` |
| Category | `07-lateral-movement` — Lateral Movement |
| MITRE Technique | `T1046` Network Service Discovery |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Network-flow based — Zeek conn.log or firewall logs show one source IP connecting to many distinct internal destinations on a narrow port set within a short window |
| Time to Triage | 05:00 (verify source IP is not the authorized vulnerability scanner; check against documented scanner baseline) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as scanner; targets: entire 10.10.10.0/24 LAN subnet |
| Chain | ◀ [AGC-049](../AGC-049-account-multi-host-auth/README.md) · next [AGC-051](../../08-command-control/AGC-051-https-beacon/README.md) (Command & Control category) ▶ |
| One-line Summary | East-west port scan from COMPROMISED-HOST-01 targeting 39 IPs across 10.10.10.0/24 on lateral-movement ports (3389/RDP, 445/SMB, 5985/WinRM). 117 TCP connection attempts in ~100 seconds. Only 2 ports open (self: 445 + 5985). 2 Sysmon EID 3 events for completed connections. Detection is primarily network-flow pattern: one source, many distinct internal destinations, narrow port set, short window. Once confirmed as non-authorized scanner, this is strong precursor evidence for imminent lateral movement. FP twin: AGC-087 (authorized internal scanner). |

## Attacker Perspective

### Tradecraft

**What:** An east-west port scan is a compromised host probing its neighbors on the same segment to find live services. The attacker picked the ports lateral movement depends on:
- **3389 (RDP):** Remote Desktop for interactive access
- **445 (SMB):** File sharing and remote administration
- **5985 (WinRM):** Windows Remote Management for command execution

The scan is groundwork: before moving, the attacker needs to know which hosts are up and which services answer.

**Why this is a network-flow detection:** Sysmon only records SUCCESSFUL TCP connections (EID 3). The failed attempts (115 of 117 here) leave no Sysmon event at all. The full pattern — one source IP probing many destinations — shows up only in:
1. Zeek conn.log on Security Onion (records every TCP SYN, whatever the outcome)
2. Firewall connection logs (allowed and denied flows)
3. Network IDS/IPS flow records

**Why at this lifecycle stage:** This is the last scenario in the Lateral Movement category, and it is the precursor that would normally PRECEDE the individual attempts in AGC-043 through AGC-049. Putting it last makes the point: catch the scan early and the host can be isolated before any of those attempts land.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- Multiple LAN hosts running as scan targets (AD-DC-01, WIN-CLIENT-01, WIN-CLIENT-02).
- No third-party scanning tools — native PowerShell TcpClient used.

**Scan parameters:**
- **Range:** 10.10.10.1 through 10.10.10.30, plus .100-.105, .200, .250, .254 (39 IPs)
- **Ports:** 3389 (RDP), 445 (SMB), 5985 (WinRM)
- **Timeout:** 500ms per connection attempt
- **Total attempts:** 117 (39 IPs x 3 ports)
- **Duration:** ~100 seconds (21:37:00 to 21:38:40 UTC)

**Results:**
| Target | Port | Result |
|---|---|---|
| 10.10.10.103 (self) | 445 | OPEN |
| 10.10.10.103 (self) | 5985 | OPEN |
| All other IPs/ports | — | Closed/Filtered (115 attempts) |

**Key observation:** Every remote host came back closed/filtered on every scanned port. That matches the network isolation of COMPROMISED-HOST-01 from the rest of the LAN seen throughout AGC-043 through AGC-049. On a production network the same scan would return live services and hand the attacker a target map.

## SOC Perspective

### Detection

**Sysmon EID 3 — Network Connection (2 events, successful connections only):**

**Event 1: TCP to self on port 5985 (WinRM)**
```
Network connection detected:
RuleName: -
UtcTime: 2026-09-15 21:37:51.366
ProcessGuid: {eb65e329-ba7b-6aa9-1604-000000001400}
ProcessId: 708
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64676
DestinationIp: 10.10.10.103
DestinationHostname: COMPROMISED-01.ashfordgrove.local
DestinationPort: 5985
```

**Event 2: TCP to self on port 445 (SMB)**
```
Network connection detected:
RuleName: -
UtcTime: 2026-09-15 21:37:51.353
ProcessGuid: {eb65e329-ba7b-6aa9-1604-000000001400}
ProcessId: 708
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64675
DestinationIp: 10.10.10.103
DestinationHostname: COMPROMISED-01.ashfordgrove.local
DestinationPort: 445
DestinationPortName: microsoft-ds
```

**Critical limitation of host-based detection:** Only 2 of 117 connection attempts produced Sysmon EID 3 events — the 2 that succeeded, both to self. The 115 failures left NO trace in Sysmon. So:
- Sysmon alone CANNOT see a port scan unless some connections succeed
- Network-flow telemetry (Zeek, firewall logs) is the only complete record of a scan
- Even with Sysmon on every host, each would see just its ONE inbound attempt — the PATTERN (one source, many destinations) exists only at the network or SIEM level

**Expected Zeek conn.log pattern (Security Onion):**
With the sensor in place, Security Onion's Zeek would log all 117 TCP SYN attempts in conn.log, along these lines:
```
# Zeek conn.log pattern (expected, not captured due to SO having no Guest Additions):
# Source: 10.10.10.103 -> Dest: 10.10.10.1:3389 (S0/REJ)
# Source: 10.10.10.103 -> Dest: 10.10.10.1:445  (S0/REJ)
# Source: 10.10.10.103 -> Dest: 10.10.10.1:5985 (S0/REJ)
# Source: 10.10.10.103 -> Dest: 10.10.10.2:3389 (S0/REJ)
# ... (117 entries, one source, many destinations, narrow port set)
```

### Investigation

**Step 1 — Network flow analysis (SIEM-level):**
Query Zeek conn.log or firewall logs for one source IP reaching an unusually high number of distinct destination IPs in a window:
- Group by: Source IP
- Count: distinct Destination IPs
- Filter: destination ports in {3389, 445, 5985, 22, 135, 5986}
- Window: 15-minute sliding
- Threshold: 10+ distinct destinations (baseline-adjusted)

Here 10.10.10.103 hit 39 distinct IPs on 3 ports in ~100 seconds. No workstation does that on its own.

**Step 2 — Exclude authorized vulnerability scanner:**
Before calling this malicious, confirm the source IP is NOT the organization's authorized vulnerability scanner:
- Check the asset inventory for the scanner's IP address
- Check the scan schedule — was a vulnerability scan authorized for this window?
- The documented scanner would be a dedicated appliance or VM with a known IP, not a user workstation

In the lab, COMPROMISED-HOST-01 (10.10.10.103) is michael.chen's workstation, NOT an authorized scanner, and no vulnerability scan was scheduled. That rules out the false positive (see AGC-087 for the authorized scanner FP twin).

**Step 3 — Assess as lateral movement precursor:**
Once the scanner is ruled out, treat the scan as the attacker preparing to move:
- The port selection (3389, 445, 5985) targets lateral-movement protocols and nothing else
- This scan would normally come before attempts like AGC-043 (RDP), AGC-044 (SMB), AGC-045 (WinRM)
- Isolating the scanning host BEFORE any of those attempts is the highest-value response

**Step 4 — Correlate with prior indicators:**
Check the scanning host (10.10.10.103) against existing alerts:
- AGC-043 through AGC-049 recorded lateral movement ATTEMPTS from this same host
- The port scan shows systematic reconnaissance, not one-off poking
- With the credential access findings (AGC-031 through AGC-036), the timeline reads: compromise -> credential theft -> reconnaissance -> lateral movement

### Report

**Verdict: True Positive** — Internal east-west port scan from a compromised workstation, aimed at lateral-movement services.

**Confidence: High** — Calibrated assessment:
1. 117 TCP connection attempts to 39 distinct internal IPs in ~100 seconds — no legitimate workstation produces that pattern.
2. The port selection (3389/445/5985) targets lateral movement protocols, not application services.
3. The source is a standard user workstation (michael.chen), not an authorized vulnerability scanner.
4. No vulnerability scan was scheduled for this window.
5. Held at High rather than Critical because a scan is reconnaissance, not an active exploit — but it still warrants P1 action to head off the lateral movement that follows.

**Response recommendation:**
1. **Isolate the scanning host IMMEDIATELY** — do not wait for lateral movement attempts. The scan alone shows the host is compromised and the attacker is expanding.
2. **Preemptive credential rotation:** Rotate every credential reachable from the scanning host before the attacker tries to use one.
3. **Network segmentation validation:** Confirm firewall rules block workstation-to-workstation traffic on lateral movement ports. In the lab, the firewall blocked all remote connections.
4. **SIEM detection rule:** Alert when one source IP connects to 10+ distinct internal IPs on lateral-movement ports (3389, 445, 5985, 22) inside a 15-minute window. Check the source against the authorized scanner whitelist.
5. **Zeek-based detection:** Security Onion conn.log is the primary layer for this pattern — Sysmon alone misses it because failed connections produce no EID 3.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1046 | Network Service Discovery | 117 TCP connection attempts from 10.10.10.103 to 39 distinct IPs on ports 3389/445/5985 in ~100 seconds. 2 Sysmon EID 3 events for successful connections (self only). Pattern visible in network flow logs: one source, many destinations, narrow LM port set, short window. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Port scan summary

```
Source:     10.10.10.103 (COMPROMISED-HOST-01)
Targets:    10.10.10.1-30, .100-.105, .200, .250, .254 (39 IPs)
Ports:      3389 (RDP), 445 (SMB), 5985 (WinRM)
Duration:   ~100 seconds (21:37:00 to 21:38:40 UTC)
Total:      117 connection attempts
Open:       2 (self: 445, 5985)
Closed:     115

Sysmon EID 3: 2 events (successful connections only)
Sysmon EID 1: 0 events (PowerShell TcpClient runs in-process)
```

### Raw Sysmon EID 3 (TCP to self:5985)

```
Network connection detected:
UtcTime: 2026-09-15 21:37:51.366
ProcessId: 708
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64676
DestinationIp: 10.10.10.103
DestinationHostname: COMPROMISED-01.ashfordgrove.local
DestinationPort: 5985
```

### Raw Sysmon EID 3 (TCP to self:445)

```
Network connection detected:
UtcTime: 2026-09-15 21:37:51.353
ProcessId: 708
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64675
DestinationIp: 10.10.10.103
DestinationHostname: COMPROMISED-01.ashfordgrove.local
DestinationPort: 445
DestinationPortName: microsoft-ds
```

### Host-based detection gap analysis

```
Detection Layer        | Scan Attempts Captured | Coverage
-----------------------|------------------------|----------
Sysmon EID 3           | 2 / 117 (1.7%)        | Successful TCP only
Sysmon EID 1           | 0 / 117 (0%)          | In-process TcpClient
Windows Firewall Log   | Not enabled            | Would capture if enabled
Zeek conn.log (SO)     | 117 / 117 (expected)  | All TCP SYN attempts
OPNsense Firewall      | Cross-zone only        | LAN-internal not logged
```

Host-based telemetry alone missed 98.3% of this scan. Network-flow monitoring (Security Onion / Zeek) is what would have caught the rest.
