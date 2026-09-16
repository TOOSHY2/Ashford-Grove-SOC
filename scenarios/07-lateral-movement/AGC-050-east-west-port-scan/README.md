# AGC-050 — East-West Internal Port Scan

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**What:** East-west port scanning is an internal network reconnaissance technique where a compromised host scans other hosts on the same network segment to discover available services. The attacker targets lateral-movement-relevant ports:
- **3389 (RDP):** Remote Desktop for interactive access
- **445 (SMB):** File sharing and remote administration
- **5985 (WinRM):** Windows Remote Management for command execution

This scan serves as a preparation phase for lateral movement — the attacker needs to know which hosts are alive and which services are available before attempting to move laterally.

**Why this is a network-flow detection:** Host-based logs (Sysmon) only capture SUCCESSFUL TCP connections (EID 3). Failed connection attempts (115 out of 117 in this case) generate no Sysmon event. The full scan pattern — one source IP sending connection attempts to many destinations — is only visible in:
1. Zeek conn.log on Security Onion (captures all TCP SYN attempts regardless of outcome)
2. Firewall connection logs (captures allowed/denied flows)
3. Network IDS/IPS flow records

**Why at this lifecycle stage:** This is the final scenario in the Lateral Movement category and represents the precursor activity that would typically PRECEDE the individual lateral movement attempts in AGC-043 through AGC-049. By placing it last, the lab demonstrates that detecting the scan early would allow preemptive isolation before any lateral movement succeeds.

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

**Key observation:** All remote hosts returned closed/filtered on all scanned ports. This is consistent with the documented network isolation of COMPROMISED-HOST-01 from other LAN hosts (confirmed across AGC-043 through AGC-049). In a production environment, the scan would discover services on live hosts, providing the attacker with a target map for subsequent lateral movement.

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

**Critical limitation of host-based detection:** Only 2 of 117 connection attempts generated Sysmon EID 3 events — the 2 that succeeded (both to self). The 115 failed scan attempts left NO host-based trace in Sysmon. This means:
- Sysmon alone CANNOT detect a port scan unless at least some connections succeed
- Network-flow detection (Zeek, firewall logs) is ESSENTIAL for scan detection
- Even if every host had Sysmon, each would only see the ONE inbound connection attempt — the scan PATTERN (one source, many destinations) is only visible at the network or SIEM aggregation level

**Expected Zeek conn.log pattern (Security Onion):**
In a properly instrumented network, Security Onion's Zeek sensor would capture all 117 TCP SYN attempts in conn.log, showing:
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
Query Zeek conn.log or firewall logs for a single source IP connecting to an abnormally high number of distinct destination IPs within a time window:
- Group by: Source IP
- Count: distinct Destination IPs
- Filter: destination ports in {3389, 445, 5985, 22, 135, 5986}
- Window: 15-minute sliding
- Threshold: 10+ distinct destinations (baseline-adjusted)

In this case: 10.10.10.103 connected to 39 distinct IPs on 3 ports in ~100 seconds. This far exceeds any legitimate workstation behavior.

**Step 2 — Exclude authorized vulnerability scanner:**
Before classifying as malicious, verify the source IP is NOT the organization's authorized vulnerability scanner:
- Check asset inventory for the scanner's IP address
- Check scan schedule — was a vulnerability scan authorized for this time window?
- The documented scanner would be a dedicated appliance or VM with a known IP, not a user workstation

In this lab: COMPROMISED-HOST-01 (10.10.10.103) is michael.chen's workstation, NOT an authorized scanner. No vulnerability scan was scheduled. This rules out the false positive scenario (see AGC-087 for the authorized scanner FP twin).

**Step 3 — Assess as lateral movement precursor:**
Once confirmed as non-authorized scanning, treat this as strong evidence that the attacker is actively preparing for lateral movement:
- The port selection (3389, 445, 5985) specifically targets lateral-movement protocols
- This scan would typically precede attempts like AGC-043 (RDP), AGC-044 (SMB), AGC-045 (WinRM)
- Proactive isolation of the scanning host BEFORE lateral movement begins is the highest-value response

**Step 4 — Correlate with prior indicators:**
Cross-reference the scanning host (10.10.10.103) with existing alerts:
- AGC-043 through AGC-049 documented lateral movement ATTEMPTS from this same host
- The port scan confirms systematic reconnaissance behavior, not opportunistic testing
- Combined with credential access findings (AGC-031 through AGC-036), this builds a complete attack timeline: compromise -> credential theft -> reconnaissance -> lateral movement

### Report

**Verdict: True Positive** — Internal east-west port scan from compromised workstation, targeting lateral-movement-specific services.

**Confidence: High** — Calibrated assessment:
1. 117 TCP connection attempts to 39 distinct internal IPs in ~100 seconds — no legitimate workstation behavior produces this pattern.
2. Port selection (3389/445/5985) specifically targets lateral movement protocols, not application services.
3. Source is a standard user workstation (michael.chen), not an authorized vulnerability scanner.
4. No vulnerability scan was scheduled for this time window.
5. Reduced from Critical because the scan alone is a precursor (reconnaissance), not an active exploit — but it warrants immediate P1 action to preempt the lateral movement that will follow.

**Response recommendation:**
1. **Isolate the scanning host IMMEDIATELY** — do not wait for lateral movement attempts. The scan itself is sufficient evidence that the host is compromised and the attacker is actively expanding.
2. **Preemptive credential rotation:** Any credentials accessible from the scanning host should be rotated before lateral movement is attempted.
3. **Network segmentation validation:** Verify that firewall rules prevent workstation-to-workstation traffic on lateral movement ports. In this lab, the firewall correctly blocked all remote connections.
4. **SIEM detection rule:** Alert when any single source IP connects to 10+ distinct internal IPs on lateral-movement ports (3389, 445, 5985, 22) within a 15-minute window. Cross-reference against authorized scanner IP whitelist.
5. **Zeek-based detection:** Security Onion conn.log analysis is the primary detection layer for this pattern — Sysmon alone is insufficient since failed connections generate no EID 3 events.

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

This gap analysis demonstrates why network-flow monitoring (Security Onion / Zeek) is essential for detecting internal reconnaissance. Host-based detection alone misses 98.3% of scan activity in this scenario.
