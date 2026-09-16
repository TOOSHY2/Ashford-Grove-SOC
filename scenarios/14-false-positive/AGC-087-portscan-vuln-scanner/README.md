# AGC-087 — Internal Port Scan: Scheduled Vulnerability Scanner (False Positive)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-087` |
| Title | Internal Port Scan: Scheduled Vulnerability Assessment |
| Category | `14-false-positive` — False Positive Triage |
| Severity | Medium (alert trigger) |
| MITRE Technique | T1046 (observed, not malicious) |
| Verdict | False Positive / Benign |
| Confidence | High |
| Malicious Twin | AGC-050 (Lateral Movement via Network Scanning) |
| Chain | ◀ [AGC-086](../AGC-086-regulatory-submission/README.md) · next [AGC-088](../AGC-088-log-clearing-retention/README.md) ▶ |

## Attacker Perspective

### Simulation

Executed a port scan from MGMT-GUI-TEMP (10.10.10.20, the documented internal vulnerability scanner host) targeting 3 LAN-NET hosts (10.10.10.100, 10.10.10.101, 10.10.10.102) across 6 standard vulnerability assessment ports. All 18 connection attempts returned closed/filtered. The scan ran as a bash script using `/dev/tcp` probes.

**Execution window**: 00:56:13 - 00:56:44 UTC on MGMT-GUI-TEMP (10.10.10.20)

## SOC Perspective

### Detection

Network IDS alert: sequential port scan detected from 10.10.10.20 (MGMT-GUI-TEMP) targeting multiple LAN-NET hosts across common service ports (22, 80, 443, 445, 3389, 5985). The scan pattern and port set match signatures for lateral movement reconnaissance (AGC-050). The triage question: is this an attacker mapping the network, or a scheduled vulnerability assessment?

### Investigation

#### Step 1: Identify the Scan Source

**Scan origin (from MGMT-GUI-TEMP output):**
```
Source: MGMT-GUI-TEMP (10.10.10.20) - documented internal scanner
Scanner Schedule: Monthly, 1st of month
Port Set: 3389,445,5985,22,80,443
Target Range: LAN-NET (10.10.10.0/24)
Owner: Security Team
```

The source IP (10.10.10.20) is the management workstation designated as the internal vulnerability scanner. This host is documented in the SOC asset inventory as the authorized scanning platform.

#### Step 2: Verify Scan Pattern

**Connection log (18 probes, all closed/filtered):**
```
[00:56:13] 10.10.10.100:22  closed/filtered
[00:56:15] 10.10.10.100:80  closed/filtered
[00:56:17] 10.10.10.100:443 closed/filtered
[00:56:19] 10.10.10.100:445 closed/filtered
[00:56:20] 10.10.10.100:3389 closed/filtered
[00:56:22] 10.10.10.100:5985 closed/filtered
[00:56:23] 10.10.10.101:22  closed/filtered
[00:56:25] 10.10.10.101:80  closed/filtered
[00:56:26] 10.10.10.101:443 closed/filtered
[00:56:28] 10.10.10.101:445 closed/filtered
[00:56:29] 10.10.10.101:3389 closed/filtered
[00:56:31] 10.10.10.101:5985 closed/filtered
[00:56:32] 10.10.10.102:22  closed/filtered
[00:56:34] 10.10.10.102:80  closed/filtered
[00:56:36] 10.10.10.102:443 closed/filtered
[00:56:38] 10.10.10.102:445 closed/filtered
[00:56:40] 10.10.10.102:3389 closed/filtered
[00:56:42] 10.10.10.102:5985 closed/filtered
```

#### Step 3: Scan Characteristics Analysis

| Characteristic | Observed | Expected (Scheduled) |
|---------------|----------|---------------------|
| **Source IP** | 10.10.10.20 (MGMT-GUI-TEMP) | 10.10.10.20 (documented scanner) |
| **Port set** | 22, 80, 443, 445, 3389, 5985 | Standard vuln assessment set |
| **Targets** | LAN-NET hosts (10.10.10.100-102) | LAN-NET (10.10.10.0/24) |
| **Pattern** | Sequential, host-by-host | Sequential sweep |
| **Timing** | ~2 seconds between probes | Non-aggressive, rate-limited |
| **Duration** | 31 seconds total | Expected for 18 probes at 2s interval |

#### Step 4: Cross-Reference Scanner Documentation

Vulnerability scanner registry:
```
Scanner Host: MGMT-GUI-TEMP (10.10.10.20)
Schedule: Monthly, 1st business day of month
Approved By: Security Team Lead (raj.patel)
Port Profile: Standard vulnerability assessment
  - 22 (SSH), 80 (HTTP), 443 (HTTPS)
  - 445 (SMB), 3389 (RDP), 5985 (WinRM)
Target Scope: LAN-NET (10.10.10.0/24)
Firewall Exception: FW-SCAN-001
```

### Report

**Verdict: False Positive / Benign** — The port scan originates from the documented internal vulnerability scanner (MGMT-GUI-TEMP, 10.10.10.20) running its scheduled monthly assessment. The source host, port set, target scope, and scan pattern all match the scanner registry entry approved by the Security Team Lead. The rate-limited, sequential probing pattern is characteristic of authorized vulnerability assessment, not attacker reconnaissance.

**Recommendation**: Close as Benign. Ensure the scanner registry (host, schedule, port profile, target scope) is documented in the SOC's asset inventory so future monthly scans are automatically suppressed or auto-closed.

**Cross-reference**: The malicious twin of this scenario is **AGC-050**, where a port scan represents unauthorized network reconnaissance by an attacker performing lateral movement discovery from a compromised host.

#### Discriminating evidence (benign vs malicious)

| Factor | AGC-087 (Benign) | AGC-050 (Malicious) |
|--------|-------------------|---------------------|
| **Source** | Documented scanner host (MGMT-GUI-TEMP) | Compromised endpoint or attacker pivot |
| **Authorization** | Scheduled, approved by Security Team | Unauthorized, no change ticket |
| **Port set** | Fixed standard assessment set (6 ports) | Broad sweep (1000+ ports) or targeted |
| **Rate** | Rate-limited (~2s per probe) | Aggressive or evasive timing |
| **Targets** | Documented scope (LAN-NET) | Opportunistic or expanding beyond scope |
| **Pattern** | Sequential host-by-host (predictable) | Random or SYN-only stealth scan |
| **Context** | From management VLAN | From user endpoint or DMZ |

### MITRE Mapping

No malicious technique applies:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1046 | Network Service Discovery | Discovery | **Observed, Benign** — Sequential port scan from documented vulnerability scanner (MGMT-GUI-TEMP, 10.10.10.20) to LAN-NET hosts. Fixed 6-port assessment set, rate-limited, matches scanner registry and schedule. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
