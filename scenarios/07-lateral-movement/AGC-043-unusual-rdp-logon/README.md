# AGC-043 -- Unusual RDP Logon (Workstation-to-Workstation)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-043` |
| Category | `07-lateral-movement` -- Lateral Movement |
| MITRE Technique | `T1021.001` Remote Services: Remote Desktop Protocol |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate -- Sysmon EID 1 captures `mstsc.exe /v:<target>` with target IP in command line |
| Time to Triage | 02:00 (verify source is a workstation not a jump host; check for legitimate remote-admin role) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `WIN-CLIENT-02` (10.10.10.102) |
| Chain | < AGC-042 (Discovery category) . next AGC-044 > |
| One-line Summary | RDP lateral movement attempt from compromised workstation to WIN-CLIENT-02: `cmdkey /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:[REDACTED]` stored credentials (cleartext password in command line), then `mstsc /v:10.10.10.102` launched. Connection did not complete (TCP 3389 unreachable on destination). Sysmon EID 1 captured all 3 events including **cleartext credential in cmdkey command line**. The workstation-to-workstation RDP pattern with pre-stored credentials is a high-confidence lateral movement indicator. |

## Attacker Perspective

### Tradecraft

**What:** RDP lateral movement uses the Remote Desktop Protocol to pivot from a compromised host to another system. The workstation-to-workstation variant is particularly suspicious because:
- Legitimate RDP traffic typically flows from a user's workstation to a SERVER (or from a jump host to a server)
- Workstation-to-workstation RDP has almost no legitimate use case except in rare peer-support scenarios
- The `cmdkey` + `mstsc` pattern (pre-storing credentials before launching RDP) indicates scripted/automated lateral movement rather than interactive use

The credential pre-staging via `cmdkey` is a specific indicator:
- `cmdkey /add:TERMSRV/<target> /user:<account> /pass:<password>` stores credentials in Windows Credential Manager
- This bypasses the interactive credential prompt that a human user would see
- The cleartext password appears in the command line, which Sysmon EID 1 captures

**Why at this lifecycle stage:** After completing discovery (AGC-037 through AGC-042), the attacker has mapped the environment and identified target hosts. The natural next step is lateral movement to expand access. RDP is a common lateral movement protocol because:
1. It provides full interactive desktop access
2. It is often allowed through firewalls (port 3389 is commonly open)
3. It uses legitimate Windows authentication (blends with normal traffic)

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `WIN-CLIENT-02` running (target host).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 20:59:25 | TCP test to 10.10.10.102:3389 | COMPROMISED-HOST-01 | CLOSED/TIMEOUT -- RDP port not reachable |
| 2 | 2026-09-15 20:59:30 | cmdkey /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:[REDACTED] | COMPROMISED-HOST-01 | Credential stored successfully |
| 3 | 2026-09-15 20:59:30 | mstsc /v:10.10.10.102 | COMPROMISED-HOST-01 | Launched (PID 1832), hung waiting for GUI, killed after 10s |
| 4 | 2026-09-15 20:59:40 | cmdkey /delete:TERMSRV/10.10.10.102 | COMPROMISED-HOST-01 | Credential cleaned up |

**Key findings:**
- RDP connection did NOT complete -- TCP 3389 was unreachable on WIN-CLIENT-02 (Windows Firewall likely blocking inbound RDP or network routing issue)
- Despite the failure, the SOURCE-SIDE evidence is complete: mstsc process creation, credential storage, and target IP are all captured
- The `cmdkey` command exposed `raj.patel`'s password in cleartext in the command line, which Sysmon EID 1 logged
- No destination-side evidence (EID 4624 Type 10) was generated because the connection never completed

**Cleanup:** Stored credentials deleted via `cmdkey /delete`. mstsc process terminated.

## SOC Perspective

### Detection

**Sysmon EID 1 -- Process Create (3 events, source host):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:59:30 | cmdkey.exe | `cmdkey.exe /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:[REDACTED]` | 1904 | Administrator | High |
| 2026-09-15 20:59:30 | mstsc.exe | `mstsc.exe /v:10.10.10.102` | 1832 | Administrator | High |
| 2026-09-15 20:59:40 | cmdkey.exe | `cmdkey.exe /delete:TERMSRV/10.10.10.102` | 5564 | Administrator | High |

All share `LogonGuid: {eb65e329-b1ac-6aa9-026c-580000000000}`.

**Critical finding:** The `cmdkey /add` command line contains `raj.patel`'s password (`[REDACTED]`) in cleartext. Sysmon EID 1 logged this credential exposure. This is both an attack indicator AND a credential compromise -- `raj.patel`'s password is now in the security event log.

**Sysmon EID 3 (Network Connection):** 0 events -- no outbound TCP connection to port 3389 was established (connection failed before TCP handshake completed).

**Security EID 4624 (destination):** No Type 10 (RemoteInteractive) logon events -- the RDP connection never completed. Detection on the destination side requires a successful connection. This makes SOURCE-SIDE detection critical for catching failed/blocked lateral movement attempts.

### Investigation

**Step 1 -- Identify workstation-to-workstation RDP pattern:**
The key indicator is `mstsc.exe /v:<IP>` where the target is another workstation (not a server or jump host). In this case: COMPROMISED-HOST-01 (workstation) -> WIN-CLIENT-02 (workstation). This pattern has very limited legitimate use:
- IT peer-support (rare, typically uses specific remote-assist tools not raw RDP)
- Developer connecting to a test machine (would use a known hostname, not bare IP)

Using a bare IP address rather than hostname further indicates enumeration-driven access rather than routine use.

**Step 2 -- Credential pre-staging analysis:**
The `cmdkey /add:TERMSRV/` + `mstsc` sequence is an automated credential staging pattern. A legitimate user would:
1. Launch mstsc
2. Type the server name
3. Enter credentials in the GUI prompt

An attacker scripts the credential storage to bypass the interactive prompt, enabling:
- Automated lateral movement across multiple hosts
- Credential reuse across sessions
- Execution from non-interactive contexts (scripts, scheduled tasks)

**Step 3 -- Credential exposure in command line:**
The `cmdkey /add` command exposed `raj.patel`'s password in cleartext. This has dual implications:
1. **Attack indicator:** Confirms the attacker possesses raj.patel's credentials (likely harvested from AGC-031 through AGC-036)
2. **Credential compromise:** The password is now in the Sysmon event log, expanding the exposure surface

**Step 4 -- Correlate with discovery chain:**
This follows the complete discovery sequence (AGC-037 through AGC-042) from the same source host. The transition from discovery to lateral movement confirms the attacker is advancing through the kill chain.

### Report

**Verdict: True Positive** -- RDP lateral movement was attempted from a compromised workstation to another workstation using pre-staged credentials.

**Confidence: High** -- Calibrated assessment:
1. Workstation-to-workstation RDP (both endpoints are standard Win11 workstations) has near-zero legitimate use in this environment.
2. The `cmdkey` credential pre-staging pattern (storing credentials before launching mstsc) is not typical of interactive human use.
3. The executing account (Administrator) is using `raj.patel`'s credentials for the RDP connection -- a different account than the one executing the command, indicating credential theft and reuse.
4. The target was specified by IP address (10.10.10.102), consistent with enumeration-driven lateral movement from AGC-041's share sweep results.
5. Even though the connection failed, the ATTEMPT is sufficient for a True Positive classification -- detection should not depend on attack success.

**Response recommendation:**
1. **Immediate: rotate raj.patel's credentials** -- the password was exposed in the cmdkey command line and is now in the Sysmon event log. raj.patel's account should be treated as compromised.
2. **Restrict workstation-to-workstation RDP** via Windows Firewall rules or GPO: deny inbound port 3389 on workstations except from designated jump hosts. This is the most effective preventive control.
3. **Detection rule (source-side):** Alert on `mstsc.exe` process creation where the `/v:` target resolves to a workstation IP (not a server or jump host). Cross-correlate with `cmdkey /add:TERMSRV/` from the same session.
4. **Detection rule (destination-side):** Alert on Security EID 4624 Logon Type 10 where the source IP belongs to a workstation subnet (for successful connections).
5. **Credential exposure alert:** Alert on `cmdkey.exe` command lines containing `/pass:` -- cleartext credential storage in command line is always a high-severity finding regardless of context.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Lateral Movement (TA0008) | T1021.001 | Remote Services: Remote Desktop Protocol | Sysmon EID 1: `mstsc.exe /v:10.10.10.102` launched by Administrator on COMPROMISED-HOST-01. Preceded by `cmdkey /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:***`. Workstation-to-workstation pattern. Connection failed (TCP 3389 unreachable). | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### Raw Sysmon EID 1 (cmdkey /add -- credential staging)

```
Process Create:
UtcTime: 2026-09-15 20:59:30.528
ProcessId: 1904
Image: C:\Windows\System32\cmdkey.exe
OriginalFileName: cmdkey.exe
CommandLine: "C:\WINDOWS\system32\cmdkey.exe" /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:[REDACTED]
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b1ac-6aa9-026c-580000000000}
LogonId: 0x586C02
IntegrityLevel: High
Hashes: MD5=BE45BBC5E0ACF6D8D9D412C688A75CFE
```

### Raw Sysmon EID 1 (mstsc -- RDP launch)

```
Process Create:
UtcTime: 2026-09-15 20:59:30.771
ProcessId: 1832
Image: C:\Windows\System32\mstsc.exe
OriginalFileName: mstsc.exe
CommandLine: "C:\WINDOWS\system32\mstsc.exe" /v:10.10.10.102
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b1ac-6aa9-026c-580000000000}
LogonId: 0x586C02
IntegrityLevel: High
Hashes: MD5=D973D92A3347B480DF39D630264E5CF2
```

### Raw Sysmon EID 1 (cmdkey /delete -- credential cleanup)

```
Process Create:
UtcTime: 2026-09-15 20:59:40.858
ProcessId: 5564
Image: C:\Windows\System32\cmdkey.exe
OriginalFileName: cmdkey.exe
CommandLine: "C:\WINDOWS\system32\cmdkey.exe" /delete:TERMSRV/10.10.10.102
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b1ac-6aa9-026c-580000000000}
LogonId: 0x586C02
IntegrityLevel: High
Hashes: MD5=BE45BBC5E0ACF6D8D9D412C688A75CFE
```
