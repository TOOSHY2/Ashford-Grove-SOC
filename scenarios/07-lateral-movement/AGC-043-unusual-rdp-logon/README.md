# AGC-043 — Unusual RDP Logon (Workstation-to-Workstation)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-043` |
| Category | `07-lateral-movement` — Lateral Movement |
| MITRE Technique | `T1021.001` Remote Services: Remote Desktop Protocol |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures `mstsc.exe /v:<target>` with target IP in command line |
| Time to Triage | 02:00 (verify source is a workstation not a jump host; check for legitimate remote-admin role) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `WIN-CLIENT-02` (10.10.10.102) |
| Chain | ◀ [AGC-042](../../06-discovery/AGC-042-ad-object-query-burst/README.md) (Discovery category) · next [AGC-044](../AGC-044-smb-admin-share/README.md) ▶ |
| One-line Summary | RDP lateral movement attempt from compromised workstation to WIN-CLIENT-02: `cmdkey /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:[REDACTED]` stored credentials (cleartext password in command line), then `mstsc /v:10.10.10.102` launched. Connection did not complete (TCP 3389 unreachable on destination). Sysmon EID 1 captured all 3 events including **cleartext credential in cmdkey command line**. The workstation-to-workstation RDP pattern with pre-stored credentials is a high-confidence lateral movement indicator. |

## Attacker Perspective

### Tradecraft

**What:** The attacker used RDP to pivot from a compromised host toward another system. The workstation-to-workstation variant stands out because:
- Legitimate RDP flows from a user's workstation to a SERVER, or from a jump host to a server
- Workstation-to-workstation RDP has almost no legitimate use outside rare peer-support cases
- The `cmdkey` + `mstsc` pattern (storing credentials before launching RDP) points to scripted lateral movement rather than interactive use

The `cmdkey` pre-staging is a specific indicator on its own:
- `cmdkey /add:TERMSRV/<target> /user:<account> /pass:<password>` stores credentials in Windows Credential Manager
- That skips the interactive credential prompt a human user would see
- The cleartext password lands in the command line, which Sysmon EID 1 captures

**Why at this lifecycle stage:** Discovery (AGC-037 through AGC-042) gave the attacker a map of the environment and a target list. Lateral movement is the next step. RDP suits it because:
1. It gives full interactive desktop access
2. Firewalls often allow it (port 3389 is commonly open)
3. It uses legitimate Windows authentication and blends with normal traffic

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `WIN-CLIENT-02` running (target host).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 20:59:25 | TCP test to 10.10.10.102:3389 | COMPROMISED-HOST-01 | CLOSED/TIMEOUT — RDP port not reachable |
| 2 | 2026-09-15 20:59:30 | cmdkey /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:[REDACTED] | COMPROMISED-HOST-01 | Credential stored successfully |
| 3 | 2026-09-15 20:59:30 | mstsc /v:10.10.10.102 | COMPROMISED-HOST-01 | Launched (PID 1832), hung waiting for GUI, killed after 10s |
| 4 | 2026-09-15 20:59:40 | cmdkey /delete:TERMSRV/10.10.10.102 | COMPROMISED-HOST-01 | Credential cleaned up |

**Key findings:**
- The RDP connection did NOT complete — TCP 3389 was unreachable on WIN-CLIENT-02 (Windows Firewall likely blocking inbound RDP, or a routing issue)
- The SOURCE-SIDE evidence is still complete: mstsc process creation, credential storage, and target IP were all captured
- The `cmdkey` command put `raj.patel`'s cleartext password in the command line, and Sysmon EID 1 logged it
- No destination-side evidence (EID 4624 Type 10) exists because the connection never completed

**Cleanup:** Stored credentials deleted via `cmdkey /delete`. mstsc process terminated.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (3 events, source host):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:59:30 | cmdkey.exe | `cmdkey.exe /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:[REDACTED]` | 1904 | Administrator | High |
| 2026-09-15 20:59:30 | mstsc.exe | `mstsc.exe /v:10.10.10.102` | 1832 | Administrator | High |
| 2026-09-15 20:59:40 | cmdkey.exe | `cmdkey.exe /delete:TERMSRV/10.10.10.102` | 5564 | Administrator | High |

All share `LogonGuid: {eb65e329-b1ac-6aa9-026c-580000000000}`.

**Critical finding:** The `cmdkey /add` command line contains `raj.patel`'s password (`[REDACTED]`) in cleartext, and Sysmon EID 1 logged it. That is both an attack indicator AND a credential compromise — `raj.patel`'s password now sits in the security event log.

**Sysmon EID 3 (Network Connection):** 0 events — no outbound TCP connection to port 3389 was established; the attempt failed before the handshake completed.

**Security EID 4624 (destination):** No Type 10 (RemoteInteractive) logon events — the RDP connection never completed. Destination-side detection needs a completed connection, so source-side telemetry is the only record of a blocked attempt like this one.

### Investigation

**Step 1 — Identify workstation-to-workstation RDP pattern:**
The indicator is `mstsc.exe /v:<IP>` where the target is another workstation, not a server or jump host. Here: COMPROMISED-HOST-01 (workstation) -> WIN-CLIENT-02 (workstation). Legitimate uses of that pattern are few:
- IT peer-support (rare, and usually done with a remote-assist tool rather than raw RDP)
- A developer connecting to a test machine (who would use a known hostname, not a bare IP)

The bare IP, rather than a hostname, points to enumeration-driven access rather than routine use.

**Step 2 — Credential pre-staging analysis:**
The `cmdkey /add:TERMSRV/` + `mstsc` sequence stages credentials ahead of the connection. A legitimate user would:
1. Launch mstsc
2. Type the server name
3. Enter credentials in the GUI prompt

Scripting the credential storage skips the interactive prompt, which gives the attacker:
- Automated lateral movement across multiple hosts
- Credential reuse across sessions
- Execution from non-interactive contexts (scripts, scheduled tasks)

**Step 3 — Credential exposure in command line:**
The `cmdkey /add` command exposed `raj.patel`'s password in cleartext. That cuts two ways:
1. **Attack indicator:** The attacker holds raj.patel's credentials, most likely harvested during AGC-031 through AGC-036
2. **Credential compromise:** The password is now in the Sysmon event log, so anyone who can read that log has it too

**Step 4 — Correlate with discovery chain:**
The attempt came from the same source host that ran the full discovery sequence (AGC-037 through AGC-042). Discovery followed by a pivot attempt shows the attacker moving on from looking to acting.

### Report

**Verdict: True Positive** — RDP lateral movement was attempted from a compromised workstation to another workstation using pre-staged credentials.

**Confidence: High** — Calibrated assessment:
1. Workstation-to-workstation RDP (both endpoints are standard Win11 workstations) has near-zero legitimate use in the lab.
2. Storing credentials with `cmdkey` before launching mstsc is not how a human uses RDP interactively.
3. The executing account (Administrator) supplied `raj.patel`'s credentials for the RDP connection — a different account from the one running the command, which reads as credential theft and reuse.
4. The target was given by IP address (10.10.10.102), consistent with a pivot driven by AGC-041's share sweep results.
5. The connection failed, but the attempt alone supports a true positive — detection should not depend on the attack succeeding.

**Response recommendation:**
1. **Immediate: rotate raj.patel's credentials** — the password was exposed in the cmdkey command line and is now in the Sysmon event log. Treat raj.patel's account as compromised.
2. **Restrict workstation-to-workstation RDP** via Windows Firewall rules or GPO: deny inbound port 3389 on workstations except from designated jump hosts.
3. **Detection rule (source-side):** Alert on `mstsc.exe` process creation where the `/v:` target resolves to a workstation IP (not a server or jump host). Correlate with `cmdkey /add:TERMSRV/` from the same session.
4. **Detection rule (destination-side):** Alert on Security EID 4624 Logon Type 10 where the source IP belongs to a workstation subnet (catches the successful connections).
5. **Credential exposure alert:** Alert on `cmdkey.exe` command lines containing `/pass:` — a cleartext credential in a command line is high severity regardless of context.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Lateral Movement (TA0008) | T1021.001 | Remote Services: Remote Desktop Protocol | Sysmon EID 1: `mstsc.exe /v:10.10.10.102` launched by Administrator on COMPROMISED-HOST-01. Preceded by `cmdkey /add:TERMSRV/10.10.10.102 /user:raj.patel /pass:***`. Workstation-to-workstation pattern. Connection failed (TCP 3389 unreachable). | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Raw Sysmon EID 1 (cmdkey /add — credential staging)

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

### Raw Sysmon EID 1 (mstsc — RDP launch)

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

### Raw Sysmon EID 1 (cmdkey /delete — credential cleanup)

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
