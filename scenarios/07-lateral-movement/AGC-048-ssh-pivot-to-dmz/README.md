# AGC-048 — SSH Pivot LAN to DMZ

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-048` |
| Category | `07-lateral-movement` — Lateral Movement |
| MITRE Technique | `T1021.004` Remote Services: SSH |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures `ssh.exe` with target host and username in command line; firewall log captures LAN->DMZ SSH rule hit |
| Time to Triage | 03:00 (verify the SSH connection is attributable to a scheduled maintenance task; cross-zone SSH from workstation is extremely high-signal) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `DMZ-LINUX-01` (10.10.20.10) |
| Chain | ◀ [AGC-047](../AGC-047-pass-the-hash/README.md) · next [AGC-049](../AGC-049-account-multi-host-auth/README.md) ▶ |
| One-line Summary | SSH lateral movement from LAN workstation to DMZ Linux host attempted. `ssh.exe dmzadmin@10.10.20.10` — connection timed out (LAN->DMZ routing blocked by firewall). Second attempt to EXT zone (`kaliadmin@10.10.40.10`) also timed out. 2 Sysmon EID 1 events captured ssh.exe with target usernames and cross-zone IPs. LAN workstation initiating SSH to DMZ is an extremely high-signal indicator — workstations have no legitimate reason to SSH to DMZ servers. |

## Attacker Perspective

### Tradecraft

**What:** SSH pivoting is a lateral movement technique where an attacker uses the SSH protocol to move from a compromised LAN host to a server in a different network zone (DMZ, external). This cross-zone movement is significant because:
- It crosses network trust boundaries (LAN -> DMZ)
- SSH provides an encrypted channel that hides command content from network monitoring
- Once on a DMZ host, the attacker can potentially reach internet-facing services and pivot further outward

**Why this is extremely high-signal:** LAN workstations have almost no legitimate reason to SSH to DMZ servers. SSH to DMZ is typically restricted to:
- Designated jump hosts / bastion hosts
- IT automation servers (Ansible, Puppet)
- Scheduled maintenance windows with specific service accounts

A standard user workstation initiating SSH to a DMZ host outside of these contexts is nearly always malicious.

**Why at this lifecycle stage:** After exhausting Windows-to-Windows lateral movement protocols (RDP, SMB, WinRM, WMI, PtH), the attacker pivots to cross-OS and cross-zone movement. The DMZ hosts Linux services that are not accessible via Windows-native protocols, so SSH is the natural next protocol.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `DMZ-LINUX-01` running (target host, 10.10.20.10).
- Windows 11 includes OpenSSH client at `C:\Windows\System32\OpenSSH\ssh.exe` (v9.5.6.2).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 21:23:46 | TCP test to 10.10.20.10:22 | COMPROMISED-HOST-01 | CLOSED/TIMEOUT — SSH port not reachable |
| 2 | 2026-09-15 21:23:51 | ssh dmzadmin@10.10.20.10 | COMPROMISED-HOST-01 | Connection timed out (LAN->DMZ blocked) |
| 3 | 2026-09-15 21:24:01 | ssh kaliadmin@10.10.40.10 | COMPROMISED-HOST-01 | Connection timed out (LAN->EXT blocked) |

**Key findings:**
- Both cross-zone SSH attempts were blocked by the OPNsense firewall (LAN->DMZ and LAN->EXT routing not permitted for workstation traffic)
- The firewall correctly enforces zone separation — this is a functioning security control
- Despite connection failure, the SSH ATTEMPT is the detection indicator. The attacker's intent to pivot cross-zone is clear from the command line
- OpenSSH client is pre-installed on Windows 11 — no additional tool installation required for SSH-based lateral movement

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (2 events):**

**Event 1: SSH to DMZ-LINUX-01**
```
Process Create:
UtcTime: 2026-09-15 21:23:51.615
ProcessId: 5448
Image: C:\Windows\System32\OpenSSH\ssh.exe
Product: OpenSSH for Windows
CommandLine: "C:\WINDOWS\System32\OpenSSH\ssh.exe" -o StrictHostKeyChecking=no
  -o ConnectTimeout=10 -o BatchMode=yes
  dmzadmin@10.10.20.10
  "echo AGC-048-pivot-success; hostname; whoami; date"
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b761-6aa9-336a-5f0000000000}
LogonId: 0x5F6A33
IntegrityLevel: High
Hashes: MD5=C6E16CAC83683DFA4244E5E86780DAFF
```

**Event 2: SSH to EXT-ATTACKER-SIM**
```
Process Create:
UtcTime: 2026-09-15 21:24:01.764
ProcessId: 2336
Image: C:\Windows\System32\OpenSSH\ssh.exe
CommandLine: "C:\WINDOWS\System32\OpenSSH\ssh.exe" -o StrictHostKeyChecking=no
  -o ConnectTimeout=10 -o BatchMode=yes
  kaliadmin@10.10.40.10
  "echo AGC-048-kali-pivot; hostname; whoami"
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b761-6aa9-336a-5f0000000000}
IntegrityLevel: High
```

**Critical indicators:**
1. **ssh.exe launched from a workstation** — standard user workstations should not initiate SSH connections
2. **Target IPs in different network zones** — 10.10.20.10 (DMZ) and 10.10.40.10 (External) are outside the LAN zone (10.10.10.x)
3. **-o StrictHostKeyChecking=no** — disabling host key verification is a common attacker flag (suppresses interactive prompts for unknown hosts)
4. **-o BatchMode=yes** — non-interactive SSH is consistent with scripted/automated lateral movement
5. **Remote command in argument** — executing commands via SSH argument (not interactive shell) indicates fire-and-forget execution

**Sysmon EID 3 (Network Connection):** 0 events — SSH connections timed out before TCP handshake completed. In a successful connection, EID 3 would show the outbound TCP connection to port 22. However, SwiftOnSecurity config may filter EID 3 for ssh.exe.

### Investigation

**Step 1 — Identify cross-zone SSH from workstation:**
The primary indicator is `ssh.exe` process creation on a workstation with a target IP in a different network zone. Parse the command line for:
- Target format: `user@IP` or `user@hostname`
- Target IP subnet: if the target is outside the source host's subnet, this is cross-zone movement
- In this case: source is 10.10.10.103 (LAN), targets are 10.10.20.10 (DMZ) and 10.10.40.10 (EXT)

**Step 2 — Check firewall logs for LAN->DMZ SSH rule:**
OPNsense should log this connection attempt against the LAN->DMZ SSH rule. Even if the connection was blocked, the firewall log records the attempt with source IP, destination IP, and timestamp. A blocked connection still means the attacker attempted cross-zone movement.

**Step 3 — Verify maintenance attribution:**
For any LAN->DMZ SSH connection (successful or attempted), verify it corresponds to a scheduled maintenance task:
- Who authorized the SSH session?
- What maintenance ticket does it correspond to?
- Is the source host a designated jump host or management workstation?

In this case: COMPROMISED-HOST-01 is a standard user workstation (michael.chen's workstation), not a jump host. There is no maintenance task to attribute this connection to. This is unattributed cross-zone SSH from a standard workstation — extremely high confidence True Positive.

**Step 4 — Cross-reference credential source:**
The SSH attempts use `dmzadmin` and `kaliadmin` usernames. Where did the attacker obtain these credentials? Cross-reference with:
- AGC-033 (browser credential store) — may have contained saved SSH passwords
- Configuration files on COMPROMISED-HOST-01 that might contain SSH keys or credentials
- The dmzadmin credential is the DMZ-LINUX-01 administrator account

### Report

**Verdict: True Positive** — Cross-zone SSH lateral movement was attempted from a LAN workstation to DMZ and external network zones.

**Confidence: High** — Calibrated assessment:
1. A standard user workstation (COMPROMISED-HOST-01) has zero legitimate reason to initiate SSH to DMZ servers. The narrow scope of legitimate LAN->DMZ SSH traffic means any unattributed connection is extremely high-signal.
2. Two cross-zone SSH attempts in rapid succession (10 seconds apart) targeting different zones (DMZ and EXT) indicates systematic enumeration, not accidental connection.
3. The `-o StrictHostKeyChecking=no -o BatchMode=yes` flags are consistent with automated/scripted lateral movement, not interactive human SSH usage.
4. The target usernames (`dmzadmin`, `kaliadmin`) are administrative accounts, confirming the attacker possesses or is attempting to use privileged credentials.
5. The firewall correctly blocked both connections — this is a successfully defended scenario, but the attempt requires incident response.

**Response recommendation:**
1. **Immediate: investigate COMPROMISED-HOST-01** — the SSH pivot attempt confirms the host is under attacker control and the attacker is actively attempting to expand beyond the LAN zone.
2. **Rotate DMZ credentials:** Change `dmzadmin` password on DMZ-LINUX-01 and revoke any SSH keys associated with this account, in case the attacker has valid credentials.
3. **Verify firewall rules:** Confirm that LAN->DMZ SSH is restricted to designated jump hosts only. The firewall correctly blocked this attempt.
4. **Detection rule:** Alert on `ssh.exe` process creation from any workstation (not a jump host/management server). Cross-reference target IP against DMZ/external subnets for elevated priority.
5. **Network segmentation validation:** This scenario validates that the OPNsense firewall correctly enforces LAN->DMZ zone separation for SSH traffic.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Lateral Movement (TA0008) | T1021.004 | Remote Services: SSH | Sysmon EID 1: `ssh.exe dmzadmin@10.10.20.10` (PID 5448) and `ssh.exe kaliadmin@10.10.40.10` (PID 2336) from workstation COMPROMISED-HOST-01. Cross-zone LAN->DMZ and LAN->EXT SSH attempts. Both connections timed out (firewall blocked). OpenSSH for Windows v9.5.6.2. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### SSH pivot attempt results

```
DMZ-LINUX-01 (10.10.20.10:22):   Connection timed out (LAN->DMZ blocked by firewall)
EXT-ATTACKER-SIM (10.10.40.10:22): Connection timed out (LAN->EXT blocked by firewall)
OpenSSH client:                   C:\Windows\System32\OpenSSH\ssh.exe v9.5.6.2
```

### Raw Sysmon EID 1 (ssh to DMZ-LINUX-01)

```
Process Create:
UtcTime: 2026-09-15 21:23:51.615
ProcessId: 5448
Image: C:\Windows\System32\OpenSSH\ssh.exe
Product: OpenSSH for Windows
FileVersion: 9.5.6.2
CommandLine: "C:\WINDOWS\System32\OpenSSH\ssh.exe" -o StrictHostKeyChecking=no
  -o ConnectTimeout=10 -o BatchMode=yes
  dmzadmin@10.10.20.10
  "echo AGC-048-pivot-success; hostname; whoami; date"
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b761-6aa9-336a-5f0000000000}
LogonId: 0x5F6A33
IntegrityLevel: High
Hashes: MD5=C6E16CAC83683DFA4244E5E86780DAFF
```

### Raw Sysmon EID 1 (ssh to EXT-ATTACKER-SIM)

```
Process Create:
UtcTime: 2026-09-15 21:24:01.764
ProcessId: 2336
Image: C:\Windows\System32\OpenSSH\ssh.exe
Product: OpenSSH for Windows
FileVersion: 9.5.6.2
CommandLine: "C:\WINDOWS\System32\OpenSSH\ssh.exe" -o StrictHostKeyChecking=no
  -o ConnectTimeout=10 -o BatchMode=yes
  kaliadmin@10.10.40.10
  "echo AGC-048-kali-pivot; hostname; whoami"
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b761-6aa9-336a-5f0000000000}
LogonId: 0x5F6A33
IntegrityLevel: High
Hashes: MD5=C6E16CAC83683DFA4244E5E86780DAFF
```
