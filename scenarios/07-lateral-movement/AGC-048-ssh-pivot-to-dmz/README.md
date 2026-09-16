# AGC-048 — SSH Pivot LAN to DMZ

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**What:** The attacker used SSH to try to move from a compromised LAN host to a server in another network zone (DMZ, external). Cross-zone movement matters because:
- It crosses a network trust boundary (LAN -> DMZ)
- SSH encrypts the channel, so network monitoring cannot see the command content
- From a DMZ host the attacker can reach internet-facing services and pivot further out

**Why this is extremely high-signal:** LAN workstations have almost no legitimate reason to SSH to DMZ servers. SSH to the DMZ is usually limited to:
- Designated jump hosts / bastion hosts
- IT automation servers (Ansible, Puppet)
- Scheduled maintenance windows with specific service accounts

A standard user workstation opening SSH to a DMZ host outside those contexts is nearly always malicious.

**Why at this lifecycle stage:** With the Windows-to-Windows protocols exhausted (RDP, SMB, WinRM, WMI, PtH), the attacker moved to cross-OS and cross-zone movement. The DMZ runs Linux services that Windows-native protocols cannot reach, so SSH is the next protocol to try.

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
- The OPNsense firewall blocked both cross-zone SSH attempts (LAN->DMZ and LAN->EXT routing is not permitted for workstation traffic)
- Zone separation held — the firewall did its job here
- The connections failed, but the SSH ATTEMPT is the detection indicator; the command line spells out the intent to pivot across zones
- The OpenSSH client ships with Windows 11, so the attacker needed no extra tooling for SSH-based lateral movement

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
1. **ssh.exe launched from a workstation** — standard user workstations should not be opening SSH connections
2. **Target IPs in different network zones** — 10.10.20.10 (DMZ) and 10.10.40.10 (External) sit outside the LAN zone (10.10.10.x)
3. **-o StrictHostKeyChecking=no** — turning off host key verification suppresses the unknown-host prompt, which attackers do to keep scripts running
4. **-o BatchMode=yes** — non-interactive SSH fits scripted lateral movement
5. **Remote command in argument** — passing the command as an SSH argument instead of opening a shell is fire-and-forget execution

**Sysmon EID 3 (Network Connection):** 0 events — the SSH connections timed out before the TCP handshake completed. A successful connection would show an outbound EID 3 to port 22, though the SwiftOnSecurity config may filter EID 3 for ssh.exe.

### Investigation

**Step 1 — Identify cross-zone SSH from workstation:**
The primary indicator is `ssh.exe` process creation on a workstation with a target IP in another network zone. Parse the command line for:
- Target format: `user@IP` or `user@hostname`
- Target IP subnet: a target outside the source host's subnet means cross-zone movement
- Here: source is 10.10.10.103 (LAN), targets are 10.10.20.10 (DMZ) and 10.10.40.10 (EXT)

**Step 2 — Check firewall logs for LAN->DMZ SSH rule:**
OPNsense should log this attempt against the LAN->DMZ SSH rule. Blocked or not, the firewall log records source IP, destination IP, and timestamp. A blocked connection still means the attacker tried to cross zones.

**Step 3 — Verify maintenance attribution:**
For any LAN->DMZ SSH connection, successful or attempted, tie it to a scheduled maintenance task:
- Who authorized the SSH session?
- Which maintenance ticket does it belong to?
- Is the source host a designated jump host or management workstation?

Here COMPROMISED-HOST-01 is a standard user workstation (michael.chen's), not a jump host, and no maintenance task covers this connection. Unattributed cross-zone SSH from a standard workstation is a high-confidence true positive.

**Step 4 — Cross-reference credential source:**
The SSH attempts use the `dmzadmin` and `kaliadmin` usernames. Where did the attacker get them? Check:
- AGC-033 (browser credential store) — may have held saved SSH passwords
- Configuration files on COMPROMISED-HOST-01 that might hold SSH keys or credentials
- The dmzadmin credential is the DMZ-LINUX-01 administrator account

### Report

**Verdict: True Positive** — Cross-zone SSH lateral movement was attempted from a LAN workstation to the DMZ and external zones.

**Confidence: High** — Calibrated assessment:
1. A standard user workstation (COMPROMISED-HOST-01) has no legitimate reason to SSH to DMZ servers. Legitimate LAN->DMZ SSH is so narrow that any unattributed connection is high-signal.
2. Two cross-zone SSH attempts 10 seconds apart against different zones (DMZ and EXT) look like systematic enumeration, not a stray connection.
3. The `-o StrictHostKeyChecking=no -o BatchMode=yes` flags fit scripted lateral movement, not a person at a terminal.
4. The target usernames (`dmzadmin`, `kaliadmin`) are administrative accounts, so the attacker holds or is guessing at privileged credentials.
5. The firewall blocked both connections — the defense held, but the attempt still needs incident response.

**Response recommendation:**
1. **Immediate: investigate COMPROMISED-HOST-01** — the SSH pivot attempt confirms the host is under attacker control and the attacker is pushing beyond the LAN zone.
2. **Rotate DMZ credentials:** Change the `dmzadmin` password on DMZ-LINUX-01 and revoke any SSH keys tied to that account, in case the attacker holds valid credentials.
3. **Verify firewall rules:** Confirm LAN->DMZ SSH is limited to designated jump hosts. The rule that blocked this attempt is the one to keep.
4. **Detection rule:** Alert on `ssh.exe` process creation from any workstation (not a jump host or management server). Raise priority when the target IP falls in a DMZ or external subnet.
5. **Network segmentation validation:** This attempt confirms the OPNsense firewall enforces LAN->DMZ zone separation for SSH traffic.

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
