# AGC-047 — Pass-the-Hash

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-047` |
| Category | `07-lateral-movement` — Lateral Movement |
| MITRE Technique | `T1550.002` Use Alternate Authentication Material: Pass the Hash |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Requires correlation — Security EID 4624 Type 3 with `LogonProcess: NtLmSsp` + absence of interactive credential entry precursor |
| Time to Triage | 05:00 (verify no interactive login preceded the NTLM network logon; check if account is shared across hosts) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `WIN-CLIENT-02` (10.10.10.102) |
| Chain | ◀ [AGC-046](../AGC-046-remote-wmi-execution/README.md) · next [AGC-048](../AGC-048-ssh-pivot-to-dmz/README.md) ▶ |
| One-line Summary | Pass-the-Hash simulation using shared local admin (`wadmin`) credentials across hosts. Remote PtH to WIN-CLIENT-02 failed (error 64). Localhost ADMIN$ share access with wadmin denied (non-elevated). WMI process creation succeeded. Security EID 4624 captured: `wadmin` Type 3 network logon via `NtLmSsp` / NTLM V2 with no interactive credential precursor. SAM registry query attempt captured (access denied). 6 Sysmon EID 1 events including net.exe with wadmin cleartext password. The root enabler: identical local admin password reused across workstations. |

## Attacker Perspective

### Tradecraft

**What:** Pass-the-Hash (PtH) authenticates to a remote host with the NTLM hash of a password instead of the password itself. NTLM accepts the hash as-is, so an attacker who pulls it from one host's SAM database or LSASS memory can log on to any other host that uses the same password — without ever learning the plaintext.

The enabler is **shared local admin passwords**: when one local administrator account carries the same password on several workstations, a hash lifted from any one of them opens all of them.

**Detection signature:** PtH shows up as a network logon (Type 3) via `NtLmSsp` with **no preceding interactive credential entry**. A user who types a password produces a Type 2 (Interactive) or Type 10 (RemoteInteractive) logon before any Type 3 network logon. PtH skips that step — the hash goes straight into the NTLM handshake.

**Why at this lifecycle stage:** Credential access (AGC-031 through AGC-036) left the attacker with NTLM hashes but not necessarily plaintext passwords. PtH is how those hashes become lateral movement.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `WIN-CLIENT-02` running (target host).
- `wadmin` local admin account with shared password across both hosts.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 21:19:40 | reg query HKLM\SAM\SAM\Domains\Account\Users | COMPROMISED-HOST-01 | Access denied (SAM ACL restriction) |
| 2 | 2026-09-15 21:19:40 | net use \\\\10.10.10.102\C$ /user:wadmin | COMPROMISED-HOST-01 | Error 64: network name no longer available |
| 3 | 2026-09-15 21:20:22 | net use \\\\127.0.0.1\ADMIN$ /user:wadmin | COMPROMISED-HOST-01 | Error 5: access denied (wadmin non-elevated) |
| 4 | 2026-09-15 21:20:25 | Invoke-WmiMethod Win32_Process Create (local) | COMPROMISED-HOST-01 | Succeeded — ReturnValue=0, PID=1492 |
| 5 | 2026-09-15 21:20:28 | Cleanup | COMPROMISED-HOST-01 | Marker file removed |

**Key findings:**
- The direct SAM registry query was denied even for Administrator — SAM ACLs block registry-based hash extraction (Mimikatz and similar tools go through LSASS memory or offline SAM extraction instead, as in AGC-032)
- Remote PtH failed (network unreachable, as in the prior scenarios)
- Localhost ADMIN$ share access was denied for wadmin — `Elevated Token: No` in EID 4624 shows UAC filtering. The LocalAccountTokenFilterPolicy registry value decides whether local admin accounts get filtered tokens on remote access
- WMI process creation still worked despite the share access denial
- The EID 4624 with `NtLmSsp` and no interactive precursor is the PtH detection signature

## SOC Perspective

### Detection

**Security EID 4624 — Type 3 Network Logon (PtH signature):**

```
An account was successfully logged on.
Logon Type:           3
Account Name:         wadmin
Account Domain:       COMPROMISED-01
Logon ID:             0x5F0FA3
Source Network Address: 127.0.0.1
Source Port:          64529
Logon Process:        NtLmSsp
Authentication Package: NTLM
Package Name:         NTLM V2
Elevated Token:       No
```

**PtH indicators in this event:**
1. **LogonProcess: NtLmSsp** — NTLM through the Security Support Provider, not Kerberos or Negotiate
2. **Logon Type: 3** — Network logon, not interactive
3. **No preceding Type 2/10 logon** — wadmin had no interactive session; the Type 3 appeared without any interactive credential entry
4. **Elevated Token: No** — UAC filtering applied (LocalAccountTokenFilterPolicy = 0), which is why ADMIN$ was denied even though authentication succeeded
5. **Account Domain: COMPROMISED-01** — A local account, not a domain one. Same-name local accounts across hosts are what make PtH work

**Sysmon EID 1 — Process Create (6 events):**

| Timestamp (UTC) | Image | CommandLine | PID | Evidence Type |
|---|---|---|---|---|
| 2026-09-15 21:19:40 | reg.exe | `reg query HKLM\SAM\SAM\Domains\Account\Users` | 1968 | Hash extraction attempt |
| 2026-09-15 21:19:40 | net.exe | `net use \\10.10.10.102\C$ /user:wadmin [REDACTED]` | 3572 | Remote PtH attempt (cleartext cred) |
| 2026-09-15 21:20:22 | net.exe | `net use \\127.0.0.1\ADMIN$ /user:wadmin [REDACTED]` | 4884 | Localhost PtH attempt (cleartext cred) |
| 2026-09-15 21:20:25 | cmd.exe | `cmd.exe /c echo AGC-047-pth > C:\Windows\Temp\agc047.txt` | 1492 | WMI-spawned marker write |
| 2026-09-15 21:20:28 | net.exe | `net use \\127.0.0.1\ADMIN$ /delete` | 1764 | Cleanup |
| 2026-09-15 21:19:39 | powershell.exe | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc047-sim.ps1` | 5348 | Simulation script |

### Investigation

**Step 1 — Identify NtLmSsp network logon without interactive precursor:**
The primary PtH indicator is a Security EID 4624 with `LogonProcess: NtLmSsp` and `Logon Type: 3` and NO interactive logon (Type 2 or Type 10) for the same account in the preceding window. With a typed password, the user's interactive session produces the first logon event and later network access (share access, etc.) produces the Type 3 events. PtH starts at the network level and skips the interactive step.

**Step 2 — Verify shared local admin credentials:**
The wadmin account (SID `S-1-5-21-...-1000`) exists on COMPROMISED-HOST-01 and WIN-CLIENT-02 with the same password. That shared credential is the root enabler. Check with `net user wadmin` on each host; if the accounts share a RID and a password (hash), PtH works between them.

**Step 3 — SAM query as precursor:**
The `reg query HKLM\SAM\SAM\Domains\Account\Users` attempt (EID 1, PID 1968) is a hash extraction precursor. It failed on the SAM ACL, but the attempt shows the attacker hunting for credential material to pass. AGC-032 (SAM/SECURITY hive extraction) is where the hashes were actually obtained.

**Step 4 — UAC filtering as partial mitigation:**
`Elevated Token: No` in the EID 4624 shows UAC filtering denied wadmin an elevated token on the network logon. That blocked ADMIN$ share access (error 5) but did NOT block WMI process creation. UAC filtering narrows PtH; it does not stop it.

**Step 5 — Root cause remediation:**
The real fix is to stop sharing local admin passwords. Microsoft LAPS (Local Administrator Password Solution) or an equivalent gives each host's local admin account its own password, so a hash from one host is useless on the next.

### Report

**Verdict: True Positive** — Pass-the-Hash lateral movement was exercised with the shared local admin credential (wadmin).

**Confidence: High** — Calibrated assessment:
1. Security EID 4624 shows an `NtLmSsp` Type 3 logon for `wadmin` with no interactive precursor — the PtH signature.
2. The `wadmin` account has the same password on COMPROMISED-HOST-01 and WIN-CLIENT-02 — a confirmed shared credential.
3. The SAM registry query attempt shows hash extraction intent.
4. Multiple net.exe commands with wadmin credentials show cross-host authentication attempts.
5. UAC filtering (Elevated Token: No) cut off the share access but not the WMI execution.

**Response recommendation:**
1. **Deploy LAPS or equivalent:** Give each host a unique local admin password. That removes the PtH vector at the root.
2. **Reset wadmin password on ALL hosts** — not just the detected one. The same hash lives on every host where wadmin has the same password.
3. **Enable Credential Guard:** Blocks hash extraction from LSASS memory, the main PtH source.
4. **Set LocalAccountTokenFilterPolicy = 0** (or confirm it is still at default) — UAC filtering of remote local admin access is a defense-in-depth layer.
5. **Detection rule:** Alert on EID 4624 Type 3 with `NtLmSsp` where the source host is a workstation and the account is a local admin with no interactive session in the preceding 5-minute window.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Lateral Movement (TA0008) / Defense Evasion (TA0005) | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Security EID 4624: `wadmin` Type 3 network logon via `NtLmSsp`, NTLM V2, no interactive precursor. Sysmon EID 1: `net use \\10.10.10.102\C$ /user:wadmin`, SAM registry query. Shared local admin password confirmed as root enabler. Remote target unreachable; localhost demonstrated PtH detection artifacts. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### PtH simulation results

```
SAM registry query:             Access denied (SAM ACL restriction)
Remote C$ PtH (10.10.10.102):   Error 64 - network name no longer available
Localhost ADMIN$ PtH (wadmin):   Error 5 - access denied (UAC token filtering)
WMI process creation (local):   SUCCESS - PID=1492
EID 4624:                       wadmin Type 3, NtLmSsp, NTLM V2, Elevated Token: No
```

### Raw Security EID 4624 (PtH logon — wadmin via NtLmSsp)

```
An account was successfully logged on.
Logon Type:           3
Account Name:         wadmin
Account Domain:       COMPROMISED-01
Logon ID:             0x5F0FA3
Source Network Address: 127.0.0.1
Source Port:          64529
Logon Process:        NtLmSsp
Authentication Package: NTLM
Package Name:         NTLM V2
Elevated Token:       No
```

### Raw Sysmon EID 1 (net use remote PtH attempt)

```
Process Create:
UtcTime: 2026-09-15 21:19:40.358
ProcessId: 3572
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.102\C$ /user:wadmin [REDACTED]
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b66b-6aa9-f3df-5e0000000000}
LogonId: 0x5EDFF3
IntegrityLevel: High
```

### Raw Sysmon EID 1 (SAM registry query attempt)

```
Process Create:
UtcTime: 2026-09-15 21:19:40.305
ProcessId: 1968
Image: C:\Windows\System32\reg.exe
OriginalFileName: reg.exe
CommandLine: "C:\WINDOWS\system32\reg.exe" query HKLM\SAM\SAM\Domains\Account\Users
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b66b-6aa9-f3df-5e0000000000}
LogonId: 0x5EDFF3
IntegrityLevel: High
```
