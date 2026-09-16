# AGC-036 — NTLM Authentication Anomaly

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-036` |
| Category | `05-credential-access` — Credential Access |
| MITRE Technique | `T1557.001` Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay (candidate — see Investigation) |
| Verdict | True Positive (Probable) |
| Confidence | Medium |
| Time to Detect | Immediate — Security EID 4624 with `AuthenticationPackageName: NTLM` and null Logon GUID |
| Time to Triage | 05:00 (must determine WHY NTLM was used instead of Kerberos before escalating) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-035](../AGC-035-password-spray/README.md) · next [AGC-037](../../06-discovery/AGC-037-system-user-discovery/README.md) (Discovery category) ▶ |
| FP Twin | AGC-084 (benign DNS pattern producing similar NTLM traffic) |
| One-line Summary | NTLM authentication observed via IP-based SMB connection on a domain-joined host. EID 4624 confirms Logon Type 3 with `NTLM V2` package and null Logon GUID (`{00000000-...}`). Root cause identified as IP-based connection bypassing Kerberos SPN lookup. Benign explanation confirmed — confidence remains Medium. |

## Attacker Perspective

### Tradecraft

**What:** In an Active Directory environment, Kerberos is the default authentication protocol. NTLM is a fallback that is less secure and vulnerable to relay attacks. When NTLM authentication occurs between two Kerberos-capable domain-joined hosts, it can indicate:

1. **Legitimate cause:** IP-based connections (no SPN for Kerberos to resolve), legacy applications, DNS misconfiguration, or broken domain trust
2. **Malicious cause:** NTLM relay attack (T1557.001) where an adversary-in-the-middle intercepts NTLM authentication and relays it to a target server, or forced NTLM downgrade as part of credential theft

An attacker can force NTLM by connecting via IP address instead of hostname, by poisoning DNS/LLMNR/NBT-NS responses, or by exploiting applications that use NTLM by default. The captured NTLM handshake can then be:
- **Relayed** to another service (NTLM relay / SMB relay)
- **Cracked offline** (NTLM V1 is trivially cracked; NTLM V2 resists but is still attackable with dictionary/rainbow tables)

**Why at this lifecycle stage:** After exhausting direct credential access techniques (AGC-031 through AGC-035), an attacker may pivot to NTLM-based attacks. Forcing NTLM fallback is a precondition for NTLM relay attacks, which can enable authentication to other services using the victim's captured credentials without knowing the password.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- Domain trust broken (discovered AGC-025) — all authentication on this host is already NTLM-only.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 20:27:44 | IP-based SMB to localhost | COMPROMISED-HOST-01 | `net use \\127.0.0.1\C$ /user:Administrator [REDACTED]` — succeeded. Forces NTLM (no Kerberos SPN for IP addresses). |
| 2 | 2026-09-15 20:27:46 | Verify connection | COMPROMISED-HOST-01 | `net use` listing confirms `\\127.0.0.1\C$` active. |
| 3 | 2026-09-15 20:27:48 | IP-based SMB to self-IP | COMPROMISED-HOST-01 | `net use \\10.10.10.103\IPC$ /user:Administrator [REDACTED]` — succeeded. Second NTLM auth generated. |
| 4 | 2026-09-15 20:28:05 | Cleanup | COMPROMISED-HOST-01 | Both connections deleted. |

**Why IP-based connection forces NTLM:**
Kerberos authentication requires a Service Principal Name (SPN) lookup: the client asks the KDC for a ticket for `cifs/hostname.domain.local`. When connecting by IP address, there is no hostname to construct the SPN, so the authentication stack falls back to NTLM. This is the most common benign cause of NTLM usage in enterprise environments.

**Cleanup:** Connections deleted. No persistent artifacts.

## SOC Perspective

### Detection

**Security EID 4624 — Successful Logon via NTLM (2 events):**

| Timestamp (UTC) | EID | Account | Source IP | Logon Type | Auth Package | NTLM Version | Logon GUID | Elevated |
|---|---|---|---|---|---|---|---|---|
| 2026-09-15 20:27:44 | 4624 | Administrator (COMPROMISED-01) | 127.0.0.1:64393 | 3 (Network) | NTLM | NTLM V2 | {00000000-0000-0000-0000-000000000000} | Yes |
| 2026-09-15 20:27:48 | 4624 | Administrator (COMPROMISED-01) | 10.10.10.103:64394 | 3 (Network) | NTLM | NTLM V2 | {00000000-0000-0000-0000-000000000000} | Yes |

**Key NTLM indicators in EID 4624:**
- `Authentication Package: NTLM` (not `Kerberos`)
- `Package Name (NTLM only): NTLM V2` — NTLM V2 is more secure than V1 but still vulnerable to relay
- `Logon GUID: {00000000-0000-0000-0000-000000000000}` — null GUID confirms no Kerberos ticket was used
- `Key Length: 128` — session key length for NTLM V2

**Sysmon EID 1 — Process Create:**

| Timestamp (UTC) | PID | CommandLine | User |
|---|---|---|---|
| 2026-09-15 20:27:48 | 5320 | `net.exe use \\10.10.10.103\IPC$ /user:Administrator [REDACTED]` | Administrator |
| 2026-09-15 20:27:46 | 1304 | `net.exe use` (connection listing) | Administrator |

### Investigation

**Step 1 — Identify NTLM usage between domain-joined hosts:**
EID 4624 shows `AuthenticationPackageName: NTLM` for network logon (Type 3) from COMPROMISED-01. Both the source and destination are the same domain-joined host (COMPROMISED-HOST-01, member of `ASHFORDGROVE` domain). In a healthy domain environment, Kerberos should be the primary authentication protocol. NTLM usage between Kerberos-capable hosts is an anomaly that warrants investigation.

**Step 2 — Determine WHY NTLM was used (critical step):**
The connection was made by IP address (`\\127.0.0.1\C$` and `\\10.10.10.103\IPC$`), not by hostname. IP-based connections bypass Kerberos SPN lookup because Kerberos requires a hostname to construct the SPN (`cifs/hostname.domain.local`). This is the most common and well-understood benign cause of NTLM fallback.

Additional contributing factor: the domain trust relationship is broken on COMPROMISED-HOST-01 (discovered in AGC-025). Even if the connection had used a hostname, Kerberos would fail because the host cannot reach the KDC (AD-DC-01 is unreachable — confirmed in AGC-035).

**Benign explanation confirmed:** IP-based connection + broken domain trust. This is NOT an active NTLM relay attack. The NTLM fallback is expected behavior given the network conditions.

**Step 3 — Why confidence remains Medium (not escalated):**
Per the investigation methodology: NTLM authentication anomalies have a substantial benign interpretation space. This scenario demonstrates a clear benign cause (IP-based connection). Escalating to High/Critical without first excluding benign explanations is exactly the kind of over-classification that leads to alert fatigue.

However, the Medium confidence is warranted because:
- NTLM V2 IS vulnerable to offline cracking and relay attacks, regardless of why it was used
- A real attacker could intentionally use IP-based connections to force NTLM as a precondition for relay
- The fact that a benign explanation exists does not eliminate the risk — it lowers the priority

**Step 4 — Comparison with FP twin AGC-084:**
AGC-084 (False Positive Triage) will present a benign DNS pattern that also produces NTLM traffic. The key difference: AGC-084's NTLM usage is entirely expected and requires no action, while AGC-036's NTLM usage is technically explained but still represents a security weakness worth addressing at the policy level.

### Report

**Verdict: True Positive (Probable)** — NTLM authentication occurred on a domain-joined host where Kerberos should be available. The immediate cause is benign (IP-based connection), but the underlying condition (NTLM enabled and usable) represents a genuine attack surface.

**Confidence: Medium** — Calibrated assessment:
1. NTLM usage confirmed via EID 4624 with null Logon GUID.
2. Benign root cause identified: IP-based SMB connection bypasses Kerberos SPN lookup.
3. No evidence of NTLM relay or credential capture.
4. The risk is the NTLM attack surface, not this specific event.

**Response recommendation:**
1. **Investigate connection context** before escalating — verify whether the NTLM usage has a benign explanation (IP-based connection, legacy application, DNS failure). Confirmed here.
2. **Do not escalate without excluding benign causes** — NTLM anomalies are high-volume, and over-classification causes alert fatigue that hides real relay attacks.
3. **Monitor for network-level relay indicators** — if no benign cause is found, correlate with network traffic (Security Onion) for SMB relay patterns: multiple SMB sessions from the same source to different targets, or an intermediary host relaying authentication.
4. **Policy recommendation (long-term):** Consider restricting NTLM at the domain level via Group Policy (`Network security: Restrict NTLM: NTLM authentication in this domain`). Audit first, then block. Hosts with a documented need for NTLM can be exempted.
5. **Fix the domain trust** — the broken trust on COMPROMISED-HOST-01 forces ALL authentication to NTLM, creating a persistent attack surface. Run `nltest /sc_reset:ashfordgrove.local` or rejoin the domain.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay (candidate) | Security EID 4624: NTLM V2 auth (Logon Type 3, null Logon GUID) for IP-based SMB connections (127.0.0.1, 10.10.10.103). Sysmon EID 1: `net.exe use` with IP target. Benign cause confirmed (IP-based connection bypasses SPN). NTLM attack surface exists but no active relay detected. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Raw EID 4624 (NTLM auth via IP)

```
An account was successfully logged on.

Subject:
    Security ID:        S-1-0-0
    Account Name:       -
    Account Domain:     -
    Logon ID:           0x0

Logon Information:
    Logon Type:         3
    Elevated Token:     Yes

New Logon:
    Security ID:        S-1-5-21-783388846-4178789021-3119572882-500
    Account Name:       Administrator
    Account Domain:     COMPROMISED-01
    Logon ID:           0x531325
    Logon GUID:         {00000000-0000-0000-0000-000000000000}

Network Information:
    Workstation Name:   COMPROMISED-01
    Source Network Address:  127.0.0.1
    Source Port:        64393

Detailed Authentication Information:
    Logon Process:      NtLmSsp
    Authentication Package: NTLM
    Package Name (NTLM only): NTLM V2
    Key Length:         128
```

### Raw Sysmon EID 1 (IP-based net use)

```
Process Create:
RuleName: -
UtcTime: 2026-09-15 20:27:48.385
ProcessId: 5320
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.103\IPC$ /user:Administrator [REDACTED]
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1,SHA256=BB3E638C8B5B6EF80847E364AEEF2796CAD25D3539CF9B41D3820FA48943E777
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc036-sim.ps1
```
