# AGC-030 — Domain Admin Logon on a Workstation

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-030` |
| Category | `04-privilege-escalation` — Privilege Escalation |
| MITRE Technique | `T1078.002` Valid Accounts: Domain Accounts |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Immediate — Security EID 4624 with Logon Type 2 (Interactive) and Administrator account on a non-DC host |
| Time to Triage | 02:00 (cross-reference account against expected-hosts baseline; confirm host is NOT a DC or PAW) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-029](../AGC-029-suspicious-sudo-linux/README.md) · next [AGC-031](../../05-credential-access/AGC-031-lsass-access/README.md) (Credential Access category) ▶ |
| One-line Summary | Built-in Administrator (RID-500) logged interactively (Logon Type 2) onto a standard domain-joined workstation that is neither a domain controller nor a privileged access workstation. Security EID 4624 and EID 4672 confirm privileged logon with full special privileges assigned. |

## Attacker Perspective

### Tradecraft

**What:** The attacker uses a highly-privileged administrative account (Domain Admin or local RID-500 Administrator) to log on interactively to a standard workstation. This is a behavioral indicator rather than a technical exploit — the technique itself (logging in) is legitimate, but the context (privileged account on a non-DC endpoint) violates security best practices and indicates either:

1. **Credential theft/reuse:** An attacker who has obtained Domain Admin credentials uses them on any available workstation to establish a foothold with maximum privileges.
2. **Lateral movement:** After compromising one host, the attacker moves laterally using stolen DA credentials, leaving authentication artifacts (cached credentials, Kerberos tickets) on every workstation they touch.
3. **Policy violation:** Even if the login is by a legitimate administrator, interactive DA logon on a workstation exposes those credentials to credential-harvesting tools (Mimikatz, procdump of LSASS) that may already be present on a compromised host.

The risk is the same regardless of intent: DA credentials on a non-DC host can be harvested by an attacker who already has local admin access on that workstation.

**Why at this lifecycle stage:** After obtaining administrative credentials (via credential access techniques like AGC-031+), the attacker uses them broadly across the network. Each interactive logon caches credentials on the target host, expanding the attack surface. Detecting this pattern early — before the credentials are harvested and reused — is the last opportunity to contain the breach at a single host.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, domain-joined to `ashfordgrove.local`.
- `AD-DC-01` running (domain services available).
- Built-in Administrator (RID-500) account used for logon.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:54:02 | Interactive logon | COMPROMISED-HOST-01 | Administrator (RID-500, SID ...500) logged on interactively (Logon Type 2) via VBoxService.exe |
| 2 | 2026-09-15 19:54:02 | Special privileges assigned | COMPROMISED-HOST-01 | EID 4672: SeDebugPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeImpersonatePrivilege, and more |
| 3 | 2026-09-15 19:54:03 | Post-logon recon | COMPROMISED-HOST-01 | `whoami` = `compromised-01\administrator`, `whoami /groups` confirms BUILTIN\Administrators membership, High Mandatory Level |
| 4 | 2026-09-15 19:54:03 | Host context verified | COMPROMISED-HOST-01 | DomainRole=1 (Member Workstation), Domain=ashfordgrove.local. NOT a DC (DomainRole < 4), NOT a PAW |

**Note on domain trust:** COMPROMISED-HOST-01's trust relationship with the ASHFORDGROVE domain is broken (error 1789, discovered during AGC-025). The local Administrator (RID-500) was used as the privileged account. In a production environment with intact domain trust, this scenario would use ASHFORDGROVE\Administrator (the Domain Admin). The detection and investigation patterns are identical — the key indicator is a highly-privileged admin account authenticating interactively on a non-DC/non-PAW endpoint.

**Cleanup:** No persistent artifacts created. This scenario is purely behavioral (authentication event).

## SOC Perspective

### Detection

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:54:02 | 4624 (Security) | Logon Success | **Logon Type:** `2` (Interactive). **Account Name:** `Administrator`. **Account Domain:** `COMPROMISED-01`. **Security ID:** `S-1-5-21-783388846-4178789021-3119572882-500` (RID-500). **Elevated Token:** `Yes`. **Workstation Name:** `COMPROMISED-01`. **Logon Process:** `Advapi`. **Authentication Package:** `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`. |
| 2026-09-15 19:54:02 | 4672 (Security) | Special Privileges | **Account:** `Administrator` (SID ...500). **Privileges:** `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, `SeSystemEnvironmentPrivilege`, `SeImpersonatePrivilege`, `SeDelegateSessionUserImpersonatePrivilege`. |
| 2026-09-15 19:54:03 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\whoami.exe`. **CommandLine:** `"C:\WINDOWS\system32\whoami.exe" /groups`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. **LogonId:** `0x3D945D` (matches EID 4624). Post-logon reconnaissance command. |

**Detection rule logic:**
```
Security EID 4624
  WHERE Logon Type IN (2, 10)
  AND Account Name IN (Domain Admins list OR RID-500 Administrator)
  AND Workstation Name NOT IN (DC list, PAW list)
```

### Investigation

**Step 1 — Establish expected-hosts baseline:**
Domain Admin accounts should only authenticate interactively on:
- Domain Controllers (AD-DC-01, DomainRole >= 4)
- Privileged Access Workstations (PAWs), if deployed
- Jump servers / bastion hosts with restricted access

COMPROMISED-HOST-01 is a standard member workstation (DomainRole=1). It is NOT in any of these categories.

**Step 2 — Confirm the logon is anomalous:**
Security EID 4624 shows `Administrator` (RID-500) with Logon Type 2 (Interactive) on `COMPROMISED-01`. The host is a domain member workstation assigned to user `michael.chen`. A built-in Administrator logon on an end-user workstation is outside the expected baseline.

**Step 3 — Assess the EID 4672 privilege set:**
The special privileges assigned include `SeDebugPrivilege` (allows reading/writing any process memory, including LSASS for credential harvesting) and `SeImpersonatePrivilege` (allows token impersonation). These privileges are standard for RID-500 but represent maximum exposure if the host is compromised.

**Step 4 — Examine post-logon activity:**
Sysmon EID 1 shows `whoami.exe /groups` executed at 19:54:03 under the Administrator session. In an attack scenario, `whoami /groups` is a standard post-exploitation reconnaissance command (Discovery, T1033). The presence of this command shortly after a DA logon increases suspicion.

**Step 5 — Credential exposure assessment:**
An interactive logon (Type 2) caches credentials in LSASS memory. If this workstation is already compromised (as its name suggests), an attacker with local admin could use Mimikatz or procdump to harvest the cached Administrator credentials. This is the primary risk of DA logon on non-DC hosts.

**Step 6 — Response is the same regardless of intent:**
Whether this logon is malicious (attacker using stolen DA credentials) or accidental (legitimate admin logging into the wrong host), the response begins the same way:
1. Force logoff the DA session immediately.
2. Reset the DA account password from a known-clean DC console.
3. Audit what the DA session did during its lifetime.
4. Scan the workstation for credential-harvesting tools.

### Report

**Verdict: True Positive** — A highly-privileged Administrator account (RID-500) logged interactively onto a standard domain-joined workstation that is neither a domain controller nor a privileged access workstation.

**Confidence: Critical** — The severity is inherently Critical regardless of intent:
1. Security EID 4624 confirms Interactive (Type 2) logon of Administrator on a member workstation.
2. EID 4672 confirms full special privileges including SeDebugPrivilege (enables credential harvesting from LSASS).
3. The workstation (COMPROMISED-HOST-01) is outside the expected-hosts baseline for administrative accounts.
4. Credentials are now cached in LSASS on this potentially-compromised endpoint.

**Response recommendation:**
1. **Immediately force logoff** the Administrator session on the workstation.
2. **Reset the Administrator password** from a known-clean domain controller console session.
3. **Audit the session** — review all process creation (Sysmon EID 1), network connections (EID 3), and file access events during the Administrator session's lifetime (LogonId 0x3D945D).
4. **Scan the workstation** for credential-harvesting tools (Mimikatz, procdump, nanodump, etc.) and any artifacts left during the session.
5. **Implement Tier-0 isolation:** Deploy a Privileged Access Workstation (PAW) policy. DA accounts should ONLY authenticate on Tier-0 systems (DCs, PAWs). Use Group Policy to restrict DA logon to specific hosts:
   ```
   Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment
   "Deny log on locally" = Domain Admins (on all non-DC/non-PAW workstations)
   ```
6. **Deploy Protected Users group:** Add DA accounts to the Protected Users security group to prevent credential caching, NTLM authentication, and DES/RC4 in Kerberos.
7. **Create a Wazuh alert rule** for EID 4624 with Logon Type 2/10 and DA-group accounts on non-DC hosts.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1078.002 | Valid Accounts: Domain Accounts | Security EID 4624: Administrator (RID-500, SID ...500) interactive logon (Type 2) on COMPROMISED-HOST-01 (DomainRole=1, member workstation). EID 4672: full special privileges including SeDebugPrivilege. Host is NOT a DC or PAW — outside expected-hosts baseline. | Critical |
| Defense Evasion (TA0005) | T1078.002 | Valid Accounts: Domain Accounts | Same evidence. Using valid administrative credentials evades detection that focuses on exploit-based or malware-based privilege escalation. The logon itself is legitimate; only the context (wrong host) makes it anomalous. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
