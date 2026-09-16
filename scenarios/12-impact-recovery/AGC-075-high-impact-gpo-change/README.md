# AGC-075 — High-Impact Group Policy Change

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-075` |
| Category | `12-impact-recovery` — Impact & Recovery |
| MITRE Technique | `T1484.001` Domain Policy Modification: Group Policy Modification |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | GPO metadata (ModificationTime and UserVersion increment on Default Domain Policy) |
| Time to Triage | 05:00 (GPO change review, scope assessment, revert) |
| Affected Systems | `AD-DC-01` (10.10.10.10) — domain-wide scope via Default Domain Policy |
| Chain | ◀ [AGC-074](../AGC-074-dmz-website-defacement/README.md) · next [AGC-076](../AGC-076-containment-recovery/README.md) ▶ |
| One-line Summary | Domain-wide Group Policy modification via `Set-GPRegistryValue` on AD-DC-01: Default Domain Policy (ID 31b2f340-016d-11d2-945f-00c04fb984f9) modified to set ScreenSaveTimeOut=1 under HKCU Desktop policy key. GPO UserVersion incremented from AD:0/SysVol:0 to AD:1/SysVol:1. ModificationTime updated to 2026-09-15 16:45:22 UTC. EID 5136 (directory service object modification) NOT captured — directory-service access auditing may not be enabled for GPO container objects on this DC. Change reverted (UserVersion AD:2/SysVol:2). This atomic technique is reused by AGC-078 as the impact phase of its attack chain. |

## Attacker Perspective

### Tradecraft

**What:** Modify a domain-wide Group Policy Object (GPO) to push attacker-desired configuration changes to every domain-joined endpoint simultaneously. GPOs are a force multiplier: a single modification on the domain controller propagates automatically to all hosts within the policy's scope, without requiring individual host access.

**Why an Attacker Uses It Here:**
- **Domain-wide impact from a single change:** Modifying the Default Domain Policy affects every domain-joined workstation and server in the ashfordgrove.local domain
- **Legitimate administration tool:** GPO changes are routine IT operations, making malicious modifications harder to distinguish from authorized changes
- **Persistence potential:** GPO-pushed settings reapply automatically every 90 minutes (default refresh), so even if an admin manually fixes a host, the GPO reapplies the malicious setting
- **Security weakening:** An attacker could disable Windows Firewall, relax password policies, disable audit logging, or push malicious scripts via GPO — far more impactful than host-level changes
- **Requires Domain Admin or equivalent:** modifying a GPO at all proves the attacker reached the highest level of Active Directory compromise

**Scope of this simulation:** The ScreenSaveTimeOut setting is deliberately low-impact (cosmetic screen saver timing), chosen to demonstrate the technique without disrupting lab infrastructure that other scenarios depend on. In a real attack, the GPO modification would target security-critical settings.

### Simulation

**Pre-conditions:**
- AD-DC-01 running, Administrator (Domain Admin) context
- GroupPolicy PowerShell module available (v1.0.0.0)
- 3 GPOs present: Default Domain Policy, Default Domain Controllers Policy, ASHFORDGROVE-PowerShell-Logging

**Execution:**
```powershell
# Modify Default Domain Policy -- set ScreenSaveTimeOut to 1 second
Set-GPRegistryValue -Name "Default Domain Policy" `
  -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" `
  -ValueName "ScreenSaveTimeOut" -Type DWord -Value 1

# Output confirmed:
# DisplayName: Default Domain Policy
# DomainName: ashfordgrove.local
# ModificationTime: 9/15/2026 4:45:22 PM
# UserVersion: AD Version: 1, SysVol Version: 1
```

**Result:** GPO modification succeeded. Default Domain Policy UserVersion incremented from 0 to 1 (AD and SysVol). ModificationTime updated to 2026-09-15 16:45:22. The change was reverted via `Remove-GPRegistryValue`, incrementing UserVersion to AD:2/SysVol:2.

## SOC Perspective

### Detection

**GPO modification metadata (primary evidence):**
```
BEFORE MODIFICATION:
  DisplayName: Default Domain Policy
  Id: 31b2f340-016d-11d2-945f-00c04fb984f9
  Owner: ASHFORDGROVE\Domain Admins
  UserVersion: AD Version: 0, SysVol Version: 0
  ComputerVersion: AD Version: 1, SysVol Version: 1

AFTER MODIFICATION (Set-GPRegistryValue):
  ModificationTime: 9/15/2026 4:45:22 PM
  UserVersion: AD Version: 1, SysVol Version: 1

AFTER REVERT (Remove-GPRegistryValue):
  ModificationTime: 9/15/2026 4:45:30 PM
  UserVersion: AD Version: 2, SysVol Version: 2
```

**DETECTION GAP — EID 5136 not captured:**
Windows Security Event ID 5136 (A directory service object was modified) was NOT observed within 5 minutes of the GPO modification. This indicates that directory-service access auditing (specifically "Audit Directory Service Changes" under Advanced Audit Policy) may not be enabled for Group Policy container objects on this domain controller. Without EID 5136, GPO modifications are invisible to security event monitoring.

**Alternative detection — GPO version tracking:**
The GPO UserVersion increment (0 -> 1 -> 2) and ModificationTime changes provide forensic evidence of modification, but these require periodic polling of GPO metadata rather than event-driven alerting.

### Investigation

**Step 1 — Identify the GPO change:**
The `Set-GPRegistryValue` command modified the Default Domain Policy, which has domain-wide scope. The registry key path (`HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop`) targets User Configuration, meaning the change applies to every domain user's desktop settings at next Group Policy refresh.

**Step 2 — Assess the modified setting:**
ScreenSaveTimeOut=1 (1 second) is a cosmetic setting in this simulation. In a real attack scenario, the same technique could modify:
- `HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware` (disable Defender domain-wide)
- `HKLM\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize` (reduce security log size to enable faster rotation and evidence destruction)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (push persistence to all users)
- Windows Firewall policies (disable network filtering domain-wide)

**Step 3 — Verify authorization:**
The modification was executed from the Administrator account (Domain Admin) on AD-DC-01. Key questions for a real investigation:
- Was a change management ticket filed for this GPO modification?
- Is this account authorized for GPO changes, and was the change within their documented scope?
- Were other GPOs modified in the same time window?

**Step 4 — Assess domain-wide scope:**
The Default Domain Policy (ID 31b2f340-016d-11d2-945f-00c04fb984f9) is linked at the domain root, meaning it applies to all OUs unless blocked. In ashfordgrove.local, this affects:
- WIN-CLIENT-01 (sarah.jenkins)
- WIN-CLIENT-02 (raj.patel)
- COMPROMISED-HOST-01 (michael.chen)
- All other domain-joined hosts

### Report

**Verdict: True Positive** — Unauthorized domain-wide Group Policy modification.

**Confidence: Critical** — Despite the low-impact setting chosen for simulation safety:
1. The GPO modification was confirmed via metadata changes (ModificationTime, UserVersion increment)
2. The Default Domain Policy has the broadest possible scope in the domain
3. The technique (Set-GPRegistryValue) can modify any registry-based policy setting
4. The same command could disable security controls domain-wide with a different ValueName
5. The GPO modification proves Domain Admin-level compromise of Active Directory
6. EID 5136 not captured represents a significant audit gap for the most impactful AD modification category

**Response recommendation:**
1. **Enable directory-service access auditing** for Group Policy container objects immediately — without EID 5136, GPO modifications are invisible to SIEM
2. **Audit all recent GPO modifications** across all domain GPOs, not just the one detected — an attacker with GPO write access likely made multiple changes
3. **Implement GPO change monitoring** via periodic `Get-GPO -All` version comparison, as a compensating control until EID 5136 auditing is enabled
4. **Review GPO delegation** — restrict Group Policy modification rights to a minimal set of monitored service accounts; consider implementing Privileged Access Workstations (PAWs) for GPO management
5. **Force immediate Group Policy refresh** (`gpupdate /force`) on all domain hosts after reverting malicious changes, to ensure the reverted settings propagate before the next automatic refresh cycle
6. **Consider GPO backup/versioning** via `Backup-GPO` scheduled tasks, enabling point-in-time recovery of any GPO to a known-good state

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Impact (TA0040) | T1484.001 | Domain Policy Modification: Group Policy Modification | Set-GPRegistryValue modified Default Domain Policy (31b2f340-016d-11d2-945f-00c04fb984f9) on AD-DC-01. UserVersion 0->1, ModificationTime updated. Domain-wide scope. EID 5136 NOT captured (audit gap). Reverted via Remove-GPRegistryValue. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### GPO modification timeline

```
TIME (UTC)               EVENT                                    EVIDENCE
2026-09-15 23:45:22.318  Set-GPRegistryValue executed              PowerShell output: SUCCESS
2026-09-15 16:45:22      GPO ModificationTime updated              Get-GPO metadata
                         UserVersion: AD:0/SysVol:0 -> AD:1/SysVol:1
2026-09-15 23:45:30      Remove-GPRegistryValue executed           PowerShell output: SUCCESS
2026-09-15 16:45:30      GPO ModificationTime updated              Get-GPO metadata
                         UserVersion: AD:1/SysVol:1 -> AD:2/SysVol:2

Note: ModificationTime reported in local server time (UTC-7),
UTC timestamps from script execution context.
```

### Domain GPO inventory

```
GPO Name                              ID                                    Status
Default Domain Policy                 31b2f340-016d-11d2-945f-00c04fb984f9  AllSettingsEnabled
Default Domain Controllers Policy     6ac1786c-016f-11d2-945f-00c04fb984f9  AllSettingsEnabled
ASHFORDGROVE-PowerShell-Logging       7ddff055-e65e-4314-8055-82aba351b1f5  AllSettingsEnabled

Note: ASHFORDGROVE-PowerShell-Logging GPO is critical for detection
in multiple other scenarios -- the guide explicitly prohibits
modifying it. Only the Default Domain Policy was targeted with
a non-security-impacting setting.
```

### Audit gap: EID 5136

```
EXPECTED: Windows Security Event ID 5136 fires when an Active
Directory object is modified, including Group Policy container
objects in the CN=Policies,CN=System,DC=ashfordgrove,DC=local
container.

OBSERVED: Zero EID 5136 events within 5 minutes of confirmed
GPO modification on AD-DC-01.

ROOT CAUSE: "Audit Directory Service Changes" (Advanced Audit
Policy Configuration > DS Access) may not be enabled, or may
not be configured to audit the groupPolicyContainer object class.

IMPACT: Without EID 5136, GPO modifications -- the single most
impactful category of Active Directory changes -- are invisible
to event-driven security monitoring. Only periodic metadata
polling (Get-GPO version comparison) can detect changes.
```
