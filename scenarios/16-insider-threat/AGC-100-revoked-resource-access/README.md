# AGC-100 — Access Attempt to Resource After Permission Revocation

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-100` |
| Title | Insider Threat: Post-Revocation Access Attempt |
| Category | `16-insider-threat` — Insider Threat |
| Severity | Benign-to-Medium |
| MITRE Technique | None (testing an authorization boundary) |
| Verdict | Access Control Working — Single Explainable Attempt |
| Confidence | High |
| Chain | ◀ [AGC-099](../AGC-099-afterhours-no-ticket/README.md) · — (last scenario) ▶ |

## Attacker Perspective

### Tradecraft

#### Revocation Record (documented before simulation)

| Field | Value |
|-------|-------|
| **Employee** | sarah.jenkins |
| **Action** | Removed from IT-Support-Project group |
| **Effective date** | 2026-09-15 |
| **Reason** | Role change from Operations to Compliance |
| **Approved by** | IT Director |

### Simulation

With the revocation record on file, the simulation tried `net use` and then `dir` against the IT-Support-Project share on AD-DC-01 (10.10.10.100) as sarah.jenkins. Both returned "The network name cannot be found" — either the share is not exposed or the network layer denied the access.

**Execution window**: 01:20:31 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

Access denied event: sarah.jenkins tried to reach `\\10.10.10.100\IT-Support-Project` the day after her removal from the IT-Support-Project access group on 2026-09-15. The share refused her, which is the revocation control doing its job.

### Investigation

#### Step 1: Confirm the Access Attempt

**Sysmon EID 1 — net.exe share access attempt (PID 5508):**
```
UtcTime: 2026-09-16 01:20:31
ProcessId: 5508
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.100\IT-Support-Project
Result: System error 67 -- The network name cannot be found.
```

#### Step 2: Verify the Revocation is Active

The attempt was **denied**, so the permission revocation from 2026-09-15 is in effect and the authorization boundary holds.

#### Step 3: Assess the Access Attempt

| Factor | Assessment |
|--------|------------|
| **Attempt count** | Single attempt (1) |
| **Timing** | 1 day after revocation (2026-09-16 vs 2026-09-15 effective date) |
| **Pattern** | No repeated attempts, no escalation, no circumvention |
| **Likely explanation** | Muscle memory / cached shortcut / not yet informed of role change |

One attempt the day after a role change has three ordinary explanations:
- sarah.jenkins still has a saved shortcut or recent-places entry for the share
- The role change notification has not reached her yet
- She opens this share out of habit and did so without thinking

#### Step 4: Check for Circumvention Indicators

| Circumvention Check | Result |
|---------------------|--------|
| Repeated access attempts | NO — single attempt only |
| Attempts via alternative paths (C$, admin shares) | NO |
| Credential switching attempts | NO |
| Escalation to IT for re-access | NO evidence |

Nothing in the telemetry points to deliberate circumvention.

#### Step 5: Spot-Check Other Recent Revocations

In production, treat this event as the trigger to test the other recent revocations, not only sarah.jenkins'. One denied attempt proves this control; the spot-check shows whether the revocation process holds everywhere else.

### Report

**Verdict: Access Control Working — Benign Single Attempt** — sarah.jenkins tried to open a share her permissions were revoked from the previous day, and the share denied her. One attempt with no escalation or circumvention fits muscle memory or a cached shortcut, not a deliberate attempt at unauthorized access.

**Severity: Benign-to-Medium** — A single explainable attempt warrants documentation but not escalation. Severity escalates to High only if:
- Repeated access attempts are detected (persistence)
- Alternative access paths are attempted (circumvention)
- The employee contacts IT requesting re-access without a legitimate business need

**Recommendation**:
1. Log and close as a working access control — the revocation is effective
2. Ensure the employee is formally notified of the role change and access scope change
3. Spot-check other recent revocations to confirm the control pattern works broadly
4. Notify employees automatically when their access permissions change, so a revoked user is not surprised by a denial
5. Recognize that NOT over-escalating a working control is itself the correct SOC call in this case

### MITRE Mapping

No MITRE ATT&CK technique applies. This scenario tests an **authorization boundary** and confirms it holds. The access attempt is the expected fallout of a role change, not an attack technique.

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
