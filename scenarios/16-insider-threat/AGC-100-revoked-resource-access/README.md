# AGC-100: Access Attempt to Resource After Permission Revocation

## Scenario Overview

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Scenario ID**    | AGC-100                                                      |
| **Title**          | Insider Threat: Post-Revocation Access Attempt               |
| **Category**       | Insider Threat (16-insider-threat)                           |
| **Severity**       | Benign-to-Medium                                             |
| **MITRE Techniques** | None (testing an authorization boundary)                    |
| **Verdict**        | Access Control Working -- Single Explainable Attempt         |
| **Confidence**     | High                                                         |

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

**Navigation:** [< AGC-099](../../16-insider-threat/AGC-099-afterhours-no-ticket/README.md) | [Final Report](../../README.md)

## Revocation Record (Documented Before Simulation)

| Field | Value |
|-------|-------|
| **Employee** | sarah.jenkins |
| **Action** | Removed from IT-Support-Project group |
| **Effective date** | 2026-09-15 |
| **Reason** | Role change from Operations to Compliance |
| **Approved by** | IT Director |

## Alert / Trigger

Access denied event: sarah.jenkins attempted to access `\\10.10.10.100\IT-Support-Project` after being removed from the IT-Support-Project access group on 2026-09-15. The access attempt was denied, confirming the revocation control is working as intended.

## Simulation Summary

Documented the permission revocation record. Attempted SMB access via `net use` and `dir` to the IT-Support-Project share on AD-DC-01 (10.10.10.100). Both attempts returned "The network name cannot be found" -- the share is either not exposed or the access was denied at the network level.

**Execution window**: 01:20:31 UTC on COMPROMISED-HOST-01

## Investigation

### Step 1: Confirm the Access Attempt

**Sysmon EID 1 -- net.exe share access attempt (PID 5508):**
```
UtcTime: 2026-09-16 01:20:31
ProcessId: 5508
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.100\IT-Support-Project
Result: System error 67 -- The network name cannot be found.
```

### Step 2: Verify the Revocation is Active

The access attempt was **denied** -- confirming that the permission revocation from 2026-09-15 is in effect. The authorization boundary is working as intended.

### Step 3: Assess the Access Attempt

| Factor | Assessment |
|--------|------------|
| **Attempt count** | Single attempt (1) |
| **Timing** | 1 day after revocation (2026-09-16 vs 2026-09-15 effective date) |
| **Pattern** | No repeated attempts, no escalation, no circumvention |
| **Likely explanation** | Muscle memory / cached shortcut / not yet informed of role change |

A single access attempt the day after a role change is most likely explainable by:
- The employee has a saved shortcut or recent-places entry to the share
- The role change notification has not yet reached the employee
- The employee habitually accesses this resource and attempted automatically

### Step 4: Check for Circumvention Indicators

| Circumvention Check | Result |
|---------------------|--------|
| Repeated access attempts | NO -- single attempt only |
| Attempts via alternative paths (C$, admin shares) | NO |
| Credential switching attempts | NO |
| Escalation to IT for re-access | NO evidence |

No indicators of deliberate circumvention are present.

### Step 5: Spot-Check Other Recent Revocations

In a production environment, use this event as a trigger to verify that other recent permission revocations are also functioning correctly. This confirms the control works broadly, not just for this case.

## MITRE ATT&CK Mapping

No MITRE ATT&CK technique applies. This scenario tests an **authorization boundary** and confirms it is working. The access attempt is a natural consequence of a role change, not an attack technique.

## Conclusion

**Verdict: Access Control Working -- Benign Single Attempt** -- sarah.jenkins attempted to access a resource from which her permissions were revoked the previous day. The access was denied, confirming the revocation control is functioning. The single attempt with no escalation or circumvention is consistent with muscle memory or a cached shortcut, not deliberate unauthorized access.

**Severity: Benign-to-Medium** -- A single explainable attempt warrants documentation but not escalation. Severity escalates to High only if:
- Repeated access attempts are detected (persistence)
- Alternative access paths are attempted (circumvention)
- The employee contacts IT requesting re-access without a legitimate business need

**Recommendation**:
1. Log and close as a working access control -- the revocation is effective
2. Ensure the employee is formally notified of the role change and access scope change
3. Spot-check other recent revocations to confirm the control pattern works broadly
4. Consider implementing automated notification to employees when their access permissions change
5. Recognize that NOT over-escalating a working control is itself the correct SOC skill being demonstrated
