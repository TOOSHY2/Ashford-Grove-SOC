# AGC-099 — After-Hours Access With No Ticket or Approval

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-099` |
| Title | Insider Threat: Off-Hours Access Without Authorization |
| Category | `16-insider-threat` — Insider Threat |
| Severity | High (requires further investigation) |
| MITRE Technique | None (procedural finding: missing approval) |
| Verdict | Confirmed Anomaly — Contact Employee/Manager |
| Confidence | Medium |
| Chain | ◀ [AGC-098](../AGC-098-service-account-interactive/README.md) · next [AGC-100](../AGC-100-revoked-resource-access/README.md) ▶ |

## Attacker Perspective

### Tradecraft

#### Baseline (documented before simulation)

| Field | Value |
|-------|-------|
| **Employee** | raj.patel |
| **Role** | IT-Support |
| **Normal working hours** | 08:00-18:00 UTC (Mon-Fri) |
| **On-call roster** | NOT LISTED for current period |
| **Emergency change ticket** | NONE FOUND |
| **Manager pre-approval** | NOT FOUND |

### Simulation

Simulated raj.patel accessing `C:\Shares\Finance\Q3-budget-2026.xlsx` at 01:20 UTC (7 hours outside the end of the normal working window). Conducted an exhaustive search for authorization records (on-call roster, change tickets, manager approval) and documented the empty result.

**Execution window**: 01:20:31 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

After-hours access detected: raj.patel accessed a sensitive resource (Finance budget file) at 01:20 UTC on a weekday, well outside the documented working hours (08:00-18:00 UTC). No on-call record, emergency change ticket, or manager approval was found to justify the off-hours access.

### Investigation

#### Step 1: Confirm the Off-Hours Access

```
Access timestamp: 2026-09-16 01:20:31 UTC
Normal working hours: 08:00-18:00 UTC (Mon-Fri)
Hours outside window: 7 hours past close
Resource accessed: C:\Shares\Finance\Q3-budget-2026.xlsx
Access result: Successful
```

#### Step 2: Search for Authorization Records

| Authorization Source | Search Result |
|---------------------|---------------|
| **On-call roster** | raj.patel NOT LISTED for current rotation |
| **Change ticket system** | NO MATCHING TICKET for 2026-09-16 |
| **Manager pre-approval** | NOT FOUND in approval records |
| **Emergency change record** | NONE on file |

The **absence of any authorization record** is the primary finding. In a production environment, this search must be exhaustive and the empty result thoroughly documented.

#### Step 3: Context Assessment

| Factor | Assessment |
|--------|------------|
| **Employee role** | IT-Support — some after-hours access may be operationally expected |
| **Resource accessed** | Finance data — outside raj.patel's role authorization (cross-reference AGC-095) |
| **Access pattern** | Single access at 01:20 UTC — not a sustained session |
| **HR context** | Resignation submitted 2026-09-10 (cross-reference AGC-096) |

**Compounding factors**: This after-hours access occurs during raj.patel's resignation notice period (AGC-096) and targets a Finance resource outside his role authorization (AGC-095 pattern). These compounding factors elevate concern.

#### Step 4: Assessment of Intent

The investigation establishes facts without presuming malice:
- **Possible benign explanation**: Forgot to submit a change ticket for legitimate maintenance work
- **Possible concern**: Accessing sensitive data during notice period without authorization
- **Resolution**: Contact the employee and manager to establish the actual reason before escalating

### Report

**Verdict: Confirmed Anomaly — Requires Further Investigation** — raj.patel accessed a sensitive Finance resource at 01:20 UTC (7 hours outside normal working hours) with no on-call record, change ticket, or manager approval on file. The access is compounded by the employee's active resignation notice period and the Finance data being outside his role authorization.

**Recommendation**:
1. Contact raj.patel and his manager to establish the reason for the off-hours access
2. If a legitimate reason exists (forgotten ticket), document it and close as procedural gap
3. If no legitimate reason, escalate per the insider threat process (coordinate with HR/Legal)
4. Document the resolution to build institutional precedent for handling similar cases
5. Review whether time-based access controls (logon hour restrictions) should be implemented for sensitive resources

### MITRE Mapping

No MITRE ATT&CK technique applies. This is an entirely **procedural finding** (missing approval for off-hours access), not a technical IOC. The detection is based on time-of-day deviation from the documented working pattern combined with the absence of authorization records.

**Cross-reference**: This scenario is the mirror-inverse of **AGC-085** (False Positive), where the same search process for authorization records yielded a positive result (documented service account schedule), leading to a benign conclusion. Here, the empty result drives the investigation forward.

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
