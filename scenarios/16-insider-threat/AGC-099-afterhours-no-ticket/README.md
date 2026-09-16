# AGC-099 — After-Hours Access With No Ticket or Approval

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

The simulation had raj.patel open `C:\Shares\Finance\Q3-budget-2026.xlsx` at 01:20 UTC, 7 hours after the normal working window closes. It then searched every authorization source (on-call roster, change tickets, manager approval) and recorded the empty result.

**Execution window**: 01:20:31 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

After-hours access: raj.patel opened the Finance budget file at 01:20 UTC on a weekday, outside his documented working hours (08:00-18:00 UTC). No on-call record, emergency change ticket, or manager approval justifies the access.

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

The **absence of any authorization record** is the primary finding. In production, the analyst must check every one of these sources and write down the empty result, because that record is what the escalation rests on.

#### Step 3: Context Assessment

| Factor | Assessment |
|--------|------------|
| **Employee role** | IT-Support — some after-hours access may be operationally expected |
| **Resource accessed** | Finance data — outside raj.patel's role authorization (cross-reference AGC-095) |
| **Access pattern** | Single access at 01:20 UTC — not a sustained session |
| **HR context** | Resignation submitted 2026-09-10 (cross-reference AGC-096) |

**Compounding factors**: This after-hours access falls inside raj.patel's resignation notice period (AGC-096) and targets a Finance resource outside his role authorization (AGC-095 pattern). Either fact alone would prompt a question; together they push the severity to High.

#### Step 4: Assessment of Intent

The investigation records facts without presuming malice:
- **Possible benign explanation**: raj.patel did legitimate maintenance work and forgot to raise a change ticket
- **Possible concern**: An employee in his notice period read Finance data he is not authorized for
- **Resolution**: Ask the employee and his manager for the actual reason before escalating

### Report

**Verdict: Confirmed Anomaly — Requires Further Investigation** — raj.patel accessed a sensitive Finance resource at 01:20 UTC (7 hours outside normal working hours) with no on-call record, change ticket, or manager approval on file. His active resignation notice period and the fact that Finance data sits outside his role authorization both make the access harder to explain away.

**Recommendation**:
1. Contact raj.patel and his manager to establish the reason for the off-hours access
2. If a legitimate reason exists (forgotten ticket), document it and close as procedural gap
3. If no legitimate reason, escalate per the insider threat process (coordinate with HR/Legal)
4. Record the resolution so the next off-hours case has a precedent to follow
5. Review whether logon hour restrictions should apply to sensitive resources such as the Finance share

### MITRE Mapping

No MITRE ATT&CK technique applies. This is a **procedural finding** (missing approval for off-hours access), not a technical IOC. The detection combines a time-of-day deviation from the documented working pattern with the absence of any authorization record.

**Cross-reference**: This scenario is the mirror image of **AGC-085** (False Positive), where the same authorization search returned a documented service account schedule and closed the case as benign. Here the empty result is what keeps the case open.

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
