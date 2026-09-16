# AGC-092 — Proactive Hunt: Abnormal Domain-Wide Logon-Time Patterns

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-092` |
| Title | Hunt: Per-Account Logon-Hour Distribution Outliers |
| Category | `15-threat-hunting` — Proactive Threat Hunting |
| Hunt Type | Hypothesis-Driven (Behavioral Baseline) |
| MITRE Technique | T1078 (Valid Accounts) |
| Hunt Result | Hypothesis Refuted (Insufficient Baseline Data) |
| Related Scenarios | AGC-008, AGC-085 |
| Chain | ◀ [AGC-091](../AGC-091-hunt-beacon-statistics/README.md) · next [AGC-093](../AGC-093-hunt-dns-entropy/README.md) ▶ |

## SOC Perspective

### Hypothesis

*Stated before any query was executed:*

> If an adversary is using compromised credentials, they will generate logon events (EID 4624) outside the legitimate account owner's historical time-of-day pattern, creating statistical outliers in the per-account logon-hour distribution.

### Investigation

#### Methodology

**Data source**: Windows Security EID 4624 (Logon) on COMPROMISED-HOST-01.

**Approach**: Extract all EID 4624 events, group by account name, compute per-account hour-of-day distribution, identify logons outside each account's historical pattern.

**Execution window**: 01:09:27 - 01:09:39 UTC

#### Results

##### Security EID 4624 Events

```
Total EID 4624 events: 56
Accounts with human/service logon events: 0
```

**Finding**: The Security log held 56 EID 4624 logon events, every one from a system or machine account (SYSTEM, machine accounts ending in `$`, or the `-` placeholder for anonymous logons). The current log window captured no logon for any human account (michael.chen, sarah.jenkins, raj.patel).

##### Analysis

The absence of human account logon events is explained by two lab constraints:

1. **Domain trust relationship broken**: COMPROMISED-HOST-01's domain trust with ashfordgrove.local is broken. Authentication is NTLM-only, and interactive logons under domain accounts do not produce standard EID 4624 entries while the trust is severed.

2. **Security log cleared**: AGC-088 (the log retention policy scenario) cleared the Security log at approximately 01:00 UTC this session, taking the historical logon data with it. The 56 events that remain were all written after the clear and are all system-level logon activity.

3. **guestcontrol logon pattern**: Administrator logons through VBoxManage guestcontrol are elevated-token logons that show up as SYSTEM-context operations, not interactive (Type 2) or network (Type 3) logons.

### Report

**Result: Hypothesis Refuted (Insufficient Baseline Data)** — There was not enough logon data to run the hunt to a conclusion. AGC-088 cleared the Security log earlier this session, the broken domain trust blocks domain account logon events, and guestcontrol produces system-context logons rather than user-context ones.

**Value of this hunt**: The method (per-account logon-hour distribution with outlier detection) works in production once months of baseline data exist. It does the most when:
- Run against the domain controller (AD-DC-01) Security log, which aggregates logon events for all domain accounts
- Based on at least 30 days of historical data to establish per-account baselines
- Filtered to interactive (Type 2), network (Type 3), and remote interactive (Type 10) logon types

**Recommendation**: Re-run this hunt against AD-DC-01, whose domain controller Security log is the authoritative logon record for every domain account. Run it monthly with a 90-day rolling baseline window. Flag any account with a logon hour more than 2 standard deviations from its historical mean.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1078 | Valid Accounts | Persistence / Privilege Escalation | **Hunted** — No human account logon events available for time-pattern analysis. Security log cleared by AGC-088 retention policy scenario. Domain trust broken prevents standard domain account logon events. Insufficient baseline data to confirm or deny the hypothesis. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
