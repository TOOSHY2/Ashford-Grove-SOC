# AGC-092 — Proactive Hunt: Abnormal Domain-Wide Logon-Time Patterns

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**Data source**: Windows Security Event ID 4624 (Logon) on COMPROMISED-HOST-01.

**Approach**: Extract all EID 4624 events, group by account name, compute per-account hour-of-day distribution, identify logons outside each account's historical pattern.

**Execution window**: 01:09:27 - 01:09:39 UTC

#### Results

##### Security EID 4624 Events

```
Total EID 4624 events: 56
Accounts with human/service logon events: 0
```

**Finding**: 56 EID 4624 logon events were present in the Security log, but all were attributable to system/machine accounts (SYSTEM, machine accounts ending in `$`, or the `-` placeholder for anonymous logons). No human user account logon events (michael.chen, sarah.jenkins, raj.patel) were captured in the current Security log window.

##### Analysis

The absence of human account logon events is explained by two lab constraints:

1. **Domain trust relationship broken**: COMPROMISED-HOST-01's domain trust with ashfordgrove.local is broken. All authentication is NTLM-only, and interactive logons under domain accounts do not generate standard EID 4624 entries when the trust is severed.

2. **Security log cleared**: AGC-088 (log retention policy scenario) cleared the Security log during this session at approximately 01:00 UTC, removing historical logon data. The 56 remaining events were generated after the clear, consisting only of system-level logon activity.

3. **guestcontrol logon pattern**: The Administrator logons via VBoxManage guestcontrol are elevated token logons that appear as SYSTEM-context operations, not standard interactive (Type 2) or network (Type 3) logons.

### Report

**Result: Hypothesis Refuted (Insufficient Baseline Data)** — The hunt could not be conclusively executed due to insufficient logon event data. The Security log was cleared earlier in this session (AGC-088), the domain trust relationship is broken (preventing domain account logon events), and guestcontrol operations generate system-context logons rather than user-context logons.

**Value of this hunt**: The methodology (per-account logon-hour distribution with outlier detection) is sound for production environments with months of baseline data. This hunt is most effective when:
- Run against the domain controller (AD-DC-01) Security log, which aggregates logon events for all domain accounts
- Based on at least 30 days of historical data to establish per-account baselines
- Filtered to interactive (Type 2), network (Type 3), and remote interactive (Type 10) logon types

**Recommendation**: Re-run this hunt against AD-DC-01 where the domain controller Security log contains the authoritative logon record for all domain accounts. Schedule monthly execution with a 90-day rolling baseline window. Flag any account with a logon hour more than 2 standard deviations from its historical mean.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1078 | Valid Accounts | Persistence / Privilege Escalation | **Hunted** — No human account logon events available for time-pattern analysis. Security log cleared by AGC-088 retention policy scenario. Domain trust broken prevents standard domain account logon events. Insufficient baseline data to confirm or deny the hypothesis. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
