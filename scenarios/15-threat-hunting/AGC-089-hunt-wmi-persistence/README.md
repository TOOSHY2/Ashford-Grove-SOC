# AGC-089: Proactive Hunt -- WMI Event-Subscription Persistence

## Scenario Overview

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Scenario ID**    | AGC-089                                                      |
| **Title**          | Hunt: WMI Event-Subscription Persistence                     |
| **Category**       | Proactive Threat Hunting (15-threat-hunting)                 |
| **Hunt Type**      | Hypothesis-Driven                                            |
| **MITRE Techniques** | T1546.003 (Event Triggered Execution: WMI Event Subscription) |
| **Hunt Result**    | Hypothesis Confirmed (Benign)                                |
| **Related Scenario** | AGC-022 (WMI Event Subscription -- reactive investigation) |

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

**Navigation:** [< AGC-088](../../14-false-positive/AGC-088-log-clearing-retention/README.md) | [AGC-090 >](../../15-threat-hunting/AGC-090-hunt-lolbin-parent-child/README.md)

## Hypothesis

*Stated before any query was executed:*

> If an adversary has planted WMI event-subscription persistence in this environment, it will appear as a triplet of `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding` objects in the WMI repository under `root/subscription`, and will evade any persistence check that only examines the Registry, Task Scheduler, and Startup folders.

## Hunt Methodology

**Data sources**: WMI repository enumeration via `Get-CimInstance` on `root/subscription` namespace; Sysmon EID 19/20/21 (WMI activity events).

**Scope**: COMPROMISED-HOST-01 (primary target; the endpoint with the highest risk profile in the environment).

**Execution window**: 01:04:19 - 01:04:24 UTC

## Hunt Queries and Results

### Query 1: __EventFilter Enumeration

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
```

**Result: 1 object found**

```
Name: SCM Event Log Filter
Query: select * from MSFT_SCMEventLogEvent
QueryLanguage: WQL
```

### Query 2: __EventConsumer Enumeration

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer
```

**Result: 1 object found**

```
__CLASS: NTEventLogEventConsumer
Name: SCM Event Log Consumer
```

### Query 3: __FilterToConsumerBinding Enumeration

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
```

**Result: 1 binding found**

```
Filter: __EventFilter (Name = "SCM Event Log Filter")
Consumer: NTEventLogEventConsumer (Name = "SCM Event Log Consumer")
```

### Query 4: Sysmon EID 19/20/21 (Historical WMI Activity)

**Result: 6 events found** -- all related to AGC-079 cleanup (prior scenario):

| Timestamp (UTC) | EID | Operation | Name | Details |
|-----------------|-----|-----------|------|---------|
| 00:15:24 | 19 | Created | AGC079UpdateFilter | `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'` |
| 00:15:25 | 20 | Created | AGC079UpdateConsumer | `powershell.exe -WindowStyle Hidden -File C:\Windows\Temp\agc079-stage2.ps1` |
| 00:16:00 | 21 | Created | Binding: AGC079UpdateFilter <-> AGC079UpdateConsumer | |
| 00:16:28 | 21 | Deleted | Binding: AGC079UpdateFilter <-> AGC079UpdateConsumer | |
| 00:16:28 | 20 | Deleted | AGC079UpdateConsumer | |
| 00:16:28 | 19 | Deleted | AGC079UpdateFilter | |

## Triage

### Found Subscription: "SCM Event Log Filter / SCM Event Log Consumer"

| Attribute | Value | Assessment |
|-----------|-------|------------|
| **Filter name** | SCM Event Log Filter | Windows built-in |
| **Filter query** | `select * from MSFT_SCMEventLogEvent` | Monitors Service Control Manager events |
| **Consumer type** | NTEventLogEventConsumer | Writes to Windows Event Log (not command execution) |
| **Consumer name** | SCM Event Log Consumer | Windows built-in |
| **Attributed to** | Windows OS (Service Control Manager subsystem) | Legitimate system component |

**Determination**: This is a **built-in Windows system WMI subscription** that writes SCM events to the Windows Event Log. The consumer type is `NTEventLogEventConsumer` (event log writer), not `CommandLineEventConsumer` or `ActiveScriptEventConsumer` (the types used for persistence/execution). This subscription is present on all standard Windows installations and is benign.

### Historical Activity: AGC-079 WMI Subscriptions (Cleaned Up)

The Sysmon EID 19/20/21 events show that the AGC-079 scenario's WMI subscriptions (`AGC079UpdateFilter` / `AGC079UpdateConsumer`) were created at 00:15:24 and subsequently deleted at 00:16:28 during scenario cleanup. These subscriptions **no longer exist** in the WMI repository, confirming successful cleanup.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Persistence / Privilege Escalation | **Hunted** -- One WMI subscription triplet found: "SCM Event Log Filter/Consumer" is a legitimate Windows system component (NTEventLogEventConsumer). No malicious CommandLine or ActiveScript consumers present. Historical AGC-079 subscriptions were created and cleaned up (Sysmon EID 19/20/21 confirm deletion). |

## Hunt Outcome

**Result: Hypothesis Confirmed (Benign)** -- The WMI repository contains one event-subscription triplet, which is a legitimate built-in Windows component (SCM Event Log Filter/Consumer using NTEventLogEventConsumer). No malicious persistence via WMI event subscriptions is currently active on COMPROMISED-HOST-01.

The Sysmon historical record confirms that a prior malicious WMI subscription (AGC-079) was planted and subsequently cleaned up. This validates that the hunt methodology would have detected active malicious subscriptions had they been present.

**Value of this hunt**: This reusable query can be scheduled as a periodic sweep across all domain endpoints. Any new `CommandLineEventConsumer` or `ActiveScriptEventConsumer` that is not attributed to a documented monitoring/management tool should trigger immediate escalation per the AGC-022 investigation playbook.

**Recommendation**: Add this WMI subscription enumeration to the SOC's periodic hunt library. Schedule monthly execution across all Windows endpoints. Alert on any non-system consumer types (CommandLine, ActiveScript) that are not in the approved software inventory.
