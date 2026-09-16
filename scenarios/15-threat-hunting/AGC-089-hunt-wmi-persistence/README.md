# AGC-089 — Proactive Hunt: WMI Event-Subscription Persistence

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-089` |
| Title | Hunt: WMI Event-Subscription Persistence |
| Category | `15-threat-hunting` — Proactive Threat Hunting |
| Hunt Type | Hypothesis-Driven |
| MITRE Technique | T1546.003 (Event Triggered Execution: WMI Event Subscription) |
| Hunt Result | Hypothesis Confirmed (Benign) |
| Related Scenario | AGC-022 (WMI Event Subscription — reactive investigation) |
| Chain | ◀ [AGC-088](../../14-false-positive/AGC-088-log-clearing-retention/README.md) · next [AGC-090](../AGC-090-hunt-lolbin-parent-child/README.md) ▶ |

## SOC Perspective

### Hypothesis

*Stated before any query was executed:*

> If an adversary has planted WMI event-subscription persistence in this environment, it will appear as a triplet of `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding` objects in the WMI repository under `root/subscription`, and will evade any persistence check that only examines the Registry, Task Scheduler, and Startup folders.

### Investigation

#### Methodology

**Data sources**: WMI repository enumeration via `Get-CimInstance` on `root/subscription` namespace; Sysmon EID 19/20/21 (WMI activity events).

**Scope**: COMPROMISED-HOST-01 (primary target; the highest-risk endpoint in the lab).

**Execution window**: 01:04:19 - 01:04:24 UTC

#### Results

##### Query 1: __EventFilter Enumeration

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
```

**Result: 1 object found**

```
Name: SCM Event Log Filter
Query: select * from MSFT_SCMEventLogEvent
QueryLanguage: WQL
```

##### Query 2: __EventConsumer Enumeration

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer
```

**Result: 1 object found**

```
__CLASS: NTEventLogEventConsumer
Name: SCM Event Log Consumer
```

##### Query 3: __FilterToConsumerBinding Enumeration

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
```

**Result: 1 binding found**

```
Filter: __EventFilter (Name = "SCM Event Log Filter")
Consumer: NTEventLogEventConsumer (Name = "SCM Event Log Consumer")
```

##### Query 4: Sysmon EID 19/20/21 (Historical WMI Activity)

**Result: 6 events found** — all related to AGC-079 cleanup (prior scenario):

| Timestamp (UTC) | EID | Operation | Name | Details |
|-----------------|-----|-----------|------|---------|
| 00:15:24 | 19 | Created | AGC079UpdateFilter | `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'` |
| 00:15:25 | 20 | Created | AGC079UpdateConsumer | `powershell.exe -WindowStyle Hidden -File C:\Windows\Temp\agc079-stage2.ps1` |
| 00:16:00 | 21 | Created | Binding: AGC079UpdateFilter <-> AGC079UpdateConsumer | |
| 00:16:28 | 21 | Deleted | Binding: AGC079UpdateFilter <-> AGC079UpdateConsumer | |
| 00:16:28 | 20 | Deleted | AGC079UpdateConsumer | |
| 00:16:28 | 19 | Deleted | AGC079UpdateFilter | |

#### Triage

##### Found Subscription: "SCM Event Log Filter / SCM Event Log Consumer"

| Attribute | Value | Assessment |
|-----------|-------|------------|
| **Filter name** | SCM Event Log Filter | Windows built-in |
| **Filter query** | `select * from MSFT_SCMEventLogEvent` | Monitors Service Control Manager events |
| **Consumer type** | NTEventLogEventConsumer | Writes to Windows Event Log (not command execution) |
| **Consumer name** | SCM Event Log Consumer | Windows built-in |
| **Attributed to** | Windows OS (Service Control Manager subsystem) | Legitimate system component |

**Determination**: This is the **built-in Windows system WMI subscription** that writes SCM events to the Windows Event Log. Its consumer is `NTEventLogEventConsumer`, an event-log writer, not `CommandLineEventConsumer` or `ActiveScriptEventConsumer`, the two types that execute code. Every standard Windows install ships with it. Benign.

##### Historical Activity: AGC-079 WMI Subscriptions (Cleaned Up)

Sysmon EID 19/20/21 show the AGC-079 subscriptions (`AGC079UpdateFilter` / `AGC079UpdateConsumer`) created at 00:15:24 and deleted at 00:16:28 during that scenario's cleanup. Neither object **exists in the repository now**, so the cleanup held.

### Report

**Result: Hypothesis Confirmed (Benign)** — The WMI repository holds one event-subscription triplet: the built-in SCM Event Log Filter/Consumer pair, using NTEventLogEventConsumer. No WMI event-subscription persistence is active on COMPROMISED-HOST-01.

The Sysmon record also shows the AGC-079 subscription being planted and then removed. The same three queries would have surfaced it while it was live, which is the check on the method.

**Value of this hunt**: The three queries are reusable and can be scheduled as a sweep across every domain endpoint. Any new `CommandLineEventConsumer` or `ActiveScriptEventConsumer` not tied to a documented monitoring or management tool goes straight to escalation under the AGC-022 investigation playbook.

**Recommendation**: Add the WMI subscription enumeration to the SOC hunt library and run it monthly across all Windows endpoints. Alert on any non-system consumer type (CommandLine, ActiveScript) that is not in the approved software inventory.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Persistence / Privilege Escalation | **Hunted** — One WMI subscription triplet found: "SCM Event Log Filter/Consumer" is a legitimate Windows system component (NTEventLogEventConsumer). No malicious CommandLine or ActiveScript consumers present. Historical AGC-079 subscriptions were created and cleaned up (Sysmon EID 19/20/21 confirm deletion). |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
