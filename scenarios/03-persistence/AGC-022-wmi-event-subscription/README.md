# AGC-022 — WMI Event-Subscription Persistence

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-022` |
| Category | `03-persistence` — Persistence |
| MITRE Technique | `T1546.003` Event Triggered Execution: WMI Event Subscription |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 19/20/21 capture the complete filter/consumer/binding triad |
| Time to Triage | 02:00 (from alert to WQL query analysis and consumer action review) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-021](../AGC-021-new-autostart-service/README.md) · next [AGC-023](../AGC-023-new-local-admin/README.md) ▶ |
| One-line Summary | Unknown WMI event subscription `AGC022Filter`/`AGC022Consumer` created with CommandLineEventConsumer executing `cmd.exe` — classic fileless persistence mechanism. |

## Attacker Perspective

### Tradecraft

**What:** The attacker creates a WMI permanent event subscription consisting of three components:
1. **Event Filter** (`__EventFilter`) — defines WHEN to trigger (a WQL query that fires on system performance data changes every 60 seconds).
2. **Event Consumer** (`CommandLineEventConsumer`) — defines WHAT to execute (`cmd.exe` writing a marker file).
3. **Binding** (`__FilterToConsumerBinding`) — links the filter to the consumer.

The attacker gets:

1. **Fileless persistence** — the subscription lives in the WMI repository (`C:\Windows\System32\wbem\Repository`), not as a file on disk. No executable to scan, no registry key to find.
2. **Survives reboots** — the WMI service (`winmgmt`) re-activates permanent subscriptions on every boot.
3. **SYSTEM-level execution** — `CommandLineEventConsumer` runs its command as `NT AUTHORITY\SYSTEM` no matter who created the subscription.
4. **Recurring execution** — the `WITHIN 60` polling interval fires the command about once a minute for as long as the host is up.
5. **Detection gap** — many organizations never enable Sysmon WMI logging (EID 19/20/21), so the technique goes unseen without that configuration.

**Why at this lifecycle stage:** With Run key, scheduled task, and service persistence in place, the attacker adds a fileless mechanism. WMI subscriptions are harder to find during incident response because they sit outside the usual persistence locations (autoruns, services, scheduled tasks).

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon active with WMI event logging (EID 19/20/21) enabled.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:11:16 | Create filter | COMPROMISED-HOST-01 | `New-CimInstance __EventFilter` — AGC022Filter with WQL polling query |
| 2 | 2026-09-15 19:11:18 | Create consumer | COMPROMISED-HOST-01 | `New-CimInstance CommandLineEventConsumer` — AGC022Consumer with cmd.exe action |
| 3 | 2026-09-15 19:11:30 | Create binding | COMPROMISED-HOST-01 | `New-CimInstance __FilterToConsumerBinding` — links filter to consumer |
| 4 | 2026-09-15 19:11:50 | Verify | COMPROMISED-HOST-01 | `Get-CimInstance` confirmed filter, consumer, and binding all registered |
| 5 | 2026-09-15 19:12:18 | Cleanup | COMPROMISED-HOST-01 | Removed binding, consumer, and filter via `Remove-CimInstance` |

**Cleanup:** All three WMI objects removed after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:11:16 | 19 | WmiFilterEvent | **Operation:** Created. **User:** `COMPROMISED-01\Administrator`. **Name:** `AGC022Filter`. **EventNamespace:** `root\cimv2`. **Query:** `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'`. |
| 2026-09-15 19:11:28 | 20 | WmiConsumerEvent | **Operation:** Created. **User:** `COMPROMISED-01\Administrator`. **Name:** `AGC022Consumer`. **Type:** Command Line. **Destination:** `cmd.exe /c echo AGC-022 test > C:\Windows\Temp\agc022.txt`. |
| 2026-09-15 19:11:50 | 21 | WmiBindingEvent | **Operation:** Created. **User:** `COMPROMISED-01\Administrator`. **Consumer:** `CommandLineEventConsumer.Name="AGC022Consumer"`. **Filter:** `__EventFilter.Name="AGC022Filter"`. |

**WMI-Activity Operational log:**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:11:30 | 5861 | Subscription activated | Full subscription details: EventFilter `AGC022Filter` bound to `CommandLineEventConsumer="AGC022Consumer"` with complete WQL query and command template in the event body. |

**Key detection signals:**
1. **Sysmon EID 19/20/21 triad** — Sysmon captured the whole lifecycle of the permanent subscription: filter creation, consumer creation, and binding. Each event carries the detail that matters (WQL query, command template, user context).
2. **CommandLineEventConsumer** type — this consumer runs commands directly, which makes it the most dangerous WMI consumer class. LogFileEventConsumer and SMTPEventConsumer carry less risk.
3. **Consumer destination analysis** — `cmd.exe /c echo ... > C:\Windows\Temp\...` is suspicious; no legitimate monitoring tool uses CommandLineEventConsumer to write echo output to Temp.
4. **WMI-Activity EID 5861** independently corroborates the activation with full object definitions.

### Investigation

**Step 1 — Confirm Sysmon WMI logging is active:**
Sysmon captured EID 19/20/21, so the SwiftOnSecurity config on this host does cover WMI subscriptions. Without those three events, WMI persistence is close to invisible in endpoint telemetry.

**Step 2 — Analyze the filter (EID 19):**
The WQL query `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'` polls system performance counters every 60 seconds. It is a generic trigger built to fire often and reliably, tied to no particular condition. The `WITHIN 60` clause puts the consumer on a roughly once-a-minute cadence.

**Step 3 — Analyze the consumer (EID 20):**
The consumer is a `CommandLineEventConsumer` with destination `cmd.exe /c echo AGC-022 test > C:\Windows\Temp\agc022.txt`. Three points:
- CommandLineEventConsumer runs as SYSTEM, the highest privilege level.
- The command writes to `C:\Windows\Temp`, a common staging location.
- No monitoring tool in the lab uses WMI CommandLineEventConsumer.

**Step 4 — Analyze the binding (EID 21):**
The binding joins AGC022Filter to AGC022Consumer and completes the triad. The subscription goes live only once all three pieces exist.

**Step 5 — Cross-reference with known WMI subscriptions:**
The host carries one other subscription: `SCM Event Log Filter` bound to `NTEventLogEventConsumer`, a built-in Windows subscription. AGC022 has no such pedigree.

### Report

**Verdict: True Positive** — An unknown WMI permanent event subscription was created with a CommandLineEventConsumer running cmd.exe to write to Temp, with nothing in the lab to justify it.

**Confidence: High** — The Sysmon EID 19/20/21 triad is complete evidence:
- Filter, consumer, and binding all created by `COMPROMISED-01\Administrator`.
- Consumer type is CommandLineEventConsumer (direct command execution as SYSTEM).
- Consumer action (`cmd.exe` writing to Temp) has no legitimate use case.
- Subscription name (`AGC022*`) not in any known software inventory.
- Only one other subscription exists on the host (the legitimate SCM Event Log subscription).

**Response recommendation:**
1. **Immediately remove all three components** (binding first, then consumer, then filter):
   ```powershell
   Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object {$_.Filter -match "AGC022"} | Remove-CimInstance
   Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Where-Object {$_.Name -eq "AGC022Consumer"} | Remove-CimInstance
   Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Where-Object {$_.Name -eq "AGC022Filter"} | Remove-CimInstance
   ```
2. **Audit all WMI subscriptions** fleet-wide — enumerate `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, and `__FilterToConsumerBinding` on every endpoint.
3. **Ensure Sysmon EID 19/20/21** are enabled domain-wide. Without these events, WMI persistence is a detection gap.
4. **Detection rule:** Alert on Sysmon EID 20 where Consumer Type is `Command Line` or `Active Script` and the Destination does not match known legitimate WMI consumers.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1546.003 | Event Triggered Execution: WMI Event Subscription | Sysmon EID 19: filter `AGC022Filter` (WQL polling query). EID 20: consumer `AGC022Consumer` (CommandLineEventConsumer, cmd.exe). EID 21: binding linking filter to consumer. WMI-Activity EID 5861 corroborates. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
