# AGC-081 — Encoded PowerShell: Legitimate Scheduled Backup (False Positive)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-081` |
| Title | Encoded PowerShell: Legitimate Scheduled Backup |
| Category | `14-false-positive` — False Positive Triage |
| Severity | Medium (alert trigger) |
| MITRE Technique | T1059.001, T1027 (observed, not malicious) |
| Verdict | False Positive / Benign |
| Confidence | High |
| Malicious Twin | AGC-013 (Encoded PowerShell download/execute) |
| Chain | ◀ [AGC-080](../../13-full-attack-chain/AGC-080-full-chain-discovery-to-service-disruption/README.md) · next [AGC-082](../AGC-082-new-admin-change-ticket/README.md) ▶ |

## Attacker Perspective

### Simulation

Created a scheduled task (`AGC081Backup`) that runs a file backup through `-EncodedCommand`. The Base64 encoding has an engineering reason: it sidesteps quoting problems with UNC paths in schtasks arguments. A change record approved by IT Operations 3 days earlier documents the task.

**Execution**: 00:32:49 - 00:33:08 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

Sysmon EID 1 captured `schtasks.exe /create` with `/tr "powershell.exe -EncodedCommand <Base64>"` on COMPROMISED-HOST-01. The `-EncodedCommand` flag fires the same rule as AGC-013 (malicious encoded PowerShell download). The triage question: the same technique used maliciously, or an admin doing routine work?

### Investigation

#### Step 1: Identify the Alert

**Sysmon EID 1 — schtasks.exe with EncodedCommand:**
```
UtcTime: 2026-09-16 00:32:49.643
ProcessId: 5348
Image: C:\Windows\System32\schtasks.exe
CommandLine: "C:\WINDOWS\system32\schtasks.exe" /create /tn AGC081Backup /tr "powershell.exe -EncodedCommand QwBvAHAAeQAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAiAEMAOgBcAFUAcwBlAHIAcwBcACoAXABEAG8AYwB1AG0AZQBuAHQAcwAiACAA..."
User: COMPROMISED-01\Administrator
```

On its face this matches AGC-013 exactly: a PowerShell invocation with a Base64-encoded command blob. Until the blob is decoded, the alert is indistinguishable from the malicious variant.

#### Step 2: Decode the Base64

```
Encoded: QwBvAHAAeQAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAiAEMAOgBcAFUAcwBlAHIAcwBcACoAXABEAG8AYwB1AG0AZQBuAHQAcwAiACAALQBEAGUAcwB0AGkAbgBhAHQAaQBvAG4AIAAiAFwAXAAxADAALgAxADAALgAxADAALgAxADAAXABCAGEAYwBrAHUAcABzAFwAJABlAG4AdgA6AEMATwBNAFAAVQBUAEUAUgBOAEEATQBFACIAIAAtAFIAZQBjAHUAcgBzAGUAIAAtAEYAbwByAGMAZQA=

Decoded: Copy-Item -Path "C:\Users\*\Documents" -Destination "\\10.10.10.10\Backups\$env:COMPUTERNAME" -Recurse -Force
```

**Analysis of decoded command**:
- **Operation**: `Copy-Item` — standard file copy cmdlet, not `Invoke-WebRequest`, `IEX`, or download-execute
- **Source**: `C:\Users\*\Documents` — standard user documents directory
- **Destination**: `\\10.10.10.10\Backups\` — internal backup share on the domain controller
- **No network beaconing**: No external IPs, no HTTP/HTTPS to attacker infrastructure
- **No credential access**: No `Get-Credential`, no DPAPI, no registry hive access
- **No persistence mechanisms**: No registry keys, no WMI subscriptions, no startup folder
- **Encoding reason**: UNC path with `$env:COMPUTERNAME` variable expansion requires careful quoting in schtasks `/tr` argument; `-EncodedCommand` avoids this entirely

#### Step 3: Cross-Reference Change Record

Pre-dated change record (approved 2026-09-13, 3 days before execution):

```
Change Record: AGC081Backup
Date Approved: 2026-09-13
Approved By: IT Operations (raj.patel)
Description: Nightly backup task using -EncodedCommand to avoid quoting issues with UNC path destination.
Schedule: Daily at 02:00
Target: COMPROMISED-HOST-01
Command: powershell.exe -EncodedCommand <base64 of Copy-Item to backup share>
Risk: Low - standard backup operation
```

The change record:
- Pre-dates the execution by 3 days (not created after-the-fact)
- Names the specific task (`AGC081Backup`) matching the schtasks `/tn` argument
- Documents the engineering reason for encoding (quoting issues)
- Identifies the approver (raj.patel, IT Operations)

#### Step 4: Confirm Schedule Consistency

The schtasks command specifies `/sc daily /st 02:00` — daily at 2:00 AM, matching the change record's "Daily at 02:00". Artifact and paper trail agree, which closes the loop.

### Report

**Verdict: False Positive / Benign** — The encoded command decodes to a `Copy-Item` backup to an internal share. The change record from IT Operations, approved before execution, shows the task was authorized. `-EncodedCommand` was chosen to avoid quoting issues with UNC paths in schtasks, not to hide anything.

**Recommendation**: Close as Benign. Allowlist the `AGC081Backup` task signature (task name + destination path pattern `\\10.10.10.10\Backups\`) so this nightly job stops paging. Do not suppress `-EncodedCommand` alerts globally — allowlist only this documented task.

**Cross-reference**: The malicious twin of this scenario is **AGC-013**, where the same `-EncodedCommand` alert reveals a download-and-execute payload targeting external attacker infrastructure with no corresponding change record.

#### Discriminating evidence (benign vs malicious)

What separates AGC-081 from its malicious twin AGC-013:

| Factor | AGC-081 (Benign) | AGC-013 (Malicious) |
|--------|-------------------|---------------------|
| **Decoded command** | `Copy-Item` to internal backup share | Download + execute from external attacker infra |
| **Network destination** | `\\10.10.10.10\Backups\` (internal DC) | External IP / attacker C2 |
| **Change record** | Pre-dated, named task, documented reason | None |
| **Encoding purpose** | Avoid UNC path quoting in schtasks | Obfuscate malicious payload |
| **Schedule** | Regular (daily 02:00), matches change record | Ad-hoc or irregular |

**Neither factor alone is sufficient**:
- A decoded command that *looks* benign but has no change record could still be an attacker hiding behind a plausible cmdlet
- A change record accepted without decoding the content is paperwork trusted over evidence

**Together**, the benign decoded content and a pre-dated change record whose details match give a clean false positive.

### MITRE Mapping

No malicious technique applies. The alert fires through the same detection rules as:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1059.001 | PowerShell | Execution | **Observed, Benign** — `-EncodedCommand` flag matches detection signature but decoded content is a standard backup operation |
| T1027 | Obfuscated Files or Information | Defense Evasion | **Observed, Benign** — Base64 encoding used for legitimate engineering reason (UNC path quoting), confirmed by change record |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
