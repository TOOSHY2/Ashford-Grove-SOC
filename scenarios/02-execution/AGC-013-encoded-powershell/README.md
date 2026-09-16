# AGC-013 — Encoded PowerShell Command

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-013` |
| Category | `02-execution` — Execution |
| MITRE Technique | `T1059.001` Command and Scripting Interpreter: PowerShell / `T1027` Obfuscated Files or Information |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures the `-EncodedCommand` flag and Base64 blob |
| Time to Triage | 02:00 (from event to decoded command analysis) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-012](../AGC-012-office-spawns-powershell/README.md) · next [AGC-014](../AGC-014-executable-from-temp/README.md) ▶ |
| One-line Summary | PowerShell executed with `-EncodedCommand` flag carrying Base64-encoded payload — classic obfuscation technique to evade command-line inspection. |

## Attacker Perspective

### Tradecraft

**What:** The attacker encodes a PowerShell command in Base64 (UTF-16LE) and passes it via the `-EncodedCommand` (or `-e`, `-enc`) parameter. The command line logged by Sysmon shows a long Base64 string instead of readable PowerShell syntax.

**Why attackers use this:**
1. **Evade simple command-line detection rules** that grep for keywords like `Invoke-WebRequest`, `Net.WebClient`, `IEX`, or `DownloadString`.
2. **Handle special characters** without escaping — nested quotes, pipes, and semicolons survive Base64 encoding cleanly.
3. **Proxy execution** — malware droppers, macros, and shellcode stagers frequently call `powershell -enc <blob>` because the Base64 string is a single argument with no quoting issues.

**Key insight:** `-EncodedCommand` does not encrypt the payload. It is trivially reversible: `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<blob>"))`. The encoding defeats a skim of the command line and simple grep rules, but an analyst or a pipeline decoder reverses it in one line.

**FP twin: AGC-081** — some legitimate tools (deployment scripts, ConfigMgr task sequences) pass complex scripts through `-EncodedCommand` so quoting survives intact. AGC-081 documents the false-positive variant where the decoded command is a benign backup script.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon running.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:37:10 | Build encoded command | COMPROMISED-HOST-01 | Plaintext: `Write-Output "AGC-013-encoded-ps-test" \| Out-File C:\Windows\Temp\agc013.txt -Encoding utf8` |
| 2 | 2026-09-15 18:37:10 | Base64 encode | COMPROMISED-HOST-01 | Encoded (244 chars): `VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEEARwBDAC0AMAAxADMALQBlAG4AYwBvAGQAZQBkAC0AcABzAC0AdABlAHMAdAAiACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAYQBnAGMAMAAxADMALgB0AHgAdAAgAC0ARQBuAGMAbwBkAGkAbgBnACAAdQB0AGYAOAA=` |
| 3 | 2026-09-15 18:37:10 | Execute | COMPROMISED-HOST-01 | `powershell.exe -EncodedCommand <blob>` (PID 6116) |
| 4 | 2026-09-15 18:37:12 | Marker confirmed | COMPROMISED-HOST-01 | `C:\Windows\Temp\agc013.txt` content: `AGC-013-encoded-ps-test` |

**Cleanup:** Marker file deleted after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:37:10 | 1 | Process Create | **powershell.exe** (PID 6116) — `CommandLine: "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAi...` — Base64 blob present |

**Key detection signal:** Sysmon EID 1 where `Image` = `powershell.exe` and `CommandLine` contains `-EncodedCommand` / `-enc` / `-e` followed by a Base64 string. This is a high-signal detection rule because:
- The `-EncodedCommand` flag itself shows intent to obfuscate.
- The detection pipeline can decode the Base64 blob automatically and attach the plaintext to the alert.

### Investigation

**Step 1 — Identify the encoded command:**
At 18:37:10 UTC Sysmon logged `powershell.exe` (PID 6116) starting with `-EncodedCommand` and a 244-character Base64 string.

**Step 2 — Decode the payload:**
```
Input:  VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEEARwBDAC0AMAAxADMALQBlAG4AYwBvAGQAZQBkAC0AcABzAC0AdABlAHMAdAAiACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAYQBnAGMAMAAxADMALgB0AHgAdAAgAC0ARQBuAGMAbwBkAGkAbgBnACAAdQB0AGYAOAA=

Decoded: Write-Output "AGC-013-encoded-ps-test" | Out-File C:\Windows\Temp\agc013.txt -Encoding utf8
```
Decoding method: `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<blob>"))`

**Step 3 — Evaluate the decoded command:**
The decoded command writes a marker string to `C:\Windows\Temp\`. In a real attack, the decoded command would typically contain:
- `Invoke-WebRequest` / `Net.WebClient.DownloadString` — second-stage download
- `IEX` (Invoke-Expression) — in-memory code execution
- `New-Object Net.Sockets.TCPClient` — reverse shell
- Registry/scheduled-task persistence commands

The payload here is a benign marker write, but the **use of `-EncodedCommand`** is the signal on its own. The blob still has to be decoded every time; the flag says nothing about what actually runs.

**Step 4 — Distinguish from legitimate use (AGC-081 cross-reference):**
Some legitimate tools use `-EncodedCommand`:
- ConfigMgr/SCCM task sequences
- Azure DevOps pipeline agents
- Enterprise backup scripts

AGC-081 walks through the benign-backup case. What separates the two:
- **Parent process:** A deployment agent (sccm, agent.worker) vs. a suspicious parent (mshta.exe, cmd.exe from temp)
- **Decoded content:** Known admin operations vs. download/execute patterns
- **Execution context:** Scheduled maintenance window vs. ad-hoc execution from a user workstation

### Report

**Verdict: True Positive** — powershell.exe (PID 6116) ran a command passed as Base64, and the marker file confirms it executed.

**Confidence: High** — The evidence chain is clear:
1. `-EncodedCommand` flag present in the Sysmon EID 1 CommandLine
2. Base64 blob decoded to the plaintext payload
3. Marker file confirms the decoded command executed
4. Execution context (ad-hoc, user workstation, no deployment agent parent) rules out legitimate use

**Response recommendation:**
1. **Decode and assess all `-EncodedCommand` instances** — the encoded blob may contain download URLs, C2 addresses, or persistence mechanisms.
2. **Investigate the parent process** — what spawned the encoded PowerShell? (Macro, exploit, persistence mechanism?)
3. **Check for follow-on activity** — network connections, file writes, registry changes after the PowerShell execution.
4. **Detection rule:** Alert on Sysmon EID 1 where `Image = powershell.exe` AND `CommandLine LIKE '%-enc%'` or `CommandLine LIKE '%-EncodedCommand%'`. Auto-decode the Base64 and include the decoded text in the alert enrichment.
5. **PowerShell Script Block Logging** (EID 4104) would capture the decoded script automatically — verify it is enabled.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Execution (TA0002) | T1059.001 | Command and Scripting Interpreter: PowerShell | powershell.exe (PID 6116) executed with `-EncodedCommand`. Decoded payload: `Write-Output "AGC-013-encoded-ps-test" \| Out-File C:\Windows\Temp\agc013.txt`. Marker file confirmed. | High |
| Defense Evasion (TA0005) | T1027 | Obfuscated Files or Information | Command encoded as Base64 (UTF-16LE, 244 chars) to evade command-line keyword detection. Trivially reversible but defeats simple grep rules. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
