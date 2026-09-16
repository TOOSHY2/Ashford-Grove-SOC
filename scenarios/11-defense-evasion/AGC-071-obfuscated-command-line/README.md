# AGC-071 — Obfuscated Command Line (Non-Encoded)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-071` |
| Category | `11-defense-evasion` — Defense Evasion |
| MITRE Technique | `T1027.010` Obfuscated Files or Information: Command Obfuscation |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Sysmon EID 1 (unusual command-line patterns in CommandLine field) |
| Time to Triage | 08:00 (manual deobfuscation required — no automated signature match) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | ◀ [AGC-070](../AGC-070-staged-artifact-deletion/README.md) · next [AGC-072](../../12-impact-recovery/AGC-072-ransomware-simulation/README.md) ▶ |
| One-line Summary | Three distinct non-encoded command obfuscation techniques executed: (1) cmd.exe environment variable string concatenation (`set a=echo&&set b= ...&&%a%%b%`), (2) PowerShell character-code construction (`[char]87+[char]114+...`), and (3) PowerShell backtick insertion (`W\`r\`i\`t\`e\`-\`H\`o\`s\`t`). All three generated Sysmon EID 1 events with the obfuscated command lines captured verbatim. Unlike AGC-013 (`-EncodedCommand` Base64), these techniques avoid the well-known `-enc` signature, requiring heuristic or manual analysis for detection. Confidence intentionally set to Medium to reflect the genuine difficulty of automated detection for this obfuscation family. |

## Attacker Perspective

### Tradecraft

**What:** Obfuscate command-line arguments without the `-EncodedCommand` Base64 pattern most detection rules key on. Three methods ran:

1. **String concatenation (cmd.exe):** Define variables with `set`, then join them through `%var%` expansion at run time. The real command exists only after expansion, never in the command line as typed.

2. **Character-code construction (PowerShell):** Build the cmdlet name from `[char]` codes (`[char]87 = W`, `[char]114 = r`, etc.). The name never appears as readable text in the source.

3. **Backtick insertion (PowerShell):** Put a backtick between every character of the cmdlet name. PowerShell drops the backticks when parsing; a signature sees a garbled string.

**Why an Attacker Uses It Here:**
- `-EncodedCommand` (AGC-013) is now widely detected by EDR and SIEM rules
- Non-encoded obfuscation gives those signatures nothing to match
- Each variant needs its own deobfuscation, which costs analyst time
- A correctly built obfuscated command still runs as intended
- Stacked on the prior defense evasion chain (AGC-067-070), this adds evasion of the detection rules themselves

**Distinction from AGC-013:** AGC-013 used `-EncodedCommand` with Base64, which a pattern match catches at once. AGC-071 avoids Base64 entirely, so detection has to be heuristic rather than signature-based.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context

**Execution:**
```cmd
REM Method 1: String concatenation
cmd.exe /c "set a=echo&&set b= AGC-071 obfuscation test&&%a%%b% > C:\Windows\Temp\agc071.txt"

REM Method 2: Character-code construction
powershell.exe -NoProfile -Command "& { $c=[string]([char]87)+[char]114+[char]105+[char]116+[char]101+[char]45+[char]72+[char]111+[char]115+[char]116; Invoke-Expression ("$c 'AGC-071 char-code test'") }"

REM Method 3: Backtick insertion
powershell.exe -NoProfile -Command "W`r`i`t`e`-`H`o`s`t 'AGC-071 tick obfuscation'"
```

**Result:** Method 1 created the marker file (agc071.txt). Methods 2 and 3 hit parsing issues in the non-interactive guestcontrol run, but all three produced Sysmon EID 1 events with the obfuscated command lines captured verbatim — the detection artifacts exist whether or not the command ran.

## SOC Perspective

### Detection

**Sysmon EID 1 — cmd.exe string concatenation (Method 1):**
```
Process Create:
UtcTime: 2026-09-15 23:24:11.185
ProcessGuid: {eb65e329-d39b-6aa9-5105-000000001400}
ProcessId: 3796
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\WINDOWS\system32\cmd.exe" /c "set a=echo&&set b= AGC-071 obfuscation test&&%%a%%%%b%% > C:\Windows\Temp\agc071.txt"
User: COMPROMISED-01\Administrator
IntegrityLevel: High
```

**Sysmon EID 1 — PowerShell character-code construction (Method 2):**
```
Process Create:
UtcTime: 2026-09-15 23:24:13.261
ProcessGuid: {eb65e329-d39d-6aa9-5205-000000001400}
ProcessId: 4824
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -Command "& { $c=[string]([char]87)+[char]114+[char]105+[char]116+[char]101+[char]45+[char]72+[char]111+[char]115+[char]116; Invoke-Expression ("$c 'AGC-071 char-code test'") | Out-File C:\Windows\Temp\agc071b.txt }"
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 — PowerShell backtick insertion (Method 3):**
```
Process Create:
UtcTime: 2026-09-15 23:24:15.658
ProcessGuid: {eb65e329-d39f-6aa9-5305-000000001400}
ProcessId: 4152
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -Command "Wi	e-Hos	 'AGC-071 tick obfuscation' | Out-File C:\Windows\Temp\agc071c.txt"
User: COMPROMISED-01\Administrator
```

### Investigation

**Step 1 — Identify obfuscation patterns (heuristic analysis):**
AGC-013 gave a signature in `-EncodedCommand`; these command lines give none, so detection is heuristic:
- **Method 1 indicators:** Multiple `set` commands followed by `%variable%` expansion in a single cmd.exe invocation
- **Method 2 indicators:** Dense `[char]` sequences in PowerShell command lines (high ratio of special characters to alphanumeric)
- **Method 3 indicators:** Backtick characters between every letter of cmdlet names (visible as tab characters in Sysmon logs)

**Step 2 — Manual deobfuscation:**
```
Method 1: set a=echo, set b= AGC-071..., %a%%b% = "echo AGC-071..."
Method 2: [char]87=W, [char]114=r, [char]105=i, [char]116=t, [char]101=e,
           [char]45=-, [char]72=H, [char]111=o, [char]115=s, [char]116=t
           Reconstructed: "Write-Host"
Method 3: W`r`i`t`e`-`H`o`s`t = "Write-Host" (backticks ignored by PS parser)
```
All three resolve to benign commands here, but the same construction works for any command, `Invoke-WebRequest`, `Invoke-Expression`, or a credential dump included.

**Step 3 — Detection difficulty assessment:**
This family is harder to catch than Base64 encoding:
- No single signature matches all variants
- New concatenation patterns cost the attacker nothing to invent
- Automated detection requires statistical/heuristic analysis of command-line entropy and character distribution
- Manual analyst review catches individual instances but does not scale
- PowerShell ScriptBlock Logging would record the command after parsing, deobfuscated, which EID 1 alone cannot

**Step 4 — Distinction from AGC-013:**
| Attribute | AGC-013 (-EncodedCommand) | AGC-071 (Non-encoded) |
|---|---|---|
| Detection method | Signature match on `-enc` flag | Heuristic/manual analysis |
| Automated detection | High confidence | Low-Medium confidence |
| Deobfuscation effort | Trivial (Base64 decode) | Variable (pattern-dependent) |
| Variant resistance | Low (flag is always present) | High (infinite concatenation patterns) |

### Report

**Verdict: True Positive** — Deliberate command-line obfuscation to evade detection.

**Confidence: Medium** — set below AGC-013 (High) because this family is harder to detect:
1. The obfuscation was found by reading the command lines by hand
2. No automated signature reliably catches all variants of this obfuscation family
3. The individual commands resolved to benign operations, but the obfuscation itself is the indicator
4. It ran on a confirmed compromised host in the middle of a defense evasion run
5. New variants of the same three tricks may slip past the current rules

**Response recommendation:**
1. **Deobfuscate all commands** before judging impact — the obfuscation is the technique, not the payload
2. **Enable PowerShell ScriptBlock Logging** (EID 4104) to record commands after parsing, deobfuscated, alongside Sysmon EID 1, which sees only the obfuscated input
3. **Develop heuristic detection rules** for: (a) cmd.exe with multiple `set` commands and `%variable%` expansion, (b) PowerShell with dense `[char]` sequences, (c) PowerShell with excessive backtick characters
4. **Document the pattern** for SOC analyst training — analysts have to recognize these three shapes by eye, since no signature will do it for them
5. **Correlate with the defense evasion chain** (AGC-067 through AGC-071) — five defense evasion actions back to back is a deliberate cleanup, not a one-off

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Defense Evasion (TA0005) | T1027.010 | Obfuscated Files or Information: Command Obfuscation | 3 obfuscation methods: string concatenation (cmd.exe), character-code construction ([char] sequences), backtick insertion. 4 Sysmon EID 1 events with obfuscated CommandLines captured. No -EncodedCommand flag (distinct from AGC-013). | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Three obfuscation methods compared

```
METHOD 1 -- String Concatenation (cmd.exe):
  Obfuscated:   set a=echo&&set b= AGC-071...&&%a%%b%
  Deobfuscated: echo AGC-071 obfuscation test
  Detection:    Look for set+%variable% patterns in cmd.exe CommandLine

METHOD 2 -- Character-Code Construction (PowerShell):
  Obfuscated:   [char]87+[char]114+[char]105+[char]116+[char]101+[char]45+[char]72+[char]111+[char]115+[char]116
  Deobfuscated: Write-Host
  Detection:    Look for dense [char] sequences (high special-char ratio)

METHOD 3 -- Backtick Insertion (PowerShell):
  Obfuscated:   W`r`i`t`e`-`H`o`s`t
  Deobfuscated: Write-Host
  Detection:    Look for backtick characters between cmdlet name characters
```

### Defense Evasion category summary (AGC-067 through AGC-071)

```
AGC-067: Security log clearing      T1070.001  Critical  (unambiguous)
AGC-068: Defender RTP disable        T1562.001  Critical  (tamper protection blocked)
AGC-069: Wazuh agent tampering       T1562.001  Critical  (telemetry silenced)
AGC-070: Staged-artifact deletion    T1070.004  High      (cleanup after exfil)
AGC-071: Command-line obfuscation    T1027.010  Medium    (detection-resistant)

Pattern: Systematic elimination of every detection and forensic layer,
followed by evidence cleanup and evasion of remaining detection rules.
```
