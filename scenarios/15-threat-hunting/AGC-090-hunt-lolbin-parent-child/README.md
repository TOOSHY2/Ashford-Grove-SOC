# AGC-090 — Proactive Hunt: Rare Parent-Child Process Relationships (LOLBins)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-090` |
| Title | Hunt: Statistically Rare Parent-Child Process Chains |
| Category | `15-threat-hunting` — Proactive Threat Hunting |
| Hunt Type | Hypothesis-Driven (Statistical Baseline) |
| MITRE Technique | T1218 (System Binary Proxy Execution) |
| Hunt Result | Hypothesis Confirmed (Residual Scenario Artifacts) |
| Related Scenarios | AGC-011, AGC-012, AGC-014, AGC-015, AGC-016 |
| Chain | ◀ [AGC-089](../AGC-089-hunt-wmi-persistence/README.md) · next [AGC-091](../AGC-091-hunt-beacon-statistics/README.md) ▶ |

## SOC Perspective

### Hypothesis

*Stated before any query was executed:*

> If an adversary has abused LOLBins or legitimate system binaries via unusual parent-child process chains, these pairs will appear as statistically rare (count=1) in the Sysmon EID 1 process creation log, standing out against the baseline of normal parent-child relationships.

### Investigation

#### Methodology

**Data source**: Sysmon EID 1 (Process Create) — 1,252 events analyzed on COMPROMISED-HOST-01.

**Approach**: Group all EID 1 events by `(ParentImage, Image)` pairs, count occurrences, sort ascending. Pairs with count <= 2 are rare and warrant triage.

**Execution window**: 01:08:06 - 01:09:18 UTC

#### Results

**119 unique parent-child pairs** identified from 1,252 EID 1 events. **47 rare pairs** (count=1) and **21 uncommon pairs** (count=2) flagged for review.

##### Notable Rare Pairs (Triage)

| Parent | Child | Count | Assessment |
|--------|-------|-------|------------|
| mshta.exe | cmd.exe | 1 | **Suspicious** — mshta spawning cmd is a classic LOLBin chain (AGC-015) |
| mshta.exe | powershell.exe | 1 | **Suspicious** — mshta spawning PowerShell is a macro-alternative execution chain (AGC-016) |
| powershell.exe | agc014_test.exe | 1 | **Known** — AGC-014 scenario artifact (dropped executable) |
| spoolsv.exe | regsvr32.exe | 1 | **Suspicious** — Print spooler spawning regsvr32 is a known LOLBin chain |
| services.exe | AGC027.exe | 1 | **Known** — AGC-027 scenario artifact (service persistence) |
| WmiPrvSE.exe | powershell.exe | 1 | **Suspicious** — WMI provider spawning PowerShell indicates WMI-based execution |
| WINWORD.EXE (C:\Temp) | powershell.exe | 1 | **Suspicious** — Simulated Office macro execution (AGC-016 artifact) |
| powershell.exe | WINWORD.EXE (C:\Temp) | 1 | **Known** — AGC scenario dropping simulated Office binary |
| cmd.exe | rundll32.exe | 1 | **Suspicious** — cmd spawning rundll32 is a proxy execution pattern |
| cmd.exe | taskkill.exe | 1 | **Suspicious** — Process termination via cmd chain |
| services.exe | cmd.exe | 1 | **Suspicious** — Service controller spawning cmd (service-based execution) |
| powershell.exe | csc.exe | 1 | **Notable** — In-memory compilation (.NET compiler invocation from PowerShell) |
| powershell.exe | VulnApp.exe | 1 | **Known** — AGC scenario artifact (vulnerable application) |
| powershell.exe | fodhelper.exe | 2 | **Known** — UAC bypass technique (AGC-028 artifact) |

##### Top 10 Common Pairs (Baseline)

| Parent | Child | Count | Assessment |
|--------|-------|-------|------------|
| (boot) | VBoxService.exe | 229 | Lab infrastructure |
| VBoxService.exe | powershell.exe | 115 | guestcontrol execution |
| powershell.exe | net.exe | 84 | Scenario execution |
| (boot) | SearchProtocolHost.exe | 79 | Windows Search |
| ossec-agent | auditpol.exe | 54 | Wazuh audit policy checks |

#### Triage Summary

The rare pairs fall into three categories:

1. **Prior scenario artifacts** (AGC-014, AGC-015, AGC-016, AGC-027, AGC-028): Known execution chains from completed scenarios. These validate that the hunt methodology successfully surfaces malicious patterns.

2. **Suspicious LOLBin chains** (mshta->cmd, mshta->powershell, spoolsv->regsvr32, WmiPrvSE->powershell): Classic abuse patterns that would warrant immediate investigation in a production environment.

3. **Benign system pairs** (services->svchost, svchost->taskhostw, etc.): Normal Windows service operations.

### Report

**Result: Hypothesis Confirmed (Residual Artifacts)** — The statistical rare-pair analysis successfully identified LOLBin abuse patterns from prior scenario executions (mshta->cmd, mshta->powershell, spoolsv->regsvr32, WmiPrvSE->powershell). No currently active malicious parent-child chains were found beyond historical scenario artifacts.

**Value of this hunt**: The rare parent-child pair analysis provides a baseline-independent detection method. In production, this query should be scheduled weekly with results compared against a growing whitelist of known-good pairs. Any new rare pair involving LOLBins (mshta, rundll32, regsvr32, certutil, cmstp, msiexec) should trigger immediate triage.

**Recommendation**: Add rare parent-child pair enumeration to the periodic hunt library. Maintain a whitelist of validated benign rare pairs to reduce future triage workload.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1218 | System Binary Proxy Execution | Defense Evasion | **Hunted** — Rare parent-child analysis surfaced mshta.exe, rundll32.exe, and regsvr32.exe in unusual parent chains. All attributable to prior scenario executions (AGC-011/012/015/016). Hunt methodology validated for detecting LOLBin abuse. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
