# AGC-034 — Kerberos Ticket Enumeration / Export

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-034` |
| Category | `05-credential-access` — Credential Access |
| MITRE Technique | `T1558` Steal or Forge Kerberos Tickets |
| Verdict | True Positive (Probable) |
| Confidence | Medium |
| Time to Detect | Immediate — Sysmon EID 1 captures `klist.exe` execution; signal is weak in isolation |
| Time to Triage | 05:00 (value is in correlation with subsequent anomalous authentication events, not in the enumeration itself) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-033](../AGC-033-browser-credential-store/README.md) · next [AGC-035](../AGC-035-password-spray/README.md) ▶ |
| One-line Summary | `klist` and `klist sessions` executed by Administrator to enumerate cached Kerberos tickets and active logon sessions. Zero Kerberos tickets found (domain trust broken — all authentication is NTLM). Sysmon EID 1 captured both commands. Signal is weak alone; investigative value is in downstream correlation. |

## Attacker Perspective

### Tradecraft

**What:** The attacker uses `klist.exe` (a built-in Windows tool) to enumerate cached Kerberos tickets in the current logon session. In a functioning domain environment, `klist` reveals:
- **TGT (Ticket Granting Ticket):** Used to request service tickets from the KDC. Stealing a TGT enables Pass-the-Ticket attacks.
- **Service Tickets (TGS):** Already-issued tickets for specific services. These can be exported and replayed on other hosts.
- **Session information:** Which accounts are logged in, their authentication method, and session IDs.

The full attack chain (not simulated in this isolated scenario):
1. `klist` to identify cached tickets and sessions
2. Extract tickets using Mimikatz (`sekurlsa::tickets /export`) or Rubeus (`dump`)
3. Import stolen tickets into another session (`kerberos::ptt`)
4. Authenticate to services using the stolen tickets (Pass-the-Ticket)

`klist` itself is a benign diagnostic tool. Administrators and end users routinely run it to troubleshoot Kerberos authentication issues. Its presence alone is not a strong indicator.

**Why at this lifecycle stage:** After credential harvesting (AGC-031 through AGC-033), the attacker surveys what Kerberos authentication material is available. Kerberos tickets are more valuable than NTLM hashes for lateral movement because they can be used for service authentication without triggering NTLM relay detections.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `AD-DC-01` running (domain controller services).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 20:07:28 | klist | COMPROMISED-HOST-01 | Cached Tickets: (0) — no Kerberos tickets in current session |
| 2 | 2026-09-15 20:07:28 | klist sessions | COMPROMISED-HOST-01 | 13 active sessions enumerated. All Administrator sessions use NTLM (not Kerberos). Machine account (ASHFORDGROVE\COMPROMISED-01$) uses Negotiate. |

**Key finding:** Zero Kerberos tickets are cached because the domain trust relationship for COMPROMISED-HOST-01 is broken (discovered in AGC-025). All authentication falls back to NTLM. No Security EID 4768 (TGT requests) or 4769 (TGS requests) were found, confirming no Kerberos activity on this host.

**Cleanup:** No artifacts created.

## SOC Perspective

### Detection

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 20:07:28 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\klist.exe` (PID 4972). **CommandLine:** `klist`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. **ParentImage:** `powershell.exe`. |
| 2026-09-15 20:07:28 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\klist.exe` (PID 5136). **CommandLine:** `klist sessions`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. **ParentImage:** `powershell.exe`. |

**No EID 4768/4769 events:** Kerberos ticket-granting activity was absent on this host because the domain trust is broken. In a functioning domain, EID 4768 (TGT request) and 4769 (service ticket request) on the DC would provide the correlation data needed to assess whether tickets are being misused.

### Investigation

**Step 1 — Assess the signal strength honestly:**
`klist` is a standard Windows diagnostic tool. Administrators use it routinely to troubleshoot Kerberos authentication, check ticket expiration, and verify service principal names. **Running klist alone is NOT a strong indicator of compromise.** This must be stated explicitly to avoid alert fatigue from overreacting to benign activity.

**Step 2 — Correlation is where the value lies:**
The investigative value of `klist` execution is in what happens NEXT:
- Does the same account authenticate on a DIFFERENT host shortly after? (lateral movement)
- Is the authentication method on the destination host unusual? (e.g., Kerberos without a preceding interactive logon = possible ticket reuse)
- Are there Rubeus or Mimikatz process creation events (`sekurlsa::tickets`, `kerberos::ptt`) near the `klist` timestamp?

Without downstream correlation, `klist` execution should be logged but not escalated.

**Step 3 — Session enumeration analysis:**
`klist sessions` output reveals 13 active sessions, all using NTLM authentication. The NTLM-only pattern is itself a finding: in a healthy domain environment, Kerberos would be the primary authentication protocol. The fallback to NTLM suggests either domain trust issues or deliberate NTLM downgrade.

**Step 4 — Context from the attack chain:**
This scenario follows credential harvesting (AGC-031 LSASS, AGC-032 SAM, AGC-033 browser credentials). In that context, `klist` is a reconnaissance step before lateral movement. The chain context elevates the signal from "benign diagnostic" to "probable attack reconnaissance," but the confidence remains Medium because `klist` alone does not prove malicious intent.

### Report

**Verdict: True Positive (Probable)** — `klist` was executed as part of a credential access reconnaissance sequence. The tool itself is benign, but its use in the context of prior credential harvesting (AGC-031/032/033) makes it a probable attack indicator.

**Confidence: Medium** — This is an honest assessment:
1. `klist` alone is weak evidence — it is a legitimate diagnostic tool.
2. Sysmon EID 1 confirmed execution by Administrator from PowerShell.
3. No Kerberos tickets were found (domain trust broken), meaning no tickets are available for theft on this host.
4. Confidence would rise to High only with downstream correlation: anomalous authentication on another host using tickets from this session.

**Response recommendation:**
1. **Do not act on `klist` alone** — monitor for downstream correlation.
2. **Flag for timeline analysis** — correlate this event with any subsequent authentication anomalies (EID 4624 with unusual LogonProcessName, EID 4769 with unexpected service targets, or Pass-the-Ticket indicators).
3. **Investigate the domain trust issue** — zero Kerberos tickets and NTLM-only authentication indicate the domain trust relationship needs repair (`nltest /sc_verify:ashfordgrove.local`).
4. **If correlated with lateral movement** — reset Kerberos tickets for affected accounts (`klist purge` on the source host, password reset to invalidate TGTs). For confirmed Pass-the-Ticket at scale, consider a `krbtgt` password reset (double reset per Microsoft guidance), but only when the scope of compromise justifies this high-impact action.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1558 | Steal or Forge Kerberos Tickets | Sysmon EID 1: `klist.exe` and `klist sessions` executed by Administrator from PowerShell. 13 sessions enumerated (all NTLM, 0 Kerberos tickets). Enumeration step in isolation — signal is weak; value is in downstream correlation with anomalous authentication. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
