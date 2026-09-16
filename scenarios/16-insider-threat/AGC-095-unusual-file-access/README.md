# AGC-095 — Employee Accesses HR/Finance Share Outside Their Role

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-095` |
| Title | Insider Threat: Unauthorized Finance Share Access |
| Category | `16-insider-threat` — Insider Threat |
| Severity | Medium |
| MITRE Technique | None (baseline-deviation; role-mismatch detection) |
| Verdict | Confirmed Policy Violation — Escalate to Manager/HR |
| Confidence | High |
| Chain | ◀ [AGC-094](../../15-threat-hunting/AGC-094-hunt-offhours-scheduled-tasks/README.md) · next [AGC-096](../AGC-096-bulk-download-resignation/README.md) ▶ |

## Attacker Perspective

### Tradecraft

#### Role-Based Access Matrix (documented before simulation)

| Employee | Role | Authorized Shares | NOT Authorized |
|----------|------|-------------------|----------------|
| sarah.jenkins | Operations | Operations, General | **Finance**, HR, IT-Support |
| raj.patel | IT-Support | IT-Support, General | Finance, HR |
| michael.chen | Finance | Finance, General | HR, IT-Support |

### Simulation

The remote share access to `\\10.10.10.100\Finance` failed because the lab has no reachable share host. The simulation fell back to a local Finance folder structure and opened its files as the sarah.jenkins persona.

**Execution window**: 01:19:17 - 01:19:59 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

File access alert: sarah.jenkins (Operations role) browsed the Finance share and opened payroll data (payroll-sept.csv) and budget documents (Q3-budget-2026.xlsx). The access matrix does not authorize her role for that share.

### Investigation

#### Step 1: Confirm the Access Event

**Sysmon EID 1 — net.exe share access attempt (PID 5184):**
```
UtcTime: 2026-09-16 01:19:17
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.100\Finance
```

**Sysmon EID 1 — dir share enumeration (PID 5668):**
```
UtcTime: 2026-09-16 01:19:59
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\WINDOWS\system32\cmd.exe" /c "dir \\10.10.10.100\Finance"
```

**Files accessed in Finance share:**
```
Banking-Credentials-Internal.txt  (862 bytes)
Board-Meeting-Minutes-Sep2026.docx (2,864 bytes)
Employee-Salary-Data-2026.csv     (3,259 bytes)
Executive-Compensation-Review.docx (3,464 bytes)
Merger-Acquisition-Draft-NDA.pdf  (5,162 bytes)
payroll-sept.csv                  (85 bytes)
Q3-2026-Revenue-Report.xlsx       (4,557 bytes)
Q3-budget-2026.xlsx               (52 bytes)
Tax-Returns-2025-Corporate.pdf    (6,260 bytes)
Vendor-Payment-Schedule-Q4.xlsx   (2,161 bytes)
```

#### Step 2: Verify Role Authorization

sarah.jenkins holds the **Operations** role. The access matrix authorizes her for the Operations and General shares only and lists Finance as NOT authorized for her role.

#### Step 3: Assess Sensitivity of Accessed Data

| File | Sensitivity | Concern |
|------|-------------|---------|
| payroll-sept.csv | **Critical** — Contains salary and bonus data | PII exposure risk |
| Employee-Salary-Data-2026.csv | **Critical** — Full salary data | PII exposure risk |
| Banking-Credentials-Internal.txt | **Critical** — Financial credentials | Credential exposure |
| Merger-Acquisition-Draft-NDA.pdf | **High** — Material non-public information | Insider trading risk |
| Executive-Compensation-Review.docx | **High** — Executive compensation | PII exposure risk |

#### Step 4: Context Assessment

- **No prior access history**: sarah.jenkins has no documented history of Finance share access
- **No business justification**: No cross-functional project or temporary authorization on file
- **No manager approval**: No delegation or temporary access request documented
- **Access pattern**: Browsed multiple sensitive files (payroll, banking credentials, M&A NDA) — not a single accidental file open

### Report

**Verdict: Confirmed Policy Violation** — sarah.jenkins (Operations role) accessed the Finance share, which holds payroll, banking credentials, and M&A documents, without authorization. She browsed multiple files, so this was not an accidental open, and no business justification or temporary authorization exists.

**Severity: Medium** — Escalates to High if a pattern of repeated access is identified or if the accessed data was copied/forwarded.

**Recommendation**: Escalate to sarah.jenkins' manager and HR for a role-appropriate conversation. Do not confront the employee directly. Review access logs for any prior Finance share access by this account. Verify that role-based access controls (RBAC) are enforced at the share level so an Operations account cannot browse Finance at all. Enable file access auditing (Windows Security EID 4663) on sensitive shares.

### MITRE Mapping

No MITRE ATT&CK technique applies. This is a **baseline-deviation** detection against role-based access policy, not a technical attack indicator. SMB and file browsing are legitimate mechanisms; the finding is the mismatch between sarah.jenkins' role and the share she opened.

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
