# AGC-097 — Personal Cloud Upload: Policy Violation

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-097` |
| Title | Insider Threat: Upload to Unsanctioned Cloud Storage |
| Category | `16-insider-threat` — Insider Threat |
| Severity | High |
| MITRE Technique | T1567.002 (Exfiltration to Cloud Storage — same technical shape, insider motive) |
| Verdict | Confirmed Policy Violation |
| Confidence | High |
| Chain | ◀ [AGC-096](../AGC-096-bulk-download-resignation/README.md) · next [AGC-098](../AGC-098-service-account-interactive/README.md) ▶ |

## Attacker Perspective

### Tradecraft

#### Acceptable Use Policy (documented before simulation)

| Category | Services |
|----------|----------|
| **Sanctioned** | SharePoint, OneDrive (corporate tenant only) |
| **Prohibited** | Personal Dropbox, Google Drive, WeTransfer, any consumer cloud |

### Simulation

sarah.jenkins built a client list (client IDs, names, AUM, contact details) and pushed it with `Invoke-WebRequest POST` to a personal-cloud endpoint that EXT-ATTACKER-SIM stood in for (10.10.40.10/personal-cloud-upload). The upload returned HTTP 200 OK.

**Execution window**: 01:19:59 - 01:20:00 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

Outbound HTTPS POST from COMPROMISED-HOST-01 to 10.10.40.10, an unsanctioned external endpoint, carrying `client-list.xlsx` (198 bytes) with client names, AUM values, and contact emails. The destination is NOT on the sanctioned cloud services allow-list.

### Investigation

#### Step 1: Confirm the Upload

**Sysmon EID 1 — PowerShell execution (parent process):**
```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc095-100-sim.ps1
```

**Upload result:**
```
Method: POST
Destination: http://10.10.40.10/personal-cloud-upload
Content-Type: application/octet-stream
Content Length: 198 bytes
Response: 200 OK
```

**Lab note**: Sysmon EID 3 does not fire for PowerShell HTTP connections (filtered by SwiftOnSecurity config).

#### Step 2: Verify Destination Against Allow-List

| Check | Result |
|-------|--------|
| Destination IP | 10.10.40.10 (external) |
| Sanctioned service? | **NO** — not SharePoint or corporate OneDrive |
| Firewall allow-list? | No specific allow-list entry for this destination |
| Data sharing agreement? | **NONE** — no DSA on file for this endpoint |

#### Step 3: Assess Data Sensitivity

**File content (client-list.xlsx):**
```
CLIENT_ID,NAME,AUM,CONTACT
CL-001,Westfield Partners,45000000,john.westfield@wp.example
CL-002,Harbor Investments,78000000,lisa.chen@hi.example
CL-003,Summit Capital,120000000,david.ahmed@sc.example
```

- **Client PII**: Names, contact emails
- **Financial data**: Assets Under Management (AUM) values
- **Business sensitivity**: Client list is a core competitive asset

#### Step 4: Distinguish from External Attack

| Factor | AGC-097 (Insider) | AGC-062 (Attacker Exfil) |
|--------|-------------------|--------------------------|
| **Actor** | Legitimate employee (sarah.jenkins) | Compromised account or attacker |
| **Prior IOCs** | None — no malware, no C2, no credential theft | Preceding attack chain visible |
| **Destination** | Consumer cloud pattern | C2 infrastructure or attacker-controlled |
| **Intent** | Policy violation (convenience or deliberate) | Data theft for adversary gain |
| **File type** | Business document (client list) | Compressed/encrypted bulk data |

### Report

**Verdict: Confirmed Policy Violation** — sarah.jenkins uploaded a client list holding PII and AUM figures to an unsanctioned external endpoint, in breach of the Acceptable Use Policy. No prior technical IOCs (malware, C2, credential theft) exist on COMPROMISED-HOST-01, so this is an insider policy violation, not an external compromise.

**Recommendation**:
1. Block the destination category (consumer cloud uploads) at the firewall/proxy
2. Handle the employee per the Acceptable Use Policy disciplinary process — not as a confirmed attacker
3. Assess whether the uploaded data constitutes a reportable data breach under applicable regulations
4. Review why DLP did not stop a client list leaving for an unsanctioned destination
5. Cross-reference with AGC-062 (attacker exfiltration) so the playbook separates insider uploads from external exfil on the prior-IOC test above

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration | **Confirmed** — Upload of client list (198 bytes) via HTTP POST to unsanctioned endpoint (10.10.40.10/personal-cloud-upload). Same technical shape as attacker exfiltration but insider motivation (no preceding attack chain). |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
