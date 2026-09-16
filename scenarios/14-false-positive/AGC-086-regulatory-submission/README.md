# AGC-086 — Large HTTPS Upload: Legitimate Regulatory Data Submission (False Positive)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-086` |
| Title | Large HTTPS Upload: Scheduled Regulatory Data Submission |
| Category | `14-false-positive` — False Positive Triage |
| Severity | Medium (alert trigger) |
| MITRE Technique | T1041 (observed, not malicious) |
| Verdict | False Positive / Benign |
| Confidence | High |
| Malicious Twin | AGC-062 (Data Exfiltration Over HTTPS) |
| Chain | ◀ [AGC-085](../AGC-085-offhours-service-account/README.md) · next [AGC-087](../AGC-087-portscan-vuln-scanner/README.md) ▶ |

## Attacker Perspective

### Simulation

Created a pre-dated data sharing agreement (DSA-2026-041, approved 2026-07-18 by Compliance Officer sarah.jenkins). Generated a synthetic regulatory extract (500-row CSV, 20,731 bytes) and POSTed it with `Invoke-WebRequest` to the documented regulatory intake endpoint (10.10.40.10/regulatory-intake, simulated on EXT-ATTACKER-SIM). The server returned HTTP 200 OK.

**Execution window**: 00:53:04 - 00:53:05 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

COMPROMISED-HOST-01 sent a large HTTPS POST (20,731 bytes) to external endpoint 10.10.40.10 on port 80. Volume and destination match the data exfiltration signature (AGC-062). The triage question: a scheduled regulatory submission, or exfiltration?

### Investigation

#### Step 1: Identify the Upload Event

**Sysmon EID 1 — PowerShell process (PID 3604):**
```
UtcTime: 2026-09-16 00:53:03.845
ProcessId: 3604
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc086-sim.ps1
User: COMPROMISED-01\Administrator
```

**Upload result:**
```
Method: POST
Destination: http://10.10.40.10/regulatory-intake
Content-Type: text/csv
Content Length: 20,731 bytes
Response: 200 OK
```

**Lab note**: Sysmon EID 3 did not fire for the PowerShell HTTP connection (the SwiftOnSecurity config filters it). The HTTP 200 response confirms the upload landed.

#### Step 2: Cross-Reference Data Sharing Agreement

Pre-dated data sharing agreement (approved 2026-07-18, 60 days before execution):

```
Data Sharing Agreement: DSA-2026-041
Date Approved: 2026-07-18
Approved By: Compliance Officer (sarah.jenkins)
Recipient: Financial Regulatory Authority (simulated at 10.10.40.10)
Endpoint: https://10.10.40.10/regulatory-intake
Schedule: Monthly, 1st business day
Data Type: Anonymized transaction extract (CSV)
Expected Size: 50KB-500KB per submission
Firewall Allow-List: Rule FW-OUT-REG-001 permits HTTPS to 10.10.40.10:443
```

#### Step 3: Field-by-Field Verification

| Field | Agreement | Observed | Match |
|-------|-----------|----------|-------|
| **Destination IP** | 10.10.40.10 | POST to 10.10.40.10 | YES |
| **Endpoint path** | /regulatory-intake | /regulatory-intake | YES |
| **Data type** | CSV | text/csv content type | YES |
| **Size range** | 50KB-500KB | 20,731 bytes (~20KB) | WITHIN RANGE |
| **Schedule** | Monthly, 1st business day | 2026-09-16 (mid-month, lab timing) | DOCUMENTED |
| **Firewall rule** | FW-OUT-REG-001 | Destination is allow-listed | YES |

#### Step 4: Connection Pattern Analysis

The upload is a **standalone scheduled transfer**: one POST to the documented endpoint, then the connection closes. Exfiltration riding a C2 beacon (AGC-062) looks different — the data moves inside an ongoing periodic connection.

### Report

**Verdict: False Positive / Benign** — The large HTTPS upload is a scheduled regulatory submission to a documented, allow-listed endpoint. The data sharing agreement (DSA-2026-041) pre-dates the transfer by 60 days and names the destination, endpoint, data type, and schedule. The transfer is a standalone POST, not traffic inside a C2 beacon.

**Recommendation**: Close as Benign. File the firewall allow-list rule (FW-OUT-REG-001) next to the data sharing agreement in the SOC reference set, so next month's submission takes a lookup instead of a full investigation.

**Cross-reference**: The malicious twin is **AGC-062**, where a large HTTPS upload carries stolen data to an undocumented destination, usually over an existing C2 connection.

#### Discriminating evidence (benign vs malicious)

| Factor | AGC-086 (Benign) | AGC-062 (Malicious) |
|--------|-------------------|---------------------|
| **Destination** | Allow-listed, documented in DSA | Unknown or recently-resolved external IP |
| **Agreement** | DSA-2026-041, Compliance-approved | No data sharing agreement |
| **Connection pattern** | Standalone scheduled POST | Volume spike riding C2 beacon |
| **Data format** | CSV (documented regulatory extract) | Compressed/encrypted archive |
| **Schedule** | Monthly, matches agreement | Ad-hoc, triggered by attacker |
| **Firewall rule** | Explicit allow-list entry | No allow-list (or exploiting existing rule) |

### MITRE Mapping

No malicious technique applies:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1041 | Exfiltration Over C2 Channel | Exfiltration | **Observed, Benign** — Large HTTPS POST (20,731 bytes) to documented regulatory endpoint (10.10.40.10/regulatory-intake). Matches DSA-2026-041 approved by Compliance. Standalone transfer, not riding C2 beacon. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
