# AGC-064 — Removable-Media Exfiltration (USB)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-064` |
| Category | `10-exfiltration` — Exfiltration |
| MITRE Technique | `T1052.001` Exfiltration Over Physical Medium: Exfiltration over USB |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (subst.exe + xcopy.exe to non-system drive letter) |
| Time to Triage | 04:00 (identify USB device connection, verify file copy to removable volume) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-063](../AGC-063-dns-tunneling/README.md) · next [AGC-065](../AGC-065-unusual-smb-transfer/README.md) ▶ |
| One-line Summary | subst.exe created virtual drive E: simulating USB mount, then xcopy.exe copied staged_usb.zip (625 bytes, 4 finance documents) to E:\. 3 Sysmon EID 1 events captured the full chain: PowerShell orchestration -> drive mount -> file copy. No Security EID 6416 (VM USB controller disabled). No network evidence (host-only exfiltration). This technique bypasses all network-based detection in the SOC stack. |

## Attacker Perspective

### Tradecraft

**What:** Copying data to a USB drive, which leaves nothing for network-based detection to see:
- No firewall logs — data never crosses the network
- No IDS/IPS alerts — no packets to inspect
- No DNS logs, no conn.log, no proxy logs
- The only detection surface is host-based telemetry: Sysmon, Windows Security audit events, and endpoint DLP

**Why an Attacker Uses It Here:**
1. After the partial success of network exfiltration in AGC-062 and AGC-063, USB is a channel no firewall rule can cut
2. At Ashford Grove Capital an insider, or an attacker with a compromised user's physical access, can walk the data out the door
3. A single USB drive can carry terabytes — far more than any network exfiltration method
4. With no network trail, detection rests entirely on how the endpoint audit policy is configured

**Key prevention control:** GPO-enforced USB write blocking on every endpoint, with a short documented exception list. Without it, the SOC can only detect after the copy has happened.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- VM USB controller disabled — simulated via `subst.exe` virtual drive mapping
- staged_usb.zip created from 4 finance documents (625 bytes)

**Execution:**
```powershell
# Create staged archive
Compress-Archive -Path "C:\Windows\Temp\agc064_exfil\*" -DestinationPath "C:\Windows\Temp\staged_usb.zip"

# Simulate USB drive mount
subst E: C:\Windows\Temp\agc064_usb

# Copy staged archive to USB (E:)
xcopy /Y C:\Windows\Temp\staged_usb.zip E:\

# Safely detach (simulate USB removal)
subst E: /D
```

**Result:** subst.exe created the virtual drive mapping and xcopy copied staged_usb.zip to E:\. Sysmon EID 1 logged both processes.

**Lab constraint:** The VM USB controller is disabled, so no virtual USB mass storage device could be attached. `subst.exe` produces the same file copy artifacts, minus EID 6416 (PnP device recognition). In production a physical USB device would log EID 6416 if Removable Storage auditing is enabled.

## SOC Perspective

### Detection

**Sysmon EID 1 — subst.exe (drive mount simulation):**
```
Process Create:
UtcTime: 2026-09-15 22:51:45.422
ProcessGuid: {eb65e329-cc01-6aa9-c004-000000001400}
ProcessId: 5176
Image: C:\Windows\System32\subst.exe
CommandLine: "C:\WINDOWS\system32\subst.exe" E: C:\Windows\Temp\agc064_usb
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=618126698DC497A68EB294493FAADC2D
```

**Sysmon EID 1 — xcopy.exe (file copy to E:):**
```
Process Create:
UtcTime: 2026-09-15 22:51:45.497
ProcessGuid: {eb65e329-cc01-6aa9-c104-000000001400}
ProcessId: 5996
Image: C:\Windows\System32\xcopy.exe
CommandLine: "C:\WINDOWS\system32\xcopy.exe" /Y C:\Windows\Temp\staged_usb.zip E:\
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=2E3735CE788AC354393E7D754174E6D5
```

**Sysmon EID 1 — PowerShell orchestration:**
```
Process Create:
UtcTime: 2026-09-15 22:51:44.085
ProcessGuid: {eb65e329-cc00-6aa9-be04-000000001400}
ProcessId: 3252
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc064-sim.ps1
User: COMPROMISED-01\Administrator
```

**Security EID 6416 — PnP Device Recognition: 0 events**
VM USB controller disabled. In production, Windows logs this event when it recognizes a physical USB device.

**Sysmon EID 11 — File Create on E:: 0 events**
Sysmon did not log EID 11 because the RuleName `EXE` filter does not match a .zip extension (same SwiftOnSecurity gap).

**Network evidence: NONE**
No EID 3, no DNS queries, no firewall logs. Nothing on the network side recorded the copy.

### Investigation

**Step 1 — Confirm USB/removable storage audit configuration:**
Security EID 6416 (PnP device recognition) produced 0 events. This could mean:
- No USB device was connected (the case here — simulated via subst)
- Removable Storage auditing is not enabled (the more dangerous conclusion)
If that audit category is disabled, a real USB copy logs no PnP event at all — a detection gap. Verify via: `auditpol /get /subcategory:"Plug and Play Events"`

**Step 2 — Identify file copy to non-system volume:**
The xcopy.exe CommandLine shows destination `E:\`, a non-system drive letter. Where USB is restricted, any file write to a non-C: volume warrants a look:
- What was the source file? (`staged_usb.zip` — an archive from `C:\Windows\Temp\`)
- What process initiated the copy? (xcopy.exe, spawned by the PowerShell script)
- Does the user have documented authorization for removable media use?

**Step 3 — Assess USB policy compliance:**
A firm handling regulated data (client PII, wire transfer records, M&A documents) should deny USB write access by default through GPO. Verify:
- `Computer Configuration > Administrative Templates > System > Removable Storage Access > Removable Disks: Deny write access`
- Is `michael.chen` on any exception list?
- If USB write is not blocked, this is an incident and a policy gap at once

### Report

**Verdict: True Positive** — File exfiltration to removable media (simulated USB drive).

**Confidence: High** — Not Critical because:
1. Virtual drive (subst.exe) rather than physical USB — no EID 6416 to confirm actual removable media
2. With a real USB device this would be Critical, since no network control can see the copy

**Response recommendation:**
1. **Physically secure the USB device** if possible — in production that drive may be the only copy of the data outside attacker control
2. **Revoke removable media permissions** for the compromised account immediately
3. **Implement GPO-enforced USB write blocking** (`Removable Disks: Deny write access`) on every endpoint as the primary preventive control
4. **Enable Removable Storage auditing** (`auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable`) so USB connections get logged
5. **Alert on file copies to non-C: volumes** from non-whitelisted processes — xcopy.exe, robocopy.exe, or Copy-Item writing to any drive letter other than C: should get a review
6. **Document that this technique is invisible to network-based SOC tools** — no firewall, IDS, proxy, or DNS log captures a USB copy

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Exfiltration (TA0010) | T1052.001 | Exfiltration Over Physical Medium: Exfiltration over USB | subst.exe E: drive mount + xcopy.exe staged_usb.zip to E:\. 3 EID 1 events. No network evidence (host-only). EID 6416 absent (VM limitation). | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Process chain: USB exfiltration operation

```
Time (UTC)          PID   Image          CommandLine
22:51:44.085        3252  powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc064-sim.ps1
22:51:45.422        5176  subst.exe      E: C:\Windows\Temp\agc064_usb
22:51:45.497        5996  xcopy.exe      /Y C:\Windows\Temp\staged_usb.zip E:\

Result: 1 file copied (staged_usb.zip, 625 bytes)
Network footprint: ZERO
```

### Detection coverage for USB exfiltration

```
Detection Source          Available?  Captures USB Exfil?
Sysmon EID 1 (process)    YES         YES (xcopy/subst commands)
Sysmon EID 11 (file)      YES         NO (.zip not matched)
Security EID 6416 (PnP)   NO*         Would capture device connect
Security EID 4663 (audit)  NO*         Would capture file access
Firewall logs             YES         NO (no network traffic)
IDS/IPS                   YES         NO (no network traffic)
DNS logs                  YES         NO (no network traffic)
Proxy logs                YES         NO (no network traffic)

* Requires explicit audit policy configuration
```
