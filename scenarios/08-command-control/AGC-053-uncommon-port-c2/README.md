# AGC-053 — Uncommon-Port C2

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-053` |
| Category | `08-command-control` — Command & Control |
| MITRE Technique | `T1571` Non-Standard Port |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Network-flow analysis — outbound connection to destination port outside the documented baseline for the source segment |
| Time to Triage | 03:00 (compare destination port against segment's documented outbound port baseline; check for legitimate application using that port) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as beacon source; `EXT-ATTACKER-SIM` (10.10.40.10:8443) as C2 destination |
| Chain | ◀ [AGC-052](../AGC-052-dns-beacon/README.md) · next [AGC-054](../AGC-054-rare-destination-domain/README.md) ▶ |
| One-line Summary | C2 beacon from COMPROMISED-HOST-01 to 10.10.40.10 on non-standard port 8443. 8 connection attempts over ~3 minutes with ~23s interval. All timed out (no service on 8443). Sysmon EID 3 does NOT capture failed TCP connections, so host-based detection missed all 8 attempts. Comparison: port 443 to same destination generated 10 EID 3 events (AGC-051); port 8443 generated 0. This demonstrates the detection gap for non-standard ports when connections fail — network-flow monitoring (Zeek, firewall logs) is essential. The key signal is comparing the destination port against the documented outbound port baseline for the LAN segment. |

## Attacker Perspective

### Tradecraft

**What:** Non-standard port C2 uses a port that is not commonly associated with the protocol being carried. In this case, HTTPS over port 8443 instead of the standard port 443. Attackers use non-standard ports because:
1. **Firewall bypass:** Some firewalls allow all outbound traffic; non-standard ports avoid protocol-specific inspection rules that only apply to standard ports
2. **IDS/IPS evasion:** Deep packet inspection is often configured only for standard port-protocol pairs (e.g., HTTP inspection on port 80, HTTPS on 443)
3. **Blending with legitimate alt-HTTPS:** Port 8443 is commonly used by legitimate services (Tomcat, VMware, some web management interfaces), providing plausible deniability

**Why port 8443 specifically:** It is the most commonly chosen alternative HTTPS port because many legitimate services use it, making it less suspicious than truly random ports (e.g., 12345). However, a LAN workstation connecting outbound to an external IP on port 8443 is not normal baseline behavior.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `EXT-ATTACKER-SIM` (10.10.40.10) running (no listener on 8443 — connections time out).

**Beacon parameters:**
- **URL:** `https://10.10.40.10:8443/beacon`
- **Interval:** ~23 seconds (20s sleep + 3s timeout)
- **Cycles:** 8
- **Duration:** ~3 minutes (21:57:35 to 22:00:16 UTC)

**Beacon timeline (all timestamps UTC):**

| Cycle | Timestamp | Delta (s) | Result |
|---|---|---|---|
| 1 | 21:57:35.225 | — | Timeout (no service on 8443) |
| 2 | 21:57:58.313 | 23.088 | Timeout |
| 3 | 21:58:21.333 | 23.020 | Timeout |
| 4 | 21:58:44.339 | 23.006 | Timeout |
| 5 | 21:59:07.374 | 23.035 | Timeout |
| 6 | 21:59:30.388 | 23.014 | Timeout |
| 7 | 21:59:53.412 | 23.024 | Timeout |
| 8 | 22:00:16.444 | 23.032 | Timeout |

**Critical observation:** All 8 connections timed out because no service was listening on port 8443 at the C2 server. Compare with AGC-051 where port 443 reached the EXT-ATTACKER-SIM HTTPS service (SSL/TLS handshake attempted). This difference reveals an important detection gap.

## SOC Perspective

### Detection

**Sysmon EID 3 — Network Connection: 0 events (port 8443)**

No Sysmon EID 3 events were generated for the 8 connection attempts to port 8443. This is because EID 3 only fires for COMPLETED TCP connections — when the TCP handshake fails (timeout/reset), no EID 3 is generated.

**Comparison with AGC-051 (same destination, standard port):**
```
Port 443 connections to 10.10.40.10 (last 30 min): 10 EID 3 events
Port 8443 connections to 10.10.40.10 (last 30 min):  0 EID 3 events
```

This demonstrates a critical Sysmon detection gap: when C2 connections fail (as they often do during initial deployment or when the C2 server is temporarily down), host-based detection via Sysmon misses them entirely. Only network-flow monitoring would capture the attempted connections.

**Where detection WOULD occur:**
1. **Zeek conn.log (Security Onion):** Would capture all 8 TCP SYN attempts regardless of outcome, with destination port 8443 clearly visible
2. **OPNsense firewall logs:** Would log the outbound connection attempts if the firewall rule permits or explicitly denies port 8443
3. **Windows Filtering Platform (EID 5156/5157):** Not audited in this configuration, but would capture allowed/blocked connections at the Windows firewall level

**Process context (from concurrent EID 1 analysis):**
The beaconing process (powershell.exe, PID running the Invoke-WebRequest loop) would be visible in Sysmon EID 1 at process creation time, but the individual beacon attempts do not generate separate EID 1 events.

### Investigation

**Step 1 — Compare outbound ports against segment baseline:**
For the LAN workstation segment, the documented baseline of normal outbound ports includes:
- 80 (HTTP), 443 (HTTPS), 53 (DNS)
- Possibly: 587/993/995 (email), 8080 (proxy)

Port 8443 is NOT in the standard LAN workstation outbound baseline. Any workstation connecting outbound on port 8443 to an external IP requires investigation.

**Step 2 — Check for legitimate application:**
Verify whether any approved software on the workstation uses port 8443:
- VMware management interfaces (not applicable to user workstations)
- Tomcat-based internal applications (would connect to internal, not external IPs)
- No legitimate application on michael.chen's workstation justifies outbound 8443 to an external IP

**Step 3 — Correlate with beacon timing (AGC-051):**
Uncommon port + periodic timing = compound C2 indicator:
- Port deviation from baseline: confirmed (8443 not in baseline)
- Timing regularity: 23s mean interval with low variance (same C2 pattern as AGC-051)
- Combined signal is stronger than either indicator alone

**Step 4 — Protocol/port mismatch analysis:**
Even though the connection failed, if it had succeeded:
- TLS handshake data (SNI, JA3 fingerprint) would reveal the client/server capabilities
- A JA3 hash matching known malware frameworks (Cobalt Strike, Metasploit) on a non-standard port is a very high-confidence indicator

### Report

**Verdict: True Positive** — C2 beaconing on non-standard port 8443.

**Confidence: High** — Calibrated assessment:
1. Port 8443 is outside the documented outbound port baseline for LAN workstations.
2. No legitimate application on this workstation justifies outbound connections to an external IP on port 8443.
3. Periodic connection pattern (23s interval, low variance) matches C2 beacon behavior.
4. Same destination IP (10.10.40.10) as confirmed C2 infrastructure (AGC-051, AGC-052).
5. The connection failures actually make this MORE suspicious — a legitimate application would not silently retry a failed connection every 23 seconds.

**Response recommendation:**
1. **Block port/destination combination** at the firewall — deny 10.10.40.10:8443 and review all non-standard outbound port policies.
2. **Enforce outbound port whitelist** via firewall policy, not just documentation. Only allow documented baseline ports for the LAN segment. This converts "detect and investigate" into "prevent and alert."
3. **Isolate the beaconing host** — same host as AGC-051/052, confirming multi-channel C2.
4. **Deploy non-standard port alerting:** Monitor for outbound connections to ports not in the segment's baseline whitelist. Alert on first occurrence, not volume threshold.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Command and Control (TA0011) | T1571 | Non-Standard Port | 8 connection attempts from 10.10.10.103 to 10.10.40.10:8443 over ~3 minutes. All timed out. Port 8443 outside LAN workstation baseline. 0 Sysmon EID 3 (failed TCP). Network-flow detection required. Same C2 destination as AGC-051/052. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Uncommon port beacon summary

```
Source:     10.10.10.103 (COMPROMISED-HOST-01)
Dest:       10.10.40.10:8443 (EXT-ATTACKER-SIM)
Port:       8443 (non-standard; standard = 443)
Attempts:   8
Duration:   ~3 minutes (21:57:35 to 22:00:16 UTC)
Result:     All timed out (no service on 8443)

Sysmon EID 3:  0 events (failed TCP connections not captured)
Comparison:    Port 443 to same dest = 10 EID 3 events (AGC-051)
```

### Detection gap analysis

```
Detection Layer        | Port 443 (AGC-051) | Port 8443 (AGC-053)
-----------------------|--------------------|---------------------
Sysmon EID 3           | 10 events          | 0 events
Sysmon EID 22 (DNS)    | 0 (raw IP)         | 0 (raw IP)
Zeek conn.log (SO)     | Would capture      | Would capture
OPNsense FW logs       | Cross-zone         | Cross-zone

Conclusion: Non-standard port C2 with failed connections is
invisible to Sysmon. Network-flow monitoring is the only
detection layer that would catch this pattern.
```
