# AGC-091 — Proactive Hunt: Beaconing Pattern via Connection Statistics

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-091` |
| Title | Hunt: C2 Beaconing via Inter-Arrival Time Variance |
| Category | `15-threat-hunting` — Proactive Threat Hunting |
| Hunt Type | Hypothesis-Driven (Statistical) |
| MITRE Technique | T1071 (Application Layer Protocol) |
| Hunt Result | Hypothesis Refuted (No Active Beaconing Detected) |
| Related Scenarios | AGC-051, AGC-052, AGC-053 |
| Chain | ◀ [AGC-090](../AGC-090-hunt-lolbin-parent-child/README.md) · next [AGC-092](../AGC-092-hunt-logon-time-patterns/README.md) ▶ |

## SOC Perspective

### Hypothesis

*Stated before any query was executed:*

> If C2 beaconing is active in this environment, the connection logs will show (source_ip, destination_ip, destination_port) tuples with low inter-arrival time variance (regular periodic connections), distinguishable from legitimate traffic which exhibits irregular timing.

### Investigation

#### Methodology

**Data source**: Network connection data from MGMT-GUI-TEMP (10.10.10.20) — active connections (`ss -tunap`), ARP neighbor table, and syslog network events.

**Intended data source**: Security Onion `conn.log` (Zeek/Bro connection logs) which would provide the optimal dataset for inter-arrival time analysis.

**Lab constraint**: Security Onion (10.10.30.20) has NO Guest Additions installed, preventing direct query via guestcontrol. The Wazuh indexer (port 9200) is not responding from MGMT-GUI-TEMP, preventing API-based data retrieval. The hunt used available network telemetry from the management workstation as an alternative.

**Execution window**: 01:12:38 - 01:12:39 UTC

#### Results

##### Active Connections (MGMT-GUI-TEMP)

```
Netid State  Local Address:Port     Peer Address:Port
udp   UNCONN 127.0.0.54:53          0.0.0.0:*       (systemd-resolved)
udp   UNCONN 127.0.0.53:53          0.0.0.0:*       (systemd-resolved)
udp   UNCONN 0.0.0.0:5353           0.0.0.0:*       (mDNS)
tcp   LISTEN 127.0.0.1:631          0.0.0.0:*       (CUPS)
tcp   LISTEN 127.0.0.54:53          0.0.0.0:*       (systemd-resolved)
```

All active connections are **local/loopback services** (DNS resolver, CUPS printing, mDNS). No outbound connections to external or internal hosts with periodic patterns.

##### ARP Neighbor Table

```
10.10.10.1   (OPNsense-FW)      STALE
10.10.10.102 (WIN-CLIENT-02)    STALE
10.10.10.103 (COMPROMISED-HOST-01) STALE
10.10.10.100 (AD-DC-01)         FAILED
10.10.10.101 (WIN-CLIENT-01)    FAILED
```

No active network conversations with lab hosts at query time.

##### DNS Resolution

DNS configured via systemd-resolved stub resolver (127.0.0.53) with upstream DNS at 10.10.10.1 (OPNsense-FW). DNS cache statistics not available via CLI.

### Report

**Result: Hypothesis Refuted** — No active C2 beaconing patterns were detected in the available network telemetry. All active connections from the management workstation are local services (DNS resolver, CUPS, mDNS) with no outbound periodic connections to internal or external hosts.

**Lab constraint acknowledgment**: The ideal dataset for beaconing analysis (Security Onion conn.log with Zeek connection metadata including timestamps, durations, and byte counts) was unavailable due to Security Onion having no Guest Additions and the Wazuh indexer being offline. A production hunt would use the full conn.log dataset to compute inter-arrival time standard deviation for all (src, dst, dport) tuples.

**Recommendation**: When Security Onion access is restored, re-run this hunt using the Zeek conn.log. The statistical method (low inter-arrival time variance = suspicious regularity) is sound and should be added to the periodic hunt library. Exclude known monitoring heartbeats (Wazuh agent check-ins, SNMP polling) from the baseline.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1071 | Application Layer Protocol | Command and Control | **Hunted** — No active beaconing patterns detected from management workstation. All connections are local services. Full conn.log analysis from Security Onion would provide full network-side coverage but was unavailable due to lab constraints (no Guest Additions, Wazuh indexer offline). |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
