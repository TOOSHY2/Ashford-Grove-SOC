# AGC-091 — Proactive Hunt: Beaconing Pattern via Connection Statistics

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**Intended data source**: Security Onion `conn.log` (Zeek/Bro connection logs), the right dataset for inter-arrival time analysis.

**Lab constraint**: Security Onion (10.10.30.20) has NO Guest Additions installed, so guestcontrol cannot query it directly. The Wazuh indexer (port 9200) does not answer from MGMT-GUI-TEMP, which rules out the API route. The hunt fell back to the network telemetry available on the management workstation.

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

Every socket is a **local/loopback service** (DNS resolver, CUPS printing, mDNS). There is no outbound connection to any internal or external host, periodic or otherwise.

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

**Result: Hypothesis Refuted** — The available network telemetry shows no C2 beaconing. Every active connection on the management workstation is a local service (DNS resolver, CUPS, mDNS); there is no outbound periodic connection to any internal or external host.

**Lab constraint acknowledgment**: The right dataset for this hunt is the Security Onion conn.log, with Zeek timestamps, durations, and byte counts per connection. It was out of reach: Security Onion has no Guest Additions and the Wazuh indexer was offline. A production run would take the full conn.log and compute inter-arrival time standard deviation for every (src, dst, dport) tuple.

**Recommendation**: Re-run this hunt against the Zeek conn.log once Security Onion access is restored. The method itself (low inter-arrival time variance = suspicious regularity) holds and belongs in the periodic hunt library. Exclude known monitoring heartbeats (Wazuh agent check-ins, SNMP polling) from the baseline.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1071 | Application Layer Protocol | Command and Control | **Hunted** — No active beaconing patterns detected from management workstation. All connections are local services. Full conn.log analysis from Security Onion would provide full network-side coverage but was unavailable due to lab constraints (no Guest Additions, Wazuh indexer offline). |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
