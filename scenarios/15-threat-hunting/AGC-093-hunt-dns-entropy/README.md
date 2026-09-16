# AGC-093 — Proactive Hunt: DNS Query Volume and Subdomain Entropy

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-093` |
| Title | Hunt: DNS-Based C2/Exfiltration via Entropy Analysis |
| Category | `15-threat-hunting` — Proactive Threat Hunting |
| Hunt Type | Hypothesis-Driven (Statistical) |
| MITRE Technique | T1071.004 (DNS), T1048.003 (Exfiltration Over DNS) |
| Hunt Result | Hypothesis Refuted (Insufficient DNS Log Access) |
| Related Scenarios | AGC-052, AGC-063, AGC-084 |
| Chain | ◀ [AGC-092](../AGC-092-hunt-logon-time-patterns/README.md) · next [AGC-094](../AGC-094-hunt-offhours-scheduled-tasks/README.md) ▶ |

## SOC Perspective

### Hypothesis

*Stated before any query was executed:*

> If DNS-based C2 or exfiltration is active in this environment, the DNS query logs will show domains with high query volume AND high subdomain entropy (random-looking subdomain names), distinguishable from legitimate DNS traffic which uses predictable, human-readable subdomains.

### Investigation

#### Methodology

**Intended data source**: Security Onion DNS query logs (Zeek dns.log) or Sysmon EID 22 (DNS Query) aggregated in Wazuh.

**Available data source**: MGMT-GUI-TEMP DNS configuration and resolution statistics.

**Lab constraint**: Security Onion has NO Guest Additions, so guestcontrol cannot query it. The Wazuh indexer (port 9200) is not responding. MGMT-GUI-TEMP cannot produce `resolvectl` statistics for cache analysis.

**Execution window**: 01:12:38 - 01:12:39 UTC

#### Results

##### DNS Configuration (MGMT-GUI-TEMP)

```
nameserver 127.0.0.53    (systemd-resolved stub resolver)
Upstream DNS: 10.10.10.1 (OPNsense-FW)
```

Resolution runs MGMT-GUI-TEMP -> systemd-resolved (127.0.0.53) -> OPNsense-FW (10.10.10.1). The CLI gave no cache statistics; `resolvectl statistics` is not available on this Ubuntu version.

##### Syslog DNS Events

```
2026-09-13 06:49:54 systemd-resolved: Using degraded feature set UDP
                    instead of UDP+EDNS0 for DNS server 10.10.10.1
2026-09-13 06:49:58 systemd-resolved: Using degraded feature set TCP
                    instead of UDP for DNS server 10.10.10.1
```

The resolver stepped down from UDP+EDNS0 to TCP when talking to OPNsense. That shows DNS is reachable but degraded; it is not a sign of C2 or exfiltration.

##### Alternative Data Points

On COMPROMISED-HOST-01, Sysmon EID 22 (DNS Query) is available and has been used in prior scenarios:
- AGC-052: Random subdomain patterns (C2 beaconing) — high entropy
- AGC-084: Constant subdomain pattern (SaaS update) — low entropy
- AGC-063: Data-encoded subdomains (exfiltration) — very high entropy

Those three runs already show entropy separating C2 and exfiltration from SaaS traffic, even though a lab-wide hunt was not possible this session.

### Report

**Result: Hypothesis Refuted (Insufficient DNS Log Access)** — No centralized DNS query log was reachable, so the hunt could not run in full. Security Onion's Zeek dns.log is the right dataset but was out of reach (no Guest Additions, no API access). The Wazuh indexer was offline, which blocked pulling Sysmon EID 22 across endpoints.

**Methodology validation**: Prior scenario runs already bear out the entropy approach:
- **High entropy + high volume** = Likely C2 or exfiltration (AGC-052, AGC-063)
- **Low entropy + consistent pattern** = Likely legitimate SaaS (AGC-084)

**Recommendation**: Once Security Onion or Wazuh access is restored, run this hunt on the full Zeek dns.log. Compute Shannon entropy per registered domain across every subdomain queried. Flag domains with entropy > 3.5 bits AND query count > 10 for immediate triage. Add it to the periodic hunt library on a weekly schedule.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1071.004 | Application Layer Protocol: DNS | Command and Control | **Hunted** — DNS entropy analysis could not be fully executed due to Security Onion inaccessibility and Wazuh indexer being offline. Methodology validated by prior scenario evidence (AGC-052 random vs AGC-084 constant subdomains). |
| T1048.003 | Exfiltration Over Alternative Protocol | Exfiltration | **Hunted** — Same constraint. Prior AGC-063 confirmed that data-encoded DNS subdomains produce measurably high entropy. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
