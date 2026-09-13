# Architecture

## Zones
| Zone | Subnet | Gateway | Trust |
|---|---|---|---|
| LAN-NET | 10.10.10.0/24 | .1 | Trusted — AD domain, employee workstations |
| DMZ-NET | 10.10.20.0/24 | .1 | Exposed — public-facing web server |
| SOC-NET | 10.10.30.0/24 | .1 | Monitoring — receives telemetry only |
| EXT-SIM-NET | 10.10.40.0/24 | .1 | Untrusted — isolated attacker infrastructure |

Each zone sits behind its own dedicated firewall interface rather than a shared VLAN trunk, closing off VLAN-hopping as an attack class.

## Systems
| System | Zone | IP | Role |
|---|---|---|---|
| OPNsense-FW | perimeter | .1 on each zone | Firewall/router, default-deny, all logged |
| AD-DC-01 | LAN-NET | 10.10.10.10 | Domain controller, ashfordgrove.local |
| WIN-CLIENT-01 | LAN-NET | 10.10.10.101 | Employee workstation |
| WIN-CLIENT-02 | LAN-NET | 10.10.10.102 | IT-support workstation |
| COMPROMISED-HOST-01 | LAN-NET | 10.10.10.103 | Phishing victim — every scenario's foothold |
| MGMT-GUI-TEMP | LAN-NET | 10.10.10.20 | Browser VM for admin GUIs |
| DMZ-LINUX-01 | DMZ-NET | 10.10.20.10 | Nginx web server, SSH, auditd |
| WAZUH-SIEM-01 | SOC-NET | 10.10.30.10 | SIEM/EDR |
| SECURITY-ONION-01 | SOC-NET | 10.10.30.20 | NSM — Zeek + Suricata |
| EXT-ATTACKER-SIM | EXT-SIM-NET | 10.10.40.10 | Kali — phishing sink, C2 sink |

## Firewall — default-deny, narrow logged exceptions only
| Rule | Ports | Purpose |
|---|---|---|
| COMPROMISED-HOST-01 → EXT-ATTACKER-SIM | SMTP/HTTP/HTTPS/DNS | Phishing, C2, exfil |
| LAN-NET → DMZ-LINUX-01 | SSH (22) | Lateral-movement pivot |
| LAN/DMZ → Internet (NAT) | HTTP/HTTPS/DNS | Updates only |
| Any → SOC-NET | Agent/NSM ports only | Telemetry in, nothing out |
