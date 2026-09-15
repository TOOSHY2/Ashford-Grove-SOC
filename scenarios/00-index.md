# Scenario Index

All 100 scenarios (AGC-001 – AGC-100), by ID. This is a **structural**
index generated from the repository's folder layout — the **Verdict** and
**Confidence** columns are marked `— (pending)` for every scenario and are
filled in only once that scenario's `README.md` is written and its verdict
is reached. Nothing here is pre-judged.

| ID | Category | Scenario | Verdict | Confidence |
|---|---|---|---|:--:|
| `AGC-001` | Phishing & Initial Access | [`AGC-001-spoofed-display-name`](01-phishing/AGC-001-spoofed-display-name/README.md) | True Positive | High |
| `AGC-002` | Phishing & Initial Access | [`AGC-002-lookalike-domain`](01-phishing/AGC-002-lookalike-domain/README.md) | True Positive | High |
| `AGC-003` | Phishing & Initial Access | [`AGC-003-credential-harvest-link`](01-phishing/AGC-003-credential-harvest-link/README.md) | True Positive | Critical |
| `AGC-004` | Phishing & Initial Access | [`AGC-004-qr-code-phish`](01-phishing/AGC-004-qr-code-phish/README.md) | True Positive | Medium |
| `AGC-005` | Phishing & Initial Access | [`AGC-005-url-shortener-redirect`](01-phishing/AGC-005-url-shortener-redirect/README.md) | True Positive | High |
| `AGC-006` | Phishing & Initial Access | [`AGC-006-html-attachment-redirect`](01-phishing/AGC-006-html-attachment-redirect/README.md) | True Positive | High |
| `AGC-007` | Phishing & Initial Access | [`AGC-007-macro-lure-document`](01-phishing/AGC-007-macro-lure-document/README.md) | True Positive | High |
| `AGC-008` | Phishing & Initial Access | [`AGC-008-password-reset-lure`](01-phishing/AGC-008-password-reset-lure/README.md) | True Positive | Critical |
| `AGC-009` | Phishing & Initial Access | [`AGC-009-oauth-consent-phish`](01-phishing/AGC-009-oauth-consent-phish/README.md) | True Positive (conceptual) | Medium |
| `AGC-010` | Phishing & Initial Access | [`AGC-010-user-reported-triage`](01-phishing/AGC-010-user-reported-triage/README.md) | Triage Complete | High |
| `AGC-011` | Execution | [`AGC-011-browser-spawns-script`](02-execution/AGC-011-browser-spawns-script/README.md) | True Positive | High |
| `AGC-012` | Execution | [`AGC-012-office-spawns-powershell`](02-execution/AGC-012-office-spawns-powershell/README.md) | True Positive | Critical |
| `AGC-013` | Execution | [`AGC-013-encoded-powershell`](02-execution/AGC-013-encoded-powershell/README.md) | True Positive | High |
| `AGC-014` | Execution | [`AGC-014-executable-from-temp`](02-execution/AGC-014-executable-from-temp/README.md) | True Positive | Medium |
| `AGC-015` | Execution | [`AGC-015-signed-binary-proxy`](02-execution/AGC-015-signed-binary-proxy/README.md) | True Positive | High |
| `AGC-016` | Execution | [`AGC-016-wmi-process-creation`](02-execution/AGC-016-wmi-process-creation/README.md) | True Positive | High |
| `AGC-017` | Execution | [`AGC-017-task-triggered-execution`](02-execution/AGC-017-task-triggered-execution/README.md) | True Positive | High |
| `AGC-018` | Execution | [`AGC-018-eicar-detection-test`](02-execution/AGC-018-eicar-detection-test/README.md) | — (pending) | — (pending) |
| `AGC-019` | Persistence | [`AGC-019-registry-run-key`](03-persistence/AGC-019-registry-run-key/README.md) | — (pending) | — (pending) |
| `AGC-020` | Persistence | [`AGC-020-scheduled-task`](03-persistence/AGC-020-scheduled-task/README.md) | — (pending) | — (pending) |
| `AGC-021` | Persistence | [`AGC-021-new-autostart-service`](03-persistence/AGC-021-new-autostart-service/README.md) | — (pending) | — (pending) |
| `AGC-022` | Persistence | [`AGC-022-wmi-event-subscription`](03-persistence/AGC-022-wmi-event-subscription/README.md) | — (pending) | — (pending) |
| `AGC-023` | Persistence | [`AGC-023-new-local-admin`](03-persistence/AGC-023-new-local-admin/README.md) | — (pending) | — (pending) |
| `AGC-024` | Persistence | [`AGC-024-browser-extension`](03-persistence/AGC-024-browser-extension/README.md) | — (pending) | — (pending) |
| `AGC-025` | Privilege Escalation | [`AGC-025-privileged-group-add`](04-privilege-escalation/AGC-025-privileged-group-add/README.md) | — (pending) | — (pending) |
| `AGC-026` | Privilege Escalation | [`AGC-026-uac-bypass-behavior`](04-privilege-escalation/AGC-026-uac-bypass-behavior/README.md) | — (pending) | — (pending) |
| `AGC-027` | Privilege Escalation | [`AGC-027-service-misconfig`](04-privilege-escalation/AGC-027-service-misconfig/README.md) | — (pending) | — (pending) |
| `AGC-028` | Privilege Escalation | [`AGC-028-dll-search-order-hijack`](04-privilege-escalation/AGC-028-dll-search-order-hijack/README.md) | — (pending) | — (pending) |
| `AGC-029` | Privilege Escalation | [`AGC-029-suspicious-sudo-linux`](04-privilege-escalation/AGC-029-suspicious-sudo-linux/README.md) | — (pending) | — (pending) |
| `AGC-030` | Privilege Escalation | [`AGC-030-domain-admin-logon-workstation`](04-privilege-escalation/AGC-030-domain-admin-logon-workstation/README.md) | — (pending) | — (pending) |
| `AGC-031` | Credential Access | [`AGC-031-lsass-access`](05-credential-access/AGC-031-lsass-access/README.md) | — (pending) | — (pending) |
| `AGC-032` | Credential Access | [`AGC-032-sam-security-hive`](05-credential-access/AGC-032-sam-security-hive/README.md) | — (pending) | — (pending) |
| `AGC-033` | Credential Access | [`AGC-033-browser-credential-store`](05-credential-access/AGC-033-browser-credential-store/README.md) | — (pending) | — (pending) |
| `AGC-034` | Credential Access | [`AGC-034-kerberos-ticket-export`](05-credential-access/AGC-034-kerberos-ticket-export/README.md) | — (pending) | — (pending) |
| `AGC-035` | Credential Access | [`AGC-035-password-spray`](05-credential-access/AGC-035-password-spray/README.md) | — (pending) | — (pending) |
| `AGC-036` | Credential Access | [`AGC-036-ntlm-auth-anomaly`](05-credential-access/AGC-036-ntlm-auth-anomaly/README.md) | — (pending) | — (pending) |
| `AGC-037` | Discovery | [`AGC-037-system-user-discovery`](06-discovery/AGC-037-system-user-discovery/README.md) | — (pending) | — (pending) |
| `AGC-038` | Discovery | [`AGC-038-domain-trust-discovery`](06-discovery/AGC-038-domain-trust-discovery/README.md) | — (pending) | — (pending) |
| `AGC-039` | Discovery | [`AGC-039-group-enumeration`](06-discovery/AGC-039-group-enumeration/README.md) | — (pending) | — (pending) |
| `AGC-040` | Discovery | [`AGC-040-service-process-discovery`](06-discovery/AGC-040-service-process-discovery/README.md) | — (pending) | — (pending) |
| `AGC-041` | Discovery | [`AGC-041-network-share-enum`](06-discovery/AGC-041-network-share-enum/README.md) | — (pending) | — (pending) |
| `AGC-042` | Discovery | [`AGC-042-ad-object-query-burst`](06-discovery/AGC-042-ad-object-query-burst/README.md) | — (pending) | — (pending) |
| `AGC-043` | Lateral Movement | [`AGC-043-unusual-rdp-logon`](07-lateral-movement/AGC-043-unusual-rdp-logon/README.md) | — (pending) | — (pending) |
| `AGC-044` | Lateral Movement | [`AGC-044-smb-admin-share`](07-lateral-movement/AGC-044-smb-admin-share/README.md) | — (pending) | — (pending) |
| `AGC-045` | Lateral Movement | [`AGC-045-winrm-movement`](07-lateral-movement/AGC-045-winrm-movement/README.md) | — (pending) | — (pending) |
| `AGC-046` | Lateral Movement | [`AGC-046-remote-wmi-execution`](07-lateral-movement/AGC-046-remote-wmi-execution/README.md) | — (pending) | — (pending) |
| `AGC-047` | Lateral Movement | [`AGC-047-pass-the-hash`](07-lateral-movement/AGC-047-pass-the-hash/README.md) | — (pending) | — (pending) |
| `AGC-048` | Lateral Movement | [`AGC-048-ssh-pivot-to-dmz`](07-lateral-movement/AGC-048-ssh-pivot-to-dmz/README.md) | — (pending) | — (pending) |
| `AGC-049` | Lateral Movement | [`AGC-049-account-multi-host-auth`](07-lateral-movement/AGC-049-account-multi-host-auth/README.md) | — (pending) | — (pending) |
| `AGC-050` | Lateral Movement | [`AGC-050-east-west-port-scan`](07-lateral-movement/AGC-050-east-west-port-scan/README.md) | — (pending) | — (pending) |
| `AGC-051` | Command & Control | [`AGC-051-https-beacon`](08-command-control/AGC-051-https-beacon/README.md) | — (pending) | — (pending) |
| `AGC-052` | Command & Control | [`AGC-052-dns-beacon`](08-command-control/AGC-052-dns-beacon/README.md) | — (pending) | — (pending) |
| `AGC-053` | Command & Control | [`AGC-053-uncommon-port-c2`](08-command-control/AGC-053-uncommon-port-c2/README.md) | — (pending) | — (pending) |
| `AGC-054` | Command & Control | [`AGC-054-rare-destination-domain`](08-command-control/AGC-054-rare-destination-domain/README.md) | — (pending) | — (pending) |
| `AGC-055` | Command & Control | [`AGC-055-powershell-outbound`](08-command-control/AGC-055-powershell-outbound/README.md) | — (pending) | — (pending) |
| `AGC-056` | Command & Control | [`AGC-056-c2-process-tree`](08-command-control/AGC-056-c2-process-tree/README.md) | — (pending) | — (pending) |
| `AGC-057` | Collection | [`AGC-057-bulk-archive-creation`](09-collection/AGC-057-bulk-archive-creation/README.md) | — (pending) | — (pending) |
| `AGC-058` | Collection | [`AGC-058-screenshot-collection`](09-collection/AGC-058-screenshot-collection/README.md) | — (pending) | — (pending) |
| `AGC-059` | Collection | [`AGC-059-browser-data-staging`](09-collection/AGC-059-browser-data-staging/README.md) | — (pending) | — (pending) |
| `AGC-060` | Collection | [`AGC-060-sensitive-share-burst`](09-collection/AGC-060-sensitive-share-burst/README.md) | — (pending) | — (pending) |
| `AGC-061` | Collection | [`AGC-061-ad-export-collection`](09-collection/AGC-061-ad-export-collection/README.md) | — (pending) | — (pending) |
| `AGC-062` | Exfiltration | [`AGC-062-large-https-upload`](10-exfiltration/AGC-062-large-https-upload/README.md) | — (pending) | — (pending) |
| `AGC-063` | Exfiltration | [`AGC-063-dns-tunneling`](10-exfiltration/AGC-063-dns-tunneling/README.md) | — (pending) | — (pending) |
| `AGC-064` | Exfiltration | [`AGC-064-removable-media-exfil`](10-exfiltration/AGC-064-removable-media-exfil/README.md) | — (pending) | — (pending) |
| `AGC-065` | Exfiltration | [`AGC-065-unusual-smb-transfer`](10-exfiltration/AGC-065-unusual-smb-transfer/README.md) | — (pending) | — (pending) |
| `AGC-066` | Exfiltration | [`AGC-066-compressed-archive-web`](10-exfiltration/AGC-066-compressed-archive-web/README.md) | — (pending) | — (pending) |
| `AGC-067` | Defense Evasion | [`AGC-067-event-log-clearing`](11-defense-evasion/AGC-067-event-log-clearing/README.md) | — (pending) | — (pending) |
| `AGC-068` | Defense Evasion | [`AGC-068-defender-disabled`](11-defense-evasion/AGC-068-defender-disabled/README.md) | — (pending) | — (pending) |
| `AGC-069` | Defense Evasion | [`AGC-069-wazuh-agent-tamper`](11-defense-evasion/AGC-069-wazuh-agent-tamper/README.md) | — (pending) | — (pending) |
| `AGC-070` | Defense Evasion | [`AGC-070-staged-artifact-deletion`](11-defense-evasion/AGC-070-staged-artifact-deletion/README.md) | — (pending) | — (pending) |
| `AGC-071` | Defense Evasion | [`AGC-071-obfuscated-command-line`](11-defense-evasion/AGC-071-obfuscated-command-line/README.md) | — (pending) | — (pending) |
| `AGC-072` | Impact & Recovery | [`AGC-072-ransomware-simulation`](12-impact-recovery/AGC-072-ransomware-simulation/README.md) | — (pending) | — (pending) |
| `AGC-073` | Impact & Recovery | [`AGC-073-critical-service-disruption`](12-impact-recovery/AGC-073-critical-service-disruption/README.md) | — (pending) | — (pending) |
| `AGC-074` | Impact & Recovery | [`AGC-074-dmz-website-defacement`](12-impact-recovery/AGC-074-dmz-website-defacement/README.md) | — (pending) | — (pending) |
| `AGC-075` | Impact & Recovery | [`AGC-075-high-impact-gpo-change`](12-impact-recovery/AGC-075-high-impact-gpo-change/README.md) | — (pending) | — (pending) |
| `AGC-076` | Impact & Recovery | [`AGC-076-containment-recovery`](12-impact-recovery/AGC-076-containment-recovery/README.md) | — (pending) | — (pending) |
| `AGC-077` | Full Attack Chain | [`AGC-077-full-chain-credential-to-ransomware`](13-full-attack-chain/AGC-077-full-chain-credential-to-ransomware/README.md) | — (pending) | — (pending) |
| `AGC-078` | Full Attack Chain | [`AGC-078-full-chain-trusted-access-to-gpo-impact`](13-full-attack-chain/AGC-078-full-chain-trusted-access-to-gpo-impact/README.md) | — (pending) | — (pending) |
| `AGC-079` | Full Attack Chain | [`AGC-079-full-chain-dmz-pivot-to-defacement`](13-full-attack-chain/AGC-079-full-chain-dmz-pivot-to-defacement/README.md) | — (pending) | — (pending) |
| `AGC-080` | Full Attack Chain | [`AGC-080-full-chain-discovery-to-service-disruption`](13-full-attack-chain/AGC-080-full-chain-discovery-to-service-disruption/README.md) | — (pending) | — (pending) |
| `AGC-081` | False Positive Triage | [`AGC-081-encoded-ps-backup`](14-false-positive/AGC-081-encoded-ps-backup/README.md) | — (pending) | — (pending) |
| `AGC-082` | False Positive Triage | [`AGC-082-new-admin-change-ticket`](14-false-positive/AGC-082-new-admin-change-ticket/README.md) | — (pending) | — (pending) |
| `AGC-083` | False Positive Triage | [`AGC-083-lsass-av-selfscan`](14-false-positive/AGC-083-lsass-av-selfscan/README.md) | — (pending) | — (pending) |
| `AGC-084` | False Positive Triage | [`AGC-084-dns-beacon-saas`](14-false-positive/AGC-084-dns-beacon-saas/README.md) | — (pending) | — (pending) |
| `AGC-085` | False Positive Triage | [`AGC-085-offhours-service-account`](14-false-positive/AGC-085-offhours-service-account/README.md) | — (pending) | — (pending) |
| `AGC-086` | False Positive Triage | [`AGC-086-regulatory-submission`](14-false-positive/AGC-086-regulatory-submission/README.md) | — (pending) | — (pending) |
| `AGC-087` | False Positive Triage | [`AGC-087-portscan-vuln-scanner`](14-false-positive/AGC-087-portscan-vuln-scanner/README.md) | — (pending) | — (pending) |
| `AGC-088` | False Positive Triage | [`AGC-088-log-clearing-retention`](14-false-positive/AGC-088-log-clearing-retention/README.md) | — (pending) | — (pending) |
| `AGC-089` | Proactive Threat Hunting | [`AGC-089-hunt-wmi-persistence`](15-threat-hunting/AGC-089-hunt-wmi-persistence/README.md) | — (pending) | — (pending) |
| `AGC-090` | Proactive Threat Hunting | [`AGC-090-hunt-lolbin-parent-child`](15-threat-hunting/AGC-090-hunt-lolbin-parent-child/README.md) | — (pending) | — (pending) |
| `AGC-091` | Proactive Threat Hunting | [`AGC-091-hunt-beacon-statistics`](15-threat-hunting/AGC-091-hunt-beacon-statistics/README.md) | — (pending) | — (pending) |
| `AGC-092` | Proactive Threat Hunting | [`AGC-092-hunt-logon-time-patterns`](15-threat-hunting/AGC-092-hunt-logon-time-patterns/README.md) | — (pending) | — (pending) |
| `AGC-093` | Proactive Threat Hunting | [`AGC-093-hunt-dns-entropy`](15-threat-hunting/AGC-093-hunt-dns-entropy/README.md) | — (pending) | — (pending) |
| `AGC-094` | Proactive Threat Hunting | [`AGC-094-hunt-offhours-scheduled-tasks`](15-threat-hunting/AGC-094-hunt-offhours-scheduled-tasks/README.md) | — (pending) | — (pending) |
| `AGC-095` | Insider Threat | [`AGC-095-hr-finance-share-access`](16-insider-threat/AGC-095-hr-finance-share-access/README.md) | — (pending) | — (pending) |
| `AGC-096` | Insider Threat | [`AGC-096-bulk-download-pre-resignation`](16-insider-threat/AGC-096-bulk-download-pre-resignation/README.md) | — (pending) | — (pending) |
| `AGC-097` | Insider Threat | [`AGC-097-personal-cloud-upload`](16-insider-threat/AGC-097-personal-cloud-upload/README.md) | — (pending) | — (pending) |
| `AGC-098` | Insider Threat | [`AGC-098-service-account-interactive`](16-insider-threat/AGC-098-service-account-interactive/README.md) | — (pending) | — (pending) |
| `AGC-099` | Insider Threat | [`AGC-099-afterhours-no-ticket`](16-insider-threat/AGC-099-afterhours-no-ticket/README.md) | — (pending) | — (pending) |
| `AGC-100` | Insider Threat | [`AGC-100-removed-resource-access`](16-insider-threat/AGC-100-removed-resource-access/README.md) | — (pending) | — (pending) |
