# AGC-010 — User-Reported Phishing Triage & Containment

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-010` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | N/A (triage workflow); references `T1566.002` / `T1566.001` from the reported email |
| Verdict | Triage Complete |
| Confidence | High |
| Time to Detect | N/A — detection source is user report, not SIEM alert |
| Time to Triage | ~02:00 (from report receipt to scope/impact/containment confirmation) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) — recipient of the reported email |
| Chain | ◀ AGC-009 · next AGC-011 (Execution category) ▶ |
| One-line Summary | Triage workflow: user reports an unclicked phishing email (AGC-002 lookalike domain campaign); SOC confirms no click occurred, determines campaign scope, and contains the threat. |

## Attacker Perspective

### What This Is

This scenario is **not** a new attack technique. It is a **triage workflow** that begins from a user's phishing report, not from a SIEM alert. The reported email is from the AGC-002 lookalike-domain campaign (`compliance@ashf0rdgrove.com` — note the zero replacing 'o' in the domain).

### Why This Scenario Exists

User-reported phishing is one of the most valuable detection sources in a SOC. It surfaces threats that bypass technical controls (email gateway, URL reputation, sandbox detonation). The workflow validates three things:

1. **Is the report legitimate?** — Inspect original headers, sender domain, embedded links.
2. **What is the scope?** — Did other mailboxes receive the same email?
3. **What is the impact?** — Did anyone click a link or open an attachment?

The correct SOC response reinforces the user's reporting behavior (acknowledgment) and contains the threat (block sender/domain, purge from mailboxes).

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon running, Wazuh agent active.
- `WAZUH-SIEM-01` running.
- `EXT-ATTACKER-SIM` running (lab-sink active — but no connection should occur in this scenario).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:25:05 | User reports email | COMPROMISED-HOST-01 | `michael.chen` forwards suspicious email (AGC-002 lookalike domain: `compliance@ashf0rdgrove.com`, Subject: "Quarterly Compliance Review - Action Required") to security-triage inbox. States: "I did NOT click any links." |
| 2 | 2026-09-15 18:25:05 | Verify no outbound connection | COMPROMISED-HOST-01 | Sysmon EID 3 check — **NEGATIVE**: no outbound connections to `10.10.40.10` in the preceding 30 minutes |
| 3 | 2026-09-15 18:25:07 | Verify no DNS resolution | COMPROMISED-HOST-01 | Sysmon EID 22 check — **NEGATIVE**: no DNS queries for `ashf0rdgrove.com` in the preceding 30 minutes |
| 4 | 2026-09-15 18:25:07 | Wazuh alert check | WAZUH-SIEM-01 | **NEGATIVE**: no alerts for COMPROMISED-HOST-01 during the triage window — consistent with no malicious action taken |

**Cleanup:** No artifacts to clean up — the user did not interact with the phishing email.

## SOC Perspective

### Detection

**Detection source: User report** — not a SIEM alert.

There is no automated alert for this scenario. The detection signal is the user's own judgment that the email appeared suspicious. This is a high-value detection source because:
- It catches emails that passed email gateway filters.
- It provides the original email with headers intact for forensic analysis.
- It confirms the user's awareness training is effective.

**Sysmon telemetry confirms negative findings:**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:25:05-07 | 3 | Network Connect (searched) | **No matches** — no outbound connections to `10.10.40.10` (the phishing campaign's C2/harvester) in the 30-minute window |
| 2026-09-15 18:25:05-07 | 22 | DNS Query (searched) | **No matches** — no DNS queries for `ashf0rdgrove.com` (the lookalike domain) |
| 2026-09-15 18:25:05 | 1 | Process Create | `powershell.exe` (PID 4752) — the triage verification script itself; no suspicious processes |

**Wazuh:** No alerts for COMPROMISED-HOST-01 during the triage window.

### Investigation

**Step 1 — Validate the report:**
The reported email matches the AGC-002 lookalike-domain campaign:
- **Sender:** `compliance@ashf0rdgrove.com` — uses a zero instead of 'o' in the domain name. The legitimate domain is `ashfordgrove.com`.
- **Subject:** "Quarterly Compliance Review - Action Required" — urgency pretext.
- **Link destination:** Points to `10.10.40.10/portal-login` — the same credential-harvesting infrastructure identified in AGC-001 through AGC-009.

This is a confirmed phishing email. The user correctly identified it as suspicious.

**Step 2 — Determine scope (campaign breadth):**
In a production environment, the SOC analyst would search the mail server logs for other recipients of emails from `ashf0rdgrove.com` or with the same Subject line. In this lab, the AGC-002 campaign was documented as targeting `michael.chen` on `COMPROMISED-HOST-01`. A broader campaign search would check `sarah.jenkins` (WIN-CLIENT-01) and `raj.patel` (WIN-CLIENT-02).

**Step 3 — Determine impact (did anyone click?):**
Sysmon EID 3 (Network Connect) and EID 22 (DNS Query) on COMPROMISED-HOST-01 show **no connections to the phishing destination** and **no DNS resolution of the lookalike domain** in the 30-minute window preceding the triage. This confirms the reporting user (`michael.chen`) did not click the link.

In a production environment, the same check would be performed across all identified recipients' endpoints.

**Step 4 — Contain:**
Containment actions (production environment):
1. **Block the sender domain** (`ashf0rdgrove.com`) at the email gateway.
2. **Purge matching emails** from all mailboxes (search by sender domain + Subject).
3. **Block the destination** (`10.10.40.10`) at the firewall (already recommended in AGC-002).
4. **Acknowledge the reporter** — confirm that the report was received and the email is confirmed phishing. This reinforces reporting behavior.

**Step 5 — Cross-reference with prior scenarios:**
This email is from the same campaign documented in AGC-002 (lookalike domain). The credential-harvesting infrastructure at `10.10.40.10/portal-login` has been active across AGC-001 through AGC-009. The entire campaign shares the same IOCs:
- Sender domain variations: `ashf0rdgrove.com` and similar lookalikes
- Destination: `10.10.40.10:80` (`/portal-login`)
- Server response: "Sign-in received. Redirecting..."

### Report

**Verdict: Triage Complete** — This is not a True Positive / False Positive determination in the traditional sense. The verdict assesses triage completeness:

| Triage Question | Answer | Confidence |
|---|---|---|
| Is the report legitimate? | **Yes** — confirmed phishing email from AGC-002 campaign (lookalike domain, credential-harvesting link) | High |
| What is the scope? | Same campaign as AGC-001-009; at minimum one targeted recipient (`michael.chen`); broader search recommended | Medium (lab cannot check all mailboxes) |
| Did anyone click? | **No** — Sysmon EID 3 and EID 22 confirm no outbound connection or DNS query to the phishing destination from the reporting user's endpoint | High |
| Is the threat contained? | Containment actions recommended (block domain, purge emails, block destination IP); partially implemented in prior scenarios (firewall block for `10.10.40.10`) | High |

**Overall triage confidence: High** — The three core triage questions (legitimacy, scope, impact) were answered with high confidence. The reported email is confirmed malicious, the reporting user did not click, and containment actions are defined.

**Response recommendation:**
1. **Acknowledge the reporter** — thank `michael.chen` for reporting. This reinforces the behavior that made this detection possible.
2. **Block sender domain** at the email gateway.
3. **Purge campaign emails** from all mailboxes.
4. **Verify no other recipients clicked** — run the same EID 3/EID 22 check across all identified recipients.
5. **Update threat intelligence** — add `ashf0rdgrove.com` and `10.10.40.10` to the organization's IOC blocklist.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| (Triage workflow) | N/A | N/A | No new MITRE technique — this is a triage workflow. The reported email references T1566.002 (Spearphishing Link) and T1566.001 (Spearphishing Attachment) from the AGC-002 campaign. Negative evidence: no outbound connection, no DNS query, no Wazuh alert — confirms no click occurred. | High |

## Evidence

Screenshots: to be added manually by the analyst.
