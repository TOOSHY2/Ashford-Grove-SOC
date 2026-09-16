# AGC-010 — User-Reported Phishing Triage & Containment

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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
| Chain | ◀ [AGC-009](../AGC-009-oauth-consent-phish/README.md) · next [AGC-011](../../02-execution/AGC-011-browser-spawns-script/README.md) (Execution category) ▶ |
| One-line Summary | Triage workflow: user reports an unclicked phishing email (AGC-002 lookalike domain campaign); SOC confirms no click occurred, determines campaign scope, and contains the threat. |

## Attacker Perspective

### Tradecraft

#### What this is

This scenario is **not** a new attack technique. It is a **triage workflow** that starts from a user's phishing report rather than a SIEM alert. The reported email belongs to the AGC-002 lookalike-domain campaign (`compliance@ashf0rdgrove.com`, with a zero in place of 'o').

#### Why this scenario exists

A user report surfaces email that got past the technical controls (gateway, URL reputation, sandbox detonation). The workflow answers three questions:

1. **Is the report legitimate?** — Inspect original headers, sender domain, embedded links.
2. **What is the scope?** — Did other mailboxes receive the same email?
3. **What is the impact?** — Did anyone click a link or open an attachment?

The response has two jobs: thank the reporter so they report again, and contain the threat (block the sender domain, purge the mail from mailboxes).

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

No automated alert fired. The signal is the user's own judgment that the email looked wrong. That is worth having because:
- It catches email that passed the gateway filters.
- It delivers the original message with headers intact.
- It shows the awareness training took.

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
- **Sender:** `compliance@ashf0rdgrove.com` — a zero in place of 'o'. The legitimate domain is `ashfordgrove.com`.
- **Subject:** "Quarterly Compliance Review - Action Required" — urgency pretext.
- **Link destination:** `10.10.40.10/portal-login`, the credential harvester seen in AGC-001 through AGC-009.

Confirmed phishing; the user called it right.

**Step 2 — Determine scope (campaign breadth):**
In production the analyst would search mail server logs for other recipients from `ashf0rdgrove.com` or with the same Subject. In the lab, AGC-002 documented `michael.chen` on `COMPROMISED-HOST-01` as the target. A wider search would cover `sarah.jenkins` (WIN-CLIENT-01) and `raj.patel` (WIN-CLIENT-02).

**Step 3 — Determine impact (did anyone click?):**
Sysmon EID 3 (Network Connect) and EID 22 (DNS Query) on COMPROMISED-HOST-01 show **no connection to the phishing destination** and **no DNS lookup of the lookalike domain** in the 30-minute window before triage. `michael.chen` did not click.

In production the same check runs on every identified recipient's endpoint.

**Step 4 — Contain:**
Containment actions (production environment):
1. **Block the sender domain** (`ashf0rdgrove.com`) at the email gateway.
2. **Purge matching emails** from all mailboxes (search by sender domain + Subject).
3. **Block the destination** (`10.10.40.10`) at the firewall (already recommended in AGC-002).
4. **Acknowledge the reporter** — tell them the report landed and the email was phishing, so they report the next one.

**Step 5 — Cross-reference with prior scenarios:**
The email belongs to the campaign documented in AGC-002. The harvester at `10.10.40.10/portal-login` has been live across AGC-001 through AGC-009, and the campaign shares one IOC set:
- Sender domain variations: `ashf0rdgrove.com` and similar lookalikes
- Destination: `10.10.40.10:80` (`/portal-login`)
- Server response: "Sign-in received. Redirecting..."

### Report

**Verdict: Triage Complete** — Not a true positive / false positive call; the verdict measures triage completeness:

| Triage Question | Answer | Confidence |
|---|---|---|
| Is the report legitimate? | **Yes** — confirmed phishing email from AGC-002 campaign (lookalike domain, credential-harvesting link) | High |
| What is the scope? | Same campaign as AGC-001-009; at minimum one targeted recipient (`michael.chen`); broader search recommended | Medium (lab cannot check all mailboxes) |
| Did anyone click? | **No** — Sysmon EID 3 and EID 22 confirm no outbound connection or DNS query to the phishing destination from the reporting user's endpoint | High |
| Is the threat contained? | Containment actions recommended (block domain, purge emails, block destination IP); partially implemented in prior scenarios (firewall block for `10.10.40.10`) | High |

**Overall triage confidence: High** — The three core triage questions (legitimacy, scope, impact) were answered with high confidence. The email is confirmed malicious, the reporter did not click, and containment actions are defined.

**Response recommendation:**
1. **Acknowledge the reporter** — thank `michael.chen`; the report is the only reason this email was caught.
2. **Block sender domain** at the email gateway.
3. **Purge campaign emails** from all mailboxes.
4. **Verify no other recipients clicked** — run the same EID 3/EID 22 check across all identified recipients.
5. **Update threat intelligence** — add `ashf0rdgrove.com` and `10.10.40.10` to the organization's IOC blocklist.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| (Triage workflow) | N/A | N/A | No new MITRE technique — this is a triage workflow. The reported email references T1566.002 (Spearphishing Link) and T1566.001 (Spearphishing Attachment) from the AGC-002 campaign. Negative evidence: no outbound connection, no DNS query, no Wazuh alert — confirms no click occurred. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
