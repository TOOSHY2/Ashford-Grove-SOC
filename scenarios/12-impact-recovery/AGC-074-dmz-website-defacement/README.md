# AGC-074 — Controlled DMZ Website Defacement

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-074` |
| Category | `12-impact-recovery` — Impact & Recovery |
| MITRE Technique | `T1491.002` Defacement: External Defacement |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | File modification timestamp on /var/www/html/index.html |
| Time to Triage | 02:00 (defacement content is self-evident — no ambiguity in intent) |
| Affected Systems | `EXT-ATTACKER-SIM` (10.10.40.10, substitute for DMZ-LINUX-01) |
| Chain | ◀ [AGC-073](../AGC-073-critical-service-disruption/README.md) · next [AGC-075](../AGC-075-high-impact-gpo-change/README.md) ▶ |
| One-line Summary | Website defacement simulation: `/var/www/html/index.html` overwritten with attacker-controlled content ("HACKED BY AGC-074") replacing the legitimate Ashford Grove Capital landing page. File modification confirmed at 2026-09-15 23:42:17 UTC via filesystem stat. Original content backed up and restored after evidence capture. This atomic technique is reused by AGC-079 as the impact phase of its SSH-pivot attack chain. Executed on EXT-ATTACKER-SIM as substitute for DMZ-LINUX-01 (Guest Additions broken at RunLevel=0). |

## Attacker Perspective

### Tradecraft

**What:** Overwrite the content of a publicly-facing web page with attacker-controlled content. Website defacement is one of the most visible forms of cyber attack — it immediately signals compromise to anyone who visits the site, causing reputational damage, loss of customer confidence, and potential regulatory scrutiny.

**Why an Attacker Uses It Here:**
- Maximum public visibility: unlike data theft or ransomware, defacement is immediately visible to every visitor
- Reputational damage to a financial services firm is especially severe — clients expect rigorous security
- Demonstrates deep access: writing to the web root proves the attacker controls the DMZ web server
- Can serve as a distraction while other attack phases (data exfiltration, persistence) continue undetected
- Some threat actors (hacktivists) use defacement as their primary objective rather than financial gain
- In the lab narrative, this represents the culmination of an SSH pivot chain (AGC-079 context)

**Lab Constraint:** DMZ-LINUX-01 (10.10.20.10) Guest Additions are broken (RunLevel=0), making guestcontrol inaccessible. EXT-ATTACKER-SIM (10.10.40.10) was used as the substitute Linux target, with its existing web server infrastructure. The defacement technique and detection methodology are identical regardless of which Linux host serves the web content.

### Simulation

**Pre-conditions:**
- EXT-ATTACKER-SIM running with web content at `/var/www/html/index.html`
- Original page content: Ashford Grove Capital landing page

**Execution:**
```bash
# Backup original content
sudo cp /var/www/html/index.html /tmp/agc074-orig.html

# Execute defacement -- overwrite index.html
echo 'HACKED BY AGC-074 - Ashford Grove Security Assessment' \
  | sudo tee /var/www/html/index.html

# Verify defacement via filesystem
sudo cat /var/www/html/index.html
# Output: HACKED BY AGC-074 - Ashford Grove Security Assessment

# Restore original content after evidence capture
sudo cp /tmp/agc074-orig.html /var/www/html/index.html
```

**Result:** The defacement was confirmed via direct file read (`sudo cat` showed the attacker content). File modification timestamp recorded at 23:42:17.765481724 UTC. Original content restored from backup.

## SOC Perspective

### Detection

**File modification evidence:**
```
File: /var/www/html/index.html
Modify: 2026-09-15 23:42:17.765481724 +0000
Content (post-defacement): "HACKED BY AGC-074 - Ashford Grove Security Assessment"
Content (pre-defacement): "<!DOCTYPE html><html><head><title>Ashford Grove Capital</title>..."
```

**Detection methods for web defacement (ordered by reliability):**

1. **File Integrity Monitoring (FIM):** Wazuh FIM or OSSEC syscheck monitoring `/var/www/html/` detects any modification to web content files. This is the primary automated detection mechanism for defacement.

2. **Web content monitoring:** External services (e.g., website change detection tools) that periodically fetch and compare page content can detect defacement within their polling interval.

3. **Visual inspection:** Any visitor to the website sees the defacement immediately. This is often how real-world defacements are first reported — by employees, customers, or the public.

4. **Auditd file access logging:** Linux auditd can log all write operations to the web root directory, capturing the process, user, and timestamp of the modification.

**Detection gap — No centralized FIM alert captured:**
The Wazuh indexer was not reachable from available vantage points during this exercise (confirmed unreachable in AGC-067). FIM alerts, if generated on the agent, could not be verified centrally. The file modification was confirmed via direct filesystem inspection.

### Investigation

**Step 1 — Confirm the defacement:**
Direct file read confirmed the content of `/var/www/html/index.html` was replaced with attacker-controlled text at 23:42:17 UTC. The original content (Ashford Grove Capital landing page) was no longer present.

**Step 2 — Identify the modification method:**
The defacement was executed via `tee` command with `sudo` privileges, writing stdin content directly to the target file. This overwrites the entire file content atomically. The `tee` command running as root indicates the attacker had elevated access to the web server.

**Step 3 — Assess the access path:**
In the lab narrative, this defacement is the impact phase of an SSH pivot chain (AGC-079). The investigation would trace backward:
- Who wrote to `/var/www/html/index.html`? (Process/user from auditd or FIM)
- How did they gain write access? (SSH session, compromised credentials)
- From where did the SSH session originate? (Pivot from another compromised host)
- What was the initial access vector? (The full attack chain answer)

**Step 4 — Assess business impact:**
For Ashford Grove Capital, a financial services firm:
- **Immediate:** Public-facing website displays attacker content instead of legitimate business page
- **Reputational:** Clients and prospects see evidence of compromise, undermining trust
- **Regulatory:** Financial regulators may require incident disclosure if client data systems share infrastructure with the compromised web server
- **Operational:** Web-based services (client portal, document access) may be disrupted

### Report

**Verdict: True Positive** — Confirmed external defacement of web content.

**Confidence: Critical** — Defacement is unambiguous by definition:
1. The file content was replaced with attacker-controlled text (confirmed via direct read)
2. The original legitimate content was eliminated
3. The modification timestamp provides precise timing (23:42:17 UTC)
4. The defacement message explicitly identifies itself as an attack
5. No legitimate business process overwrites web content with "HACKED BY" messages

**Response recommendation:**
1. **Immediate content restoration** from the most recent known-good backup or version control — every second the defaced page is live increases reputational damage
2. **Revoke access** to the web server: rotate all credentials (SSH keys, service account passwords) and audit authorized users
3. **Implement FIM on web root** (`/var/www/html/`) if not already configured — Wazuh syscheck with `realtime=yes` provides near-instant detection of file modifications
4. **Deploy web content integrity checking** using cryptographic hashes (compare served content against known-good hashes at regular intervals)
5. **Investigate the access chain** (see AGC-079 for the full SSH pivot narrative) — the defacement proves access was obtained, but the root cause must be found and closed
6. **Prepare communications plan** for public disclosure if this were a production incident — financial services firms have regulatory obligations for security incident reporting
7. **Consider web application firewall (WAF)** with file write protection to prevent unauthorized modification of static content

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Impact (TA0040) | T1491.002 | Defacement: External Defacement | /var/www/html/index.html overwritten with "HACKED BY AGC-074" at 2026-09-15 23:42:17 UTC. Original Ashford Grove Capital page replaced. File modification confirmed via stat and direct read. Restored from backup after evidence capture. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Defacement before/after

```
BEFORE (original legitimate content):
=====================================
<!DOCTYPE html>
<html>
<head><title>Ashford Grove Capital</title></head>
<body>
<h1>Welcome to Ashford Grove Capital</h1>
<p>Investment Management and Advisory Services</p>
<p>Established 2018 - Licensed and Regulated</p>
</body>
</html>

AFTER (defacement content):
============================
HACKED BY AGC-074 - Ashford Grove Security Assessment

FILESYSTEM EVIDENCE:
====================
File: /var/www/html/index.html
Modify: 2026-09-15 23:42:17.765481724 +0000
Method: sudo tee (atomic file overwrite)
```

### Lab constraint note

```
DMZ-LINUX-01 (10.10.20.10) -- intended target per scenario design
  Guest Additions: broken (RunLevel=0)
  guestcontrol: NOT AVAILABLE
  Web server: unreachable from available vantage points

EXT-ATTACKER-SIM (10.10.40.10) -- substitute target used
  Guest Additions: functional
  Web root: /var/www/html/ (existing nginx serving phishing lab page)
  Original content: Ashford Grove Capital landing page (from prior setup)
  
The defacement technique (file overwrite via sudo tee) and detection
methodology (FIM, stat, file content comparison) are identical
regardless of target host.
```
