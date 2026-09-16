# AGC-096 — Bulk Document Download Before Resignation

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-096` |
| Title | Insider Threat: Bulk File Copy During Notice Period |
| Category | `16-insider-threat` — Insider Threat |
| Severity | High |
| MITRE Technique | None (behavioral signal: volume + HR timing) |
| Verdict | Confirmed Anomaly — Coordinate Security/HR/Legal |
| Confidence | High |
| Chain | ◀ [AGC-095](../AGC-095-unusual-file-access/README.md) · next [AGC-097](../AGC-097-personal-cloud-upload/README.md) ▶ |

## Attacker Perspective

### Tradecraft

#### HR Record (documented before simulation)

| Field | Value |
|-------|-------|
| **Employee** | raj.patel |
| **Role** | IT-Support |
| **Resignation submitted** | 2026-09-10 |
| **Last day** | 2026-09-24 |
| **Normal daily file access** | 5-15 files/day |

### Simulation

The simulation created 50 IT documentation files in the IT-Support share, then ran a single bulk `Copy-Item` to `C:\Users\raj.patel\Downloads\bulk-copy\` to mimic a departing employee collecting work product.

**Execution window**: 01:19:59 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

Anomalous file access volume: raj.patel copied 50 files from the IT-Support share to his Downloads folder in one operation, 5x the documented daily baseline of 5-15 files. The spike falls inside his resignation notice period (submitted 2026-09-10, last day 2026-09-24).

### Investigation

#### Step 1: Quantify the Volume Anomaly

```
Files copied in single operation: 50
Normal daily baseline: 5-15 files/day
Volume ratio: 5x above daily baseline
File types: IT documentation (network diagrams, .vsdx format)
```

#### Step 2: Correlate with HR Timeline

| Event | Date | Days Before Last Day |
|-------|------|---------------------|
| Resignation submitted | 2026-09-10 | 14 days |
| **Bulk copy detected** | **2026-09-16** | **8 days** |
| Last day | 2026-09-24 | 0 days |

The bulk copy lands in the middle of raj.patel's notice period — the window in which a departing employee is most likely to hoard data.

#### Step 3: Assess Material Value

The copied files are IT documentation (network diagrams). raj.patel's IT-Support role authorizes him to read them, but collecting all 50 at once raises three concerns:
- Intellectual property being taken to a competitor
- Network architecture documentation being used for unauthorized access after departure
- Contractual obligations regarding work product ownership

#### Step 4: Context Check

- **Authorized access**: YES — raj.patel is authorized to access IT-Support share
- **Normal volume**: NO — 50 files is 5x the daily baseline
- **HR flag**: YES — resignation notice on file
- **Business justification**: UNKNOWN — no documented handover task requiring bulk download

### Report

**Verdict: Confirmed Anomaly** — raj.patel copied 50 files, 5x his baseline, midway through his notice period. That combination of volume and HR timing warrants a coordinated investigation.

**Recommendation**: Coordinate a joint Security-HR-Legal response:
1. **Do NOT confront the employee directly** or revoke access without coordination
2. HR to verify whether a handover task was assigned that would explain the volume
3. Legal to assess contractual obligations regarding work product
4. Security to monitor for subsequent outbound transfer (USB, email, cloud upload)
5. Set up a standing HR-to-Security notification for every resignation and termination so the SOC can watch the notice period from day one

### MITRE Mapping

No MITRE ATT&CK technique applies. The detection rests on a **behavioral deviation** (the volume spike) correlated with **HR context** (resignation timing), not on technical attack indicators. The copy itself used a legitimate mechanism against a share raj.patel is authorized to read.

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
