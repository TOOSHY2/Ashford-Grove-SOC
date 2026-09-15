# Execution Log

Running tally of all 100 scenario executions.

## Session 1 — 2026-09-15

| # | Scenario | Start (UTC) | End (UTC) | Verdict | Notes |
|---|---|---|---|---|---|
| 1 | AGC-001 Spoofed Display-Name Phishing | 2026-09-15 16:48:27 | 2026-09-15 16:55:00 | True Positive (High) | No automated phishing alert; detection via manual header inspection. Detection gap: no email gateway/SPF/DKIM. |
| 2 | AGC-002 Lookalike-Domain Phishing | 2026-09-15 16:56:02 | 2026-09-15 17:02:19 | True Positive (High) | Homoglyph domain ashfordgr0ve.local (zero-for-O). Sysmon EID 22 caught NXDOMAIN DNS query. No automated phishing alert. Detection gap: no homoglyph/edit-distance rule. |
