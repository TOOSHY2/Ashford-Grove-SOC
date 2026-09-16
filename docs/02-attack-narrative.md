# Attack Narrative

An external attacker sends a phishing email. An employee on COMPROMISED-HOST-01 clicks it. From that single foothold, the attacker executes code, establishes persistence, escalates privileges, harvests credentials, maps the network, moves laterally into the DMZ, calls home for command and control, collects and exfiltrates data, and in the final stages tries to cover their tracks and cause damage before the SOC catches and contains them.

Scenarios AGC-001 through AGC-076 walk this one continuous timeline, stage by stage. AGC-077 through AGC-080 each re-run the full path — initial access through impact — via a different technique combination, as standalone complete incidents. AGC-081 through AGC-100 step outside the narrative entirely: false-positive triage, proactive hunting, and insider-threat detection, none of which are part of the attacker's story.

## Numbering note

AGC scenario numbering follows this narrative's chronological order, not the literal MITRE ATT&CK tactic sequence — MITRE tactics are goals, not an enforced order. Defense Evasion and Collection/Command-and-Control are intentionally repositioned relative to the official tactic list to match the story.

## Execution order

The main narrative (AGC-001 – AGC-076) was executed in ID order so that each scenario's foothold, artefacts, and telemetry genuinely inherit from the one before it. The four full-chain incidents (AGC-077 – AGC-080) were then run as standalone end-to-end replays, followed by the twenty judgment-track scenarios (AGC-081 – AGC-100), several of which hunt for or triage residual artefacts left by the main narrative.
