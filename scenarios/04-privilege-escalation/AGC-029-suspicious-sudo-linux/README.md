# AGC-029 — Suspicious sudo Usage (GTFOBins Escape)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-029` |
| Category | `04-privilege-escalation` — Privilege Escalation |
| MITRE Technique | `T1548.003` Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — journalctl captures sudo invocations with full COMMAND string including the shell-escape syntax |
| Time to Triage | 02:00 (cross-reference sudo COMMAND against GTFOBins database; confirm UID transition) |
| Affected Systems | `EXT-ATTACKER-SIM` (Kali Linux, 10.10.40.10) — used as substitute for DMZ-LINUX-01 (Guest Additions at RunLevel=0, SSH blocked by firewall) |
| Chain | ◀ [AGC-028](../AGC-028-dll-search-order-hijack/README.md) · next [AGC-030](../AGC-030-domain-admin-logon-workstation/README.md) ▶ |
| One-line Summary | Overly-permissive sudoers entry for `vim.tiny` exploited via GTFOBins shell-escape technique to obtain interactive root shell. Confirmed via journalctl sudo logs showing full COMMAND with shell invocation. Secondary escape via `find -exec` also confirmed. |

## Attacker Perspective

### Tradecraft

**What:** The attacker abuses an overly-permissive sudoers entry granting NOPASSWD access to a binary that can spawn a shell. GTFOBins (https://gtfobins.github.io/) catalogs Unix binaries that break out of restricted environments, escalate privileges, or move files.

The attack pattern:
1. **Identify sudo permissions:** `sudo -l` reveals what the compromised user can run as root.
2. **Cross-reference with GTFOBins:** the attacker checks whether any permitted binary has a known shell escape.
3. **Execute the escape:** for `vim`, it is `sudo vim -c ':!/bin/bash'` — vim's `:!` spawns a shell, and because vim runs as root via sudo, that shell inherits root.
4. **Alternative escapes:** `find -exec`, `awk 'BEGIN {system("/bin/bash")}'`, `less` (then `!bash`), `nmap --interactive`, and dozens more.

The result is an interactive root shell: full escalation from a standard user account.

**Why at this lifecycle stage:** Holding a user account from phishing, credential theft, or lateral movement, the attacker reviews the local sudo configuration. Broad NOPASSWD grants get handed out for convenience over least privilege, and one such entry for a GTFOBins-capable binary turns any user-level compromise into root.

### Simulation

**Pre-conditions:**
- `EXT-ATTACKER-SIM` (Kali Linux) running, `kaliadmin` user context with passwordless sudo.
- Used as substitute for `DMZ-LINUX-01` because DMZ-LINUX-01 Guest Additions are at RunLevel=0 (guestcontrol unavailable) and SSH from other lab VMs is blocked by the OPNsense firewall.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:47:08 | Check auditd | EXT-ATTACKER-SIM | `systemctl is-active auditd` returned `inactive` — auditd not installed on Kali |
| 2 | 2026-09-15 19:47:08 | Create vulnerable sudoers | EXT-ATTACKER-SIM | Added `/etc/sudoers.d/agc029-vuln`: `kaliadmin ALL=(ALL) NOPASSWD: /usr/bin/vim.tiny` |
| 3 | 2026-09-15 19:47:08 | GTFOBins vim escape | EXT-ATTACKER-SIM | `sudo vim.tiny -es -c ':!/bin/bash -c "whoami; id"'` — output: `root`, `uid=0(root) gid=0(root) groups=0(root)` |
| 4 | 2026-09-15 19:47:08 | GTFOBins find escape | EXT-ATTACKER-SIM | `sudo find /tmp -maxdepth 0 -exec whoami \;` — output: `root` |
| 5 | 2026-09-15 19:47:08 | Collect evidence | EXT-ATTACKER-SIM | journalctl `_COMM=sudo` captured all invocations with full COMMAND strings |
| 6 | 2026-09-15 19:47:09 | Cleanup | EXT-ATTACKER-SIM | Removed `/etc/sudoers.d/agc029-vuln` |

**Cleanup:** Vulnerable sudoers entry removed. No persistent changes.

## SOC Perspective

### Detection

**Primary detection source:** System journal (journalctl) capturing sudo invocations.

auditd was not running here (inactive, not installed), a finding in itself — auditd is the primary Linux auditing framework and belongs on every production Linux host. Without it, sudo logging falls back to syslog/journal entries from the sudo PAM module.

| Timestamp (UTC) | Source | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:47:08 | journalctl (_COMM=sudo) | sudo invocation | `kaliadmin : PWD=/ ; USER=root ; COMMAND=/usr/bin/vim.tiny -es -c ':!/bin/bash -c "whoami; id; echo AGC029-ROOT-SHELL-ACHIEVED; echo GTFOBINS-VIM-ESCAPE; echo done"' -c :q` |
| 2026-09-15 19:47:08 | journalctl (_COMM=sudo) | PAM session | `pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)` |
| 2026-09-15 19:47:08 | journalctl (_COMM=sudo) | sudo invocation | `kaliadmin : PWD=/ ; USER=root ; COMMAND=/usr/bin/find /tmp -maxdepth 0 -exec whoami ;` |
| 2026-09-15 19:47:08 | journalctl (_COMM=sudo) | PAM session | `pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)` |
| 2026-09-15 19:47:08 | journalctl (_COMM=sudo) | sudoers modification | `kaliadmin : PWD=/ ; USER=root ; COMMAND=/usr/bin/tee /etc/sudoers.d/agc029-vuln` — the attacker used sudo to write their own sudoers entry |

**Detection gap:** auditd is inactive. With auditd running, the following additional evidence would be available:
- EXECVE audit records with full argument vectors
- UID/GID transition records for the spawned shell
- File access audit trails for `/etc/sudoers.d/` modifications
- Wazuh integration via Linux audit rules forwarding to the SIEM

### Investigation

**Step 1 — Identify suspicious sudo COMMAND patterns:**
The journalctl entry for PID 983 shows `COMMAND=/usr/bin/vim.tiny -es -c ':!/bin/bash ...'`. The `:!` inside a vim command argument is a shell-escape: it tells vim to run a shell command. The user is not editing a file; they are using vim's shell-escape to spawn a root shell via sudo.

**Step 2 — Confirm UID transition:**
The PAM log records `session opened for user root(uid=0) by (uid=1000)`. UID 1000 (kaliadmin) became UID 0 (root) through the sudo call, and the spawned bash inherits the root UID.

**Step 3 — Identify secondary escape technique:**
PID 990 shows `COMMAND=/usr/bin/find /tmp -maxdepth 0 -exec whoami ;`. find's `-exec` is another GTFOBins escape — whatever follows `-exec` runs with find's privileges, and find is root via sudo, so the exec'd command runs as root.

**Step 4 — Audit sudoers modification:**
PID 973 shows `COMMAND=/usr/bin/tee /etc/sudoers.d/agc029-vuln` — the attacker used existing sudo access to write a NEW sudoers entry granting themselves NOPASSWD on vim.tiny. That is privilege persistence: fix the original overly-permissive entry and the attacker's own sudoers file survives.

**Step 5 — Cross-reference with account baseline:**
Check whether `kaliadmin`, or the equivalent service or maintenance account, has a documented need for sudo access to vim. Maintenance accounts often carry broad sudo grants for convenience, but NOPASSWD on an editor or file utility is almost never required for their work.

**Step 6 — Pattern reuse note:**
Apply the same approach — filter sudo logs for GTFOBins-capable binaries carrying shell-escape arguments — on any Linux host where sudo abuse is suspected. A Wazuh rule matching the sudo COMMAND field against known GTFOBins patterns automates it.

### Report

**Verdict: True Positive** — The attacker used a GTFOBins shell-escape to gain root through an overly-permissive sudoers entry. Two escapes were confirmed, vim `:!` and find `-exec`, both yielding `uid=0(root)`.

**Confidence: High** — journalctl sudo logs explicitly show:
1. The full COMMAND string including the `:!/bin/bash` shell-escape syntax.
2. PAM UID transition from 1000 to 0 (root).
3. The attacker also modified `/etc/sudoers.d/` to create a persistent backdoor entry.
4. Both vim and find escapes independently confirmed root access.

**Response recommendation:**
1. **Kill the root shell** immediately — terminate any active sessions spawned via the GTFOBins escape.
2. **Audit and harden sudoers** across all Linux hosts:
   - Remove NOPASSWD entries unless operationally critical.
   - Never grant sudo access to GTFOBins-capable binaries (vim, less, find, awk, nmap, python, perl, etc.) without explicit `NOEXEC` tag: `user ALL=(ALL) NOPASSWD: NOEXEC: /usr/bin/vim`.
   - Use `sudoedit` instead of `sudo vim` for file editing — sudoedit blocks shell escapes.
3. **Check `/etc/sudoers.d/`** for unauthorized entries — the attacker showed they can write custom sudoers files.
4. **Enable auditd** on all Linux hosts with rules for:
   - `sudo` invocations (already covered by default audit rules)
   - File writes to `/etc/sudoers` and `/etc/sudoers.d/`
   - UID/GID changes (privilege transitions)
5. **Deploy Wazuh Linux agent** with audit log forwarding for centralized detection.
6. **Create detection rules** matching sudo COMMAND fields against GTFOBins patterns:
   ```
   Rule: sudo COMMAND contains "vim" AND (":!" OR "-c" with shell reference)
   Rule: sudo COMMAND contains "find" AND "-exec"
   Rule: sudo COMMAND contains "awk" AND "system("
   ```

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | journalctl: `kaliadmin` executed `sudo vim.tiny -es -c ':!/bin/bash ...'` spawning root shell (uid=0). PAM confirmed UID transition 1000->0. Secondary `sudo find -exec whoami` also returned root. Overly-permissive sudoers entry (`NOPASSWD: /usr/bin/vim.tiny`) enabled the escape. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

**Note on host substitution:** This scenario ran on EXT-ATTACKER-SIM (Kali Linux) rather than the designated DMZ-LINUX-01, whose Guest Additions are at RunLevel=0 (guestcontrol unavailable) and where SSH from other lab VMs times out because OPNsense firewall rules block inter-zone traffic on port 22. The technique and detection patterns hold across Linux distributions.
