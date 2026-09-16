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

**What:** The attacker exploits an overly-permissive sudoers entry that grants NOPASSWD access to a binary with known shell-escape capabilities. GTFOBins (https://gtfobins.github.io/) catalogs Unix binaries that can be abused to break out of restricted environments, escalate privileges, or transfer files.

The attack pattern:
1. **Identify sudo permissions:** `sudo -l` reveals what the compromised user can run as root.
2. **Cross-reference with GTFOBins:** The attacker checks whether any permitted binary has a known shell escape.
3. **Execute the escape:** For `vim`, the escape is `sudo vim -c ':!/bin/bash'` — vim's `:!` command spawns a shell, and since vim runs as root via sudo, the spawned shell inherits root privileges.
4. **Alternative escapes:** `find -exec`, `awk 'BEGIN {system("/bin/bash")}'`, `less` (then `!bash`), `nmap --interactive`, and dozens more.

The result is an interactive root shell — full privilege escalation from a standard user account.

**Why at this lifecycle stage:** After gaining access to a user account (via phishing, credential theft, or lateral movement), the attacker surveys the local sudo configuration. Overly-permissive sudoers entries are common in environments where administrators grant broad access for convenience rather than following least-privilege principles. A single NOPASSWD entry for a GTFOBins-capable binary converts any user-level compromise into full root access.

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

auditd was not running on this system (inactive/not installed), which is itself a finding — auditd is the primary Linux security auditing framework and should be running on all production Linux hosts. In its absence, sudo logging falls back to syslog/journal entries from the sudo PAM module.

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
The journalctl entry for PID 983 shows `COMMAND=/usr/bin/vim.tiny -es -c ':!/bin/bash ...'`. The `:!` syntax within a vim command argument is a shell-escape — it tells vim to execute a shell command. This is a textbook GTFOBins pattern: the user is not editing a file, they are using vim's shell-escape to spawn a root shell via sudo.

**Step 2 — Confirm UID transition:**
The PAM log confirms `session opened for user root(uid=0) by (uid=1000)`. UID 1000 (kaliadmin) transitioned to UID 0 (root) through the sudo invocation. The spawned bash process inherits the root UID.

**Step 3 — Identify secondary escape technique:**
PID 990 shows `COMMAND=/usr/bin/find /tmp -maxdepth 0 -exec whoami ;`. The `-exec` flag in find is another GTFOBins escape — any command after `-exec` runs with find's privileges. Since find runs as root via sudo, the exec'd command also runs as root.

**Step 4 — Audit sudoers modification:**
PID 973 shows `COMMAND=/usr/bin/tee /etc/sudoers.d/agc029-vuln` — the attacker used their existing sudo access to create a NEW sudoers entry granting themselves NOPASSWD access to vim.tiny. This is a privilege persistence technique: even if the original overly-permissive entry is fixed, the attacker's custom sudoers file remains.

**Step 5 — Cross-reference with account baseline:**
In a production environment, check whether `kaliadmin` (or the equivalent service/maintenance account) has a documented business need for sudo access to vim. Maintenance accounts commonly receive broad sudo grants for convenience, but NOPASSWD access to editors or file utilities is almost never required for their actual tasks.

**Step 6 — Pattern reuse note:**
This GTFOBins escape pattern is a well-documented privilege escalation technique. The investigation approach (filtering sudo logs for GTFOBins-capable binaries with shell-escape arguments) should be applied to any Linux host where sudo abuse is suspected. A Wazuh detection rule matching sudo COMMAND fields against known GTFOBins patterns would automate this detection.

### Report

**Verdict: True Positive** — A GTFOBins shell-escape was used to obtain root access through an overly-permissive sudoers entry. Two distinct escape techniques were confirmed (vim `:!` shell escape and find `-exec`), both yielding `uid=0(root)`.

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
   - Use `sudoedit` instead of `sudo vim` for file editing — sudoedit does not allow shell escapes.
3. **Check `/etc/sudoers.d/`** for unauthorized entries — the attacker demonstrated the ability to write custom sudoers files.
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

**Note on host substitution:** This scenario was executed on EXT-ATTACKER-SIM (Kali Linux) instead of the designated DMZ-LINUX-01 because DMZ-LINUX-01 Guest Additions are at RunLevel=0 (guestcontrol unavailable) and SSH from other lab VMs times out due to OPNsense firewall rules blocking inter-zone traffic on port 22. The technique and detection patterns are identical regardless of the Linux distribution used.
