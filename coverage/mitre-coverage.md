# MITRE ATT&CK Coverage — SOC Detection Engineering Lab

Every rule in `rules/` exists to cover a technique below. Coverage is deliberately depth-first on credential access, persistence and lateral movement — the techniques a SOC analyst sees weekly — rather than thin coverage of every technique in the framework.

| Tactic | Technique | ID | Rule(s) |
|---|---|---|---|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | LSASS Memory Access from Non-System Process (Sysmon 10) |
| Execution | PowerShell | T1059.001 | PowerShell Encoded or Obfuscated Command Execution |
| Lateral Movement | SMB/Windows Admin Shares (PsExec-style) | T1021.002 | PsExec-Style Lateral Movement Service Creation (7045) |
| Credential Access | Kerberos Tickets: Kerberoasting | T1558.003 | Kerberoasting - Service Ticket Request with RC4 Encryption (4769) |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 | DCSync - Directory Replication from Non-DC Account (4662) |
| Lateral Movement | Alternate Authentication Material: Pass the Hash | T1550.002 | Pass-the-Hash Style Logon - Explicit Credentials (4648 / 4624 Type 9) |
| Persistence | Scheduled Task | T1053.005 | Scheduled Task Creation with Suspicious Content (4698) |
| Persistence | Registry Run Keys / Startup | T1547.001 | Registry Run Key Persistence via Sysmon (Event ID 13) |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Linux SSH Brute Force - Multiple Failed Passwords |
| Credential Access | /etc/passwd and /etc/shadow | T1003.008 | Linux Sudo Access to Shadow File or Root Shell |
| Privilege Escalation | Sudo and Sudo Caching | T1548.003 | Linux Sudo Access to Shadow File or Root Shell |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | Possible DNS Tunneling - Abnormally Long Subdomain Queries |
| Initial Access | Exploit Public-Facing Application | T1190 | Web Exploitation Attempt - SQL Injection or Web Shell in Access Logs |

**Summary:** 13 techniques across 7 tactics, 12 tested Sigma rules.

## Use with ATT&CK Navigator

1. Open the ATT&CK Navigator web app.
2. Choose *Open Existing Layer → Upload from local* and select `coverage/navigator-layer.json`.
3. Covered techniques render in red. Regenerate the layer whenever a rule is added so the picture never drifts from the code.

## Known gaps (honest)

- No process-creation (Sysmon 1) content rules yet (e.g. Office spawning a shell) — planned; telemetry is already in place.
- Cloud control-plane techniques are covered by the companion AWS SOC automation project, not duplicated here.
- The DNS rule is a length heuristic and needs per-domain baselining before production use.