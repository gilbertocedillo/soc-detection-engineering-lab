# Sample Detection / Triage Report — L2 Analyst

> Written against the synthetic events in `sample-logs/`. Names, hosts and IPs are fictional lab data. This is the report format I use in the lab: evidence first, verdict second, actions always traceable to a rule and a technique.

---

**Alert ID:** LAB-2026-1020-014
**Rule:** `rules/05_dcsync_directory_replication.yml` — *DCSync - Directory Replication from Non-DC Account (4662)*
**Severity:** Critical (rule level) · **Verdict: TRUE POSITIVE** · **Status:** Escalated to IR / contained in lab timeline

## Summary

At 08:22:03Z, domain controller **DC01** logged Security Event **4662** in which the standard user account **j.martinez** requested directory replication rights (DS-Replication-Get-Changes `1131f6aa-…` and Get-Changes-All `1131f6ad-…`) against the domain naming context. Only domain controllers (machine accounts) and the identity-sync service should ever hold or exercise these rights. A standard user exercising them is, by definition, a DCSync attack in progress: the caller can extract password hashes for every account in the domain, including KRBTGT.

## Evidence (from `sample-logs/windows-security-sample.jsonl`)

| Time (UTC) | Host | Event | Key fields |
|---|---|---|---|
| 08:14:02 | WS-FIN-014 | Sysmon 10 | Unknown tool (`credtool.exe` in Downloads) opened `lsass.exe`, GrantedAccess `0x1010` — Rule 01 also fired |
| 08:15:44 | WS-FIN-014 | 4688 | `powershell.exe -enc <base64>` long encoded command — Rule 02 |
| 08:19:31–08:20:22 | DC01 | 4769 ×4 | RC4 (`0x17`) tickets for MSSQLSvc / HTTP / WSMAN / LDAP SPNs from 10.0.4.21 — Rule 04 (Kerberoasting) |
| 08:22:03 | DC01 | **4662** | **j.martinez, replication GUIDs, non-DC account — this alert** |
| 08:24:37 | WS-FIN-014 | 4648 | Explicit-credential logon as `administrator` to SRV-FILE-01 — Rule 06 |
| 08:26:12 | WS-FIN-014 | 4698 | Scheduled task `\UpdaterHelper` running encoded PowerShell from `%TEMP%` — Rule 07 |
| 08:27:55 | WS-FIN-014 | Sysmon 13 | Run-key value pointing at the same `%TEMP%\upd.ps1` — Rule 08 |

No single event here is ambiguous in context: this is one continuous intrusion chain on one workstation pivoting to the DC, not seven unrelated coincidences.

## ATT&CK mapping

- **T1003.001** LSASS Memory (08:14) → **T1059.001** PowerShell (08:15) → **T1558.003** Kerberoasting (08:19) → **T1003.006 DCSync (this alert)** → **T1550.002** Pass-the-Hash (08:24) → **T1053.005 / T1547.001** persistence (08:26–08:27).

## Why this is not a false positive

- The account is a standard user, not a DC machine account (the rule's `$`-suffix filter) and not the allowlisted sync service.
- The same account and source host generated four other high-fidelity alerts within 14 minutes.
- There is no change ticket, admin tooling baseline, or red-team notice covering WS-FIN-014 / j.martinez in this window (checked before escalating — in the lab, by design).

## Impact assessment

Assume **domain-wide credential compromise**: if the DCSync request succeeded, the attacker holds NTLM hashes for all accounts and can forge Kerberos tickets after obtaining KRBTGT. Workstation-level containment alone is insufficient.

## Recommended actions (escalation)

1. **Immediately:** disable `j.martinez`, isolate WS-FIN-014 and SRV-FILE-01 from the network (preserve for imaging — do not wipe).
2. **Within the hour:** force password resets for all privileged accounts; plan the double KRBTGT reset procedure with the identity team.
3. **Hunt:** sweep all DCs for 4662 with replication GUIDs (any account), and all endpoints for the `upd.ps1` filename / `\UpdaterHelper` task and Run-key value.
4. **Eradicate/recover:** rebuild WS-FIN-014 from known-good media; review SPN service accounts for weak passwords (the Kerberoasting leg) and move them to gMSA / AES-only encryption.
5. **Detection follow-up:** this rule performed as designed. Add a companion alert for *successful* high-volume 4769 RC4 bursts per user (Rule 04 threshold tuning) — tracked in the lab roadmap.

## Analyst note on confidence

Confidence is **high** not because one log line looks scary, but because five independent telemetry sources corroborate one narrative in ATT&CK order. That — not the severity label on any single rule — is what justifies waking up the IR lead.
