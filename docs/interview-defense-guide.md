# Interview Defense Guide — SOC Detection Engineering Lab

## The honest framing

I **designed and directed** this lab: I chose the techniques, the telemetry, the rule logic, the false-positive conditions and the test design, and I built it with AI assistance for implementation, reviewing and validating every rule and query. That is the accurate sentence, and it is a strong one — it is exactly how detection teams increasingly work.

**Never claim:** that I hand-typed every line from memory, or that these rules ran in a production SIEM at an employer. They run against synthetic sample logs in this repo — and I can prove every claim that *is* in the repo, live, in under a minute (`validate_rules.py` + the test suite).

What makes this project defensible is that it is **tested**: most candidates say "I wrote Sigma rules." Fewer can show a green test run proving the rules fire on attack samples and stay silent on benign ones.

## 30-second pitch

> "I built a detection-as-code lab: 12 Sigma rules covering 13 ATT&CK techniques — LSASS access, encoded PowerShell, PsExec, Kerberoasting, DCSync, Pass-the-Hash, persistence, SSH brute force, DNS tunneling, SQLi. Sigma is the source of truth; every rule also ships as Splunk SPL and Elastic KQL. The part I'm most proud of is the testing: sample attack logs that must fire every rule, a benign corpus that must fire none, and a validator that checks structure, UUIDs and ATT&CK tags — all runnable with one command."

## 5 design decisions to defend

1. **Sigma as the portable source of truth.** Vendor lock-in is the default failure of detection content. Writing in Sigma once and mirroring to SPL/KQL means the logic survives a SIEM migration, and the tests target the Sigma, not a vendor's dialect.
2. **False positives are part of the rule, not an afterthought.** Every rule carries a written `falsepositives` field and, where the telemetry allows it, an explicit filter (system processes for LSASS, DC machine accounts for DCSync). A rule you can't tune is a rule the SOC will disable.
3. **Test logs matter as much as rules.** Detection content without fixtures rots silently when schemas change. The malicious corpus fires **all 12** rules; the benign corpus — real-looking admin activity, not empty logs — fires **zero**. That second corpus is the harder and more valuable one.
4. **Coverage is ATT&CK-driven, depth-first.** I mapped gaps with the Navigator layer and deliberately went deep on credential access and persistence — the highest-frequency, highest-impact techniques for a SOC — instead of sprinkling one shallow rule per tactic for a prettier heatmap.
5. **Telemetry before logic.** Half the rules are worthless without the right logging: Sysmon 10/13, 4662 with the correct SACLs, PowerShell Script Block Logging, 4698 auditing. Each rule's prerequisites are documented in the README because "we don't log that" is the #1 real-world reason detections fail.

## Likely Q&A

- **"Why does your Kerberoasting rule need a threshold?"** A single RC4 4769 can be a legacy app. The *pattern* (one user, many SPNs, RC4, short window) is the attack. The Sigma selection catches the unit event; the SPL applies count > 3 by user/SPN — I documented that split instead of pretending Sigma selections aggregate by themselves.
- **"How would you reduce LSASS rule noise in production?"** Expand the source-image allowlist from the actual EDR inventory, require the dumping process to be unsigned or in a user-writable path, and alert at higher severity only when correlated with a second signal from the same host within an hour.
- **"Your matcher isn't a real Sigma backend — why?"** Honest scope: it's a CI-friendly regression stand-in so the content is testable anywhere. Production conversion is pySigma's job; that conversion step is on the roadmap, and the SPL/KQL files already show the converted forms.
- **"What's the first rule you'd add?"** Sysmon 1 process-creation pack — Office child processes, download cradles, living-off-the-land binaries. The telemetry and test pattern are already in place; it's an additive change.
- **"DCSync vs. normal replication — how do you tell?"** Who is asking. Replication rights exercised by a DC machine account or the sync service is the design of AD; the same GUIDs from a standard user workstation account is never legitimate. Identity context, not the event ID, is the detection.
- **"How does this connect to your other projects?"** Those generate and automate the *response* to alerts (isolation, PRs, notifications). This lab is the detection layer underneath — the part that decides an alert deserves to exist at all.

## Before any interview (30 minutes)

1. Run `python3 scripts/validate_rules.py` and `python3 tests/test_rules.py` — know the green output by sight.
2. Pick two rules (suggest DCSync and Kerberoasting) and be able to explain every field, filter and false positive without notes.
3. Read `docs/detection-report-sample.md` — be ready to walk the 08:14 → 08:27 attack chain in ATT&CK order.
4. Open the Navigator layer and explain one honest gap and why it's a gap.
