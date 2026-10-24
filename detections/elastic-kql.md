# Elastic KQL — SOC Detection Engineering Lab

One Elastic query per Sigma rule, numbered to match `rules/`. Field names assume Winlogbeat/Sysmon conventions (`winlog.event_data.*`, `event.code`). Where KQL alone cannot aggregate (rules 4 and 9), the Kibana aggregation form used in the lab is shown.

## 1. LSASS Memory Access from Non-System Process (Sysmon 10)

- **Sigma rule:** `rules/01_lsass_credential_dumping_sysmon.yml`
- **ATT&CK:** attack.t1003.001 | **Level:** high

```
event.code: "10" and winlog.event_data.TargetImage: *\\lsass.exe and winlog.event_data.GrantedAccess: ("0x1010" or "0x1410" or "0x147a") and not winlog.event_data.SourceImage: (*MsMpEng.exe or *csrss.exe)
```

## 2. PowerShell Encoded or Obfuscated Command Execution

- **Sigma rule:** `rules/02_powershell_encoded_command.yml`
- **ATT&CK:** attack.t1059.001 | **Level:** high

```
event.code: ("4688" or "4104") and process.name: "powershell.exe" and process.command_line: (*-enc* or *EncodedCommand* or *FromBase64String* or *DownloadString*)
```

## 3. PsExec-Style Lateral Movement Service Creation (7045)

- **Sigma rule:** `rules/03_psexec_lateral_movement_service.yml`
- **ATT&CK:** attack.t1021.002 | **Level:** high

```
event.code: "7045" and (winlog.event_data.ServiceName: PSEXESVC* or winlog.event_data.ImagePath: (*PsExec* or *PSEXESVC*))
```

## 4. Kerberoasting - Service Ticket Request with RC4 Encryption (4769)

- **Sigma rule:** `rules/04_kerberoasting_spn_ticket_rc4.yml`
- **ATT&CK:** attack.t1558.003 | **Level:** medium

```
event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17" and not winlog.event_data.ServiceName: "krbtgt"
```

## 5. DCSync - Directory Replication from Non-DC Account (4662)

- **Sigma rule:** `rules/05_dcsync_directory_replication.yml`
- **ATT&CK:** attack.t1003.006 | **Level:** critical

```
event.code: "4662" and winlog.event_data.Properties: (*1131f6aa-9c07-11d1-f79f-00c04fc2d2d2* or *1131f6ad-9c07-11d1-f79f-00c04fc2d2d2*) and not user.name: *$
```

## 6. Pass-the-Hash Style Logon - Explicit Credentials (4648 / 4624 Type 9)

- **Sigma rule:** `rules/06_pass_the_hash_explicit_logon.yml`
- **ATT&CK:** attack.t1550.002 | **Level:** high

```
(event.code: "4648" and winlog.event_data.TargetServerName: *) or (event.code: "4624" and winlog.event_data.LogonType: "9" and winlog.event_data.AuthenticationPackageName: ("Negotiate" or "NTLM"))
```

## 7. Scheduled Task Creation with Suspicious Content (4698)

- **Sigma rule:** `rules/07_scheduled_task_persistence.yml`
- **ATT&CK:** attack.t1053.005 | **Level:** medium

```
event.code: "4698" and winlog.event_data.TaskContent: (*powershell* or *cmd.exe* or *mshta* or *-enc*)
```

## 8. Registry Run Key Persistence via Sysmon (Event ID 13)

- **Sigma rule:** `rules/08_registry_run_key_persistence.yml`
- **ATT&CK:** attack.t1547.001 | **Level:** medium

```
event.code: "13" and registry.path: (*CurrentVersion*Run*) and registry.data.strings: (*Temp* or *AppData* or *powershell* or *.vbs*)
```

## 9. Linux SSH Brute Force - Multiple Failed Passwords

- **Sigma rule:** `rules/09_linux_ssh_brute_force.yml`
- **ATT&CK:** attack.t1110.001 | **Level:** medium

```
message: "Failed password for" | summarize Failures = count() by SrcIp = source.ip, bin(@timestamp, 5m) | where Failures >= 10
```

## 10. Linux Sudo Access to Shadow File or Root Shell

- **Sigma rule:** `rules/10_linux_sudo_shadow_root_shell.yml`
- **ATT&CK:** attack.t1003.008, attack.t1548.003 | **Level:** high

```
message: *sudo* and message: (*/etc/shadow* or */bin/su* or */bin/bash*)
```

## 11. Possible DNS Tunneling - Abnormally Long Subdomain Queries

- **Sigma rule:** `rules/11_dns_tunneling_long_subdomains.yml`
- **ATT&CK:** attack.t1071.004 | **Level:** medium

```
dns.question.name: * | extend Label = tostring(split(dns.question.name, ".")[0]) | extend LabelLen = strlen(Label) | where LabelLen >= 40
```

## 12. Web Exploitation Attempt - SQL Injection or Web Shell in Access Logs

- **Sigma rule:** `rules/12_web_sqli_webshell_access.yml`
- **ATT&CK:** attack.t1190 | **Level:** high

```
url.path: (*UNION*SELECT* or *cmd=* or *shell.php*) or user_agent.original: (*sqlmap* or *nikto*)
```
