# Splunk SPL — SOC Detection Engineering Lab

One SPL query per Sigma rule, numbered to match `rules/`. Index names (`wineventlog`, `linux`, `web`, `dns`) are lab conventions. Aggregation logic that Sigma backends express as correlations is written directly into the SPL where relevant (rules 4 and 9).

## 1. LSASS Memory Access from Non-System Process (Sysmon 10)

- **Sigma rule:** `rules/01_lsass_credential_dumping_sysmon.yml`
- **ATT&CK:** attack.t1003.001 | **Level:** high

```
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010","0x1410","0x147a","0x143a","0x1fffff") NOT SourceImage IN ("*\\MsMpEng.exe","*\\csrss.exe","*\\wininit.exe","*\\services.exe") | table _time, ComputerName, SourceImage, TargetImage, GrantedAccess, User
```

## 2. PowerShell Encoded or Obfuscated Command Execution

- **Sigma rule:** `rules/02_powershell_encoded_command.yml`
- **ATT&CK:** attack.t1059.001 | **Level:** high

```
index=wineventlog (EventCode=4688 OR EventCode=4104) process_name="*\\powershell.exe" (CommandLine="* -enc *" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*" OR CommandLine="*DownloadString(*") | table _time, ComputerName, User, CommandLine, parent_process_name
```

## 3. PsExec-Style Lateral Movement Service Creation (7045)

- **Sigma rule:** `rules/03_psexec_lateral_movement_service.yml`
- **ATT&CK:** attack.t1021.002 | **Level:** high

```
index=wineventlog EventCode=7045 (Service_Name="PSEXESVC*" OR ImagePath="*PsExec*" OR ImagePath="*PSEXESVC*") | table _time, ComputerName, Service_Name, ImagePath, Account_Name
```

## 4. Kerberoasting - Service Ticket Request with RC4 Encryption (4769)

- **Sigma rule:** `rules/04_kerberoasting_spn_ticket_rc4.yml`
- **ATT&CK:** attack.t1558.003 | **Level:** medium

```
index=wineventlog EventCode=4769 TicketEncryptionType="0x17" ServiceName!="krbtgt" IpAddress!="::1" | stats count BY TargetUserName, ServiceName, IpAddress | where count > 3
```

## 5. DCSync - Directory Replication from Non-DC Account (4662)

- **Sigma rule:** `rules/05_dcsync_directory_replication.yml`
- **ATT&CK:** attack.t1003.006 | **Level:** critical

```
index=wineventlog EventCode=4662 (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2d2d2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2d2d2*") SubjectUserName!="*$" | table _time, ComputerName, SubjectUserName, ObjectName, Properties
```

## 6. Pass-the-Hash Style Logon - Explicit Credentials (4648 / 4624 Type 9)

- **Sigma rule:** `rules/06_pass_the_hash_explicit_logon.yml`
- **ATT&CK:** attack.t1550.002 | **Level:** high

```
index=wineventlog ((EventCode=4648 Target_Server_Name!="localhost") OR (EventCode=4624 LogonType=9 AuthenticationPackageName IN ("Negotiate","NTLM"))) | table _time, ComputerName, TargetUserName, IpAddress, LogonType, AuthenticationPackageName
```

## 7. Scheduled Task Creation with Suspicious Content (4698)

- **Sigma rule:** `rules/07_scheduled_task_persistence.yml`
- **ATT&CK:** attack.t1053.005 | **Level:** medium

```
index=wineventlog EventCode=4698 (TaskContent="*powershell*" OR TaskContent="*cmd.exe*" OR TaskContent="*mshta*" OR TaskContent="*\\Temp\\*" OR TaskContent="* -enc *") | table _time, ComputerName, SubjectUserName, TaskName, TaskContent
```

## 8. Registry Run Key Persistence via Sysmon (Event ID 13)

- **Sigma rule:** `rules/08_registry_run_key_persistence.yml`
- **ATT&CK:** attack.t1547.001 | **Level:** medium

```
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\CurrentVersion\\Run*" (Details="*\\Temp\\*" OR Details="*\\AppData\\*" OR Details="*powershell*" OR Details="*.vbs*") | table _time, ComputerName, Image, TargetObject, Details, User
```

## 9. Linux SSH Brute Force - Multiple Failed Passwords

- **Sigma rule:** `rules/09_linux_ssh_brute_force.yml`
- **ATT&CK:** attack.t1110.001 | **Level:** medium

```
index=linux sourcetype=linux_secure "Failed password" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | bin _time span=5m | stats count BY src_ip, _time | where count >= 10
```

## 10. Linux Sudo Access to Shadow File or Root Shell

- **Sigma rule:** `rules/10_linux_sudo_shadow_root_shell.yml`
- **ATT&CK:** attack.t1003.008, attack.t1548.003 | **Level:** high

```
index=linux sourcetype=linux_secure sudo (COMMAND="*/etc/shadow*" OR COMMAND="*/bin/su*" OR COMMAND="*/bin/bash") | table _time, host, user, COMMAND
```

## 11. Possible DNS Tunneling - Abnormally Long Subdomain Queries

- **Sigma rule:** `rules/11_dns_tunneling_long_subdomains.yml`
- **ATT&CK:** attack.t1071.004 | **Level:** medium

```
index=dns | rex field=query "^(?<label>[^.]+)\." | eval label_len=len(label) | where label_len >= 40 | stats count BY src_ip, query, label_len | sort - label_len
```

## 12. Web Exploitation Attempt - SQL Injection or Web Shell in Access Logs

- **Sigma rule:** `rules/12_web_sqli_webshell_access.yml`
- **ATT&CK:** attack.t1190 | **Level:** high

```
index=web sourcetype=access_combined (uri="*UNION SELECT*" OR uri="* OR 1=1*" OR uri="*cmd=*" OR uri="*shell.php*" OR useragent="*sqlmap*") | table _time, src_ip, method, uri, status, useragent
```
