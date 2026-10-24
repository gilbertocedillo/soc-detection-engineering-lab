#!/usr/bin/env python3
"""
Lightweight lab matcher for the Sigma rules in ../rules/.

This is intentionally NOT a full Sigma backend (use pySigma + a real SIEM for
that). Each check mirrors the *selection logic* of one rule with simple
field/keyword tests over individual log units, so the detection content can be
regression-tested in CI without a Splunk/Elastic instance. Units are single
events: one JSON object per line for JSONL, one line for text logs.
URL-decoding is applied to web units because access logs are percent-encoded
(the Sigma selections and SPL in this repo assume the SIEM's decoded `uri`
field; the matcher reproduces that here).
"""
import json, re
from collections import Counter
from urllib.parse import unquote_plus

SSH_IP = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
DNS_Q = re.compile(r"query=([A-Za-z0-9._-]+)")

def load_units(paths):
    """Return a list of unit dicts: {raw, text (lower), event (dict|None)}."""
    units = []
    for p in paths:
        for line in open(p, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line:
                continue
            ev = None
            if line.startswith("{"):
                try: ev = json.loads(line)
                except Exception: ev = None
            units.append({"raw": line, "text": unquote_plus(line).lower(), "event": ev})
    return units

def _eid(u, *ids):
    return u["event"] is not None and u["event"].get("EventID") in ids

def _field(u, name):
    if u["event"] is None: return ""
    return str(u["event"].get(name, ""))

CHECKS = {
 "01_lsass_credential_dumping_sysmon": lambda u: _eid(u, 10) and "lsass.exe" in _field(u, "TargetImage").lower()
    and _field(u, "GrantedAccess").lower() in ("0x1010", "0x1410", "0x147a", "0x143a", "0x1fffff")
    and not any(s in _field(u, "SourceImage").lower() for s in ("msmpeng.exe", "csrss.exe", "wininit.exe", "services.exe")),
 "02_powershell_encoded_command": lambda u: "powershell" in u["text"] and any(k in u["text"] for k in (" -enc ", "-encodedcommand", "frombase64string", "downloadstring(")),
 "03_psexec_lateral_movement_service": lambda u: _eid(u, 7045) and ("psexec" in u["text"] or "psexesvc" in u["text"]),
 "04_kerberoasting_spn_ticket_rc4": lambda u: _eid(u, 4769) and _field(u, "TicketEncryptionType") == "0x17"
    and any(s in _field(u, "ServiceName") for s in ("MSSQLSvc", "HTTP", "WSMAN", "LDAP")),
 "05_dcsync_directory_replication": lambda u: _eid(u, 4662) and "1131f6a" in u["text"]
    and not _field(u, "SubjectUserName").endswith("$"),
 "06_pass_the_hash_explicit_logon": lambda u: _eid(u, 4648) or (_eid(u, 4624) and _field(u, "LogonType") == "9"),
 "07_scheduled_task_persistence": lambda u: _eid(u, 4698) and any(k in _field(u, "TaskContent").lower() for k in ("powershell", "cmd.exe", "mshta", "\\temp\\", " -enc ")),
 "08_registry_run_key_persistence": lambda u: _eid(u, 13) and "currentversion\\run" in _field(u, "TargetObject").lower()
    and any(k in _field(u, "Details").lower() for k in ("\\temp\\", "\\appdata\\", "powershell", ".vbs")),
 "10_linux_sudo_shadow_root_shell": lambda u: "sudo" in u["text"] and any(k in u["text"] for k in ("command=/bin/cat /etc/shadow", "command=/usr/bin/cat /etc/shadow", "command=/bin/su", "command=/bin/bash")),
 "11_dns_tunneling_long_subdomains": lambda u: _dns_long(u),
 "12_web_sqli_webshell_access": lambda u: any(k in u["text"] for k in ("union select", "' or '1'='1", " or 1=1", "sqlmap", "shell.php", "cmd=")) and ("http" in u["text"]),
}

def _dns_long(u):
    m = DNS_Q.search(u["raw"])
    if m:
        return len(m.group(1).split(".")[0]) >= 40
    return False

def evaluate(stem, units):
    """True if rule `stem` fires on the corpus. SSH brute force is a counting rule."""
    if stem == "09_linux_ssh_brute_force":
        ips = [SSH_IP.search(u["raw"]).group(1) for u in units
               if "Failed password" in u["raw"] and SSH_IP.search(u["raw"])]
        return any(c >= 10 for c in Counter(ips).values())
    check = CHECKS.get(stem)
    if check is None:
        raise KeyError(f"No matcher implemented for {stem}")
    return any(check(u) for u in units)

ALL_STEMS = sorted(list(CHECKS.keys()) + ["09_linux_ssh_brute_force"])
