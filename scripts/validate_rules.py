#!/usr/bin/env python3
"""Standalone Sigma rule validator: YAML parse + required fields + UUID + ATT&CK tag format.
Usage: python3 scripts/validate_rules.py   (exit 1 if any rule fails)"""
import pathlib, re, sys, uuid
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED = ["title", "id", "status", "description", "references", "author", "date", "tags", "logsource", "detection", "falsepositives", "level"]
TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")

def main():
    files = sorted((ROOT / "rules").glob("*.yml"))
    seen, failures = set(), 0
    for f in files:
        problems = []
        try:
            rule = yaml.safe_load(f.read_text())
        except Exception as e:
            print(f"FAIL {f.name}: YAML parse error: {e}"); failures += 1; continue
        for k in REQUIRED:
            if k not in rule or rule[k] in (None, "", []): problems.append(f"missing {k}")
        try:
            u = str(uuid.UUID(str(rule.get("id"))))
            if u in seen: problems.append("duplicate id")
            seen.add(u)
        except Exception: problems.append("id is not a valid UUID")
        if "detection" in rule and "condition" not in rule["detection"]: problems.append("no detection.condition")
        tech = [t for t in (rule.get("tags") or []) if str(t).startswith("attack.t")]
        if not tech: problems.append("no ATT&CK technique tag")
        for t in tech:
            if not TAG.match(str(t)): problems.append(f"bad tag {t}")
        if rule.get("level") not in ("low", "medium", "high", "critical"): problems.append("bad level")
        if problems:
            failures += 1; print(f"FAIL {f.name}: {'; '.join(problems)}")
        else:
            print(f"PASS {f.name}: {rule['title']} [{rule['level']}] tags={','.join(tech)}")
    print(f"\n{len(files) - failures}/{len(files)} rules valid")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
