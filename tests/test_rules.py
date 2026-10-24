#!/usr/bin/env python3
"""
Test harness for the SOC Detection Engineering Lab.

Runs with pytest (`pytest tests/`) OR standalone (`python3 tests/test_rules.py`)
via the built-in runner at the bottom — no third-party test dependency required.
Requires PyYAML (declared in the lab notes / README) for Sigma parsing.
"""
import json, pathlib, re, sys, uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import yaml
from matcher import load_units, evaluate, ALL_STEMS

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE_FILES = sorted((ROOT / "rules").glob("*.yml"))
SAMPLES = ROOT / "sample-logs"

def _rules():
    return {p.stem: yaml.safe_load(p.read_text()) for p in RULE_FILES}

def _malicious_units():
    return load_units([SAMPLES / "windows-security-sample.jsonl", SAMPLES / "linux-auth-sample.log",
                       SAMPLES / "web-access-sample.log", SAMPLES / "dns-query-sample.log"])

def _benign_units():
    return load_units([SAMPLES / "benign-sample.log"])

# ---------- Sigma structure validation ----------
def test_at_least_12_rules_exist():
    assert len(RULE_FILES) >= 12, f"expected >=12 rules, found {len(RULE_FILES)}"

def test_rules_have_required_sigma_fields():
    required = ["title", "id", "status", "description", "references", "author", "date", "tags", "logsource", "detection", "falsepositives", "level"]
    for stem, rule in _rules().items():
        for f in required:
            assert f in rule and rule[f] not in (None, "", []), f"{stem}: missing/empty field {f}"
        assert "condition" in rule["detection"], f"{stem}: detection.condition missing"
        assert rule["level"] in ("low", "medium", "high", "critical"), f"{stem}: bad level"

def test_rule_ids_are_valid_unique_uuids():
    ids = [str(r["id"]) for r in _rules().values()]
    for i in ids: uuid.UUID(i)
    assert len(ids) == len(set(ids)), "duplicate rule UUIDs"

def test_attack_tags_format():
    pat = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
    for stem, rule in _rules().items():
        tech = [t for t in rule["tags"] if t.startswith("attack.t")]
        assert tech, f"{stem}: no ATT&CK technique tag"
        for t in tech: assert pat.match(t), f"{stem}: malformed tag {t}"

def test_every_rule_has_spl_and_kql():
    spl = (ROOT / "detections" / "splunk-spl.md").read_text()
    kql = (ROOT / "detections" / "elastic-kql.md").read_text()
    for stem, rule in _rules().items():
        assert rule["title"] in spl, f"SPL missing: {rule['title']}"
        assert rule["title"] in kql, f"KQL missing: {rule['title']}"
        assert f"rules/{stem}.yml" in spl and f"rules/{stem}.yml" in kql

def test_navigator_layer_matches_rule_techniques():
    layer = json.loads((ROOT / "coverage" / "navigator-layer.json").read_text())
    layer_ids = {t["techniqueID"].lower() for t in layer["techniques"]}
    rule_ids = {t.replace("attack.", "") for r in _rules().values() for t in r["tags"] if t.startswith("attack.t")}
    assert rule_ids <= layer_ids, f"Navigator missing techniques: {rule_ids - layer_ids}"

# ---------- Behaviour: malicious samples fire ----------
def test_all_windows_rules_fire():
    units = _malicious_units()
    for stem in [s for s in ALL_STEMS if s[:2] in ("01", "02", "03", "04", "05", "06", "07", "08")]:
        assert evaluate(stem, units), f"rule did not fire on malicious samples: {stem}"

def test_linux_ssh_brute_force_fires():
    assert evaluate("09_linux_ssh_brute_force", _malicious_units())

def test_linux_sudo_shadow_fires():
    assert evaluate("10_linux_sudo_shadow_root_shell", _malicious_units())

def test_dns_tunneling_fires():
    assert evaluate("11_dns_tunneling_long_subdomains", _malicious_units())

def test_web_sqli_webshell_fires():
    assert evaluate("12_web_sqli_webshell_access", _malicious_units())

def test_at_least_six_rules_fire_overall():
    units = _malicious_units()
    fired = [s for s in ALL_STEMS if evaluate(s, units)]
    assert len(fired) >= 6, f"only fired: {fired}"

# ---------- Behaviour: benign samples stay quiet ----------
def test_benign_samples_trigger_no_rules():
    units = _benign_units()
    fired = [s for s in ALL_STEMS if evaluate(s, units)]
    assert fired == [], f"false positives on benign corpus: {fired}"

def test_sample_log_files_exist_and_nonempty():
    for name in ["windows-security-sample.jsonl", "linux-auth-sample.log", "web-access-sample.log", "benign-sample.log"]:
        p = SAMPLES / name
        assert p.exists() and p.stat().st_size > 200, f"sample missing/small: {name}"

if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"PASS {name}")
        except AssertionError as e:
            failed += 1; print(f"FAIL {name}: {e}")
        except Exception as e:
            failed += 1; print(f"ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
