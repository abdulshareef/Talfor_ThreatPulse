import json
import os

from threatpulse import simulate
from threatpulse.evidence import verify_ledger
from threatpulse.hunt import apply_feedback, run_hunt


def test_all_hypotheses_detected(demo):
    r = simulate.evaluate(demo["alerts"], demo["truth"])
    assert r["missed"] == [], r["detected"]
    assert r["detected"]["ML"] == ["TP-ML"]  # the learning layer caught what no rule covers


def test_low_false_positives(demo):
    r = simulate.evaluate(demo["alerts"], demo["truth"])
    assert r["false_positives"] <= 5
    # every benign alert should rank below every true intrusion alert from a rule
    tp_scores = [a["score"] for a in demo["alerts"] if str(a["event"].get("RecordID", "")).startswith("ATK-")
                 and a["kind"] == "rule"]
    fp_scores = [a["score"] for a in r["fp_alerts"]]
    if fp_scores:
        assert max(fp_scores) < min(tp_scores)


def test_attack_chains(demo):
    chains = demo["summary"]["chains"]
    assert chains[0]["host"].startswith(("WS-07", "SRV-01")) and len(chains[0]["tactics"]) >= 4


def test_manifest_and_ledger(demo):
    run_dir = demo["summary"]["run_dir"]
    m = json.load(open(os.path.join(run_dir, "manifest.json")))
    assert m["case_id"] == "TEST-1" and len(m["inputs"][0]["sha256"]) == 64
    assert verify_ledger(os.path.join(run_dir, "alerts.jsonl"), m["ledger_head"])[0]
    annex = open(os.path.join(run_dir, "evidence_annex.md")).read()
    assert "jurisdiction-neutral" in annex and m["inputs"][0]["sha256"] in annex
    assert m["started_local"] and m["finished_local"]
    assert os.path.exists(os.path.join(run_dir, "report.html"))


def test_feedback_suppresses_recurring_fp_and_keeps_detections(demo):
    r = simulate.evaluate(demo["alerts"], demo["truth"])
    onedrive = [a for a in r["fp_alerts"] if "onedrive" in a["image"].lower()]
    assert len(onedrive) >= 3
    for a in onedrive[:3]:
        apply_feedback(demo["state"], demo["runs"], a["alert_id"], "fp", analyst="pytest")
    s = run_hunt([demo["files"]["hunt"]], demo["state"], demo["runs"], learn=False)
    alerts = [json.loads(l)["record"] for l in open(os.path.join(s["run_dir"], "alerts.jsonl"))]
    r2 = simulate.evaluate(alerts, demo["truth"])
    assert s["suppressed_by_learning"] >= len(onedrive)
    assert r2["false_positives"] == 0
    # still catches everything except first-seen logon, which is (correctly) no longer first-seen
    assert set(r2["missed"]) <= {"H07b"}
    fb = os.path.join(demo["state"], "feedback.jsonl")
    assert verify_ledger(fb)[0]
