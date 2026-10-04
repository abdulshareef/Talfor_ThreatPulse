"""Hunt pipeline: rules -> analytics -> learning -> fusion -> evidence ledger."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from . import analytics as analytics_mod
from .events import Event, read_events, sha256_file
from .evidence import (EvidenceLedger, environment, now_pair, ruleset_digest, tool_source_digest,
                       write_certificate_annex)
from .learn.features import is_process_event, registry_features, static_features, vectorise
from .learn.model import ThreatModel
from .rules import Hit, RuleSet

ML_RULE_ID = "TP-ML"

# Technique -> tactic (subset used by the built-in rules, for chain scoring).
TACTICS = {
    "T1566": "initial-access", "T1204": "execution", "T1059": "execution", "T1047": "execution",
    "T1569": "execution", "T1003": "credential-access", "T1027": "defense-evasion",
    "T1140": "defense-evasion", "T1218": "defense-evasion", "T1070": "defense-evasion",
    "T1562": "defense-evasion", "T1036": "defense-evasion", "T1105": "command-and-control",
    "T1071": "command-and-control", "T1573": "command-and-control", "T1568": "command-and-control",
    "T1547": "persistence", "T1053": "persistence", "T1543": "persistence", "T1021": "lateral-movement",
    "T1078": "lateral-movement", "T1490": "impact", "T1486": "impact", "T1048": "exfiltration",
}


def band(p: float) -> str:
    if p >= 0.85:
        return "critical"
    if p >= 0.6:
        return "high"
    if p >= 0.3:
        return "medium"
    return "low"


@dataclass
class HuntConfig:
    learn: bool = True
    anomaly_threshold: float = 0.85
    max_raw_chars: int = 4000


@dataclass
class HuntStats:
    events: int = 0
    process_events: int = 0
    rule_hits: int = 0
    suppressed: int = 0
    alerts: int = 0
    anomaly_alerts: int = 0
    seconds: float = 0.0
    by_rule: Dict[str, int] = field(default_factory=dict)

    @property
    def eps(self) -> float:
        return self.events / self.seconds if self.seconds else 0.0


class Hunter:
    def __init__(self, ruleset: RuleSet, model: Optional[ThreatModel] = None,
                 config: Optional[HuntConfig] = None, baseline: bool = False):
        self.rules = ruleset
        self.model = model or ThreatModel()
        self.cfg = config or HuntConfig()
        self.baseline = baseline
        self.stats = HuntStats()
        self.analytics: Dict[str, analytics_mod.Analytic] = {}
        for r in ruleset.rules:
            if r.type == "analytic":
                a = analytics_mod.build(r.analytic, r.params)
                a.restore(self.model.analytic_state.get(r.id, {}))
                if baseline and isinstance(a, analytics_mod.FirstSeen):
                    a.learn_only = True
                self.analytics[r.id] = a
        self._ml_seen: set = set()
        self._seq = 0

    # ------------------------------------------------------------------------
    def _signature(self, rule_id: str, ev: Event, details: Dict[str, Any]) -> str:
        extra = details.get("destination") or details.get("parent_domain") or details.get("new_pair") or ""
        # Host is deliberately excluded: the same benign software behaves the same on every
        # endpoint, so feedback on one host teaches the model about all of them.
        return f"{rule_id}|{ev.get('tp_parent', '')}|{ev.get('tp_image', '')}|{extra}"

    def process(self, ev: Event) -> Optional[Dict[str, Any]]:
        st = self.stats
        st.events += 1
        self.model.events_seen += 1
        hits: List[Hit] = []
        for rule in self.rules.candidates(ev):
            if rule.type == "match":
                if rule.matcher(ev):
                    hits.append(Hit(rule.id, rule.title, rule.severity, rule.severity_score, rule.mitre, ev))
            else:
                if rule.matcher is not None and not rule.matcher(ev):
                    continue
                d = self.analytics[rule.id].process(ev)
                if d:
                    hits.append(Hit(rule.id, rule.title, rule.severity, rule.severity_score, rule.mitre, ev, d))

        feats: Dict[str, float] = {}
        learn_item = None
        if is_process_event(ev):
            st.process_events += 1
            self.model.process_events_seen += 1
            feats = static_features(ev)
            pair = f"{ev.get('tp_parent')}>{ev.get('tp_image')}"
            ih = f"{ev.get('tp_host')}|{ev.get('tp_image')}"
            feats["pair_rarity"] = self.model.pair_rarity.score(pair)
            feats["image_host_rarity"] = self.model.image_host_rarity.score(ih)
            vec = vectorise(feats)
            pct = self.model.hst.score(vec)
            feats["hst_percentile"] = pct
            feats["hst_anomaly"] = pct ** 6  # sharpen: only the tail matters
            learn_item = (vec, pair, ih)

        if self.baseline:
            self._learn(learn_item)
            return None
        if not hits and not feats:
            return None

        fusion = self.model.fusion
        active: List[Hit] = []
        sigs: List[str] = []
        for h in hits:
            st.rule_hits += 1
            sig = self._signature(h.rule_id, ev, h.details)
            if fusion.signature_suppressed(sig) or fusion.rule_suppressed(h.rule_id):
                st.suppressed += 1
                continue
            active.append(h)
            sigs.append(sig)

        f = dict(feats)
        if not feats and ev.get("EventID") == 13 and ev.get("tp_channel") == "sysmon":
            f.update(registry_features(ev))
        f["url_or_b64"] = max(f.get("has_url", 0.0), f.get("has_b64", 0.0))
        if active:
            f["rule_severity"] = max(h.severity_score for h in active)
            f["rule_count"] = min(1.0, len(active) / 3.0)
            f["rule_reliability"] = sum(fusion.rule_reliability(h.rule_id) for h in active) / len(active)
            strengths = [float(h.details.get("beacon_score", 1.0)) for h in active if h.details]
            f["analytic_strength"] = max(strengths) if strengths else 0.0
        p = fusion.predict(f)

        kind = "rule"
        if not active:
            # Anti-poisoning: only events the model considers benign enter the baseline.
            if p < 0.5 and self.cfg.learn:
                self._learn(learn_item)
            if not feats or not self.model.warmed or p < self.cfg.anomaly_threshold:
                return None
            sig = self._signature(ML_RULE_ID, ev, {})
            if sig in self._ml_seen or fusion.signature_suppressed(sig):
                return None
            self._ml_seen.add(sig)
            sigs = [sig]
            kind = "anomaly"
            st.anomaly_alerts += 1

        st.alerts += 1
        for h in active:
            st.by_rule[h.rule_id] = st.by_rule.get(h.rule_id, 0) + 1
        return self._build_alert(ev, active, f, p, kind, sigs)

    def _learn(self, item) -> None:
        if item is None:
            return
        vec, pair, ih = item
        self.model.hst.learn(vec)
        self.model.pair_rarity.learn(pair)
        self.model.image_host_rarity.learn(ih)

    def _build_alert(self, ev, active: List[Hit], f, p, kind, sigs) -> Dict[str, Any]:
        self._seq += 1
        raw = {k: v for k, v in ev.items() if not k.startswith("tp_")}
        raw_s = json.dumps(raw, default=str)
        if len(raw_s) > self.cfg.max_raw_chars:
            raw = {"_truncated": raw_s[: self.cfg.max_raw_chars]}
        ts = ev.get("tp_ts") or 0.0
        if active:
            rule_ids = [h.rule_id for h in active]
            titles = [h.title for h in active]
            mitre = sorted({m for h in active for m in h.mitre})
            details = {h.rule_id: h.details for h in active if h.details}
        else:
            rule_ids = [ML_RULE_ID]
            titles = ["Behavioural anomaly — rare process behaviour for this environment"]
            mitre = []
            details = {}
        reasons = [f"{k} {'+' if v > 0 else ''}{v}" for k, v in self.model.fusion.explain(f)]
        basis = f"{ts}|{ev.get('tp_host')}|{ev.get('RecordID', '')}|{'/'.join(rule_ids)}|{self._seq}"
        return {
            "alert_id": hashlib.sha256(basis.encode()).hexdigest()[:16],
            "kind": kind,
            "time": datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else "",
            "ts": ts,
            "host": ev.get("Computer", ""),
            "user": ev.get("User", "") or ev.get("TargetUserName", ""),
            "event_id": ev.get("EventID"),
            "channel": ev.get("tp_channel"),
            "image": ev.get("Image", ""),
            "parent": ev.get("ParentImage", ""),
            "command_line": ev.get("CommandLine", ""),
            "rules": rule_ids,
            "titles": titles,
            "mitre": mitre,
            "score": round(p, 4),
            "priority": band(p),
            "why": reasons,
            "details": details,
            "features": {k: round(v, 4) for k, v in f.items()},
            "signatures": sigs,
            "event": raw,
        }

    def finish(self) -> None:
        for rid, a in self.analytics.items():
            st = a.export()
            if st:
                self.model.analytic_state[rid] = st


# ----------------------------------------------------------------------------
# Correlation into attack chains
# ----------------------------------------------------------------------------

def correlate(alerts: List[Dict[str, Any]], gap_s: float = 3600) -> List[Dict[str, Any]]:
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for a in alerts:
        by_host.setdefault(str(a.get("host", "")).lower(), []).append(a)
    chains = []
    for host, items in by_host.items():
        items.sort(key=lambda a: a.get("ts") or 0)
        cur: List[Dict[str, Any]] = []
        for a in items:
            if cur and (a.get("ts") or 0) - (cur[-1].get("ts") or 0) > gap_s:
                chains.append(cur)
                cur = []
            cur.append(a)
        if cur:
            chains.append(cur)
    out = []
    for c in chains:
        tactics = sorted({TACTICS.get(m.split(".")[0], "") for a in c for m in a["mitre"]} - {""})
        combined = 1.0
        for a in c:
            combined *= (1 - a["score"])
        risk = 1 - combined
        if len(tactics) >= 3:
            risk = max(risk, 0.9)
        out.append({"host": c[0]["host"], "start": c[0]["time"], "end": c[-1]["time"], "alerts": len(c),
                    "tactics": tactics, "risk": round(risk, 4), "alert_ids": [a["alert_id"] for a in c]})
    out.sort(key=lambda x: (-len(x["tactics"]), -x["risk"]))
    return out


# ----------------------------------------------------------------------------
# High-level run
# ----------------------------------------------------------------------------

def run_hunt(inputs: List[str], state_dir: str, out_dir: str, extra_rules: Iterable[str] = (),
             learn: bool = True, operator: str = "", case_id: str = "", llm=None, llm_top: int = 5,
             anomaly_threshold: float = 0.85, progress=None) -> Dict[str, Any]:
    ruleset, errors = RuleSet.load(extra_rules)
    model_path = os.path.join(state_dir, "model.json")
    digest_before = ThreatModel.digest(model_path)
    model = ThreatModel.load(model_path)

    started_utc, started_ist = now_pair()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(3).hex()
    run_dir = os.path.join(out_dir, run_id)
    os.makedirs(run_dir, exist_ok=True)

    manifest: Dict[str, Any] = {
        "run_id": run_id, "case_id": case_id, "operator": operator,
        "started_utc": started_utc, "started_ist": started_ist,
        "environment": environment(), "tool_digest": tool_source_digest(),
        "inputs": [{"path": os.path.abspath(p), "size": os.path.getsize(p), "sha256": sha256_file(p)} for p in inputs],
        "rules_loaded": len(ruleset.rules), "rule_errors": errors,
        "ruleset_digest": ruleset_digest([r.path for r in ruleset.rules]),
        "model_digest_before": digest_before, "learning_enabled": learn,
    }

    hunter = Hunter(ruleset, model, HuntConfig(learn=learn, anomaly_threshold=anomaly_threshold))
    ledger = EvidenceLedger(os.path.join(run_dir, "alerts.jsonl"))
    alerts: List[Dict[str, Any]] = []
    t0 = time.perf_counter()
    for path in inputs:
        for ev in read_events(path):
            a = hunter.process(ev)
            if a is not None:
                alerts.append(a)
            if progress and hunter.stats.events % 50000 == 0:
                progress(hunter.stats)
    hunter.finish()
    hunter.stats.seconds = time.perf_counter() - t0

    alerts.sort(key=lambda a: -a["score"])
    if llm is not None:
        for a in alerts[:llm_top]:
            try:
                a["narrative"] = llm.narrate(a)
                a["narrative_model"] = llm.model
            except Exception as exc:  # noqa: BLE001
                a["narrative_error"] = str(exc)[:200]
    for a in alerts:
        ledger.append(a)
    ledger.close()

    if learn:
        manifest["model_digest_after"] = model.save(model_path)
    chains = correlate(alerts)
    fin_utc, fin_ist = now_pair()
    st = hunter.stats
    manifest.update({
        "finished_utc": fin_utc, "finished_ist": fin_ist, "events_processed": st.events,
        "alerts": len(alerts), "ledger_head": ledger.head,
    })
    summary = {
        "run_id": run_id, "run_dir": run_dir, "events": st.events, "process_events": st.process_events,
        "alerts": len(alerts), "rule_alerts": len(alerts) - st.anomaly_alerts, "anomaly_alerts": st.anomaly_alerts,
        "suppressed_by_learning": st.suppressed, "by_rule": st.by_rule, "seconds": round(st.seconds, 3),
        "events_per_second": round(st.eps), "model_warmed": model.warmed, "chains": chains,
        "rule_errors": errors,
    }
    with open(os.path.join(run_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    with open(os.path.join(run_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    write_certificate_annex(run_dir, manifest)
    from .report import write_report
    write_report(run_dir, summary, alerts)
    return summary


def run_baseline(inputs: List[str], state_dir: str, extra_rules: Iterable[str] = ()) -> Dict[str, Any]:
    ruleset, _ = RuleSet.load(extra_rules)
    model_path = os.path.join(state_dir, "model.json")
    model = ThreatModel.load(model_path)
    hunter = Hunter(ruleset, model, baseline=True)
    t0 = time.perf_counter()
    for path in inputs:
        for ev in read_events(path):
            hunter.process(ev)
    hunter.finish()
    digest = model.save(model_path)
    return {"events": hunter.stats.events, "process_events": hunter.stats.process_events,
            "seconds": round(time.perf_counter() - t0, 3), "model_warmed": model.warmed,
            "model_sha256": digest}


def find_alert(out_dir: str, alert_id: str) -> Optional[Dict[str, Any]]:
    if not os.path.isdir(out_dir):
        return None
    for run in sorted(os.listdir(out_dir), reverse=True):
        p = os.path.join(out_dir, run, "alerts.jsonl")
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                if alert_id in line:
                    rec = json.loads(line)["record"]
                    if rec["alert_id"] == alert_id:
                        rec["_run"] = run
                        return rec
    return None


def apply_feedback(state_dir: str, out_dir: str, alert_id: str, verdict: str, analyst: str = "",
                   note: str = "") -> Dict[str, Any]:
    alert = find_alert(out_dir, alert_id)
    if alert is None:
        raise KeyError(f"alert {alert_id} not found under {out_dir}")
    label = 1 if verdict.lower() in ("tp", "true", "malicious", "1") else 0
    model_path = os.path.join(state_dir, "model.json")
    model = ThreatModel.load(model_path)
    before = model.fusion.predict(alert["features"])
    model.fusion.feedback(alert["features"], label, alert["rules"], alert["signatures"])
    after = model.fusion.predict(alert["features"])
    model.save(model_path)
    fb = EvidenceLedger(os.path.join(state_dir, "feedback.jsonl"))
    t_utc, _ = now_pair()
    fb.append({"time": t_utc, "alert_id": alert_id, "run": alert["_run"], "label": "tp" if label else "fp",
               "analyst": analyst, "note": note, "score_before": round(before, 4), "score_after": round(after, 4)})
    fb.close()
    return {"alert_id": alert_id, "label": "tp" if label else "fp", "score_before": round(before, 4),
            "score_after": round(after, 4),
            "signature_suppressed": [s for s in alert["signatures"] if model.fusion.signature_suppressed(s)]}
