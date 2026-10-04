"""Command-line interface: ``threatpulse <command>``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from . import TOOL_NAME, __author__, __version__

DEFAULT_STATE = os.environ.get("THREATPULSE_STATE", ".threatpulse")
DEFAULT_OUT = os.environ.get("THREATPULSE_RUNS", "threatpulse_runs")

BANNER = f"{TOOL_NAME} v{__version__} — {__author__} (TALFOR)"


def _expand(paths: List[str]) -> List[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                out += [os.path.join(root, f) for f in sorted(files)
                        if f.lower().endswith((".jsonl", ".json", ".ndjson", ".csv", ".evtx"))]
        else:
            out.append(p)
    return out


def _print_summary(s, top_alerts=None):
    print(f"\n  events      {s['events']:,}  ({s['events_per_second']:,} events/s, {s['seconds']}s)")
    print(f"  alerts      {s['alerts']}  (rules {s['rule_alerts']}, learned anomalies {s['anomaly_alerts']}, "
          f"suppressed by feedback {s['suppressed_by_learning']})")
    if not s["model_warmed"]:
        print("  note        learning model not warmed yet — run `threatpulse baseline` on clean data first")
    if s.get("rule_errors"):
        print(f"  rule errors {len(s['rule_errors'])} (see summary.json)")
    if s["chains"]:
        print("\n  attack chains")
        for c in s["chains"][:5]:
            print(f"   - {c['host']:<22} risk {c['risk']:.2f}  {c['alerts']:>3} alerts  {', '.join(c['tactics'])}")
    if top_alerts:
        print("\n  top alerts")
        for a in top_alerts:
            print(f"   [{a['priority']:<8} {a['score']:.2f}] {a['alert_id']}  {a['host']:<20} {' / '.join(a['titles'])[:70]}")
    print(f"\n  report      {os.path.join(s['run_dir'], 'report.html')}")
    print(f"  evidence    {os.path.join(s['run_dir'], 'alerts.jsonl')} (hash-chained) + certificate_annex.md\n")


def cmd_hunt(a):
    from .hunt import run_hunt
    from .llm import get_client
    inputs = _expand(a.inputs)
    if not inputs:
        sys.exit("no input files")
    llm = get_client(a.llm, a.llm_url, a.llm_model)
    if llm is not None and not llm.available():
        print(f"  warning: Ollama not reachable at {llm.url}; continuing without narratives", file=sys.stderr)
        llm = None
    print(BANNER)
    s = run_hunt(inputs, a.state, a.out, extra_rules=a.rules or [], learn=not a.no_learn,
                 operator=a.operator, case_id=a.case, llm=llm, llm_top=a.llm_top,
                 anomaly_threshold=a.anomaly_threshold)
    alerts = []
    with open(os.path.join(s["run_dir"], "alerts.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            alerts.append(json.loads(line)["record"])
            if len(alerts) >= a.top:
                break
    if a.json:
        print(json.dumps(s, indent=2))
    else:
        _print_summary(s, alerts)


def cmd_baseline(a):
    from .hunt import run_baseline
    print(BANNER)
    r = run_baseline(_expand(a.inputs), a.state, extra_rules=a.rules or [])
    print(f"  learned from {r['events']:,} events ({r['process_events']:,} process) in {r['seconds']}s")
    print(f"  model warmed: {r['model_warmed']}   sha256: {r['model_sha256']}")


def cmd_feedback(a):
    from .hunt import apply_feedback
    r = apply_feedback(a.state, a.out, a.alert_id, a.verdict, analyst=a.analyst, note=a.note)
    print(f"  {r['alert_id']} labelled {r['label'].upper()} — score {r['score_before']:.3f} -> {r['score_after']:.3f}")
    for s in r["signature_suppressed"]:
        print(f"  signature now auto-suppressed: {s}")


def cmd_rules(a):
    from .rules import RuleSet
    from .rules.engine import load_rules_from_path
    if a.action == "validate":
        rules, errors = load_rules_from_path(a.path, include_drafts=True)
        print(f"  {len(rules)} rules compiled, {len(errors)} errors")
        for f, e in errors:
            print(f"   ! {f}: {e}")
        sys.exit(1 if errors else 0)
    rs, errors = RuleSet.load(a.rules or [])
    for r in rs.rules:
        print(f"  {r.id:<10} {r.severity:<9} {r.type:<8} {','.join(r.mitre):<28} {r.title}")
    print(f"\n  {len(rs.rules)} rules loaded" + (f", {len(errors)} skipped" if errors else ""))


def cmd_verify(a):
    from .evidence import verify_ledger
    from .events import sha256_file
    run_dir = a.run if os.path.isdir(a.run) else os.path.join(a.out, a.run)
    manifest = json.load(open(os.path.join(run_dir, "manifest.json"), encoding="utf-8"))
    ok, n, head, msg = verify_ledger(os.path.join(run_dir, "alerts.jsonl"), manifest.get("ledger_head"))
    print(f"  ledger   {'OK ' if ok else 'FAIL'}  {n} entries  head {head[:16]}…  {msg}")
    all_ok = ok
    for inp in manifest["inputs"]:
        if os.path.exists(inp["path"]):
            same = sha256_file(inp["path"]) == inp["sha256"]
            all_ok &= same
            print(f"  input    {'OK ' if same else 'FAIL'}  {os.path.basename(inp['path'])}")
        else:
            print(f"  input    n/a   {os.path.basename(inp['path'])} (not present to re-hash)")
    sys.exit(0 if all_ok else 2)


def cmd_llm(a):
    from .llm import DEFAULT_MODEL, DEFAULT_URL, OllamaClient
    client = OllamaClient(a.llm_url or DEFAULT_URL, a.llm_model or DEFAULT_MODEL)
    if not client.available():
        sys.exit(f"Ollama not reachable at {client.url} — install from https://ollama.com and `ollama pull {client.model}`")
    intel = open(a.intel, encoding="utf-8").read() if os.path.exists(a.intel) else a.intel
    drafts = a.drafts or os.path.join(os.path.dirname(__file__), "rules", "drafts")
    r = client.draft_rule(intel, drafts)
    print(f"  draft rule {r['id']} written to {r['path']}")
    print("  review it, set `status: stable`, then move it into your rules directory to enable it.")


def cmd_demo(a):
    from . import simulate
    from .hunt import run_baseline, run_hunt
    base = a.dir
    print(BANNER)
    print("  generating synthetic Windows telemetry with an embedded intrusion…")
    f = simulate.generate(os.path.join(base, "data"))
    state, runs = os.path.join(base, "state"), os.path.join(base, "runs")
    b = run_baseline([f["baseline"]], state)
    print(f"  baseline: learned {b['events']:,} clean events in {b['seconds']}s")
    s = run_hunt([f["hunt"]], state, runs, operator="demo")
    alerts = [json.loads(l)["record"] for l in open(os.path.join(s["run_dir"], "alerts.jsonl"), encoding="utf-8")]
    ev = simulate.evaluate(alerts, json.load(open(f["truth"])))
    _print_summary(s, alerts[:8])
    print("  ground truth")
    for scn in ev["scenarios"]:
        hit = ev["detected"].get(scn) or []
        print(f"   {'✔' if hit else '✘'} {scn:<8} {', '.join(hit)}")
    print(f"   benign alerts (false positives): {ev['false_positives']} {ev['false_positive_rules']}")
    if ev["fp_alerts"]:
        print("\n  teach it: mark a false positive, e.g.")
        print(f"   threatpulse feedback {ev['fp_alerts'][0]['alert_id']} fp --state {state} --out {runs}")


def cmd_serve(a):
    try:
        import uvicorn
        from .dashboard.app import create_app
    except ImportError:
        sys.exit("dashboard needs: pip install 'talfor-threatpulse[dashboard]'")
    print(BANNER)
    print(f"  dashboard on http://{a.host}:{a.port}")
    uvicorn.run(create_app(a.state, a.out), host=a.host, port=a.port, log_level="warning")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threatpulse", description=BANNER)
    p.add_argument("--version", action="version", version=BANNER)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--state", default=DEFAULT_STATE, help="model/state directory (default: .threatpulse)")
        sp.add_argument("--out", default=DEFAULT_OUT, help="runs directory (default: threatpulse_runs)")

    h = sub.add_parser("hunt", help="hunt through log files")
    h.add_argument("inputs", nargs="+", help="files or directories (.jsonl/.json/.csv/.evtx)")
    common(h)
    h.add_argument("--rules", action="append", help="extra rule dir/file (native or Sigma); repeatable")
    h.add_argument("--no-learn", action="store_true", help="do not update the model during this hunt")
    h.add_argument("--operator", default="", help="examiner name for the evidence manifest")
    h.add_argument("--case", default="", help="case / reference number")
    h.add_argument("--top", type=int, default=10)
    h.add_argument("--anomaly-threshold", type=float, default=0.85)
    h.add_argument("--llm", action="store_true", help="add local-LLM narratives (Ollama)")
    h.add_argument("--llm-top", type=int, default=5)
    h.add_argument("--llm-url")
    h.add_argument("--llm-model")
    h.add_argument("--json", action="store_true")
    h.set_defaults(fn=cmd_hunt)

    b = sub.add_parser("baseline", help="learn normal behaviour from clean logs (no alerts)")
    b.add_argument("inputs", nargs="+")
    common(b)
    b.add_argument("--rules", action="append")
    b.set_defaults(fn=cmd_baseline)

    f = sub.add_parser("feedback", help="label an alert true/false positive so the model learns")
    f.add_argument("alert_id")
    f.add_argument("verdict", choices=["tp", "fp"])
    common(f)
    f.add_argument("--analyst", default="")
    f.add_argument("--note", default="")
    f.set_defaults(fn=cmd_feedback)

    r = sub.add_parser("rules", help="list or validate rules")
    r.add_argument("action", choices=["list", "validate"])
    r.add_argument("path", nargs="?", default=os.path.join(os.path.dirname(__file__), "rules", "builtin"))
    r.add_argument("--rules", action="append")
    r.set_defaults(fn=cmd_rules)

    v = sub.add_parser("verify", help="verify evidence ledger and input hashes of a run")
    v.add_argument("run", help="run directory or run id")
    common(v)
    v.set_defaults(fn=cmd_verify)

    l = sub.add_parser("hypothesize", help="draft a new hypothesis rule from threat intel (local LLM)")
    l.add_argument("intel", help="text or path to a file containing threat-intel")
    l.add_argument("--drafts")
    l.add_argument("--llm-url")
    l.add_argument("--llm-model")
    l.set_defaults(fn=cmd_llm)

    d = sub.add_parser("demo", help="generate synthetic data, learn a baseline, hunt, and score against ground truth")
    d.add_argument("--dir", default="threatpulse_demo")
    d.set_defaults(fn=cmd_demo)

    s = sub.add_parser("serve", help="web dashboard with one-click TP/FP feedback")
    common(s)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8046)
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
