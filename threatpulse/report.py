"""Self-contained HTML hunt report (works offline, phone-friendly)."""
from __future__ import annotations

import html
import json
import os
from typing import Any, Dict, List

from . import TOOL_NAME, __author__, __version__

_CSS = """
:root{--navy:#06315C;--lime:#CFE63A;--bg:#f5f7fa;--card:#fff;--ink:#14202e;--mute:#5b6b7c;--line:#dde3ea}
@media (prefers-color-scheme:dark){:root{--bg:#0b1724;--card:#12233a;--ink:#e6edf5;--mute:#9db0c4;--line:#22384f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Calibri,Segoe UI,system-ui,sans-serif}
header{background:var(--navy);color:#fff;padding:18px 16px;border-bottom:4px solid var(--lime)}
header h1{margin:0;font-size:20px}header p{margin:4px 0 0;color:#c9d6e3;font-size:13px}
main{max-width:1100px;margin:0 auto;padding:16px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.kpi b{display:block;font-size:22px}.kpi span{color:var(--mute);font-size:12px}
h2{font-size:16px;margin:22px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:10px}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;margin:2px 4px 2px 0;background:var(--line)}
.critical{background:#b3261e;color:#fff}.high{background:#e8710a;color:#fff}.medium{background:#f2c94c;color:#222}.low{background:#9aa5b1;color:#fff}
.anomaly{background:var(--lime);color:#222}
code,pre{font-family:"Courier New",monospace;font-size:12px}pre{white-space:pre-wrap;word-break:break-all;margin:6px 0 0;color:var(--mute)}
.row{display:flex;flex-wrap:wrap;gap:6px;align-items:center}.mute{color:var(--mute)}
footer{color:var(--mute);font-size:12px;text-align:center;padding:24px 16px}
"""


def _e(x: Any) -> str:
    return html.escape(str(x if x is not None else ""))


def write_report(run_dir: str, summary: Dict[str, Any], alerts: List[Dict[str, Any]], limit: int = 500) -> str:
    chains_html = "".join(
        f"<div class='card'><div class='row'><b>{_e(c['host'])}</b>"
        f"<span class='tag {('critical' if c['risk'] >= .85 else 'high' if c['risk'] >= .6 else 'medium')}'>risk {c['risk']:.2f}</span>"
        f"<span class='mute'>{_e(c['start'])} → {_e(c['end'])} · {c['alerts']} alerts</span></div>"
        f"<div>{''.join(f'<span class=tag>{_e(t)}</span>' for t in c['tactics'])}</div></div>"
        for c in summary.get("chains", [])[:20]
    ) or "<p class='mute'>No chains.</p>"
    cards = []
    for a in alerts[:limit]:
        tags = "".join(f"<span class='tag'>{_e(m)}</span>" for m in a["mitre"])
        kind = "<span class='tag anomaly'>learned anomaly</span>" if a["kind"] == "anomaly" else ""
        why = ", ".join(_e(w) for w in a.get("why", []))
        det = f"<pre>{_e(json.dumps(a['details']))}</pre>" if a.get("details") else ""
        narr = f"<p><i>{_e(a['narrative'])}</i></p>" if a.get("narrative") else ""
        cards.append(
            f"<div class='card'><div class='row'><span class='tag {a['priority']}'>{a['priority']} {a['score']:.2f}</span>{kind}"
            f"<b>{_e(' / '.join(a['titles']))}</b></div>"
            f"<div class='mute'>{_e(a['time'])} · {_e(a['host'])} · {_e(a['user'])} · <code>{_e(' '.join(a['rules']))}</code> · id <code>{_e(a['alert_id'])}</code></div>"
            f"<div>{tags}</div>"
            f"<pre>{_e(a.get('parent'))} → {_e(a.get('image'))}\n{_e(a.get('command_line'))}</pre>{det}"
            f"<div class='mute'>why: {why}</div>{narr}</div>"
        )
    s = summary
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ThreatPulse Hunt Report</title><style>{_CSS}</style></head>
<body><header><h1>{TOOL_NAME} — Hunt Report</h1><p>Run {_e(s['run_id'])} · v{__version__} · {__author__}</p></header><main>
<div class="kpis">
<div class="kpi"><b>{s['events']:,}</b><span>events</span></div>
<div class="kpi"><b>{s['alerts']}</b><span>alerts</span></div>
<div class="kpi"><b>{s['rule_alerts']}</b><span>rule alerts</span></div>
<div class="kpi"><b>{s['anomaly_alerts']}</b><span>learned anomalies</span></div>
<div class="kpi"><b>{s['suppressed_by_learning']}</b><span>suppressed by feedback</span></div>
<div class="kpi"><b>{s['events_per_second']:,}</b><span>events / sec</span></div>
</div>
<h2>Attack chains</h2>{chains_html}
<h2>Alerts (ranked by fused score)</h2>{''.join(cards) or "<p class='mute'>No alerts.</p>"}
</main><footer>Scores are investigative leads for human review, not findings of fact. Ledger integrity: <code>threatpulse verify</code>.</footer></body></html>"""
    path = os.path.join(run_dir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
