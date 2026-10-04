"""Minimal FastAPI dashboard: browse runs, open reports, label alerts TP/FP.

Binds to 127.0.0.1 by default. It has no authentication — do not expose it
on a network without putting it behind an authenticating reverse proxy.
"""
from __future__ import annotations

import html
import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

from .. import TOOL_NAME, __version__
from ..hunt import apply_feedback

PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse Dashboard</title><style>
:root{--navy:#06315C;--lime:#CFE63A;--bg:#f5f7fa;--card:#fff;--ink:#14202e;--mute:#5b6b7c;--line:#dde3ea}
@media (prefers-color-scheme:dark){:root{--bg:#0b1724;--card:#12233a;--ink:#e6edf5;--mute:#9db0c4;--line:#22384f}}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Calibri,Segoe UI,system-ui,sans-serif}
header{background:var(--navy);color:#fff;padding:14px 16px;border-bottom:4px solid var(--lime)}
main{max-width:1000px;margin:auto;padding:16px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0}
button{border:0;border-radius:6px;padding:6px 12px;margin-right:6px;cursor:pointer}.tp{background:#b3261e;color:#fff}.fp{background:var(--lime)}
code{font-family:"Courier New",monospace;font-size:12px;word-break:break-all}.mute{color:var(--mute)}select{padding:6px}
</style></head><body><header><b>%TITLE%</b></header><main>
<p><select id="run"></select> <a id="rep" target="_blank">open full report</a></p><div id="list"></div></main>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function runs(){const r=await (await fetch('api/runs')).json();$('#run').innerHTML=r.map(x=>`<option>${esc(x)}</option>`).join('');if(r.length)load(r[0]);}
async function load(run){$('#rep').href='runs/'+encodeURIComponent(run)+'/report';
 const a=await (await fetch('api/runs/'+encodeURIComponent(run)+'/alerts')).json();
 $('#list').innerHTML=a.map(x=>`<div class=card><b>${esc(x.priority)} ${x.score.toFixed(2)}</b> ${esc(x.titles.join(' / '))}
 <div class=mute>${esc(x.time)} · ${esc(x.host)} · ${esc(x.rules.join(' '))}</div><code>${esc(x.command_line||x.image)}</code>
 <div style="margin-top:6px"><button class=tp onclick="fb('${x.alert_id}','tp',this)">True positive</button>
 <button class=fp onclick="fb('${x.alert_id}','fp',this)">False positive</button><span class=mute></span></div></div>`).join('')||'<p class=mute>No alerts.</p>';}
async function fb(id,v,btn){const r=await fetch('api/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_id:id,verdict:v})});
 const j=await r.json();btn.parentElement.querySelector('span').textContent=r.ok?` learned: ${j.score_before} → ${j.score_after}`:' error';}
$('#run').onchange=e=>load(e.target.value);runs();
</script></body></html>"""


class Feedback(BaseModel):
    alert_id: str
    verdict: str
    analyst: str = ""
    note: str = ""


def create_app(state_dir: str, out_dir: str) -> FastAPI:
    app = FastAPI(title=TOOL_NAME, version=__version__)

    def _run_dir(run: str) -> str:
        if os.sep in run or "/" in run or ".." in run:
            raise HTTPException(400, "bad run id")
        d = os.path.join(out_dir, run)
        if not os.path.isdir(d):
            raise HTTPException(404, "run not found")
        return d

    @app.get("/", response_class=HTMLResponse)
    def index():
        return PAGE.replace("%TITLE%", html.escape(f"{TOOL_NAME} v{__version__}"))

    @app.get("/api/runs")
    def runs():
        if not os.path.isdir(out_dir):
            return []
        return sorted((d for d in os.listdir(out_dir) if os.path.isdir(os.path.join(out_dir, d))), reverse=True)

    @app.get("/api/runs/{run}/alerts")
    def alerts(run: str):
        p = os.path.join(_run_dir(run), "alerts.jsonl")
        out = []
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)["record"]
                rec.pop("event", None)
                out.append(rec)
        return JSONResponse(out)

    @app.get("/runs/{run}/report")
    def report(run: str):
        return FileResponse(os.path.join(_run_dir(run), "report.html"))

    @app.post("/api/feedback")
    def feedback(fb: Feedback):
        if fb.verdict not in ("tp", "fp"):
            raise HTTPException(400, "verdict must be tp or fp")
        try:
            return apply_feedback(state_dir, out_dir, fb.alert_id, fb.verdict, fb.analyst, fb.note)
        except KeyError as exc:
            raise HTTPException(404, str(exc))

    return app
