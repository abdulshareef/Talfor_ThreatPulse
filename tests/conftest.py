import json
import os

import pytest

from threatpulse import simulate
from threatpulse.events import normalise
from threatpulse.hunt import run_baseline, run_hunt


def ev(**kw):
    kw.setdefault("Channel", "Microsoft-Windows-Sysmon/Operational")
    kw.setdefault("UtcTime", "2026-10-01 05:00:00.000")
    return normalise(kw)


@pytest.fixture(scope="session")
def demo(tmp_path_factory):
    base = tmp_path_factory.mktemp("demo")
    files = simulate.generate(str(base / "data"))
    state, runs = str(base / "state"), str(base / "runs")
    run_baseline([files["baseline"]], state)
    summary = run_hunt([files["hunt"]], state, runs, operator="pytest", case_id="TEST-1")
    alerts = [json.loads(l)["record"] for l in open(os.path.join(summary["run_dir"], "alerts.jsonl"))]
    truth = json.load(open(files["truth"]))
    return {"files": files, "state": state, "runs": runs, "summary": summary, "alerts": alerts, "truth": truth}
