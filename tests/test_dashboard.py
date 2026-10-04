import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from threatpulse.dashboard.app import create_app  # noqa: E402


def test_dashboard(demo):
    c = TestClient(create_app(demo["state"], demo["runs"]))
    assert c.get("/").status_code == 200
    runs = c.get("/api/runs").json()
    assert runs
    alerts = c.get(f"/api/runs/{runs[-1]}/alerts").json()
    assert alerts and "event" not in alerts[0]
    assert c.get("/api/runs/..%2F..%2Fetc/alerts").status_code in (400, 404)
    r = c.post("/api/feedback", json={"alert_id": alerts[0]["alert_id"], "verdict": "tp"})
    assert r.status_code == 200 and r.json()["label"] == "tp"
    assert c.post("/api/feedback", json={"alert_id": "nope", "verdict": "maybe"}).status_code == 400
