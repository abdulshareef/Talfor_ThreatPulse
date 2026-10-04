import random

from threatpulse import analytics
from threatpulse.learn import FusionModel, HalfSpaceTrees, RarityModel


def test_hst_flags_outlier():
    rng = random.Random(1)
    m = HalfSpaceTrees(n_features=3, window_size=200)
    for _ in range(1500):
        m.learn([rng.gauss(0.3, 0.03), rng.gauss(0.6, 0.03), 0.0])
    normal = m.score([0.3, 0.6, 0.0])
    outlier = m.score([0.95, 0.05, 1.0])
    assert outlier > 0.95 > normal


def test_hst_roundtrip():
    m = HalfSpaceTrees(n_features=2, window_size=50)
    for i in range(300):
        m.learn([i % 7 / 7, 0.5])
    m2 = HalfSpaceTrees.restore(m.export())
    assert abs(m.score([0.1, 0.5]) - m2.score([0.1, 0.5])) < 1e-9


def test_rarity():
    r = RarityModel(min_total=10)
    assert r.score("a") == 0.0  # not ready
    for _ in range(50):
        r.learn("common")
    assert r.score("never") == 1.0 and r.score("common") < 0.1


def test_fusion_feedback_learns_and_suppresses():
    f = FusionModel()
    feats = {"rule_severity": 0.55, "rule_count": 0.33, "rule_reliability": 0.5}
    p0 = f.predict(feats)
    sig = "TP-H06||onedrive.exe|"
    for _ in range(3):
        f.feedback(feats, 0, ["TP-H06"], [sig])
    assert f.predict(feats) < p0
    assert f.signature_suppressed(sig)
    assert f.rule_reliability("TP-H06") < 0.5
    f.feedback(feats, 1, ["TP-H06"], [sig])
    assert not f.signature_suppressed(sig)  # a confirmed TP lifts suppression


def test_fusion_ranks_rule_plus_anomaly_above_rule_alone():
    f = FusionModel()
    base = {"rule_severity": 0.8, "rule_count": 0.33, "rule_reliability": 0.5}
    assert f.predict({**base, "pair_rarity": 1, "user_path": 1}) > f.predict(base)


def test_beacon_detects_periodic_not_random():
    rng = random.Random(3)
    b = analytics.build("beacon", {"min_connections": 10, "max_cv": 0.15})
    t, fired = 0.0, None
    for _ in range(15):
        t += 60 + rng.uniform(-1, 1)
        fired = fired or b.process({"tp_host": "h", "tp_image": "x.exe", "DestinationIp": "1.2.3.4", "tp_ts": t})
    assert fired and fired["jitter_cv"] < 0.05
    b2 = analytics.build("beacon", {"min_connections": 10, "max_cv": 0.15})
    t, fired = 0.0, None
    for _ in range(40):
        t += rng.expovariate(1 / 60)
        fired = fired or b2.process({"tp_host": "h", "tp_image": "x.exe", "DestinationIp": "1.2.3.4", "tp_ts": t})
    assert fired is None


def test_dns_tunnel_and_parent_domain():
    assert analytics.parent_domain("a.b.example.co.in") == "example.co.in"
    d = analytics.build("dns_tunnel", {"suspicious_queries": 5})
    rng = random.Random(2)
    out = None
    for i in range(10):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(40))
        out = out or d.process({"tp_host": "h", "QueryName": f"{label}.evil.xyz", "tp_ts": float(i)})
    assert out and out["parent_domain"] == "evil.xyz"
    assert d.process({"tp_host": "h", "QueryName": "www.microsoft.com", "tp_ts": 1.0}) is None


def test_first_seen_needs_baseline():
    fs = analytics.build("first_seen", {"fields": ["u", "h"], "min_baseline": 3})
    for u in "abc":
        assert fs.process({"u": u, "h": "srv"}) is None
    assert fs.process({"u": "a", "h": "srv"}) is None
    assert fs.process({"u": "z", "h": "srv"})["new_pair"] == "z|srv"
