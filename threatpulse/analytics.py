"""Stateful analytics used by ``type: analytic`` rules.

Each analytic keeps small per-key state, so it streams in constant memory per
entity. State is JSON-serialisable and persisted with the model, so baselines
(e.g. first-seen logon pairs) survive between hunts.
"""
from __future__ import annotations

import math
from collections import Counter, deque
from statistics import mean, pstdev
from typing import Any, Dict, Optional

from .events import Event, basename


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_SLD = {"co", "com", "net", "org", "gov", "ac", "edu", "nic", "res", "gen", "firm", "ind"}


def parent_domain(q: str) -> str:
    labels = [x for x in q.lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class Analytic:
    name = "base"

    def __init__(self, params: Dict[str, Any]):
        self.params = params
        self.state: Dict[str, Any] = {}

    def process(self, ev: Event) -> Optional[Dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    def export(self) -> Dict[str, Any]:
        return {}

    def restore(self, data: Dict[str, Any]) -> None:
        pass


class Beacon(Analytic):
    """Low-jitter periodic outbound connections per (host, image, dest, port)."""

    name = "beacon"

    def __init__(self, params):
        super().__init__(params)
        self.min_conn = int(params.get("min_connections", 10))
        self.max_cv = float(params.get("max_cv", 0.15))
        self.min_iv = float(params.get("min_interval", 5))
        self.max_iv = float(params.get("max_interval", 3600))
        self.exclude = {x.lower() for x in params.get("exclude_images", [])}
        self.series: Dict[str, deque] = {}
        self.fired: set = set()

    def process(self, ev):
        if ev.get("tp_image") in self.exclude:
            return None
        dest = ev.get("DestinationIp") or ev.get("DestinationHostname") or ""
        key = f"{ev.get('tp_host')}|{ev.get('tp_image')}|{dest}|{ev.get('DestinationPort', '')}"
        if key in self.fired:
            return None
        dq = self.series.get(key)
        if dq is None:
            dq = self.series[key] = deque(maxlen=max(self.min_conn * 2, 32))
        dq.append(float(ev.get("tp_ts", 0.0)))
        if len(dq) < self.min_conn:
            return None
        ts = sorted(dq)[-self.min_conn:]
        ivs = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
        if len(ivs) < self.min_conn - 2:
            return None
        mu = mean(ivs)
        if not (self.min_iv <= mu <= self.max_iv):
            return None
        cv = pstdev(ivs) / mu if mu else 1.0
        if cv <= self.max_cv:
            self.fired.add(key)
            return {"destination": dest, "port": ev.get("DestinationPort"), "connections": len(dq),
                    "mean_interval_s": round(mu, 2), "jitter_cv": round(cv, 4),
                    "beacon_score": round(max(0.0, 1 - cv / self.max_cv), 3)}
        return None


class Burst(Analytic):
    """Too many events per key in a sliding window."""

    name = "burst"

    def __init__(self, params):
        super().__init__(params)
        self.fields = params.get("key_fields", ["Computer", "Image"])
        self.window = float(params.get("window", 60))
        self.threshold = int(params.get("threshold", 300))
        self.exclude = {x.lower() for x in params.get("exclude_images", [])}
        self.buckets: Dict[str, deque] = {}
        self.last_fire: Dict[str, float] = {}

    def process(self, ev):
        if ev.get("tp_image") in self.exclude:
            return None
        key = "|".join(str(ev.get(f, "")).lower() for f in self.fields)
        t = float(ev.get("tp_ts", 0.0))
        dq = self.buckets.setdefault(key, deque())
        dq.append(t)
        while dq and t - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold and t - self.last_fire.get(key, -1e18) > self.window:
            self.last_fire[key] = t
            return {"events_in_window": len(dq), "window_s": self.window}
        return None


class FirstSeen(Analytic):
    """Fires when a key combination appears that was never observed before.

    Learns continuously; only fires after ``min_baseline`` distinct keys exist.
    """

    name = "first_seen"

    def __init__(self, params):
        super().__init__(params)
        self.fields = params.get("fields", [])
        self.min_baseline = int(params.get("min_baseline", 50))
        self.seen: set = set()
        self.learn_only = False

    def process(self, ev):
        key = "|".join(str(ev.get(f, "")).lower() for f in self.fields)
        if key in self.seen:
            return None
        ready = len(self.seen) >= self.min_baseline and not self.learn_only
        self.seen.add(key)
        if ready:
            return {"new_pair": key, "baseline_size": len(self.seen) - 1}
        return None

    def export(self):
        return {"seen": sorted(self.seen)}

    def restore(self, data):
        self.seen = set(data.get("seen", []))


class DnsTunnel(Analytic):
    name = "dns_tunnel"

    def __init__(self, params):
        super().__init__(params)
        self.window = float(params.get("window", 300))
        self.min_len = int(params.get("min_label_len", 24))
        self.min_ent = float(params.get("min_entropy", 3.5))
        self.sus_thr = int(params.get("suspicious_queries", 8))
        self.uniq_thr = int(params.get("unique_subdomains", 80))
        self.allow = {d.lower() for d in params.get("allow_domains", [])}
        self.buckets: Dict[str, deque] = {}
        self.last_fire: Dict[str, float] = {}

    def process(self, ev):
        q = str(ev.get("QueryName", "")).lower().strip(".")
        if not q or "." not in q:
            return None
        parent = parent_domain(q)
        if parent in self.allow:
            return None
        sub = q[: -len(parent)].strip(".") if q.endswith(parent) else ""
        if not sub:
            return None
        longest = max(sub.split("."), key=len)
        ent = shannon_entropy(longest)
        suspicious = len(longest) >= self.min_len and ent >= self.min_ent
        key = f"{ev.get('tp_host')}|{parent}"
        t = float(ev.get("tp_ts", 0.0))
        dq = self.buckets.setdefault(key, deque())
        dq.append((t, sub, suspicious))
        while dq and t - dq[0][0] > self.window:
            dq.popleft()
        n_sus = sum(1 for _, _, s in dq if s)
        n_uniq = len({s for _, s, _ in dq})
        if (n_sus >= self.sus_thr or n_uniq >= self.uniq_thr) and t - self.last_fire.get(key, -1e18) > self.window:
            self.last_fire[key] = t
            return {"parent_domain": parent, "suspicious_queries": n_sus, "unique_subdomains": n_uniq,
                    "sample_label_entropy": round(ent, 3), "sample_query": q[:120]}
        return None


ANALYTICS = {c.name: c for c in (Beacon, Burst, FirstSeen, DnsTunnel)}


def build(name: str, params: Dict[str, Any]) -> Analytic:
    if name not in ANALYTICS:
        raise ValueError(f"unknown analytic '{name}'")
    return ANALYTICS[name](params)


__all__ = ["build", "shannon_entropy", "parent_domain", "basename", "Analytic"]
