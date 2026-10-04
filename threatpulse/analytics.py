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
        self.web_ports = {str(p) for p in params.get("web_ports", [80, 443, 8080, 8443])}
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
            port = str(ev.get("DestinationPort", ""))
            # Periodicity says "C2-like", not which protocol or whether it is encrypted.
            # Only claim the Web-protocols sub-technique when the port supports it.
            mitre = ["T1071.001"] if port in self.web_ports else ["T1071"]
            return {"destination": dest, "port": port, "connections": len(dq),
                    "mean_interval_s": round(mu, 2), "jitter_cv": round(cv, 4),
                    "beacon_score": round(max(0.0, 1 - cv / self.max_cv), 3), "mitre": mitre}
        return None


_COMMON_EXT = {"tmp", "log", "txt", "dat", "db", "etl", "pf", "dll", "exe", "json", "xml", "ini", "lnk",
               "docx", "xlsx", "pptx", "doc", "xls", "pdf", "jpg", "png", "zip", "cab", "msi", "cache", ""}


def _exts(path: str):
    name = str(path).replace("/", "\\").rsplit("\\", 1)[-1].lower()
    parts = name.split(".")
    last = parts[-1] if len(parts) > 1 else ""
    prev = parts[-2] if len(parts) > 2 else ""
    return last, prev


class Burst(Analytic):
    """Too many file writes by one process in a sliding window.

    A burst on its own is a behavioural signal, not proof of encryption. T1486 is
    attached only when encryption indicators are present: most files in the burst
    share one *uncommon* extension appended onto a normal one (``report.xlsx.lockd``).
    """

    name = "burst"

    def __init__(self, params):
        super().__init__(params)
        self.fields = params.get("key_fields", ["Computer", "Image"])
        self.window = float(params.get("window", 60))
        self.threshold = int(params.get("threshold", 300))
        self.ext_ratio = float(params.get("encryption_ext_ratio", 0.7))
        self.exclude = {x.lower() for x in params.get("exclude_images", [])}
        self.buckets: Dict[str, deque] = {}
        self.last_fire: Dict[str, float] = {}

    def process(self, ev):
        if ev.get("tp_image") in self.exclude:
            return None
        key = "|".join(str(ev.get(f, "")).lower() for f in self.fields)
        t = float(ev.get("tp_ts", 0.0))
        dq = self.buckets.setdefault(key, deque())
        dq.append((t, _exts(ev.get("TargetFilename", ""))))
        while dq and t - dq[0][0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold and t - self.last_fire.get(key, -1e18) > self.window:
            self.last_fire[key] = t
            counts = Counter(last for _, (last, _p) in dq)
            ext, n = counts.most_common(1)[0]
            ratio = n / len(dq)
            appended = sum(1 for _, (last, prev) in dq if last == ext and prev in _COMMON_EXT and prev) / len(dq)
            indicator = ratio >= self.ext_ratio and ext not in _COMMON_EXT and appended >= 0.5
            return {"events_in_window": len(dq), "window_s": self.window,
                    "dominant_extension": ext, "dominant_ratio": round(ratio, 3),
                    "encryption_indicator": indicator, "mitre": ["T1486"] if indicator else []}
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


class Dga(Analytic):
    """DGA-like resolution: one host failing to resolve many distinct, random-looking
    registrable domains in a short window (malware cycling generated domains until
    one is registered). Different from tunnelling, which uses many *subdomains*
    of a single, resolving parent domain."""

    name = "dga"

    def __init__(self, params):
        super().__init__(params)
        self.window = float(params.get("window", 600))
        self.min_len = int(params.get("min_label_len", 8))
        self.min_ent = float(params.get("min_entropy", 3.0))
        self.threshold = int(params.get("distinct_domains", 15))
        self.ok_status = {str(x) for x in params.get("success_status", ["0"])}
        self.allow = {d.lower() for d in params.get("allow_domains", [])}
        self.buckets: Dict[str, deque] = {}
        self.last_fire: Dict[str, float] = {}

    def process(self, ev):
        q = str(ev.get("QueryName", "")).lower().strip(".")
        status = str(ev.get("QueryStatus", "0")).strip()
        if not q or "." not in q or status in self.ok_status:
            return None
        dom = parent_domain(q)
        if dom in self.allow:
            return None
        label = dom.split(".")[0]
        if len(label) < self.min_len or shannon_entropy(label) < self.min_ent:
            return None
        host = ev.get("tp_host")
        t = float(ev.get("tp_ts", 0.0))
        dq = self.buckets.setdefault(host, deque())
        dq.append((t, dom))
        while dq and t - dq[0][0] > self.window:
            dq.popleft()
        distinct = {d for _, d in dq}
        if len(distinct) >= self.threshold and t - self.last_fire.get(host, -1e18) > self.window:
            self.last_fire[host] = t
            return {"failed_random_domains": len(distinct), "window_s": self.window,
                    "examples": sorted(distinct)[:5]}
        return None


ANALYTICS = {c.name: c for c in (Beacon, Burst, FirstSeen, DnsTunnel, Dga)}


def build(name: str, params: Dict[str, Any]) -> Analytic:
    if name not in ANALYTICS:
        raise ValueError(f"unknown analytic '{name}'")
    return ANALYTICS[name](params)


__all__ = ["build", "shannon_entropy", "parent_domain", "basename", "Analytic"]
