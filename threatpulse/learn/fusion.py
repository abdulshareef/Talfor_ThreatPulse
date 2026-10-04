"""Fusion model: turns rule hits + anomaly signals into one calibrated threat score,
and learns from analyst feedback.

Two learning mechanisms work together:

1. **Online logistic regression** over a small, explainable feature vector.
   It ships with expert-set prior weights (so it is useful on day one) and is
   updated by SGD every time an analyst labels an alert true/false positive,
   with a replay buffer for stability.
2. **Bayesian rule reliability** — a Beta(TP+1, FP+1) posterior per rule and per
   alert *signature* (rule + parent + image + host). Signatures that are
   repeatedly marked false positive are auto-suppressed; rules that are mostly
   noise are down-weighted.
"""
from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Sequence, Tuple

FUSION_FEATURES = ["bias", "rule_severity", "rule_count", "rule_reliability", "hst_anomaly",
                   "pair_rarity", "image_host_rarity", "user_path", "masquerade", "url_or_b64",
                   "analytic_strength"]

# Expert priors. Interpretable: log-odds contribution of each signal.
PRIOR_WEIGHTS = {
    "bias": -4.0,
    "rule_severity": 4.5,
    "rule_count": 1.0,
    "rule_reliability": 1.2,
    "hst_anomaly": 2.0,
    "pair_rarity": 2.2,
    "image_host_rarity": 1.0,
    "user_path": 1.1,
    "masquerade": 2.6,
    "url_or_b64": 0.9,
    "analytic_strength": 1.0,
}


def _sigmoid(z: float) -> float:
    if z < -30:
        return 0.0
    if z > 30:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


class FusionModel:
    def __init__(self, lr: float = 0.15, l2: float = 0.01, replay: int = 2000):
        self.w = dict(PRIOR_WEIGHTS)
        self.lr = lr
        self.l2 = l2
        self.replay_max = replay
        self.replay: List[Tuple[List[float], int]] = []
        self.rule_stats: Dict[str, List[int]] = {}       # rule_id -> [tp, fp]
        self.sig_stats: Dict[str, List[int]] = {}        # signature -> [tp, fp]
        self.updates = 0

    # -- reliability ----------------------------------------------------------
    def rule_reliability(self, rule_id: str) -> float:
        tp, fp = self.rule_stats.get(rule_id, [0, 0])
        return (tp + 1) / (tp + fp + 2)

    def signature_suppressed(self, sig: str, min_fp: int = 3) -> bool:
        tp, fp = self.sig_stats.get(sig, [0, 0])
        return fp >= min_fp and tp == 0

    def rule_suppressed(self, rule_id: str, min_fp: int = 8, max_precision: float = 0.1) -> bool:
        tp, fp = self.rule_stats.get(rule_id, [0, 0])
        return fp >= min_fp and (tp + 1) / (tp + fp + 2) < max_precision

    # -- scoring --------------------------------------------------------------
    def vector(self, f: Dict[str, float]) -> List[float]:
        return [1.0 if k == "bias" else float(f.get(k, 0.0)) for k in FUSION_FEATURES]

    def predict(self, f: Dict[str, float]) -> float:
        x = self.vector(f)
        return _sigmoid(sum(self.w[k] * xi for k, xi in zip(FUSION_FEATURES, x)))

    def explain(self, f: Dict[str, float], top: int = 4) -> List[Tuple[str, float]]:
        x = self.vector(f)
        contrib = [(k, self.w[k] * xi) for k, xi in zip(FUSION_FEATURES, x) if k != "bias"]
        contrib.sort(key=lambda kv: -abs(kv[1]))
        return [(k, round(v, 3)) for k, v in contrib[:top] if abs(v) > 0.05]

    # -- learning -------------------------------------------------------------
    def _sgd(self, x: Sequence[float], y: int) -> None:
        p = _sigmoid(sum(self.w[k] * xi for k, xi in zip(FUSION_FEATURES, x)))
        g = p - y
        for k, xi in zip(FUSION_FEATURES, x):
            prior = PRIOR_WEIGHTS[k]
            # L2 pulls towards expert prior, not zero — feedback adapts, never erases.
            self.w[k] -= self.lr * (g * xi + self.l2 * (self.w[k] - prior))

    def feedback(self, features: Dict[str, float], label: int, rule_ids: Sequence[str],
                 signatures: Sequence[str], rng: random.Random | None = None) -> None:
        y = 1 if label else 0
        x = self.vector(features)
        for _ in range(3):
            self._sgd(x, y)
        rng = rng or random.Random(self.updates)
        if self.replay:
            for xr, yr in rng.sample(self.replay, min(32, len(self.replay))):
                self._sgd(xr, yr)
        self.replay.append((x, y))
        if len(self.replay) > self.replay_max:
            self.replay.pop(0)
        for r in rule_ids:
            s = self.rule_stats.setdefault(r, [0, 0])
            s[0 if y else 1] += 1
        for sg in signatures:
            s = self.sig_stats.setdefault(sg, [0, 0])
            s[0 if y else 1] += 1
        self.updates += 1

    # -- persistence ----------------------------------------------------------
    def export(self) -> Dict[str, Any]:
        return {"w": self.w, "replay": self.replay, "rule_stats": self.rule_stats,
                "sig_stats": self.sig_stats, "updates": self.updates}

    @classmethod
    def restore(cls, d: Dict[str, Any]) -> "FusionModel":
        m = cls()
        m.w.update(d.get("w", {}))
        m.replay = [(list(x), int(y)) for x, y in d.get("replay", [])]
        m.rule_stats = {k: list(v) for k, v in d.get("rule_stats", {}).items()}
        m.sig_stats = {k: list(v) for k, v in d.get("sig_stats", {}).items()}
        m.updates = int(d.get("updates", 0))
        return m
