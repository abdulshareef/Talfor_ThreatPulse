"""Streaming Half-Space Trees (Tan, Ting & Liu, IJCAI 2011).

Constant time and memory per event, no labels needed, and adapts to drift by
swapping the reference mass profile every ``window_size`` events. Features
must be scaled to [0, 1]. Implemented in pure Python with array-backed
complete binary trees so the model serialises cleanly to JSON (no pickle —
loading a pickled model from an untrusted source is code execution).
"""
from __future__ import annotations

import random
from bisect import bisect_left
from collections import deque
from typing import Any, Dict, List, Sequence


class HalfSpaceTrees:
    def __init__(self, n_features: int, n_trees: int = 25, height: int = 8,
                 window_size: int = 250, seed: int = 46):
        self.n_features = n_features
        self.n_trees = n_trees
        self.height = height
        self.window_size = window_size
        self.seed = seed
        self.n_nodes = 2 ** (height + 1) - 1
        rng = random.Random(seed)
        self.feat: List[List[int]] = []
        self.split: List[List[float]] = []
        for _ in range(n_trees):
            feats, splits = [], []
            lo = [0.0] * n_features
            hi = [1.0] * n_features
            self._build(rng, 0, 0, lo, hi, feats, splits)
            self.feat.append(feats)
            self.split.append(splits)
        self.r_mass = [[0] * self.n_nodes for _ in range(n_trees)]
        self.l_mass = [[0] * self.n_nodes for _ in range(n_trees)]
        self.counter = 0
        self.windows_completed = 0
        # Empirical distribution of reference masses -> calibrated percentile scores.
        self._recent: deque = deque(maxlen=4000)
        self._sorted: List[float] = []

    def _build(self, rng, idx, depth, lo, hi, feats, splits):
        # Pre-size lists lazily so idx addressing works for a complete tree.
        while len(feats) <= idx:
            feats.append(-1)
            splits.append(0.0)
        if depth == self.height:
            return
        q = rng.randrange(self.n_features)
        # Random perturbation of the workspace (as in the paper) keeps trees diverse.
        s = rng.uniform(lo[q], hi[q])
        mid = (lo[q] + hi[q]) / 2.0
        mid = (mid + s) / 2.0
        feats[idx] = q
        splits[idx] = mid
        old_hi = hi[q]
        hi[q] = mid
        self._build(rng, 2 * idx + 1, depth + 1, lo, hi, feats, splits)
        hi[q] = old_hi
        old_lo = lo[q]
        lo[q] = mid
        self._build(rng, 2 * idx + 2, depth + 1, lo, hi, feats, splits)
        lo[q] = old_lo

    @property
    def ready(self) -> bool:
        return self.windows_completed >= 1

    def _mass(self, x: Sequence[float]) -> float:
        total = 0.0
        size_limit = 0.1 * self.window_size
        for t in range(self.n_trees):
            feats, splits, r = self.feat[t], self.split[t], self.r_mass[t]
            idx, depth = 0, 0
            while depth < self.height and r[idx] >= size_limit:
                idx = 2 * idx + 1 if x[feats[idx]] < splits[idx] else 2 * idx + 2
                depth += 1
            total += r[idx] * (2 ** depth)
        return total

    def score(self, x: Sequence[float]) -> float:
        """Calibrated anomaly score in [0, 1]: the fraction of recently seen
        (baseline) events that sit in denser regions than *x*. 0.99 means
        "rarer than 99% of what this model has learned". 0 until warmed up."""
        if not self.ready or len(self._sorted) < 100:
            return 0.0
        m = self._mass(x)
        below = bisect_left(self._sorted, m)  # baseline events with lower mass (rarer)
        return 1.0 - below / len(self._sorted)

    def learn(self, x: Sequence[float]) -> None:
        for t in range(self.n_trees):
            feats, splits, l = self.feat[t], self.split[t], self.l_mass[t]
            idx = 0
            for _ in range(self.height + 1):
                l[idx] += 1
                if feats[idx] < 0:
                    break
                idx = 2 * idx + 1 if x[feats[idx]] < splits[idx] else 2 * idx + 2
        if self.ready:
            self._recent.append(self._mass(x))
        self.counter += 1
        if self.counter >= self.window_size:
            self.r_mass = self.l_mass
            self.l_mass = [[0] * self.n_nodes for _ in range(self.n_trees)]
            self.counter = 0
            self.windows_completed += 1
            self._sorted = sorted(self._recent)

    def score_learn(self, x: Sequence[float]) -> float:
        s = self.score(x)
        self.learn(x)
        return s

    # -- persistence ---------------------------------------------------------
    def export(self) -> Dict[str, Any]:
        return {"n_features": self.n_features, "n_trees": self.n_trees, "height": self.height,
                "window_size": self.window_size, "seed": self.seed, "r_mass": self.r_mass,
                "l_mass": self.l_mass, "counter": self.counter, "windows_completed": self.windows_completed,
                "recent": list(self._recent)}

    @classmethod
    def restore(cls, d: Dict[str, Any]) -> "HalfSpaceTrees":
        m = cls(d["n_features"], d["n_trees"], d["height"], d["window_size"], d["seed"])
        m.r_mass, m.l_mass = d["r_mass"], d["l_mass"]
        m.counter, m.windows_completed = d["counter"], d["windows_completed"]
        m._recent = deque(d.get("recent", []), maxlen=4000)
        m._sorted = sorted(m._recent)
        return m
