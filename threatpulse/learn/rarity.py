"""Frequency-based rarity models (learned baselines of 'what normally happens here')."""
from __future__ import annotations

from typing import Any, Dict


class RarityModel:
    """Counts occurrences of a key (e.g. parent→child process pair).

    ``score`` returns 1.0 for never-seen keys and decays towards 0 as a key
    becomes common. Returns 0 until ``min_total`` observations exist, so a
    fresh install does not flood analysts with "rare" everything.
    """

    def __init__(self, min_total: int = 500, max_keys: int = 200_000):
        self.counts: Dict[str, int] = {}
        self.total = 0
        self.min_total = min_total
        self.max_keys = max_keys

    @property
    def ready(self) -> bool:
        return self.total >= self.min_total

    def score(self, key: str) -> float:
        if not self.ready:
            return 0.0
        c = self.counts.get(key, 0)
        return 1.0 / (1.0 + c) ** 0.75

    def learn(self, key: str) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1
        self.total += 1
        if len(self.counts) > self.max_keys:
            # prune singletons — they are the cheapest to forget
            self.counts = {k: v for k, v in self.counts.items() if v > 1}

    def export(self) -> Dict[str, Any]:
        return {"counts": self.counts, "total": self.total, "min_total": self.min_total}

    @classmethod
    def restore(cls, d: Dict[str, Any]) -> "RarityModel":
        m = cls(min_total=d.get("min_total", 500))
        m.counts = dict(d.get("counts", {}))
        m.total = int(d.get("total", 0))
        return m
