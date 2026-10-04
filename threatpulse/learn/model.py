"""Persistent model state (JSON, never pickle)."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict

from .features import HST_FEATURES
from .fusion import FusionModel
from .hst import HalfSpaceTrees
from .rarity import RarityModel

MODEL_VERSION = 1


class ThreatModel:
    def __init__(self):
        self.hst = HalfSpaceTrees(n_features=len(HST_FEATURES), n_trees=25, height=8, window_size=500)
        self.pair_rarity = RarityModel(min_total=500)        # parent -> child process
        self.image_host_rarity = RarityModel(min_total=500)  # image on this host
        self.fusion = FusionModel()
        self.analytic_state: Dict[str, Dict[str, Any]] = {}
        self.events_seen = 0
        self.process_events_seen = 0

    @property
    def warmed(self) -> bool:
        return self.hst.ready and self.pair_rarity.ready

    def export(self) -> Dict[str, Any]:
        return {
            "model_version": MODEL_VERSION,
            "hst": self.hst.export(),
            "pair_rarity": self.pair_rarity.export(),
            "image_host_rarity": self.image_host_rarity.export(),
            "fusion": self.fusion.export(),
            "analytic_state": self.analytic_state,
            "events_seen": self.events_seen,
            "process_events_seen": self.process_events_seen,
        }

    @classmethod
    def restore(cls, d: Dict[str, Any]) -> "ThreatModel":
        m = cls()
        m.hst = HalfSpaceTrees.restore(d["hst"])
        m.pair_rarity = RarityModel.restore(d["pair_rarity"])
        m.image_host_rarity = RarityModel.restore(d["image_host_rarity"])
        m.fusion = FusionModel.restore(d["fusion"])
        m.analytic_state = d.get("analytic_state", {})
        m.events_seen = d.get("events_seen", 0)
        m.process_events_seen = d.get("process_events_seen", 0)
        return m

    # -- files ---------------------------------------------------------------
    def save(self, path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        data = json.dumps(self.export(), separators=(",", ":"), sort_keys=True).encode()
        digest = hashlib.sha256(data).hexdigest()
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
        with open(path + ".sha256", "w") as fh:
            fh.write(digest + "\n")
        return digest

    @classmethod
    def load(cls, path: str) -> "ThreatModel":
        if not os.path.exists(path):
            return cls()
        with open(path, "rb") as fh:
            data = fh.read()
        sidecar = path + ".sha256"
        if os.path.exists(sidecar):
            want = open(sidecar).read().strip()
            if hashlib.sha256(data).hexdigest() != want:
                raise ValueError(f"model integrity check failed for {path}")
        return cls.restore(json.loads(data))

    @staticmethod
    def digest(path: str) -> str:
        if not os.path.exists(path):
            return ""
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
