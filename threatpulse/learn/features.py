"""Feature extraction for process-creation events (Sysmon 1 / Security 4688)."""
from __future__ import annotations

import math
import re
from typing import Dict, List

from ..analytics import shannon_entropy
from ..events import Event

PROCESS_EVENTS = {("sysmon", 1), ("security", 4688)}

_USER_WRITABLE = ("\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "\\downloads\\",
                  "\\public\\", "\\perflogs\\", "\\$recycle.bin\\", "\\windows\\tasks\\")
_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "wininit.exe",
                 "winlogon.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe", "rundll32.exe",
                 "dllhost.exe", "conhost.exe", "lsm.exe", "searchindexer.exe"}
_URL = re.compile(r"https?://|\\\\\d{1,3}\.\d{1,3}\.", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

HST_FEATURES = ["cmd_len", "cmd_entropy", "n_args", "user_path", "masquerade", "has_url",
                "has_b64", "hour_sin", "hour_cos", "pair_rarity", "image_host_rarity"]


def is_process_event(ev: Event) -> bool:
    return (ev.get("tp_channel"), ev.get("EventID")) in PROCESS_EVENTS


def static_features(ev: Event) -> Dict[str, float]:
    img_path = str(ev.get("Image", "") or "").lower()
    cmd = str(ev.get("CommandLine", "") or "")
    image = ev.get("tp_image", "")
    ts = float(ev.get("tp_ts", 0.0) or 0.0)
    hour = (ts % 86400) / 3600.0
    in_user = any(p in img_path for p in _USER_WRITABLE)
    masquerade = image in _SYSTEM_NAMES and bool(img_path) and "\\windows\\" not in img_path
    return {
        "cmd_len": min(1.0, math.log1p(len(cmd)) / math.log1p(2000)),
        "cmd_entropy": min(1.0, shannon_entropy(cmd) / 6.0),
        "n_args": min(1.0, len(cmd.split()) / 30.0),
        "user_path": 1.0 if in_user else 0.0,
        "masquerade": 1.0 if masquerade else 0.0,
        "has_url": 1.0 if (_URL.search(cmd) or _IP.search(cmd)) else 0.0,
        "has_b64": 1.0 if _B64.search(cmd) else 0.0,
        "hour_sin": (math.sin(2 * math.pi * hour / 24) + 1) / 2,
        "hour_cos": (math.cos(2 * math.pi * hour / 24) + 1) / 2,
    }


def vectorise(feats: Dict[str, float]) -> List[float]:
    return [float(feats.get(k, 0.0)) for k in HST_FEATURES]


def registry_features(ev: Event) -> Dict[str, float]:
    """Context for Sysmon 13 (registry value set): inspect the *value* being written,
    e.g. the program an autorun key will launch."""
    details = str(ev.get("Details", "") or "")
    low = details.lower()
    m = re.search(r"([a-z]:\\[^\"]+?\.(?:exe|dll|bat|ps1|vbs|js|hta|scr))", low)
    target = m.group(1) if m else ""
    name = target.rsplit("\\", 1)[-1] if target else ""
    # user-writable autorun targets are common for legitimate per-user apps (OneDrive,
    # Teams), so only the strong signals are used here.
    return {
        "masquerade": 1.0 if name in _SYSTEM_NAMES and "\\windows\\" not in target else 0.0,
        "has_url": 1.0 if _URL.search(details) else 0.0,
        "has_b64": 1.0 if _B64.search(details) else 0.0,
    }
