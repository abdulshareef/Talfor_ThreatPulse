"""Event ingestion and normalisation for Windows telemetry.

Supported inputs
----------------
* JSON Lines (one event per line) — flat Sysmon-style fields, or Winlogbeat /
  Elastic Agent documents (``winlog.event_data`` is flattened automatically).
* JSON arrays of events.
* CSV with a header row.
* EVTX files (requires the optional ``python-evtx`` package).

Every event is normalised to a flat ``dict`` keyed by the familiar Sysmon /
Windows field names (``EventID``, ``Image``, ``CommandLine`` ...). A few
derived fields prefixed with ``tp_`` are added for fast matching.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, Optional

Event = Dict[str, Any]

# Channel aliases so rules can say "sysmon" or "security".
CHANNEL_ALIASES = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "security",
    "system": "system",
    "microsoft-windows-windows defender/operational": "defender",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell",
}

_TIME_FIELDS = ("UtcTime", "TimeCreated", "@timestamp", "timestamp", "SystemTime", "EventTime")


def parse_time(value: Any) -> Optional[float]:
    """Return a POSIX timestamp (UTC) from the many time formats Windows logs use."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    s = str(value).strip()
    s = s.replace("Z", "+00:00")
    # Sysmon UtcTime: "2026-10-04 08:01:02.123"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    try:
        # Trim excess fractional digits (EVTX uses 7) for fromisoformat.
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def basename(path: Any) -> str:
    if not path:
        return ""
    p = str(path).replace("/", "\\")
    return p.rsplit("\\", 1)[-1].lower()


def _flatten_beats(doc: Event) -> Event:
    """Flatten Winlogbeat / Elastic Agent style documents."""
    winlog = doc.get("winlog")
    if not isinstance(winlog, dict):
        return doc
    out: Event = {}
    out.update(winlog.get("event_data") or {})
    out.update(winlog.get("user_data") or {})
    out["EventID"] = winlog.get("event_id", doc.get("event", {}).get("code"))
    out["Channel"] = winlog.get("channel", "")
    out["Computer"] = winlog.get("computer_name", doc.get("host", {}).get("name", ""))
    out["TimeCreated"] = doc.get("@timestamp")
    return out


def normalise(raw: Event) -> Event:
    ev = _flatten_beats(dict(raw))
    # EventID as int
    try:
        ev["EventID"] = int(str(ev.get("EventID", "0")).strip() or 0)
    except ValueError:
        ev["EventID"] = 0
    ch = str(ev.get("Channel", "")).strip()
    ev["tp_channel"] = CHANNEL_ALIASES.get(ch.lower(), ch.lower() or "sysmon")
    # timestamp
    ts = None
    for f in _TIME_FIELDS:
        if f in ev:
            ts = parse_time(ev[f])
            if ts is not None:
                break
    ev["tp_ts"] = ts if ts is not None else 0.0
    # Security 4688 uses NewProcessName / ParentProcessName — alias to Sysmon names.
    if "NewProcessName" in ev and "Image" not in ev:
        ev["Image"] = ev["NewProcessName"]
    if "ParentProcessName" in ev and "ParentImage" not in ev:
        ev["ParentImage"] = ev["ParentProcessName"]
    if "ProcessCommandLine" in ev and "CommandLine" not in ev:
        ev["CommandLine"] = ev["ProcessCommandLine"]
    ev["tp_image"] = basename(ev.get("Image"))
    ev["tp_parent"] = basename(ev.get("ParentImage"))
    ev["tp_host"] = str(ev.get("Computer", "") or "").lower()
    ev["tp_user"] = str(ev.get("User", "") or ev.get("TargetUserName", "") or "").lower()
    return ev


# ----------------------------------------------------------------------------
# Readers
# ----------------------------------------------------------------------------

def _read_jsonl(fh: io.TextIOBase) -> Iterator[Event]:
    first = fh.read(1)
    if not first:
        return
    rest = fh.read()
    text = first + rest
    if first == "[":
        for doc in json.loads(text):
            yield doc
        return
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield json.loads(line)


def _read_csv(fh: io.TextIOBase) -> Iterator[Event]:
    yield from csv.DictReader(fh)


def _read_evtx(path: str) -> Iterator[Event]:  # pragma: no cover - optional dependency
    try:
        import Evtx.Evtx as evtx  # type: ignore
        from xml.etree import ElementTree as ET
    except ImportError as exc:
        raise RuntimeError("EVTX support needs: pip install python-evtx") from exc
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    with evtx.Evtx(path) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            sysn = root.find(f"{ns}System")
            ev: Event = {}
            if sysn is not None:
                ev["EventID"] = (sysn.findtext(f"{ns}EventID") or "0").strip()
                ev["Channel"] = sysn.findtext(f"{ns}Channel") or ""
                ev["Computer"] = sysn.findtext(f"{ns}Computer") or ""
                tc = sysn.find(f"{ns}TimeCreated")
                if tc is not None:
                    ev["TimeCreated"] = tc.get("SystemTime")
            ed = root.find(f"{ns}EventData")
            if ed is not None:
                for d in ed.findall(f"{ns}Data"):
                    name = d.get("Name")
                    if name:
                        ev[name] = d.text or ""
            ud = root.find(f"{ns}UserData")
            if ud is not None:
                for el in ud.iter():
                    tag = el.tag.split("}")[-1]
                    if el.text and el.text.strip():
                        ev.setdefault(tag, el.text.strip())
            yield ev


def read_events(path: str) -> Iterator[Event]:
    """Yield normalised events from a file, choosing a reader by extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".evtx":
        for raw in _read_evtx(path):
            yield normalise(raw)
        return
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        reader = _read_csv if ext == ".csv" else _read_jsonl
        for raw in reader(fh):
            if isinstance(raw, dict):
                yield normalise(raw)


def read_many(paths: Iterable[str]) -> Iterator[Event]:
    for p in paths:
        yield from read_events(p)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
