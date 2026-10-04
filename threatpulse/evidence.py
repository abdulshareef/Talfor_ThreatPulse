"""Forensic soundness: hash-chained evidence ledger, run manifest and a
jurisdiction-neutral technical annexure that records the particulars courts
commonly require when electronic evidence is authenticated (integrity hashes,
the system and tool that produced it, timestamps, operator, chain of custody).

Every alert is written as one JSON line whose ``hash`` is
``SHA-256(prev_hash || canonical_json(record))``. Altering, inserting,
deleting or re-ordering any line breaks the chain, which ``verify`` detects.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import TOOL_NAME, __author__, __version__

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def chain_hash(prev: str, record: Dict[str, Any]) -> str:
    return hashlib.sha256((prev + canonical(record)).encode("utf-8")).hexdigest()


class EvidenceLedger:
    def __init__(self, path: str):
        self.path = path
        self.prev = GENESIS
        self.seq = 0
        if os.path.exists(path):  # resume an existing chain
            for line in open(path, "r", encoding="utf-8"):
                if line.strip():
                    entry = json.loads(line)
                    self.prev = entry["hash"]
                    self.seq = entry["seq"]
        self._fh = open(path, "a", encoding="utf-8")

    def append(self, record: Dict[str, Any]) -> str:
        self.seq += 1
        h = chain_hash(self.prev, record)
        entry = {"seq": self.seq, "prev_hash": self.prev, "record": record, "hash": h}
        self._fh.write(canonical(entry) + "\n")
        self._fh.flush()
        self.prev = h
        return h

    def close(self) -> None:
        self._fh.close()

    @property
    def head(self) -> str:
        return self.prev


def verify_ledger(path: str, expected_head: Optional[str] = None) -> Tuple[bool, int, str, str]:
    """Return (ok, entries, head_hash, message)."""
    prev = GENESIS
    n = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, n, prev, f"line {lineno}: not valid JSON"
            if entry.get("prev_hash") != prev:
                return False, n, prev, f"line {lineno}: chain broken (prev_hash mismatch)"
            if entry.get("seq") != n + 1:
                return False, n, prev, f"line {lineno}: sequence gap"
            if chain_hash(prev, entry["record"]) != entry.get("hash"):
                return False, n, prev, f"line {lineno}: record content altered"
            prev = entry["hash"]
            n += 1
    if expected_head is not None and prev != expected_head:
        return False, n, prev, "head hash differs from manifest (entries truncated or appended)"
    return True, n, prev, "ledger intact"


def now_pair() -> Tuple[str, str]:
    """Return (UTC, local time of the processing machine incl. its UTC offset)."""
    t = datetime.now(timezone.utc)
    return t.isoformat(timespec="seconds"), t.astimezone().isoformat(timespec="seconds")


def environment() -> Dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "tool": f"{TOOL_NAME} {__version__}",
    }


def tool_source_digest() -> str:
    """SHA-256 over the tool's own source + rule files, so the exact build is attestable."""
    root = os.path.dirname(os.path.abspath(__file__))
    h = hashlib.sha256()
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in ("__pycache__", "drafts"))
        for f in sorted(files):
            if f.endswith((".py", ".yml", ".yaml", ".html")):
                p = os.path.join(base, f)
                h.update(os.path.relpath(p, root).replace("\\", "/").encode())
                with open(p, "rb") as fh:
                    h.update(fh.read())
    return h.hexdigest()


def write_evidence_annex(run_dir: str, manifest: Dict[str, Any]) -> str:
    inputs = manifest.get("inputs", [])
    rows = "\n".join(f"| {i+1} | `{os.path.basename(x['path'])}` | {x['size']} | `{x['sha256']}` |"
                     for i, x in enumerate(inputs))
    env = manifest.get("environment", {})
    text = f"""# Technical Annexure — Automated Threat Hunt

**Technical particulars of the processing of electronic records**

> This annexure records how an automated analysis run was performed: which
> records were examined, their cryptographic hashes, the computer and tool
> used, and how integrity can be re-verified. It is jurisdiction-neutral and is
> intended to support whatever authentication, certification or expert-report
> requirements apply where the evidence is presented. It is **not** itself a
> legal certificate or declaration; that must be prepared and signed by the
> competent person under the applicable law.

## 1. Case and operator
| Field | Value |
|---|---|
| Case / reference | {manifest.get('case_id') or '—'} |
| Operator | {manifest.get('operator') or '—'} |
| Run ID | `{manifest['run_id']}` |
| Started (UTC / local) | {manifest['started_utc']} / {manifest['started_local']} |
| Completed (UTC / local) | {manifest.get('finished_utc', '—')} / {manifest.get('finished_local', '—')} |

## 2. Computer resource used for processing
| Field | Value |
|---|---|
| Hostname | {env.get('hostname')} |
| Operating system | {env.get('os')} ({env.get('machine')}) |
| Runtime | Python {env.get('python')} |
| Tool | {env.get('tool')} — {__author__} |
| Tool build digest (SHA-256 of source + rules) | `{manifest.get('tool_digest')}` |

## 3. Electronic records examined (hashed before processing)
| # | File | Size (bytes) | SHA-256 |
|---|---|---|---|
{rows}

## 4. Processing particulars
| Field | Value |
|---|---|
| Events processed | {manifest.get('events_processed')} |
| Rules loaded | {manifest.get('rules_loaded')} (rule-set digest `{manifest.get('ruleset_digest')}`) |
| Learning model before run | `{manifest.get('model_digest_before') or 'none (fresh model)'}` |
| Learning model after run | `{manifest.get('model_digest_after') or 'unchanged'}` |
| Online learning during run | {manifest.get('learning_enabled')} |
| Alerts recorded | {manifest.get('alerts')} |
| Evidence ledger | `alerts.jsonl` — SHA-256 hash chain |
| Ledger head hash | `{manifest.get('ledger_head')}` |

## 5. Integrity statement (technical)
The input files listed in section 3 were opened read-only and their SHA-256
values computed before analysis. Findings were written to a hash-chained
ledger; integrity can be re-verified at any time with:

```
threatpulse verify {os.path.basename(run_dir)}
```

Machine-learning scores are investigative leads that rank events for human
review. They are not, by themselves, conclusions of fact.
"""
    path = os.path.join(run_dir, "evidence_annex.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def ruleset_digest(rule_paths: List[str]) -> str:
    h = hashlib.sha256()
    for p in sorted(set(rule_paths)):
        if p and os.path.exists(p):
            with open(p, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()
