"""Deterministic rule engine.

Native ThreatPulse rules and Sigma rules share one detection syntax (the Sigma
``detection`` block), compiled once into Python closures and indexed by
``(channel, EventID)`` so each event is only tested against rules that can
possibly match it. This logsource dispatch is the main reason the engine is fast.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import yaml

from ..events import Event

log = logging.getLogger(__name__)

SEVERITY = {"informational": 0.1, "info": 0.1, "low": 0.3, "medium": 0.55, "high": 0.8, "critical": 0.95}

Matcher = Callable[[Event], bool]


@dataclass
class Rule:
    id: str
    title: str
    severity: str = "medium"
    mitre: List[str] = field(default_factory=list)
    hypothesis: str = ""
    type: str = "match"  # match | analytic
    logsource: List[Tuple[str, Optional[int]]] = field(default_factory=list)
    matcher: Optional[Matcher] = None
    analytic: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    source: str = "native"  # native | sigma
    path: str = ""
    status: str = "stable"
    falsepositives: List[str] = field(default_factory=list)

    @property
    def severity_score(self) -> float:
        return SEVERITY.get(str(self.severity).lower(), 0.5)


@dataclass
class Hit:
    rule_id: str
    title: str
    severity: str
    severity_score: float
    mitre: List[str]
    event: Event
    details: Dict[str, Any] = field(default_factory=dict)


class RuleError(ValueError):
    pass


# ----------------------------------------------------------------------------
# Field matchers
# ----------------------------------------------------------------------------

def _to_str(v: Any) -> str:
    return "" if v is None else str(v).lower()


def _value_matcher(fieldname: str, modifiers: List[str], values: List[Any]) -> Matcher:
    mods = set(modifiers)
    all_mode = "all" in mods
    if "exists" in mods:
        want = bool(values[0]) if values else True
        return lambda ev: (fieldname in ev and ev[fieldname] not in (None, "")) == want

    for numop in ("gt", "gte", "lt", "lte"):
        if numop in mods:
            thr = float(values[0])
            ops = {
                "gt": lambda x: x > thr,
                "gte": lambda x: x >= thr,
                "lt": lambda x: x < thr,
                "lte": lambda x: x <= thr,
            }
            op = ops[numop]

            def num_match(ev: Event, op=op) -> bool:
                try:
                    return op(float(ev.get(fieldname)))
                except (TypeError, ValueError):
                    return False

            return num_match

    if "re" in mods:
        pats = [re.compile(str(v), re.IGNORECASE) for v in values]
        tests = [lambda s, p=p: p.search(s) is not None for p in pats]
    else:
        lowered = []
        for v in values:
            if v is None:
                lowered.append(None)
            else:
                lowered.append(_to_str(v))
        if "contains" in mods:
            tests = [lambda s, v=v: v is not None and v in s for v in lowered]
        elif "startswith" in mods:
            tests = [lambda s, v=v: v is not None and s.startswith(v) for v in lowered]
        elif "endswith" in mods:
            tests = [lambda s, v=v: v is not None and s.endswith(v) for v in lowered]
        else:
            # Exact (case-insensitive) with Sigma-style * and ? wildcards.
            exact = set()
            wild = []
            null_ok = False
            for v in lowered:
                if v is None:
                    null_ok = True
                elif "*" in v or "?" in v:
                    wild.append(re.compile(fnmatch.translate(v), re.IGNORECASE | re.DOTALL))
                else:
                    exact.add(v)
            if not all_mode:
                def exact_match(ev: Event) -> bool:
                    raw = ev.get(fieldname)
                    if raw is None or raw == "":
                        return null_ok
                    s = _to_str(raw)
                    if s in exact:
                        return True
                    return any(p.match(s) for p in wild)

                return exact_match
            tests = [lambda s, v=v: s == v for v in exact] + [lambda s, p=p: p.match(s) is not None for p in wild]

    combine = all if all_mode else any

    def match(ev: Event) -> bool:
        raw = ev.get(fieldname)
        if raw is None:
            return False
        s = _to_str(raw)
        return combine(t(s) for t in tests)

    return match


def _keyword_matcher(values: List[Any]) -> Matcher:
    kws = [_to_str(v).strip("*") for v in values]

    def match(ev: Event) -> bool:
        for k, v in ev.items():
            if k.startswith("tp_") or not isinstance(v, str):
                continue
            lv = v.lower()
            if any(kw in lv for kw in kws):
                return True
        return False

    return match


def _selection_matcher(sel: Any) -> Matcher:
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            subs = [_selection_matcher(x) for x in sel]
            return lambda ev: any(m(ev) for m in subs)
        return _keyword_matcher(sel)
    if isinstance(sel, dict):
        parts: List[Matcher] = []
        for key, val in sel.items():
            fieldname, *mods = str(key).split("|")
            mods = [m.lower() for m in mods if m.lower() not in ("i", "cased", "windash")]
            if "in" in mods:
                mods.remove("in")
            values = val if isinstance(val, list) else [val]
            parts.append(_value_matcher(fieldname, mods, values))
        return lambda ev: all(m(ev) for m in parts)
    if isinstance(sel, str):
        return _keyword_matcher([sel])
    raise RuleError(f"unsupported selection type: {type(sel).__name__}")


# ----------------------------------------------------------------------------
# Condition parser (recursive descent)
# ----------------------------------------------------------------------------

_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*\-\.]+")


def compile_condition(cond: str, selections: Dict[str, Matcher]) -> Matcher:
    if "|" in cond:
        raise RuleError("aggregation conditions are not supported")
    tokens = _TOKEN.findall(cond)
    pos = 0

    def peek() -> Optional[str]:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def names_for(pattern: str) -> List[Matcher]:
        if pattern == "them":
            return [m for n, m in selections.items() if not n.startswith("_")]
        found = [m for n, m in selections.items() if fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise RuleError(f"no selection matches '{pattern}'")
        return found

    def expr() -> Matcher:
        left = term()
        while peek() and peek().lower() == "or":
            take()
            right = term()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    def term() -> Matcher:
        left = factor()
        while peek() and peek().lower() == "and":
            take()
            right = factor()
            left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, right)
        return left

    def factor() -> Matcher:
        tok = peek()
        if tok is None:
            raise RuleError("unexpected end of condition")
        low = tok.lower()
        if low == "not":
            take()
            inner = factor()
            return lambda ev: not inner(ev)
        if tok == "(":
            take()
            inner = expr()
            if peek() != ")":
                raise RuleError("missing ')'")
            take()
            return inner
        if low in ("1", "any", "all") and pos + 1 < len(tokens) and tokens[pos + 1].lower() == "of":
            take(); take()
            ms = names_for(take())
            if low == "all":
                return lambda ev: all(m(ev) for m in ms)
            return lambda ev: any(m(ev) for m in ms)
        take()
        if tok not in selections:
            raise RuleError(f"unknown selection '{tok}'")
        return selections[tok]

    result = expr()
    if pos != len(tokens):
        raise RuleError(f"trailing tokens in condition: {tokens[pos:]}")
    return result


def compile_detection(detection: Dict[str, Any]) -> Matcher:
    detection = dict(detection)
    cond = detection.pop("condition", None)
    detection.pop("timeframe", None)
    if cond is None:
        raise RuleError("detection has no condition")
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    selections = {name: _selection_matcher(sel) for name, sel in detection.items()}
    return compile_condition(str(cond), selections)


# ----------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------

SIGMA_CATEGORY = {
    "process_creation": [("sysmon", 1), ("security", 4688)],
    "network_connection": [("sysmon", 3)],
    "process_access": [("sysmon", 10)],
    "file_event": [("sysmon", 11)],
    "file_delete": [("sysmon", 23), ("sysmon", 26)],
    "registry_set": [("sysmon", 13)],
    "registry_add": [("sysmon", 12)],
    "registry_delete": [("sysmon", 12)],
    "registry_event": [("sysmon", 12), ("sysmon", 13), ("sysmon", 14)],
    "dns_query": [("sysmon", 22)],
    "image_load": [("sysmon", 7)],
    "driver_load": [("sysmon", 6)],
    "create_remote_thread": [("sysmon", 8)],
    "raw_access_thread": [("sysmon", 9)],
    "pipe_created": [("sysmon", 17), ("sysmon", 18)],
    "wmi_event": [("sysmon", 19), ("sysmon", 20), ("sysmon", 21)],
    "ps_script": [("powershell", 4104)],
    "ps_module": [("powershell", 4103)],
}
SIGMA_SERVICE = {"security": "security", "system": "system", "sysmon": "sysmon",
                 "powershell": "powershell", "windefend": "defender"}


def _native_logsource(ls: Any) -> List[Tuple[str, Optional[int]]]:
    out: List[Tuple[str, Optional[int]]] = []
    items = ls if isinstance(ls, list) else [ls]
    for item in items:
        if not item:
            continue
        ch = str(item.get("channel", "sysmon")).lower()
        ids = item.get("event_id")
        if ids is None:
            out.append((ch, None))
        else:
            for i in ids if isinstance(ids, list) else [ids]:
                out.append((ch, int(i)))
    return out


def _sigma_logsource(ls: Dict[str, Any]) -> List[Tuple[str, Optional[int]]]:
    product = str(ls.get("product", "")).lower()
    if product and product != "windows":
        raise RuleError(f"product '{product}' not supported (Windows only in v0.1)")
    cat = ls.get("category")
    if cat:
        if cat not in SIGMA_CATEGORY:
            raise RuleError(f"logsource category '{cat}' not mapped")
        return SIGMA_CATEGORY[cat]
    svc = ls.get("service")
    if svc and str(svc).lower() in SIGMA_SERVICE:
        return [(SIGMA_SERVICE[str(svc).lower()], None)]
    raise RuleError("logsource not mapped")


def rule_from_dict(doc: Dict[str, Any], path: str = "") -> Rule:
    is_sigma = "logsource" in doc and isinstance(doc.get("logsource"), dict) and (
        "product" in doc["logsource"] or "category" in doc["logsource"] or "service" in doc["logsource"]
    ) and "channel" not in doc["logsource"]
    rid = str(doc.get("id") or os.path.splitext(os.path.basename(path))[0])
    if is_sigma:
        tags = doc.get("tags") or []
        mitre = [t.split(".", 1)[1].upper() for t in tags if str(t).lower().startswith("attack.t")]
        rule = Rule(
            id=rid,
            title=str(doc.get("title", rid)),
            severity=str(doc.get("level", "medium")),
            mitre=mitre,
            hypothesis=str(doc.get("description", "")),
            logsource=_sigma_logsource(doc["logsource"]),
            source="sigma",
            path=path,
            status=str(doc.get("status", "experimental")),
            falsepositives=list(doc.get("falsepositives") or []),
        )
        rule.matcher = compile_detection(doc["detection"])
        return rule

    rule = Rule(
        id=rid,
        title=str(doc.get("title", rid)),
        severity=str(doc.get("severity", "medium")),
        mitre=[str(m) for m in doc.get("mitre", [])],
        hypothesis=str(doc.get("hypothesis", "")),
        type=str(doc.get("type", "match")),
        logsource=_native_logsource(doc.get("logsource")),
        path=path,
        status=str(doc.get("status", "stable")),
        falsepositives=list(doc.get("falsepositives") or []),
    )
    if rule.type == "match":
        rule.matcher = compile_detection(doc["detection"])
    elif rule.type == "analytic":
        rule.analytic = str(doc["analytic"])
        rule.params = dict(doc.get("params") or {})
        if "detection" in doc:  # optional pre-filter
            rule.matcher = compile_detection(doc["detection"])
    else:
        raise RuleError(f"unknown rule type '{rule.type}'")
    return rule


def load_rules_from_path(path: str, include_drafts: bool = False) -> Tuple[List[Rule], List[Tuple[str, str]]]:
    """Load every ``.yml``/``.yaml`` rule under *path*. Returns (rules, errors)."""
    files: List[str] = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, dirs, names in os.walk(path):
            if not include_drafts and os.path.basename(root) == "drafts":
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if include_drafts or d != "drafts"]
            files += [os.path.join(root, n) for n in sorted(names) if n.endswith((".yml", ".yaml"))]
    rules: List[Rule] = []
    errors: List[Tuple[str, str]] = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                for doc in yaml.safe_load_all(fh):
                    if not doc:
                        continue
                    if str(doc.get("status", "")).lower() in ("draft", "deprecated") and not include_drafts:
                        continue
                    rules.append(rule_from_dict(doc, f))
        except Exception as exc:  # noqa: BLE001 - report and continue
            errors.append((f, str(exc)))
    return rules, errors


BUILTIN_DIR = os.path.join(os.path.dirname(__file__), "builtin")


class RuleSet:
    """Indexed collection of compiled rules."""

    def __init__(self, rules: Iterable[Rule]):
        self.rules: List[Rule] = []
        self._index: Dict[Tuple[str, Optional[int]], List[Rule]] = {}
        seen = set()
        for r in rules:
            if r.id in seen:
                log.warning("duplicate rule id %s ignored (%s)", r.id, r.path)
                continue
            seen.add(r.id)
            self.rules.append(r)
            for key in r.logsource or [("*", None)]:
                self._index.setdefault(key, []).append(r)

    @classmethod
    def load(cls, extra_paths: Iterable[str] = (), builtin: bool = True) -> Tuple["RuleSet", List[Tuple[str, str]]]:
        rules: List[Rule] = []
        errors: List[Tuple[str, str]] = []
        if builtin:
            r, e = load_rules_from_path(BUILTIN_DIR)
            rules += r
            errors += e
        for p in extra_paths:
            r, e = load_rules_from_path(p)
            rules += r
            errors += e
        return cls(rules), errors

    def candidates(self, ev: Event) -> List[Rule]:
        ch = ev.get("tp_channel", "")
        eid = ev.get("EventID")
        out = self._index.get((ch, eid), [])
        extra = self._index.get((ch, None))
        wild = self._index.get(("*", None))
        if extra or wild:
            out = list(out) + (extra or []) + (wild or [])
        return out

    def get(self, rule_id: str) -> Optional[Rule]:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None
