"""
How many checks students ran, per school, day and verdict band. Numbers only: no text, no sender, nothing about the
student. It gives a career center the number that shows the tool is used ("1,240 messages checked this month, 37
flagged before anyone reported them") and lets an empty review queue say what students handled on their own.

    counts.record(school, band)                 called by /analyze; only schools in schools.json are counted
    counts.flush()                              writes what's pending (every FLUSH_N checks or FLUSH_SECONDS)
    counts.totals(school, since_day) -> {"checks": n, "flagged": n}     school "" sums every school
    counts.record_hit(template_key)             a check matched a confirmed scam script (template memory)
    counts.hits(keys, since_day="") -> {key: n} how many later checks each confirmed script flagged

Counting is best-effort: a store outage loses a few counts, never a check.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import threading
import time
from typing import Optional

log = logging.getLogger(__name__)
BANDS = ("clear", "caution", "review", "block")
FLAGGED = ("review", "block")
FLUSH_N = int(os.environ.get("CHECK_COUNT_FLUSH_N", "50"))
FLUSH_SECONDS = float(os.environ.get("CHECK_COUNT_FLUSH_SECONDS", "60"))
_pending: dict = {}
_hits: dict = {}
_lock = threading.Lock()
_last = {"at": time.time()}


def _store(st=None):
    if st is not None:
        return st
    from .store import get_store
    return get_store()


def _known(school: str) -> bool:
    from . import guardrails
    return bool(school) and school in guardrails._config()


def record(school: str, band: str, st=None) -> None:
    """Count one check. Never raises."""
    try:
        if band not in BANDS or not _known(school):
            return
        key = (school, dt.datetime.now(dt.timezone.utc).date().isoformat(), band)
        with _lock:
            _pending[key] = _pending.get(key, 0) + 1
            due = sum(_pending.values()) >= FLUSH_N or time.time() - _last["at"] >= FLUSH_SECONDS
        if due:
            flush(st)
    except Exception:                                   # noqa: BLE001 - counting must never break a check
        log.exception("check count failed")


def record_hit(key: str, st=None) -> None:
    """Count one check that matched a confirmed scam script. The key is the script's hash, never its text."""
    try:
        if not key or len(key) > 64:
            return
        k = (key, dt.datetime.now(dt.timezone.utc).date().isoformat())
        with _lock:
            _hits[k] = _hits.get(k, 0) + 1
            due = sum(_hits.values()) >= FLUSH_N or time.time() - _last["at"] >= FLUSH_SECONDS
        if due:
            flush(st)
    except Exception:                                   # noqa: BLE001
        log.exception("template hit count failed")


def flush(st=None) -> None:
    with _lock:
        rows = [(s, d, b, n) for (s, d, b), n in _pending.items()]
        hits = [(k, d, n) for (k, d), n in _hits.items()]
        _pending.clear()
        _hits.clear()
        _last["at"] = time.time()
    if rows:
        try:
            _store(st).add_check_counts(rows)
        except Exception:                               # noqa: BLE001
            log.exception("could not save %d check counts", sum(r[3] for r in rows))
    if hits:
        try:
            _store(st).add_template_hits(hits)
        except Exception:                               # noqa: BLE001
            log.exception("could not save %d template hits", sum(r[2] for r in hits))


def hits(keys, since: str = "", st=None) -> dict:
    """Later checks each confirmed script flagged, by template key (pending ones included)."""
    keys = [k for k in keys if k]
    if not keys:
        return {}
    try:
        out = dict(_store(st).template_hits(keys, since))
    except Exception:                                   # noqa: BLE001
        out = {}
    with _lock:
        for (k, d), n in _hits.items():
            if k in keys and d >= since:
                out[k] = out.get(k, 0) + n
    return out


def totals(school: str, since: str, st=None, until: Optional[str] = None) -> dict:
    """Checks and flagged checks from `since` (YYYY-MM-DD, inclusive) to `until` (exclusive), counting what's
    still pending in this process too."""
    out = {"checks": 0, "flagged": 0}
    try:
        rows = _store(st).check_counts(school, since)
    except Exception:                                   # noqa: BLE001
        rows = []
    with _lock:
        rows = list(rows) + [(d, b, n) for (s, d, b), n in _pending.items() if not school or s == school]
    for day, band, n in rows:
        if day < since or (until and day >= until):
            continue
        out["checks"] += n
        if band in FLAGGED:
            out["flagged"] += n
    return out
