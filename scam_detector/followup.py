"""
Outcome tracking: did the warning work?

    open_case(result, school="", path=CASES, now=None) -> code         when a student opts in to a follow-up
    record_outcome(code, happened, verified="", path=OUTCOMES) -> bool  when they come back (about 14 days later)

No detector knows whether it was right. A student who checks a message can opt in to "check back with me"; they get
a random case code (a link they keep), and LureCheck stores only what it decided, never the text:

    cases.jsonl     {"case": sha256(code), "date", "school", "band", "score", "rules": [rule ids], "model_flag"}
    outcomes.jsonl  {"case": sha256(code), "date", "happened": [...], "verified": "job_real"|"job_fake"|"unsure"|""}

The code itself is never stored, so a stored record can't be traced back to the student. tools/outcome_report.py
joins the two: how often a warned student still lost money, and which "clear" verdicts turned out to be scams (the
misses the rules and model need to learn from).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import List, Optional

from .recovery import HAPPENED
from .store import get_store

DATA = Path(os.environ.get("LURECHECK_DATA", Path(__file__).resolve().parent / "data"))
CASES = DATA / "cases.jsonl"
OUTCOMES = DATA / "outcomes.jsonl"
FOLLOW_UP_DAYS = 14
VERIFIED = ("job_real", "job_fake", "unsure", "")
# Outcomes that mean the student lost money, data or access.
LOSS = frozenset({"shared_personal_info", "shared_bank_details", "shared_login", "deposited_check", "sent_money",
                  "gift_cards", "crypto", "shipped_packages", "installed_software"})


def _h(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()


def _append(path, record: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def open_case(result: dict, school: str = "", path=None, now: Optional[dt.date] = None) -> str:
    code = secrets.token_urlsafe(9)
    today = now or dt.datetime.now(dt.timezone.utc).date()
    findings = result.get("findings", [])
    rec = {
        "case": _h(code), "date": today.isoformat(), "school": "".join(c for c in school.lower() if c.isalnum())[:40],
        "band": result.get("band", ""), "score": result.get("score", 0),
        "rules": sorted({f["rule_id"] for f in findings if f.get("rule_id") != "model_second_look"}),
        "model_flag": any(f.get("rule_id") == "model_second_look" for f in findings)}
    if path:
        _append(path, rec)                              # explicit file: tests and offline use
    else:
        get_store().add_case(rec)
    return code


def follow_up_date(now: Optional[dt.date] = None) -> str:
    return ((now or dt.datetime.now(dt.timezone.utc).date()) + dt.timedelta(days=FOLLOW_UP_DAYS)).isoformat()


def record_outcome(code: str, happened: List[str], verified: str = "", path=None,
                   now: Optional[dt.date] = None) -> bool:
    """False when the input isn't usable (no code, unknown values); nothing is written then."""
    happened = [h for h in dict.fromkeys(happened or []) if h in HAPPENED or h == "nothing"]
    if not code or not code.strip() or verified not in VERIFIED or not happened:
        return False
    rec = {"case": _h(code), "date": (now or dt.datetime.now(dt.timezone.utc).date()).isoformat(),
           "happened": happened, "verified": verified}
    if path:
        _append(path, rec)
        return True
    return get_store().add_outcome(rec)                 # False when the case code is unknown (Postgres)


def load(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
