"""
Canary for scripts tuned against the public page (plan item 12).

    python -m scam_detector.tools.tuning_watch               # weekly table from the follow-up cases
    python -m scam_detector.tools.tuning_watch --json

Some rules are "private": they run in the API but are never shipped in the public page (rulepack "private": true).
A scammer who tests a script against the page can make the public rules go quiet; the private ones still see it.
So this counts, per week, the flagged cases (review or block) that the public rules alone would have let through:
the private rules were the only reason the student was warned. If that share jumps, someone is tuning against the
page, and it's time to review which public rules they're dodging (and maybe add a new private one).

Scores here are recomputed from the stored rule ids and the rulepack weights (the follow-up keeps no text), so they
are approximate: they ignore repeat-match bonuses and findings that aren't rules.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import defaultdict
from pathlib import Path

RULEPACK = Path(__file__).resolve().parent.parent / "rulepack" / "core.json"
REVIEW = 35
ALERT_MIN_CASES = 5


def rule_table(path=RULEPACK) -> dict:
    core = json.loads(Path(path).read_text(encoding="utf-8"))
    return {r["id"]: r for r in core["rules"]}


def private_only(case: dict, rules: dict) -> bool:
    """Flagged, but only because of private rules."""
    if case.get("band") not in ("review", "block"):
        return False
    fired = [rules[r] for r in case.get("rules", []) if r in rules]
    public = [r for r in fired if not r.get("private")]
    if not any(r.get("private") for r in fired):
        return False
    if any(r.get("severity") == "critical" for r in public):
        return False
    return sum(int(r.get("weight", 0)) for r in public) < REVIEW


def weekly(cases: list, rules: dict) -> list:
    weeks = defaultdict(lambda: {"flagged": 0, "private_only": 0})
    for c in cases:
        try:
            d = dt.date.fromisoformat(c.get("date", "")[:10])
        except ValueError:
            continue
        week = (d - dt.timedelta(days=d.weekday())).isoformat()
        if c.get("band") in ("review", "block"):
            weeks[week]["flagged"] += 1
            weeks[week]["private_only"] += private_only(c, rules)
    return [{"week": w, **v, "share": round(v["private_only"] / v["flagged"], 3) if v["flagged"] else 0.0}
            for w, v in sorted(weeks.items())]


def alert(rows: list) -> str:
    """A plain-language alert when the latest week's share is well above the weeks before it."""
    if len(rows) < 2 or rows[-1]["flagged"] < ALERT_MIN_CASES:
        return ""
    before = [r for r in rows[:-1] if r["flagged"]]
    base = sum(r["private_only"] for r in before) / max(1, sum(r["flagged"] for r in before))
    last = rows[-1]["share"]
    if last >= 0.2 and last >= 2 * base:
        return (f"Week of {rows[-1]['week']}: {rows[-1]['private_only']} of {rows[-1]['flagged']} flagged cases were "
                f"caught only by server-only rules ({last:.0%}, usually {base:.0%}). Scripts may be tuned against the "
                f"public page; review which public rules they now avoid.")
    return ""


def main(argv=None) -> int:
    from ..store import get_store
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rows = weekly(get_store().cases(), rule_table())
    msg = alert(rows)
    if a.json:
        print(json.dumps({"weeks": rows, "alert": msg}, indent=1))
        return 0
    print("| Week | Flagged | Caught only by server-only rules | Share |\n|---|---|---|---|")
    for r in rows:
        print(f"| {r['week']} | {r['flagged']} | {r['private_only']} | {r['share']:.0%} |")
    print("\n" + (msg or "No sign of tuning against the public page."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
