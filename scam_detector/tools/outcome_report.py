"""
What happened after the verdict: the follow-up numbers a career center (and the pitch) needs.

    python -m scam_detector.tools.outcome_report                 # data/cases.jsonl + data/outcomes.jsonl
    python -m scam_detector.tools.outcome_report --school fsu --json

For every case with an outcome it reports, by the band the student was shown:
  * how many came back, how many lost money, data or access, and how many later found the job was fake or real;
  * the misses: cases shown "clear" or "caution" that turned out to be scams or cost the student something, with the
    rules that did fire. Those are the next things to label and learn from.
  * false alarms: cases shown "review" or "block" where the student verified the job was real.

Numbers are only from students who opted in and came back, so they are a lower bound on harm and say nothing about
students who never checked. Report them that way.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from ..followup import CASES, LOSS, OUTCOMES, load

BANDS = ("clear", "caution", "review", "block")


def summarize(cases: list, outcomes: list, school: str = "") -> dict:
    by_case = {c["case"]: c for c in cases if not school or c.get("school") == school}
    latest = {}
    for o in outcomes:                                   # the last answer for a case wins
        if o.get("case") in by_case:
            latest[o["case"]] = o
    table = {b: Counter() for b in BANDS}
    misses, false_alarms = [], []
    for case, o in latest.items():
        c = by_case[case]
        band = c.get("band") if c.get("band") in BANDS else "clear"
        lost = bool(LOSS & set(o.get("happened", [])))
        t = table[band]
        t["came_back"] += 1
        t["lost_something"] += lost
        t["verified_fake"] += o.get("verified") == "job_fake"
        t["verified_real"] += o.get("verified") == "job_real"
        if band in ("clear", "caution") and (lost or o.get("verified") == "job_fake"):
            misses.append({"date": c["date"], "band": band, "rules": c.get("rules", []), "happened": o.get("happened")})
        if band in ("review", "block") and o.get("verified") == "job_real":
            false_alarms.append({"date": c["date"], "band": band, "rules": c.get("rules", [])})
    opened = Counter(c.get("band", "clear") for c in by_case.values())
    return {"school": school or "all", "cases_opened": sum(opened.values()), "opened_by_band": dict(opened),
            "by_band": {b: dict(table[b]) for b in BANDS}, "misses": misses, "false_alarms": false_alarms,
            "missed_rule_counts": dict(Counter(r for m in misses for r in m["rules"]))}


def text(s: dict) -> str:
    lines = [f"Outcomes for {s['school']}: {s['cases_opened']} follow-ups opened", "",
             "| Shown | Came back | Lost something | Later found fake | Later found real |", "|---|---|---|---|---|"]
    for b in BANDS:
        t = s["by_band"][b]
        lines.append(f"| {b} | {t.get('came_back', 0)} | {t.get('lost_something', 0)} | {t.get('verified_fake', 0)} | "
                     f"{t.get('verified_real', 0)} |")
    lines += ["", f"Misses (shown clear or caution, turned out bad): {len(s['misses'])}",
              f"False alarms (shown review or block, job was real): {len(s['false_alarms'])}",
              "Only students who opted in and came back are counted."]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--cases", default=str(CASES))
    ap.add_argument("--outcomes", default=str(OUTCOMES))
    ap.add_argument("--school", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    s = summarize(load(a.cases), load(a.outcomes), a.school)
    print(json.dumps(s, indent=1) if a.json else text(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
