"""
The monthly trends report for a career center (scam_detector/trends.py).

    python -m scam_detector.tools.trends --school fsu                       # last full month, Markdown
    python -m scam_detector.tools.trends --school fsu --month 2026-10 -o fsu-2026-10.md
    python -m scam_detector.tools.trends --school fsu --json                # the numbers, for a dashboard

Uses the database when DATABASE_URL is set, otherwise the development files. Counts only reviewer-confirmed scams;
names no student.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


def last_full_month(today=None) -> str:
    t = today or dt.date.today()
    return f"{t.year - 1}-12" if t.month == 1 else f"{t.year}-{t.month - 1:02d}"


def main(argv=None) -> int:
    from .. import guardrails, trends
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--school", required=True)
    ap.add_argument("--month", default="", help="YYYY-MM; default the last full month")
    ap.add_argument("-o", "--out", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    month = a.month or last_full_month()
    try:
        dt.date.fromisoformat(month + "-01")
    except ValueError:
        print("--month must be YYYY-MM", file=sys.stderr)
        return 2
    data = trends.monthly(a.school, month)
    text = (json.dumps({**data, "retrains": dict(data["retrains"])}, indent=1, default=str) if a.json
            else trends.render(data, guardrails.school_name(a.school) or None))
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {a.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
