"""
Turn public scam reports into rows the rule miner can read.

    python -m scam_detector.tools.import_reports saved.txt --source r/scams -o public_reports.jsonl
    python -m scam_detector.tools.import_reports bbb.csv --source "BBB Scam Tracker" -o public_reports.jsonl
    python -m scam_detector.tools.mine_candidates public_reports.jsonl scam_detector/data/*.jsonl -o proposed.json

Input: a .txt file with one report per blank-line-separated block, or a .csv with a "text" (or "description")
column. Copy the reports yourself from the public pages; this tool never fetches anything, so it stays within
each site's terms.

Every row is labeled "scam" with needs_review: true and a provenance line. Email addresses, phone numbers and
wallets are masked, because victims often paste the scammer's details next to their own. Rows from here are for
rule mining only: they are written by victims, not by scammers, and are not a substitute for reviewer-labeled
training data. train_model.py does not read them unless you add the file yourself.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from ..reports import mask

MIN_CHARS = 60


def read_blocks(path: Path) -> list:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return [(r.get("text") or r.get("description") or "").strip() for r in rows]
    return [b.strip() for b in re.split(r"\n\s*\n", path.read_text(encoding="utf-8"))]


def to_rows(blocks: list, source: str) -> list:
    seen, out = set(), []
    for b in blocks:
        b = mask(re.sub(r"[ \t]+", " ", b)).strip()
        key = re.sub(r"\W+", " ", b.lower()).strip()
        if len(b) < MIN_CHARS or key in seen:
            continue
        seen.add(key)
        out.append({"label": "scam", "title": "", "company": "", "description": b, "source": source,
                    "provenance": "public report, unreviewed", "needs_review": True, "context_flags": []})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("input")
    ap.add_argument("--source", required=True, help="where the reports came from, e.g. r/scams")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args(argv)
    rows = to_rows(read_blocks(Path(a.input)), a.source)
    with open(a.out, "a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} report(s) to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
