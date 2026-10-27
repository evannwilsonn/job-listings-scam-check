"""
Review student reports: the human step between a report and the network.

    python -m scam_detector.tools.review_queue                      # list pending reports
    python -m scam_detector.tools.review_queue --set 3 confirmed --reviewer "E. Wilson" --note "same script as wave 12"
    python -m scam_detector.tools.review_queue --set 4 dismissed --reviewer "E. Wilson" --note "real staffing agency"

Reads the queue /report writes (REPORT_QUEUE_PATH, default scam_detector/data/report_queue.jsonl). Only reports
marked confirmed here reach tools/export_evidence.py, so nothing a student (or a scammer posing as one) submits
becomes an indicator without a person reading it. The file is rewritten atomically.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

QUEUE = Path(os.environ.get("REPORT_QUEUE_PATH", Path(__file__).resolve().parent.parent / "data" / "report_queue.jsonl"))
DECISIONS = ("confirmed", "dismissed")


def read(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def write(path, rows: list) -> None:
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    tmp.replace(p)


def decide(rows: list, index: int, decision: str, reviewer: str, note: str = "", now=None) -> dict:
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")
    if not reviewer.strip():
        raise ValueError("a reviewer name is required")
    r = rows[index]
    r.update({"status": decision, "reviewer": reviewer.strip()[:80], "note": note.strip()[:500],
              "reviewed_at": (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0).isoformat()})
    return r


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--queue", default=str(QUEUE))
    ap.add_argument("--set", nargs=2, metavar=("INDEX", "DECISION"))
    ap.add_argument("--reviewer", default="")
    ap.add_argument("--note", default="")
    ap.add_argument("--all", action="store_true", help="list reviewed reports too")
    a = ap.parse_args(argv)
    rows = read(a.queue)
    if a.set:
        try:
            r = decide(rows, int(a.set[0]), a.set[1], a.reviewer, a.note)
        except (ValueError, IndexError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        write(a.queue, rows)
        print(f"report {a.set[0]} -> {r['status']} by {r['reviewer']}")
        return 0
    for i, r in enumerate(rows):
        if r.get("status") != "reported" and not a.all:
            continue
        ind = r.get("indicators", {})
        print(f"[{i}] {r.get('received', '')[:10]} {r.get('school') or '-'} {r.get('status')} "
              f"outcome={r.get('outcome') or '-'} domains={ind.get('domains', [])} wallets={len(ind.get('wallets', []))}")
        print("     " + r.get("text_masked", "")[:240].replace("\n", " "))
    return 0


if __name__ == "__main__":
    sys.exit(main())
