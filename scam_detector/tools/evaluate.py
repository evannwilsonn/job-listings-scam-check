"""
Evaluation harness.

Runs the scorer against labeled corpora and reports, per corpus:

  * fraud axis: did a scam land in the block/review bands, and did a legitimate
    posting stay out of them?
  * lead-gen axis: was an aggregator / lead-generation listing flagged? (This is a
    separate verdict, not a scam band; see leadgen.py.)
  * which rules fire on legitimate postings (the noisy ones), and which rules carry
    the scam detections.

Corpus rows are JSON Lines:

    {"label": "scam"|"lead_gen"|"legit", "title": "...", "company": "...",
     "description": "posting text ONLY", "url": "a -> b -> c" (optional),
     "context_flags": ["signup_wall_reported"] (optional), "notes": "labeler notes"}

Keep the labeler's observations in `notes` and `context_flags`, never inside
`description`. The description is exactly what a user would paste; anything else
lets the detector read your answer key.

Usage:
    python -m scam_detector.tools.evaluate data/real_corpus_clean.jsonl
    python -m scam_detector.tools.evaluate data/*.jsonl --observed
    python -m scam_detector.tools.evaluate data/stress_legit.jsonl --verbose

Network lookups are off by default so evaluation is fast and deterministic.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from ..scorer import score_posting

THRESHOLDS = {
    "block":   {"block"},
    "review":  {"block", "review"},
    "caution": {"block", "review", "caution"},
}
LABELS = ("scam", "lead_gen", "legit")


def load_corpus(path: Path) -> list[dict]:
    rows = []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"skipping malformed line {i}: {e}", file=sys.stderr)
            continue
        if row.get("label") not in LABELS:
            print(f"skipping line {i}: label must be one of {LABELS}", file=sys.stderr)
            continue
        rows.append(row)
    return rows


def score_row(row: dict, run_network: bool = False, observed: bool = False):
    chain = [u.strip() for u in row.get("url", "").split("->") if u.strip()]
    return score_posting(
        title=row.get("title", ""), description=row.get("description", ""),
        company=row.get("company", ""), run_network=run_network,
        context_flags=row.get("context_flags", []) if observed else None,
        url_chain=chain or None,
    )


def evaluate(corpus: list[dict], threshold: str = "review", run_network: bool = False,
             observed: bool = False) -> dict:
    bands = THRESHOLDS[threshold]
    out = {"n": len(corpus), "threshold": threshold, "observed": observed,
           "scam": [0, 0], "lead_gen": [0, 0], "legit_ok": 0, "legit_total": 0,
           "misses": [], "false_positives": [], "rules_on_legit": Counter(), "rules_on_bad": Counter(),
           "rows": []}
    for row in corpus:
        res = score_row(row, run_network, observed)
        fraud_flag = res.band in bands
        lead_flag = bool(res.lead_gen.get("flag"))
        rules = [f["rule_id"] for f in res.findings]
        entry = {"label": row["label"], "title": row.get("title", ""), "score": res.score,
                 "band": res.band, "lead_gen": lead_flag, "rules": rules}
        out["rows"].append(entry)
        if row["label"] == "scam":
            out["scam"][1] += 1
            if fraud_flag:
                out["scam"][0] += 1
            else:
                out["misses"].append(entry)
            out["rules_on_bad"].update(rules)
        elif row["label"] == "lead_gen":
            out["lead_gen"][1] += 1
            if lead_flag or fraud_flag:
                out["lead_gen"][0] += 1
            else:
                out["misses"].append(entry)
            out["rules_on_bad"].update(rules)
        else:
            out["legit_total"] += 1
            if fraud_flag:
                out["false_positives"].append(entry)
            else:
                out["legit_ok"] += 1
            out["rules_on_legit"].update(rules)
    return out


def summarize(r: dict) -> str:
    parts = []
    if r["scam"][1]:
        parts.append(f"scam {r['scam'][0]}/{r['scam'][1]} caught")
    if r["lead_gen"][1]:
        parts.append(f"lead_gen {r['lead_gen'][0]}/{r['lead_gen'][1]} flagged")
    if r["legit_total"]:
        parts.append(f"legit {r['legit_ok']}/{r['legit_total']} left alone")
    return "; ".join(parts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate the scam detector against labeled data.")
    ap.add_argument("corpora", nargs="+", type=Path, help="one or more JSONL labeled corpora")
    ap.add_argument("--threshold", choices=list(THRESHOLDS), default="review",
                    help="fraud band that counts as flagged (default: review)")
    ap.add_argument("--observed", action="store_true",
                    help="also feed each row's context_flags (things a user would report)")
    ap.add_argument("--network", action="store_true", help="run live domain/MX lookups")
    ap.add_argument("--verbose", action="store_true", help="print every row")
    args = ap.parse_args(argv)

    for path in args.corpora:
        corpus = load_corpus(path)
        if not corpus:
            print(f"{path}: no valid rows", file=sys.stderr)
            continue
        r = evaluate(corpus, args.threshold, args.network, args.observed)
        mode = "with observed flags" if args.observed else "blind (text + url only)"
        print(f"\n{path.name}  n={r['n']}  {mode}  flag if fraud band in {sorted(THRESHOLDS[args.threshold])}")
        print("  " + summarize(r))
        if args.verbose:
            for e in r["rows"]:
                print(f"    {e['label']:8} {e['band']:8} {e['score']:3} lead={e['lead_gen']!s:5} {e['title'][:50]}  {e['rules']}")
        for e in r["misses"]:
            print(f"  MISSED ({e['label']}): {e['title'][:60]!r} score {e['score']} ({e['band']})")
        for e in r["false_positives"]:
            print(f"  FALSE POSITIVE: {e['title'][:60]!r} score {e['score']} ({e['band']}) rules={e['rules']}")
        if r["rules_on_legit"]:
            noisy = ", ".join(f"{k} x{v}" for k, v in r["rules_on_legit"].most_common(6))
            print(f"  rules firing on legit postings: {noisy}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
