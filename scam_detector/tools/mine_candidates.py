"""
Propose new rules from the postings the detector missed.

Feed it labeled data (your corpora, plus reviewer decisions exported from the job
board with tools/export_labeled.py). It looks for phrases that:

  * appear in at least --min-support flag-worthy postings that the detector
    scored below the review band (the misses),
  * never appear in any legitimate posting it was given, and
  * are not already matched by an existing rule.

Phrases that occur in the same postings are grouped into one rule. It writes a
rulepack FRAGMENT whose rules all have status "proposed" and "reviewed": false. Proposed
rules are inert: the engine ignores them until a person reads them, runs the
regression gate, and promotes them:

    python -m scam_detector.tools.mine_candidates data/*.jsonl -o proposed.json
    python -m scam_detector.tools.regress --candidate proposed.json
    python -m scam_detector.tools.regress --candidate proposed.json --promote

Why a human stays in the loop: the postings are written by the people you are
defending against. Anything that promoted itself automatically could be steered
by an attacker who submits crafted text. The miner only suggests; you decide.

With a handful of examples it will (correctly) propose little. It gets useful when
the review queue has produced dozens of labeled misses.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .. import rules as rules_mod
from .evaluate import THRESHOLDS, load_corpus, score_row

STOP = set("""a an and are as at be by for from has have i if in is it of on or our that the their this to
we with you your will can not no all any who what when where how they them us was were been being into
than then there these those about also just more most other some such only own same so too very
""".split())


def ngrams(text: str, n_min=2, n_max=4):
    words = re.findall(r"[a-z0-9$%'\-]+", rules_mod.normalize(text).lower())
    for n in range(n_min, n_max + 1):
        for i in range(len(words) - n + 1):
            gram = words[i:i + n]
            if gram[0] in STOP or gram[-1] in STOP:
                continue
            if sum(w not in STOP for w in gram) < 2:
                continue
            yield " ".join(gram)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("corpora", nargs="+", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("proposed.json"))
    ap.add_argument("--min-support", type=int, default=2)
    ap.add_argument("--max-rules", type=int, default=20)
    args = ap.parse_args(argv)

    rows = [r for p in args.corpora for r in load_corpus(p)]
    flagged_bands = THRESHOLDS["review"]
    misses, legit = [], []
    for r in rows:
        if r["label"] == "legit":
            legit.append(r)
        else:
            res = score_row(r, observed=False)
            if res.band not in flagged_bands and not res.lead_gen.get("flag"):
                misses.append(r)

    legit_grams = set()
    for r in legit:
        legit_grams.update(ngrams(r.get("title", "") + " " + r.get("description", "")))

    support: dict[str, set] = {}
    for idx, r in enumerate(misses):
        for g in set(ngrams(r.get("description", ""))):
            support.setdefault(g, set()).add(idx)

    existing = rules_mod.RULES
    qualifying = {}
    for gram, docs in support.items():
        if len(docs) < args.min_support or gram in legit_grams:
            continue
        if any(rx.search(gram) for rule in existing for rx in rule.patterns):
            continue
        qualifying[gram] = frozenset(docs)
    # One phrase should become one rule: drop any gram contained in a longer one seen in the same postings.
    kept = [g for g, d in qualifying.items()
            if not any(g != h and g in h and qualifying[h] == d for h in qualifying)]
    # Phrases that occur in exactly the same postings describe the same technique: one rule, several phrases.
    clusters: dict[frozenset, list] = {}
    for g in kept:
        clusters.setdefault(qualifying[g], []).append(g)
    ordered = sorted(clusters.items(), key=lambda kv: (-len(kv[0]), sorted(kv[0])))[:args.max_rules]

    rules = []
    for i, (docs, grams) in enumerate(ordered, 1):
        grams = sorted(grams, key=lambda g: (-len(g), g))[:8]
        rules.append({
            "id": f"cand_{i:02d}", "status": "proposed", "reviewed": False,
            "severity": "warning", "weight": 20,
            "title": "Technique seen in missed scams (needs your review)",
            "why": f"These phrases appeared together in {len(docs)} flag-worthy postings the detector missed "
                   f"and in no legitimate posting provided. Edit the title and explanation before promoting.",
            "phrases": grams, "patterns": [], "guards": ["negation"],
            "min_matches": 1, "bonus": 3, "added": "mined", "source": f"mine_candidates support={len(docs)}",
        })
    out = {"version": "proposed", "rules": rules,
           "evidence": {"missed_postings": len(misses), "legit_postings_checked": len(legit)}}
    args.out.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(f"{len(misses)} missed posting(s), {len(legit)} legit posting(s) checked -> {len(rules)} candidate rule(s) in {args.out}")
    for r in rules:
        print(f"  {r['id']}: {', '.join(repr(p) for p in r['phrases'][:4])}  ({r['source']})")
    if rules:
        print("  Next: open the file, keep what is really the technique (prefer a regex for the behavior),\n"
              "  set severity/weight, and set \"reviewed\": true on each rule you approve.")
    if not rules:
        print("  Nothing met the bar. That is expected with a small corpus; add more labeled misses.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
