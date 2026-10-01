"""
Regression gate for rule changes.

The point of a rulepack you can edit is that anyone (you, a reviewer, the miner)
can add a rule. The point of this gate is that a new rule cannot quietly make the
detector worse. A candidate passes only if:

  1. It causes ZERO new fraud flags on the hard-legit set (data/stress_legit.jsonl)
     and on legit rows in every other corpus.
  2. It does not reduce scam recall on any corpus versus the recorded baseline.

Usage:
    # Check the current rulepack against the recorded baseline
    python -m scam_detector.tools.regress

    # Test a candidate rulepack fragment (proposed rules are treated as active for the test)
    python -m scam_detector.tools.regress --candidate proposed.json

    # After a person has reviewed the candidate: append it to core.json and re-record the baseline
    python -m scam_detector.tools.regress --candidate proposed.json --promote

    # Record the current numbers as the new baseline (after an intentional change)
    python -m scam_detector.tools.regress --write-baseline

Exit status is 0 on pass, 1 on regression, so it can run in CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import rules as rules_mod
from .evaluate import evaluate, load_corpus

DATA = Path(__file__).resolve().parent.parent / "data"
BASELINE = DATA / "baseline.json"
CORE = Path(rules_mod.__file__).parent / "rulepack" / "core.json"
CORPORA = ["real_corpus_clean", "external_scams", "synthetic_scams", "stress_legit", "field_2026_09"]


def measure(rules=None) -> dict:
    if rules is not None:
        saved = rules_mod.RULES
        rules_mod.RULES = rules
    try:
        result = {}
        for name in CORPORA:
            path = DATA / f"{name}.jsonl"
            if not path.exists():
                continue
            corpus = load_corpus(path)
            blind = evaluate(corpus, observed=False)
            obs = evaluate(corpus, observed=True)
            result[name] = {
                "scam_caught": blind["scam"][0], "scam_total": blind["scam"][1],
                "lead_flagged_blind": blind["lead_gen"][0], "lead_flagged_observed": obs["lead_gen"][0],
                "lead_total": blind["lead_gen"][1],
                "false_positives": [e["title"] for e in blind["false_positives"]],
                "legit_total": blind["legit_total"],
            }
        return result
    finally:
        if rules is not None:
            rules_mod.RULES = saved


def compare(new: dict, base: dict) -> list[str]:
    problems = []
    for name, cur in new.items():
        prev = base.get(name)
        for fp in cur["false_positives"]:
            if not prev or fp not in prev["false_positives"]:
                problems.append(f"{name}: NEW false positive on {fp!r}")
        if prev:
            if cur["scam_caught"] < prev["scam_caught"]:
                problems.append(f"{name}: scam recall dropped {prev['scam_caught']} -> {cur['scam_caught']}")
            for k in ("lead_flagged_blind", "lead_flagged_observed"):
                if cur[k] < prev[k]:
                    problems.append(f"{name}: {k} dropped {prev[k]} -> {cur[k]}")
    return problems


def next_version(current: str) -> str:
    """Date-based version, with a counter when several promotions land on the same day."""
    import datetime as dt
    base = dt.date.today().strftime("%Y.%m.%d")
    if current == base:
        return base + ".2"
    if current.startswith(base + "."):
        return f"{base}.{int(current.rsplit('.', 1)[1]) + 1}"
    return base


def _candidate_rules(path: str):
    """Core rules plus the candidate's rules, with status 'proposed' treated as active."""
    spec = json.loads(Path(path).read_text(encoding="utf-8"))
    core_rules, _ = rules_mod.load_rulepack("")
    core_ids = {r.id for r in core_rules}
    extra = []
    for s in spec.get("rules", []):
        s = dict(s, status="active")
        # Promotion into the core pack allows the core weight range; the tighter cap on
        # SCAM_RULEPACK_EXTRA hot-fix rules is enforced when those are loaded.
        rule = rules_mod._compile_rule(s, extra=False)
        if rule.id in core_ids:
            raise rules_mod.RulepackError(f"candidate {rule.id!r} would replace a core rule")
        extra.append(rule)
    return core_rules + extra, spec


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--candidate", help="JSON rulepack fragment to test")
    ap.add_argument("--promote", action="store_true", help="append passing candidate to core.json")
    ap.add_argument("--write-baseline", action="store_true")
    args = ap.parse_args(argv)

    spec = None
    rules = None
    if args.candidate:
        try:
            rules, spec = _candidate_rules(args.candidate)
        except (rules_mod.RulepackError, OSError, json.JSONDecodeError) as e:
            print(f"Candidate rejected: {e}", file=sys.stderr)
            return 1

    rules_mod.reload_rules("")
    base = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    current = measure(rules)

    if args.write_baseline:
        BASELINE.write_text(json.dumps(current, indent=1) + "\n")
        print(f"baseline written to {BASELINE}")
        return 0

    for name, cur in current.items():
        print(f"{name:20} scam {cur['scam_caught']}/{cur['scam_total']}  "
              f"lead blind {cur['lead_flagged_blind']}/{cur['lead_total']} observed {cur['lead_flagged_observed']}/{cur['lead_total']}  "
              f"false positives {len(cur['false_positives'])}/{cur['legit_total']}")
    problems = compare(current, base)
    if problems:
        print("\nREGRESSION:")
        for p in problems:
            print("  -", p)
        return 1
    print("\nPASS: no new false positives, no recall drops.")

    if args.promote:
        if not spec:
            print("--promote needs --candidate", file=sys.stderr)
            return 1
        unreviewed = [s["id"] for s in spec["rules"] if s.get("reviewed") is not True]
        if unreviewed:
            print(f"\nRefusing to promote: {', '.join(unreviewed)} not marked \"reviewed\": true.\n"
                  "Read each rule, set its severity/weight, and mark it reviewed yourself.", file=sys.stderr)
            return 1
        core = json.loads(CORE.read_text(encoding="utf-8"))
        for s in spec["rules"]:
            core["rules"].append({k: v for k, v in dict(s, status="active").items() if k != "reviewed"})
        core["version"] = next_version(core["version"])
        CORE.write_text(json.dumps(core, indent=1) + "\n", encoding="utf-8")
        rules_mod.reload_rules("")
        BASELINE.write_text(json.dumps(measure(), indent=1) + "\n")
        print(f"promoted {len(spec['rules'])} rule(s) into core.json (version {core['version']}); baseline updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
