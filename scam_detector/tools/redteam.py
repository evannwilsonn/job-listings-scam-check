"""Red-team the detector: rewrite known scams the way a scammer dodging filters would, and measure how many still get caught.

    python -m scam_detector.tools.redteam                      # offline rewrites only (no key needed)
    python -m scam_detector.tools.redteam --ai --per-seed 3    # also asks the AI (needs ANTHROPIC_API_KEY) for paraphrases

Output: data/redteam_eval.jsonl (the variants) and models/REDTEAM_REPORT.md (what slipped through and which trick did it).

The variants are an EVALUATION set only. They are never trained on (train_model.py doesn't read this file): a model trained on
its own attacker's rewrites learns the rewriter, not scammers. What slips through is for a person to read and turn into rules.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
ROOT = PKG.parent
sys.path.insert(0, str(ROOT))

from scam_detector import ml                    # noqa: E402
from scam_detector.scorer import score_posting  # noqa: E402

DATA = PKG / "data"
SEED_FILES = ["field_2026_09_holdout.jsonl", "field_2026_10_holdout.jsonl", "external_scams.jsonl"]
OUT = DATA / "redteam_eval.jsonl"
# Variants that a fix was based on become permanent regression tests (the release gate checks them); every new run
# generates fresh variants for evaluation, so the evaluation set is never the one the fixes were tuned on.
REGRESSION = DATA / "redteam_regression.jsonl"
REPORT = PKG / "models" / "REDTEAM_REPORT.md"

# Swaps a scammer makes to dodge keyword filters, grouped so the report can say which trick worked.
SYNONYMS = {
    "check": ["cheque", "payment document", "funds instrument"], "gift card": ["store voucher", "reward card", "e-code"],
    "telegram": ["the blue chat app", "T-gram", "tele gram"], "whatsapp": ["WA", "whats app", "the green app"],
    "equipment": ["work tools", "setup items", "office kit"], "deposit": ["cash in", "mobile-load", "put in"],
    "bitcoin": ["BTC", "digital coin", "crypto asset"], "zelle": ["Z-pay", "bank app transfer"],
    "weekly": ["every 7 days", "per week", "each week"], "interview": ["screening chat", "meeting"],
    "vendor": ["supplier", "our partner store"], "remote": ["from home", "online-based"],
}
LEET = str.maketrans({"a": "@", "o": "0", "e": "3", "i": "1"})
ZW = "​"


def _swap(text: str, rng: random.Random) -> str:
    out = text
    for k, alts in SYNONYMS.items():
        out = re.sub(rf"\b{re.escape(k)}\b", lambda m: rng.choice(alts), out, flags=re.I)
    return out


def _leet_keywords(text: str, rng: random.Random) -> str:
    return re.sub(r"\b(check|gift|card|telegram|whatsapp|deposit|bitcoin|crypto|zelle|cash)\b",
                  lambda m: m.group(0).translate(LEET), text, flags=re.I)


def _zero_width(text: str, rng: random.Random) -> str:
    return re.sub(r"\b(check|gift|telegram|whatsapp|deposit|bitcoin|payment|bank)\b",
                  lambda m: ZW.join(m.group(0)), text, flags=re.I)


def _polite_rewrite(text: str, rng: random.Random) -> str:
    t = re.sub(r"(?i)\b(urgent|urgently|immediately|asap|right away)\b", "when convenient", text)
    t = re.sub(r"(?i)\bkindly\b", "please", t)
    return "Hope your semester is going well! " + t + " Let me know if you have questions, happy to help."


def _drop_money(text: str, rng: random.Random) -> str:
    return re.sub(r"\$\s?\d[\d,]*(?:\.\d\d)?", "competitive pay", text)


TRICKS = {"synonyms": _swap, "leetspeak": _leet_keywords, "zero_width": _zero_width, "polite_tone": _polite_rewrite,
          "no_dollar_amounts": _drop_money}


def offline_variants(row: dict, rng: random.Random) -> list[dict]:
    out = []
    for name, fn in TRICKS.items():
        out.append({"trick": name, "title": row.get("title", ""), "description": fn(row["description"], rng)})
    combo = _polite_rewrite(_swap(row["description"], rng), rng)
    out.append({"trick": "synonyms+polite_tone", "title": row.get("title", ""), "description": combo})
    return out


def ai_variants(row: dict, n: int) -> list[dict]:
    try:
        import ai                               # NoleCareerShield's AI helper; not part of this standalone repo
    except ImportError:
        print("--ai needs NoleCareerShield's ai.py; skipping AI rewrites", file=sys.stderr)
        return []
    schema = {"type": "object", "properties": {"variants": {"type": "array", "items": {"type": "string"}, "maxItems": n}},
              "required": ["variants"]}
    system = ("You help test a university's job-scam detector. Rewrite the scam below the way a scammer would to avoid "
              "keyword filters: same scheme and same asks, different wording, natural tone, no obvious red-flag words. "
              "Keep any contact details as they are. Return plain text variants only.")
    try:
        got = ai.structured(system, ai.tag("scam", row["description"], 6000), "variants", schema)
    except Exception as e:                      # noqa: BLE001
        print(f"AI rewrite failed for {row.get('id')}: {e}", file=sys.stderr)
        return []
    return [{"trick": "ai_paraphrase", "title": row.get("title", ""), "description": v[:8000]} for v in got.get("variants", [])[:n]]


def caught(title: str, description: str, company: str = "") -> tuple[bool, str]:
    res = score_posting(title, description, company, run_network=False)
    if res.band in ("review", "block"):
        return True, "rules"
    m = ml.load()
    if m:
        p = m.predict(title, description, company, "", res.findings, res.score)
        if p["flag"]:
            return True, "model"
    return False, res.band


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def main(argv=None) -> dict:
    a = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    a.add_argument("--ai", action="store_true", help="also ask the AI for paraphrases")
    a.add_argument("--per-seed", type=int, default=2)
    a.add_argument("--limit", type=int, default=60, help="max scam seeds")
    a.add_argument("--seed", type=int, default=None, help="default: a new one every run, so each evaluation is fresh")
    a.add_argument("--save-regression", action="store_true",
                   help="add this run's slipped variants to redteam_regression.jsonl once you've fixed them (the release gate checks them)")
    a.add_argument("--regression", default=str(REGRESSION))
    a.add_argument("--out", default=str(OUT))
    a.add_argument("--report", default=str(REPORT))
    args = a.parse_args(argv)
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(1 << 30)
    rng = random.Random(seed)
    regression = load(Path(args.regression))
    reg_texts = {r["description"] for r in regression}
    seeds = [r for f in SEED_FILES for r in load(DATA / f) if r.get("label") == "scam" and r.get("description")]
    rng.shuffle(seeds)
    seeds = seeds[:args.limit]
    for i, s in enumerate(seeds):
        s.setdefault("id", f"seed{i + 1}")
    rows, by_trick, slipped = [], {}, []
    base_caught = 0
    for s in seeds:
        ok0, _ = caught(s.get("title", ""), s["description"], s.get("company", ""))
        base_caught += ok0
        vs = offline_variants(s, rng) + (ai_variants(s, args.per_seed) if args.ai else [])
        for v in vs:
            ok, how = caught(v["title"], v["description"], s.get("company", ""))
            t = by_trick.setdefault(v["trick"], [0, 0])
            t[0] += ok
            t[1] += 1
            row = {"id": f"{s.get('id', 'seed')}-{v['trick']}", "seed": s.get("id"), "label": "scam", "trick": v["trick"],
                   "title": v["title"], "company": s.get("company", ""), "description": v["description"], "caught_by": how if ok else None}
            rows.append(row)
            if not ok and ok0 and v["description"] not in reg_texts:
                slipped.append(row)
    Path(args.out).write_text("".join(json.dumps(r) + "\n" for r in rows))
    lines = ["# Red-team report", "",
             f"{len(seeds)} scam seeds from the holdouts and archives; the originals are caught {base_caught}/{len(seeds)}.",
             "Each seed is rewritten with the tricks below. A variant counts as caught when the rules send it to a person or the "
             f"model flags it. Run seed {seed}: every run makes new variants, so fixes are never graded on the variants they were "
             "built from.", "",
             "| Trick | Variants caught |", "|---|---|"]
    lines += [f"| {k} | {v[0]}/{v[1]} |" for k, v in sorted(by_trick.items())]
    lines += ["", f"## Slipped through ({len(slipped)}): the original was caught, the rewrite wasn't", ""]
    for r in slipped[:25]:
        lines.append(f"- **{r['trick']}** (seed {r['seed']}): {r['description'][:220]}")
    reg_caught = sum(caught(r.get("title", ""), r["description"], r.get("company", ""))[0] for r in regression)
    lines += ["", f"## Regression set: {reg_caught}/{len(regression)} still caught",
              "Variants saved after a fix was made for them (`--save-regression`). The release gate requires every new model to "
              "catch at least as many as the active one.", "",
              "These are for a person to read and turn into rules or normalization. They are never trained on."]
    if args.save_regression and slipped:
        with Path(args.regression).open("a", encoding="utf-8") as fh:
            for r in slipped:
                fh.write(json.dumps({k: r[k] for k in ("id", "seed", "label", "trick", "title", "company", "description")}) + "\n")
        lines.append(f"Saved {len(slipped)} slipped variants to the regression set.")
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:12 + len(by_trick)]))
    return {"seeds": len(seeds), "by_trick": by_trick, "slipped": len(slipped), "seed": seed, "regression": [reg_caught, len(regression)]}


if __name__ == "__main__":
    main()
