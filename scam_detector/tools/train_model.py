"""
Train the learned layer (scam_detector/ml.py) and ship it only if it earns it.

    pip install -r requirements-dev.txt          # scikit-learn is for training only
    python -m scam_detector.tools.train_model                       # train, test, write if it passes
    python -m scam_detector.tools.train_model --extra labeled.jsonl # add reviewer decisions (export_labeled.py)
    python -m scam_detector.tools.train_model --dry-run             # report only
    python -m scam_detector.tools.train_model --propose proposed.json   # also write the wording it learned as rule candidates

What it trains on
  * Every real labeled corpus in data/ except the frozen holdout, plus the synthetic scams at half weight,
    plus any --extra files. Labels: scam = 1; legit and lead_gen = 0 (lead-gen has its own axis).
  * Near-copies count once: rows whose wording overlaps heavily are grouped and share one row's weight, and
    cross-validation never splits a group. A training row that near-copies a holdout row is dropped, so the
    holdout stays unseen.
  * Adversarial copies: every training scam is also seen rewritten the way a filter-dodging scammer would
    (the offline tricks in tools/redteam.py: synonyms, leetspeak, zero-width characters, a polite tone, no dollar
    amounts), at AUG_WEIGHT of the original's weight. They are made inside each training fold, never from a
    holdout row, so the frozen holdouts and data/redteam_eval.jsonl stay unseen. --no-augment turns this off.

What it learns from (model format 2, see ml.py): which rules fired, words and phrases, pieces of words, and
the shape of the text (how much it talks to "you", requirements and benefits language, shouting, emoji, ...).

What it must pass before it writes models/scam_model.json
  1. Holdout (data/field_2026_09_holdout.jsonl + field_2026_10_holdout.jsonl, never trained on): the rules plus the
     model catch more scams than the rules alone, and no fewer than the model currently shipped.
  2. No new false alarms: not one legit row that the rules leave alone gets flagged by the model, on the
     holdout or on the hard-legit set (data/stress_legit.jsonl, also never trained on).
The threshold is picked from cross-validation on the training rows, as the lowest one that flags no legit row
the rules leave alone, plus a MARGIN of 0.1 (the legit rows are few), and never below 0.5.

Every run writes models/TRAINING_REPORT.md with the numbers, including the wording the model now weighs that no
rule covers (the "learned, not yet a rule" list): what a person should read next.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import sys
from pathlib import Path

import numpy as np

from .. import ml
from ..rules import run_text_rules
from ..scorer import score_posting

try:
    from scipy.sparse import csr_matrix, hstack
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedGroupKFold
except ImportError:                                                   # pragma: no cover
    raise SystemExit("Training needs scikit-learn: pip install -r requirements-dev.txt")

DATA = Path(os.environ.get("LURECHECK_DATA", Path(__file__).resolve().parent.parent / "data"))
MODELS = ml.MODEL_PATH.parent
TRAIN_FILES = ["field_2026_09_tune.jsonl", "field_2026_10_tune.jsonl", "boards_2026_10_train.jsonl", "boards_2026_10_rules.jsonl",
               "labeled_seed.jsonl", "real_corpus_clean.jsonl", "external_scams.jsonl", "candidates_2026_10_22.jsonl",
               "live_in_2026_10_22.jsonl"]
HALF_WEIGHT = ["synthetic_scams.jsonl"]
HOLDOUTS = ["field_2026_09_holdout.jsonl", "field_2026_10_holdout.jsonl"]     # frozen, never trained on
HARD_LEGIT = "stress_legit.jsonl"
RULE_SCALE = 3.0
SHAPE_SCALE = 1.0
C = 4.0
NEAR_COPY = 0.6          # word-trigram overlap (Jaccard) that counts as the same template
MARGIN = 0.1             # added to the lowest safe threshold: the quiet legit rows are few, so the edge they set is not exact
AUG_WEIGHT = 0.3       # weight of each adversarial copy of a training scam, relative to the original
AUG_SEED = 7
CHAR_MAX = 6000
DRIFT_BINS = 10


def load(path: Path, weight: float = 1.0) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("label") in ("scam", "legit", "lead_gen"):
                r["_w"], r["_src"] = weight, path.name
                rows.append(r)
    return rows


def text_of(r: dict) -> str:
    return ml.posting_text(r.get("title", ""), r.get("description", ""), r.get("company", ""), r.get("url") or r.get("apply_url") or "")


def shingles(r: dict) -> set:
    t = ml.tokens(text_of(r))
    return {" ".join(t[i:i + 3]) for i in range(max(1, len(t) - 2))}


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def rules_for(r: dict) -> dict:
    if "_rules" not in r:
        url = r.get("url") or r.get("apply_url") or ""
        res = score_posting(r.get("title", ""), r.get("description", ""), r.get("company", ""), run_network=False,
                            url_chain=[url] if url else None)
        r["_rules"] = {"findings": res.findings, "score": res.score, "flag": res.band in ("review", "block")}
    return r["_rules"]


def groups(rows: list[dict]) -> list[int]:
    sh = [shingles(r) for r in rows]
    parent = list(range(len(rows)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            if jaccard(sh[i], sh[j]) >= NEAR_COPY:
                parent[find(i)] = find(j)
    return [find(i) for i in range(len(rows))]


def adversarial_copies(rows: list[dict], weight: float = AUG_WEIGHT, seed: int = AUG_SEED) -> list[dict]:
    """Rewrites of the scams in `rows` the way a filter-dodging scammer would (tools/redteam.py's offline tricks).
    Only ever called on training rows."""
    from .redteam import offline_variants
    rng = random.Random(seed)
    out = []
    for r in rows:
        if r["label"] != "scam":
            continue
        for v in offline_variants(r, rng):
            c = {k: val for k, val in r.items() if k != "_rules"}
            c.update({"description": v["description"], "_w": r["_w"] * weight, "_aug": v["trick"]})
            out.append(c)
    return out


class Trained:
    def __init__(self, rows: list[dict], rule_ids: list[str], augment: bool = True):
        self.rule_ids = rule_ids
        rows = list(rows) + (adversarial_copies(rows) if augment else [])
        self.tfidf = TfidfVectorizer(analyzer=ml.analyzer, min_df=2, sublinear_tf=True, max_features=3000)
        self.ctfidf = TfidfVectorizer(analyzer=ml.char_analyzer, min_df=3, sublinear_tf=True, max_features=CHAR_MAX)
        X = self._X(rows, fit=True)
        y = np.array([r["label"] == "scam" for r in rows], dtype=int)
        self.lr = LogisticRegression(C=C, class_weight="balanced", max_iter=5000)
        self.lr.fit(X, y, sample_weight=np.array([r["_w"] for r in rows]))

    def _X(self, rows, fit=False):
        texts = [text_of(r) for r in rows]
        T = self.tfidf.fit_transform(texts) if fit else self.tfidf.transform(texts)
        Cm = self.ctfidf.fit_transform(texts) if fit else self.ctfidf.transform(texts)
        S = csr_matrix(np.array([ml.shape_features(t) for t in texts])) * SHAPE_SCALE
        R = csr_matrix(np.array([ml.rule_features(rules_for(r)["findings"], rules_for(r)["score"], self.rule_ids) for r in rows]) * RULE_SCALE)
        return hstack([T, Cm, S, R]).tocsr()

    def proba(self, rows):
        return self.lr.predict_proba(self._X(rows))[:, 1]

    def blocks(self) -> tuple[dict, dict, list, list]:
        """(word vocab, char vocab, shape coefficients, rule coefficients) from the fitted model."""
        coef = self.lr.coef_[0]
        nw, nc, ns = len(self.tfidf.vocabulary_), len(self.ctfidf.vocabulary_), len(ml.SHAPE)
        vocab = {t: [round(float(self.tfidf.idf_[i]), 6), round(float(coef[i]), 6)] for t, i in sorted(self.tfidf.vocabulary_.items())}
        cvocab = {t: [round(float(self.ctfidf.idf_[i]), 6), round(float(coef[nw + i]), 6)] for t, i in sorted(self.ctfidf.vocabulary_.items())}
        shape = [round(float(c), 6) for c in coef[nw + nc:nw + nc + ns]]
        rules = [round(float(c), 6) for c in coef[nw + nc + ns:]]
        return vocab, cvocab, shape, rules

    def export(self, threshold: float, meta: dict) -> dict:
        vocab, cvocab, shape, rules = self.blocks()
        spec = {"format": ml.FORMAT, "threshold": round(threshold, 4), "rule_scale": RULE_SCALE, "shape_scale": SHAPE_SCALE,
                "rule_ids": self.rule_ids, "rule_coef": rules, "shape_coef": shape, "intercept": round(float(self.lr.intercept_[0]), 6),
                "vocab": vocab, "cvocab": cvocab, **meta}
        spec["version"] = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:12]
        return spec


def system_flags(rows, probs, threshold):
    """What the site does: the rules flag it, or the model does (the model can only add)."""
    return [rules_for(r)["flag"] or p >= threshold for r, p in zip(rows, probs)]


def tally(rows, flags) -> dict:
    t = {"scam": 0, "scam_total": 0, "legit_flagged": [], "legit_total": 0, "lead_called_scam": 0, "lead_total": 0}
    for r, f in zip(rows, flags):
        lab = r["label"]
        if lab == "scam":
            t["scam_total"] += 1; t["scam"] += bool(f)
        elif lab == "legit":
            t["legit_total"] += 1
            if f:
                t["legit_flagged"].append(r.get("id") or r.get("title", "")[:60])
        else:
            t["lead_total"] += 1; t["lead_called_scam"] += bool(f)
    return t


def line(name, t) -> str:
    lead = f" | {t['lead_called_scam']}/{t['lead_total']}" if t["lead_total"] else " | -"
    return (f"| {name} | {t['scam']}/{t['scam_total']} | {len(t['legit_flagged'])}/{t['legit_total']}{lead} |"
            if t["scam_total"] or t["legit_total"] else f"| {name} | - | - | - |")


def conformal_quantiles(oof, y, alpha: float = 0.1) -> dict:
    """Class-conditional (Mondrian) split conformal from out-of-fold probabilities: each class keeps its own 1-alpha
    coverage, so the rare scam class isn't under-covered. The site calls a case 'uncertain' when the prediction set
    isn't exactly one class, and routes it to a person first."""
    out = {"alpha": alpha}
    for name, scores in (("q_scam", [1 - p for p, t in zip(oof, y) if t == 1]), ("q_legit", [p for p, t in zip(oof, y) if t == 0])):
        n = len(scores)
        if n < 5:
            out[name] = 1.0
            continue
        k = min(n, int(np.ceil((n + 1) * (1 - alpha))))
        out[name] = round(float(sorted(scores)[k - 1]), 6)
    return out


def histogram(values, bins: int = DRIFT_BINS) -> list[float]:
    """Share of values in each of `bins` equal-width bins over [0, 1] (what drift.py compares live traffic against)."""
    counts = [0] * bins
    for v in values:
        counts[min(bins - 1, max(0, int(float(v) * bins)))] += 1
    n = max(1, len(values))
    return [round(c / n, 4) for c in counts]


def gate(rules_h: dict, new_h: dict, rules_s: dict, new_s: dict, cur_h: dict | None = None) -> list[str]:
    """Why a candidate may not ship (empty list = it may)."""
    problems = []
    if new_h["scam"] < rules_h["scam"]:
        problems.append("catches fewer holdout scams than the rules alone")
    if cur_h and new_h["scam"] < cur_h["scam"]:
        problems.append(f"catches fewer holdout scams than the shipped model ({cur_h['scam']})")
    if new_h["scam"] == rules_h["scam"] and not cur_h:
        problems.append("adds nothing over the rules on the holdout")
    for name, before, after in (("holdout", rules_h, new_h), ("hard-legit set", rules_s, new_s)):
        extra = sorted(set(after["legit_flagged"]) - set(before["legit_flagged"]))
        if extra:
            problems.append(f"new false alarm(s) on the {name}: {', '.join(map(str, extra))}")
    return problems


# ---------- what it learned that no rule covers ----------

def learned_phrases(model: Trained, rows: list[dict], top: int = 25, min_scam: int = 2) -> list[dict]:
    """Words and phrases the model weighs toward scam that no rule matches on their own, with how many training scams and
    legit rows contain them. The reviewer's reading list: each is a candidate rule, never a rule by itself."""
    vocab, _, _, _ = model.blocks()
    by_row = [set(ml.analyzer(text_of(r))) for r in rows]
    out = []
    for term, (idf, coef) in sorted(vocab.items(), key=lambda kv: -kv[1][1]):
        if coef <= 0:
            break
        in_scam = sum(1 for r, s in zip(rows, by_row) if r["label"] == "scam" and term in s)
        in_legit = sum(1 for r, s in zip(rows, by_row) if r["label"] != "scam" and term in s)
        if in_scam < min_scam or in_legit > in_scam // 3:
            continue
        if run_text_rules(term):                 # a rule already fires on this wording alone
            continue
        out.append({"term": term, "weight": round(coef, 3), "scam_rows": in_scam, "legit_rows": in_legit})
        if len(out) >= top:
            break
    return out


def proposal_fragment(learned: list[dict], rows_total: int) -> dict:
    """A rulepack fragment in the same shape as tools/mine_candidates.py writes: status 'proposed', inert until a person
    marks it reviewed and tools/regress.py --promote passes."""
    rules = []
    for i, p in enumerate([x for x in learned if " " in x["term"]][:10], 1):
        rules.append({
            "id": f"learned_{i:02d}", "status": "proposed", "reviewed": False, "severity": "warning", "weight": 15,
            "title": "Wording the model learned (needs your review)",
            "why": (f"The trained model weighs \"{p['term']}\" toward scam (+{p['weight']}); it appears in {p['scam_rows']} labeled scams "
                    f"and {p['legit_rows']} legitimate postings of {rows_total}. Edit the title, phrases and weight before promoting."),
            "phrases": [p["term"]], "patterns": [], "guards": ["negation"], "min_matches": 1, "bonus": 0,
            "added": "learned", "source": f"train_model weight={p['weight']} support={p['scam_rows']}",
        })
    return {"version": "proposed", "rules": rules, "evidence": {"training_rows": rows_total}}


LAST_RESULT: dict = {}      # what the last main() call did, for learning.py: ok, version, report, rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--extra", nargs="*", default=[], help="more labeled JSONL, e.g. export_labeled.py output")
    ap.add_argument("--dry-run", action="store_true", help="report only, never write the model")
    ap.add_argument("--out", default=str(ml.MODEL_PATH))
    ap.add_argument("--holdout-extra", nargs="*", default=[], help="more frozen holdout JSONL (the live board's monthly holdout)")
    ap.add_argument("--current", default="", help="the model a candidate must not do worse than (default: --out, else the repo model)")
    ap.add_argument("--report-dir", default=str(MODELS), help="where TRAINING_REPORT.md goes")
    ap.add_argument("--no-augment", action="store_true", help="train without adversarial copies of the training scams")
    ap.add_argument("--propose", default="", help="write the wording the model learned as a proposed rulepack fragment here")
    a = ap.parse_args(argv)
    LAST_RESULT.clear()
    augment = not a.no_augment

    holdout = [r for f in HOLDOUTS for r in load(DATA / f)] + [r for f in a.holdout_extra for r in load(Path(f))]
    hard = load(DATA / HARD_LEGIT)
    train = [r for f in TRAIN_FILES for r in load(DATA / f)] + [r for f in HALF_WEIGHT for r in load(DATA / f, 0.5)]
    train += [r for f in a.extra for r in load(Path(f))]

    # exact duplicates count once; anything that near-copies a holdout row leaves training
    seen, dedup = set(), []
    for r in train:
        k = " ".join(ml.tokens(text_of(r)))
        if k not in seen:
            seen.add(k); dedup.append(r)
    hsh = [shingles(r) for r in holdout + hard]
    leak = [r for r in dedup if any(jaccard(shingles(r), h) >= NEAR_COPY for h in hsh)]
    train = [r for r in dedup if r not in leak]
    g = groups(train)
    size = {k: g.count(k) for k in set(g)}
    for r, k in zip(train, g):
        r["_w"] = r["_w"] / size[k]

    rule_ids = sorted({f["rule_id"] for r in train for f in rules_for(r)["findings"]})
    y = np.array([r["label"] == "scam" for r in train], dtype=int)

    # threshold from out-of-fold predictions (5 folds, templates never split); novelty measured the same way
    oof, oof_novelty = np.zeros(len(train)), np.zeros(len(train))
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=7).split(train, y, g):
        m = Trained([train[i] for i in tr], rule_ids, augment)
        test = [train[i] for i in te]
        oof[te] = m.proba(test)
        fold = ml.Model(m.export(0.5, {}))
        oof_novelty[te] = [fold.novelty(r.get("title", ""), r.get("description", ""), r.get("company", ""), r.get("url") or "") for r in test]
    quiet_legit = [i for i, r in enumerate(train) if r["label"] == "legit" and not rules_for(r)["flag"]]
    threshold = 0.95
    for t in np.arange(0.5, 0.951, 0.01):
        if all(oof[i] < t for i in quiet_legit):
            threshold = round(min(0.95, float(t) + MARGIN), 2)
            break
    cv = tally(train, system_flags(train, oof, threshold))
    conformal = conformal_quantiles(oof, y)
    drift_ref = {"score_hist": histogram(oof), "novelty_hist": histogram(oof_novelty), "rows": len(train),
                 "flag_rate": round(float(np.mean(oof >= threshold)), 4), "novelty_mean": round(float(np.mean(oof_novelty)), 4)}

    model = Trained(train, rule_ids, augment)
    rules_h, rules_s = tally(holdout, [rules_for(r)["flag"] for r in holdout]), tally(hard, [rules_for(r)["flag"] for r in hard])
    hold_p = model.proba(holdout)
    new_h = tally(holdout, system_flags(holdout, hold_p, threshold))
    per_file = []
    for f in HOLDOUTS + [Path(x).name for x in a.holdout_extra]:
        idx = [i for i, r in enumerate(holdout) if r["_src"] == f]
        rows_f = [holdout[i] for i in idx]
        per_file += [line(f"  {f}, rules alone", tally(rows_f, [rules_for(r)["flag"] for r in rows_f])),
                     line(f"  {f}, rules + this model", tally(rows_f, system_flags(rows_f, [hold_p[i] for i in idx], threshold)))]
    new_s = tally(hard, system_flags(hard, model.proba(hard), threshold))

    cur_path = Path(a.current) if a.current else (Path(a.out) if Path(a.out).exists() else ml.MODEL_PATH)
    current = ml.load(cur_path) if cur_path.exists() else None
    cur_h = None
    if current:
        cur_p = [current.predict(r.get("title", ""), r.get("description", ""), r.get("company", ""), r.get("url") or "",
                                 rules_for(r)["findings"], rules_for(r)["score"])["probability"] for r in holdout]
        cur_h = tally(holdout, system_flags(holdout, cur_p, current.threshold))

    problems = gate(rules_h, new_h, rules_s, new_s, cur_h)
    ok = not problems

    learned = learned_phrases(model, train)
    counts = {k: int(sum(r["label"] == k for r in train)) for k in ("scam", "legit", "lead_gen")}
    n_aug = len(adversarial_copies(train)) if augment else 0
    meta = {"conformal": conformal, "drift_ref": drift_ref, "trained_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
            "trained_on": {"rows": len(train), **counts, "files": sorted({r["_src"] for r in train}), "adversarial_copies": n_aug,
                           "dropped_near_copies_of_holdout": len(leak), "template_groups": len(size)},
            "holdout": {"rules": [rules_h["scam"], rules_h["scam_total"], len(rules_h["legit_flagged"])],
                        "with_model": [new_h["scam"], new_h["scam_total"], len(new_h["legit_flagged"])]}}
    report = "\n".join([
        f"# Model training report ({meta['trained_at']})", "",
        f"Trained on {len(train)} rows ({counts['scam']} scam, {counts['legit']} legit, {counts['lead_gen']} lead-gen) in "
        f"{len(size)} template groups, plus {n_aug} adversarial copies of the training scams at {AUG_WEIGHT:g} weight. "
        f"Dropped {len(leak)} training rows that near-copied a holdout or hard-legit row.",
        f"Threshold {threshold:.2f} (lowest that flags no rules-quiet legit row in cross-validation, plus a {MARGIN:g} margin). Model format {ml.FORMAT}: "
        f"rules, words and phrases, pieces of words, and the shape of the text.", "",
        "| Set | Scams caught | Legit wrongly flagged | Lead-gen called scam |", "|---|---|---|---|",
        line("Cross-validation, rules + model", cv),
        line("Holdout, rules alone", rules_h),
        *( [line("Holdout, rules + shipped model", cur_h)] if cur_h else []),
        line("Holdout, rules + this model", new_h),
        *per_file,
        line("Hard-legit set, rules alone", rules_s),
        line("Hard-legit set, rules + this model", new_s), "",
        "**Result: " + ("passed" if ok else "did not pass: " + "; ".join(problems)) + "**", "",
        "## Learned, not yet a rule", "",
        "Wording the model now weighs toward scam that no rule fires on by itself. Read these; the useful ones become rules "
        "(`--propose` writes them as a proposed rulepack fragment for tools/regress.py).", "",
        "| Wording | Weight | In labeled scams | In legit rows |", "|---|---|---|---|",
        *([f"| {p['term']} | +{p['weight']} | {p['scam_rows']} | {p['legit_rows']} |" for p in learned] or ["| (nothing above the bar yet) | | | |"]), "",
        "Numbers this small are a sanity check, not a measured accuracy. Add reviewer decisions with --extra and retrain.",
    ])
    Path(a.report_dir).mkdir(parents=True, exist_ok=True)
    (Path(a.report_dir) / "TRAINING_REPORT.md").write_text(report + "\n")
    print(report)
    if a.propose:
        Path(a.propose).write_text(json.dumps(proposal_fragment(learned, len(train)), indent=1) + "\n")
        print(f"\nwrote {a.propose} ({len([x for x in learned if ' ' in x['term']][:10])} proposed rule(s), all inert until reviewed)")
    LAST_RESULT.update({"ok": ok, "problems": problems, "report": report, "rows": len(train), "holdout_rows": len(holdout),
                        "holdout": meta["holdout"], "threshold": threshold, "version": None, "written": False, "learned": learned})
    if ok and not a.dry_run:
        spec = model.export(threshold, meta)
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(a.out) + ".tmp")
        tmp.write_text(json.dumps(spec, separators=(",", ":"), sort_keys=True))
        tmp.replace(a.out)                                  # atomic: the site never reads a half-written model
        LAST_RESULT.update({"version": spec["version"], "written": True})
        print(f"\nwrote {a.out} (version {spec['version']}, {len(spec['vocab'])} phrases, {len(spec['cvocab'])} word pieces, "
              f"{len(rule_ids)} rules)")
    elif not ok:
        print("\nModel not written.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
