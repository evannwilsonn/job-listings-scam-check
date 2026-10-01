"""
The learned layer: a small model that reads a posting the way a reviewer would and asks
"does this look like the scams we've labeled?"

What it is
  * Logistic regression over two kinds of evidence:
      - which rules fired (and the rules' total score), so it learns how much each rule
        should really count, and
      - words and two-word phrases (TF-IDF), so it can pick up wording no rule covers yet.
  * Trained by `python -m scam_detector.tools.train_model` from the labeled corpora plus
    reviewer decisions exported from the board. The result is one JSON file
    (models/scam_model.json). No scikit-learn at run time: inference below is plain Python,
    and demo/ml.js does the same maths in the browser.

What it is allowed to do
  * Only escalate. When the rules say "clear" or "caution" and the model is confident,
    the listing goes to a person with the finding "model_second_look". It never lowers a
    rule verdict and never rejects anything on its own.
  * Explain itself: the finding names the rules and phrases that pushed it up.

Turn it off with SCAM_MODEL=off (for example while a new model is being checked).
"""

from __future__ import annotations

import json
import math
import os
import re
from functools import lru_cache
from pathlib import Path

from .rules import normalize

MODEL_PATH = Path(__file__).resolve().parent / "models" / "scam_model.json"
FORMAT = 1

_TOKEN = re.compile(r"\$?[a-z0-9]+")
_DIGIT = re.compile(r"[0-9]")
# Leftovers from how examples were collected, not from the postings themselves: redaction placeholders
# ("[NAME REDACTED]", "[...]", "[phone]"), email header labels ("From:", "Subject:") and URL schemes. Without this
# the model learns "archived email = scam" instead of anything about the job.
_PLACEHOLDER = re.compile(r"\[[^\]\n]{0,40}\]|\([^)\n]{0,40}redacted[^)\n]{0,40}\)|\bredacted\b", re.IGNORECASE)
_HEADER = re.compile(r"^[ \t>]*(?:from|to|cc|sent|date|subject)[ \t]*:", re.IGNORECASE | re.MULTILINE)
_SCHEME = re.compile(r"https?://|www\.", re.IGNORECASE)


def clean(text: str) -> str:
    return _SCHEME.sub(" ", _HEADER.sub(" ", _PLACEHOLDER.sub(" ", text or "")))


# ---------- features (train_model.py uses these exact functions) ----------

def tokens(text: str) -> list[str]:
    """Lowercased words from normalized text. Digits become 0 so '$500 weekly' and '$400 weekly' look alike."""
    return _TOKEN.findall(_DIGIT.sub("0", normalize(clean(text)).lower()))


def analyzer(text: str) -> list[str]:
    """Words and two-word phrases."""
    t = tokens(text)
    return t + [a + " " + b for a, b in zip(t, t[1:])]


def posting_text(title: str, description: str, company: str = "", url: str = "") -> str:
    return "\n".join(x for x in (title or "", company or "", description or "", url or "") if x)


def rule_features(findings: list[dict], score: int, rule_ids: list[str]) -> list[float]:
    fired = {f["rule_id"] for f in findings}
    return [1.0 if rid in fired else 0.0 for rid in rule_ids] + [min(100, score) / 100.0]


# ---------- the model ----------

class Model:
    def __init__(self, spec: dict):
        if spec.get("format") != FORMAT:
            raise ValueError(f"unknown model format {spec.get('format')!r}")
        self.spec = spec
        self.version = spec["version"]
        self.threshold = float(spec["threshold"])
        self.rule_scale = float(spec["rule_scale"])
        self.rule_ids = spec["rule_ids"]
        self.rule_coef = spec["rule_coef"]                 # len(rule_ids) + 1 (the score)
        self.vocab = spec["vocab"]                         # term -> [idf, coef]
        self.intercept = float(spec["intercept"])
        self.trained_on = spec.get("trained_on", {})

    def contributions(self, title: str, description: str, company: str = "", url: str = "",
                      findings: list[dict] | None = None, score: int = 0) -> tuple[float, list[tuple[str, str, float]]]:
        """Return (logit, [(kind, name, contribution)]). TF-IDF with sublinear tf, smooth idf and L2 norm,
        the same as scikit-learn's TfidfVectorizer with the analyzer above."""
        counts: dict[str, int] = {}
        for term in analyzer(posting_text(title, description, company, url)):
            if term in self.vocab:
                counts[term] = counts.get(term, 0) + 1
        vals = {t: (1.0 + math.log(c)) * self.vocab[t][0] for t, c in counts.items()}
        norm = math.sqrt(sum(v * v for v in vals.values())) or 1.0
        parts = [("phrase", t, v / norm * self.vocab[t][1]) for t, v in vals.items()]
        rf = rule_features(findings or [], score, self.rule_ids)
        names = self.rule_ids + ["rule score"]
        parts += [("rule", names[i], x * self.rule_scale * self.rule_coef[i]) for i, x in enumerate(rf) if x]
        return self.intercept + sum(p[2] for p in parts), parts

    def predict(self, title: str, description: str, company: str = "", url: str = "",
                findings: list[dict] | None = None, score: int = 0) -> dict:
        logit, parts = self.contributions(title, description, company, url, findings, score)
        p = 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, logit))))
        top = sorted((x for x in parts if x[2] > 0), key=lambda x: -x[2])[:5]
        conf = self.spec.get("conformal") or {}
        if conf:
            pset = ([] if 1 - p > conf.get("q_scam", 1) else ["scam"]) + ([] if p > conf.get("q_legit", 1) else ["legit"])
        else:
            pset = ["scam"] if p >= self.threshold else ["legit"]
        return {"probability": round(p, 4), "flag": p >= self.threshold, "threshold": self.threshold,
                # Uncertain: the 90%-coverage conformal set can't settle it the way the threshold did (a scam it can't rule
                # out while the threshold says no flag, or an empty/both set). Only used to send cases to a person first.
                "set": pset, "uncertain": len(pset) != 1 or (("scam" in pset) != (p >= self.threshold)),
                "version": self.version, "because": [{"kind": k, "name": n, "weight": round(w, 3)} for k, n, w in top]}


@lru_cache(maxsize=4)
def _load(path: str, mtime: float) -> Model:
    return Model(json.loads(Path(path).read_text()))


def active_path() -> Path:
    """The model the site uses: one retrained on the live board (SCAM_MODEL_PATH, written by learning.py) when it
    exists, otherwise the one shipped in the repo."""
    live = os.environ.get("SCAM_MODEL_PATH", "")
    return Path(live) if live and Path(live).exists() else MODEL_PATH


def load(path: Path | None = None) -> Model | None:
    """The active model, or None when it's missing or switched off."""
    if os.environ.get("SCAM_MODEL", "").lower() in ("off", "0", "false", "no"):
        return None
    p = Path(path or active_path())
    if not p.exists():
        return None
    return _load(str(p), p.stat().st_mtime)


# ---------- staged releases (set by the site's release.py; None means: just the active model) ----------

ROUTE = None      # fn(key, active_model) -> (model to serve, model to score alongside or None)
OBSERVE = None    # fn(key, served_version, served_pred, other_version, other_pred)


def posting_key(title: str, description: str, company: str = "", url: str = "") -> str:
    import hashlib
    return hashlib.sha256(" ".join(tokens(posting_text(title, description, company, url))).encode()).hexdigest()


# ---------- the one thing the rest of the site calls ----------

def second_look(title: str, description: str, company: str = "", url: str = "",
                findings: list[dict] | None = None, score: int = 0, rule_titles: dict | None = None,
                model: Model | None = None) -> dict | None:
    """A finding to add when the model is confident and the rules weren't, else None.
    The caller decides what it escalates (never more than 'send to a person' / 'be careful')."""
    m = model or load()
    if m is None:
        return None
    pred = m.predict(title, description, company, url, findings, score)
    if model is None and ROUTE is not None:
        # During a staged release the site serves the candidate for a stable slice of listings and scores the rest with
        # it in the background (learning's release.py). The hook never raises into a scam check.
        try:
            key = posting_key(title, description, company, url)
            served, other = ROUTE(key, m)
            if served is not m:
                m, pred = served, served.predict(title, description, company, url, findings, score)
            if OBSERVE is not None:
                other_pred = other.predict(title, description, company, url, findings, score) if other is not None else None
                OBSERVE(key, m.version, pred, other.version if other is not None else None, other_pred)
        except Exception:                                   # noqa: BLE001
            pass
    if not pred["flag"]:
        return None
    titles = rule_titles or {f["rule_id"]: f["title"] for f in (findings or [])}
    reasons = []
    for b in pred["because"]:
        if b["kind"] == "rule" and b["name"] != "rule score":
            reasons.append(titles.get(b["name"], b["name"].replace("_", " ")))
        elif b["kind"] == "phrase":
            reasons.append(f'"{b["name"]}"')
    n = m.trained_on.get("rows")
    trained = f"a model trained on {n} labeled listings" if n else "the trained model"
    return {
        "rule_id": "model_second_look", "severity": "warning", "weight": 0,
        "title": "Worth a second look",
        "why": (f"No single rule is sure, but {trained} rates this {round(pred['probability'] * 100)}% likely to be a scam. "
                "It can send something to a person or suggest caution; it never rejects anything on its own."),
        "matched": reasons[:4],
        "model": {"probability": pred["probability"], "version": pred["version"]},
    }
