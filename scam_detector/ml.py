"""
The learned layer: a small model that reads a posting the way a reviewer would and asks
"does this look like the scams we've labeled?"

What it is
  * Logistic regression over four kinds of evidence (model format 2):
      - which rules fired (and the rules' total score), so it learns how much each rule
        should really count;
      - words and two-word phrases (TF-IDF), so it can pick up wording no rule covers yet;
      - character pieces of each word (3-5 letters, TF-IDF), so "ch3que", "whats app" and
        "cheque" still look like what they are after the normalizer has done what it can;
      - the shape of the text: how much it talks to "you", how much it lists requirements
        and benefits, shouting, emoji, money mentions, pay talk with no amount, and so on
        (see SHAPE below). These are what a reviewer notices before reading a single rule.
  * Trained by `python -m scam_detector.tools.train_model` from the labeled corpora plus
    reviewer decisions exported from the board. The result is one JSON file
    (models/scam_model.json). No scikit-learn at run time: inference below is plain Python,
    and demo/ml.js does the same maths in the browser. Format-1 files (words + rules only)
    still load.

What it is allowed to do
  * Only escalate. When the rules say "clear" or "caution" and the model is confident,
    the listing goes to a person with the finding "model_second_look". It never lowers a
    rule verdict and never rejects anything on its own.
  * Explain itself: the finding names the rules, phrases and traits that pushed it up.

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
FORMAT = 2
FORMATS = (1, 2)

_TOKEN = re.compile(r"\$?[a-z0-9]+")
_DIGIT = re.compile(r"[0-9]")
# Leftovers from how examples were collected, not from the postings themselves: redaction placeholders
# ("[NAME REDACTED]", "[...]", "[phone]", "person12"), email header labels ("From:", "Subject:") and URL schemes. Without
# this the model learns "archived email = scam" instead of anything about the job.
_PLACEHOLDER = re.compile(r"\[[^\]\n]{0,40}\]|\([^)\n]{0,40}redacted[^)\n]{0,40}\)|\bredacted\b|\bperson[0-9]+\b", re.IGNORECASE)
_HEADER = re.compile(r"^[ \t>]*(?:from|to|cc|sent|date|subject)[ \t]*:", re.IGNORECASE | re.MULTILINE)
_SCHEME = re.compile(r"https?://|www\.", re.IGNORECASE)


def clean(text: str) -> str:
    return _SCHEME.sub(" ", _HEADER.sub(" ", _PLACEHOLDER.sub(" ", text or "")))


# ---------- features (train_model.py uses these exact functions; demo/ml.js mirrors them) ----------

def tokens(text: str) -> list[str]:
    """Lowercased words from normalized text. Digits become 0 so '$500 weekly' and '$400 weekly' look alike."""
    return _TOKEN.findall(_DIGIT.sub("0", normalize(clean(text)).lower()))


def analyzer(text: str) -> list[str]:
    """Words and two-word phrases."""
    t = tokens(text)
    return t + [a + " " + b for a, b in zip(t, t[1:])]


CHAR_NGRAMS = (3, 4, 5)


def char_analyzer(text: str) -> list[str]:
    """Pieces of each word, with a space marking the word's edges ("che", "cheq", " che", "que ")."""
    out = []
    for w in tokens(text):
        w = " " + w + " "
        for n in CHAR_NGRAMS:
            out.extend(w[i:i + n] for i in range(len(w) - n + 1))
    return out


def posting_text(title: str, description: str, company: str = "", url: str = "") -> str:
    return "\n".join(x for x in (title or "", company or "", description or "", url or "") if x)


# The shape of the text. Every value is in [0, 1]; counts are capped so one long posting can't dominate. The regexes
# are written to behave the same in Python and JavaScript (no \w, no lookbehind), because demo/ml.js has the same list.
_RE = {
    "money": r"\$\s?[0-9][0-9,]*(?:\.[0-9][0-9])?|\b[0-9][0-9,]*\s?(?:dollars|usd)\b",
    "payword": r"\b(?:pay|paid|salary|wage|stipend|earn|earning|compensation|commission|bonus|allowance)\b",
    "per": r"\b(?:per|a|each|every)\s+(?:hour|hr|week|month|year|day|task|survey)\b|\b(?:hourly|weekly|monthly|daily|biweekly)\b",
    "urgent": r"\b(?:urgent|urgently|immediately|asap|right away|today|now|limited|hurry|quick|fast|instant)\b",
    "contact": r"\b(?:whatsapp|telegram|text me|text us|signal|wechat|dm me|email me|contact me|reach me|reply with|send your|cell|mobile)\b|\+?[0-9]{3}[-. )][0-9]{3}[-. ][0-9]{4}",
    "email": r"[A-Za-z0-9._+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+",
    "freemail": r"@(?:gmail|yahoo|outlook|hotmail|aol|icloud|proton|protonmail|mail)\.",
    "url": r"https?://|www\.|\b[A-Za-z0-9-]+\.(?:com|net|org|io|co|info|biz|xyz|site|online|app)\b",
    "shout": r"\b[A-Z]{4,}\b",
    "you": r"\byou(?:r|rs|rself)?\b",
    "we": r"\b(?:we|our|us|company|organization|team)\b",
    "student": r"\b(?:student|students|campus|university|college|semester|undergrad|freshman|sophomore)\b",
    "edu": r"@[A-Za-z0-9.-]+\.edu\b",
    "req": r"\b(?:require|required|requirements|qualification|qualifications|degree|bachelor|experience|years of)\b",
    "eeo": r"\b(?:equal opportunity|eeo|background check|drug screen|benefits|401k|dental|vision|pto|health insurance)\b",
    "nonascii": r"[^\x00-\x7f]",
    "emoji": r"[\U0001F300-\U0001FAFF☀-➿]",
    "excl": r"!",
    "digit": r"[0-9]",
    "noexp": r"\bno (?:prior |previous )?experience\b|\bno experience (?:needed|required|necessary)\b|\banyone can\b",
    "flex": r"\b(?:flexible|at your convenience|own hours|your own schedule|work from home|remote|anywhere|home[- ]based)\b",
    "task": r"\b(?:task|tasks|survey|surveys|data entry|typing|errand|errands|shopping|personal assistant|virtual assistant)\b",
    "legal": r"\b(?:llc|inc\.?|corporation|corp\.?|ltd|nonprofit|non-profit|department of|office of)\b",
}
_SHAPE_RE = {k: re.compile(v, 0 if k in ("shout", "nonascii", "emoji", "excl", "digit") else re.IGNORECASE) for k, v in _RE.items()}
SHAPE = ["length", "money", "pay_no_amount", "per_period", "urgency", "contact_channel", "email", "free_mail", "url", "shouting",
         "talks_to_you", "talks_as_we", "student", "edu_address", "requirements", "benefits_eeo", "non_ascii", "emoji", "exclamation",
         "digits", "no_experience", "flexible", "tasks", "legal_entity"]
SHAPE_TITLES = {"length": "short text", "money": "money mentions", "pay_no_amount": "pay talk with no amount", "per_period": "pay per period",
                "urgency": "urgency", "contact_channel": "personal contact channel", "email": "email address in text", "free_mail": "free-mail address",
                "url": "web addresses", "shouting": "SHOUTING", "talks_to_you": "written at 'you'", "talks_as_we": "speaks as a company",
                "student": "aimed at students", "edu_address": ".edu address", "requirements": "lists requirements", "benefits_eeo": "benefits and compliance language",
                "non_ascii": "unusual characters", "emoji": "emoji", "exclamation": "exclamation marks", "digits": "many digits",
                "no_experience": "no experience needed", "flexible": "flexible / work from home", "tasks": "tasks and errands", "legal_entity": "named legal entity"}


def _n(key: str, text: str) -> int:
    return len(_SHAPE_RE[key].findall(text))


def shape_features(text: str) -> list[float]:
    """Traits of the cleaned text (collection leftovers stripped first, as for the words)."""
    raw = clean(text)
    n = max(1, len(raw))
    words = max(1, len(raw.split()))
    money, pay = _n("money", raw), _n("payword", raw)
    return [
        min(1.0, math.log(1 + len(raw)) / 10),
        min(1.0, money / 3),
        1.0 if pay and not money else 0.0,
        min(1.0, _n("per", raw) / 3),
        min(1.0, _n("urgent", raw) / 3),
        min(1.0, _n("contact", raw) / 3),
        min(1.0, _n("email", raw) / 2),
        1.0 if _SHAPE_RE["freemail"].search(raw) else 0.0,
        min(1.0, _n("url", raw) / 3),
        min(1.0, _n("shout", raw) / 5),
        min(1.0, _n("you", raw) / words * 10),
        min(1.0, _n("we", raw) / words * 10),
        min(1.0, _n("student", raw) / 3),
        1.0 if _SHAPE_RE["edu"].search(raw) else 0.0,
        min(1.0, _n("req", raw) / 4),
        min(1.0, _n("eeo", raw) / 3),
        min(1.0, _n("nonascii", raw) / n * 20),
        min(1.0, _n("emoji", raw) / 3),
        min(1.0, _n("excl", raw) / 5),
        min(1.0, _n("digit", raw) / n * 10),
        1.0 if _SHAPE_RE["noexp"].search(raw) else 0.0,
        min(1.0, _n("flex", raw) / 3),
        min(1.0, _n("task", raw) / 3),
        1.0 if _SHAPE_RE["legal"].search(raw) else 0.0,
    ]


def rule_features(findings: list[dict], score: int, rule_ids: list[str]) -> list[float]:
    fired = {f["rule_id"] for f in findings}
    return [1.0 if rid in fired else 0.0 for rid in rule_ids] + [min(100, score) / 100.0]


def _tfidf_parts(terms: list[str], vocab: dict, kind: str) -> list[tuple[str, str, float]]:
    """TF-IDF with sublinear tf, smooth idf and L2 norm, the same as scikit-learn's TfidfVectorizer, times each term's
    coefficient. vocab: term -> [idf, coef]."""
    counts: dict[str, int] = {}
    for term in terms:
        if term in vocab:
            counts[term] = counts.get(term, 0) + 1
    vals = {t: (1.0 + math.log(c)) * vocab[t][0] for t, c in counts.items()}
    norm = math.sqrt(sum(v * v for v in vals.values())) or 1.0
    return [(kind, t, v / norm * vocab[t][1]) for t, v in vals.items()]


# ---------- the model ----------

class Model:
    def __init__(self, spec: dict):
        if spec.get("format") not in FORMATS:
            raise ValueError(f"unknown model format {spec.get('format')!r}")
        self.spec = spec
        self.format = int(spec["format"])
        self.version = spec["version"]
        self.threshold = float(spec["threshold"])
        self.rule_scale = float(spec["rule_scale"])
        self.rule_ids = spec["rule_ids"]
        self.rule_coef = spec["rule_coef"]                 # len(rule_ids) + 1 (the score)
        self.vocab = spec["vocab"]                         # term -> [idf, coef]
        self.cvocab = spec.get("cvocab", {})               # format 2: character piece -> [idf, coef]
        self.shape_coef = spec.get("shape_coef", [])       # format 2: one per SHAPE entry
        self.shape_scale = float(spec.get("shape_scale", 1.0))
        self.intercept = float(spec["intercept"])
        self.trained_on = spec.get("trained_on", {})

    def contributions(self, title: str, description: str, company: str = "", url: str = "",
                      findings: list[dict] | None = None, score: int = 0) -> tuple[float, list[tuple[str, str, float]]]:
        """Return (logit, [(kind, name, contribution)])."""
        text = posting_text(title, description, company, url)
        parts = _tfidf_parts(analyzer(text), self.vocab, "phrase")
        if self.format >= 2:
            parts += _tfidf_parts(char_analyzer(text), self.cvocab, "piece")
            sf = shape_features(text)
            parts += [("trait", SHAPE[i], x * self.shape_scale * self.shape_coef[i]) for i, x in enumerate(sf) if x and i < len(self.shape_coef)]
        rf = rule_features(findings or [], score, self.rule_ids)
        names = self.rule_ids + ["rule score"]
        parts += [("rule", names[i], x * self.rule_scale * self.rule_coef[i]) for i, x in enumerate(rf) if x]
        return self.intercept + sum(p[2] for p in parts), parts

    def predict(self, title: str, description: str, company: str = "", url: str = "",
                findings: list[dict] | None = None, score: int = 0) -> dict:
        logit, parts = self.contributions(title, description, company, url, findings, score)
        p = 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, logit))))
        # Character pieces are many and tiny; they are shown rolled up into one line so the explanation stays readable.
        rolled: dict[tuple[str, str], float] = {}
        for k, n, w in parts:
            if k != "piece":
                rolled[(k, n)] = rolled.get((k, n), 0.0) + w
        pieces = sum(w for k, _, w in parts if k == "piece")
        if pieces > 0:
            rolled[("piece", "spelling of the words")] = pieces
        top = sorted(((k, n, w) for (k, n), w in rolled.items() if w > 0), key=lambda x: -x[2])[:5]
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

    def novelty(self, title: str, description: str, company: str = "", url: str = "") -> float:
        """How much of this text the model has never seen: the share of its words and phrases that are not in the vocabulary.
        Close to 1 means the model is guessing; drift.py watches this over time."""
        terms = analyzer(posting_text(title, description, company, url))
        if not terms:
            return 1.0
        return round(sum(1 for t in terms if t not in self.vocab) / len(terms), 4)


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


# ---------- hooks set by the site (None means: just the active model) ----------

ROUTE = None      # release.py: fn(key, active_model) -> (model to serve, model to score alongside or None)
OBSERVE = None    # release.py: fn(key, served_version, served_pred, other_version, other_pred)
MONITOR = None    # drift.py: fn(key, pred, novelty) - records what the model sees in the wild, never what anyone decided


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
    if model is None and (ROUTE is not None or MONITOR is not None):
        # During a staged release the site serves the candidate for a stable slice of listings and scores the rest with
        # it in the background (learning's release.py); drift.py keeps a tally of scores and novelty. Hooks never raise
        # into a scam check.
        try:
            key = posting_key(title, description, company, url)
            if ROUTE is not None:
                served, other = ROUTE(key, m)
                if served is not m:
                    m, pred = served, served.predict(title, description, company, url, findings, score)
                if OBSERVE is not None:
                    other_pred = other.predict(title, description, company, url, findings, score) if other is not None else None
                    OBSERVE(key, m.version, pred, other.version if other is not None else None, other_pred)
            if MONITOR is not None:
                MONITOR(key, pred, m.novelty(title, description, company, url))
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
        elif b["kind"] == "trait":
            reasons.append(SHAPE_TITLES.get(b["name"], b["name"].replace("_", " ")))
        elif b["kind"] == "piece":
            reasons.append(b["name"])
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
