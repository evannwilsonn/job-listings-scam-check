"""
Text rule engine.

The rules themselves are DATA (rulepack/core.json), not code, so new scam
techniques can be added, versioned and regression-tested without touching this
file. This module is the engine: it normalizes text, applies rules, and handles
the context that separates a scam from a legitimate posting that happens to use
the same words:

  negation   "we will never ask for a training fee" must not fire advance_fee
  post_hire  "SSN for payroll upon hire" must not fire banking_pii
  obfuscation  "t e l e g r a m", "wh@tsapp", zero-width characters, look-alike letters

Every finding still reports the exact text that matched, so no score is a black box.

Operators can add rules without editing the package by pointing the environment
variable SCAM_RULEPACK_EXTRA at a JSON file in the same format. Extra rules may
only ADD detections (they cannot replace or weaken core rule ids), and only rules
whose status is "active" are loaded, so machine-proposed rules sit inert until a
person promotes them.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

MAX_TEXT = 20000          # never scan more than this many characters
MAX_PATTERN_LEN = 400
MAX_RULES = 300


@dataclass
class Finding:
    rule_id: str
    severity: str      # "critical" | "warning" | "note"
    weight: int
    title: str
    why: str
    matched: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "severity": self.severity, "weight": self.weight,
            "title": self.title, "why": self.why, "matched": self.matched,
        }


# ---------- normalization ----------

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
# Common Cyrillic/Greek look-alikes used to dodge keyword filters.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ѕ": "s", "ο": "o", "α": "a", "ρ": "p",
    "’": "'", "‘": "'", "“": '"', "”": '"',
})
_SPACED_LETTERS = re.compile(r"(?<![a-z0-9])(?:[a-z][ .\-_*]){4,}[a-z](?![a-z0-9])", re.IGNORECASE)
_LEET_INSIDE_WORD = re.compile(r"(?<=[a-z])[@$0134](?=[a-z])", re.IGNORECASE)
_LEET_MAP = {"@": "a", "$": "s", "0": "o", "1": "i", "3": "e", "4": "a"}


def normalize(text: str) -> str:
    """Fold obfuscation so 'T e l e g r a m' and 'wh@tsapp' match like the plain words."""
    text = unicodedata.normalize("NFKC", text or "")
    text = text.translate(_ZERO_WIDTH).translate(_HOMOGLYPHS)
    text = _SPACED_LETTERS.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), text)
    text = _LEET_INSIDE_WORD.sub(lambda m: _LEET_MAP[m.group(0)], text)
    return text[:MAX_TEXT]


# ---------- guards ----------

_NEGATORS = re.compile(
    r"\b(?:no|never|not|without|zero|nor|neither|free of|isn't|aren't|doesn't|won't|don't|do not|"
    r"does not|will not|cannot|can't)\b", re.IGNORECASE)
_REQUIRE_VERBS = re.compile(r"\b(?:must|need to|needs to|have to|required to|you will pay|you pay)\b", re.IGNORECASE)
_AFTER_CUES = re.compile(
    r"\b(?:at no (?:cost|charge)|no cost|free of charge|for free|is free|are free|free to you|"
    r"covered by|paid for by|paid by|we (?:pay|cover)|is waived|are waived)\b", re.IGNORECASE)
_POST_HIRE = re.compile(
    r"\b(?:upon\s+(?:hire|being hired|acceptance|offer)|"
    r"after\s+(?:you(?:'re| are)\s+|being\s+|an?\s+|your\s+|the\s+)?(?:hired|hire|offer|accepted|acceptance|background check|first)|"
    r"once\s+(?:you(?:'re| are)\s+)?(?:hired|accepted)|once\s+your\s+background|"
    r"for\s+(?:payroll|i-?9|tax|w-?4)|i-?9|w-?4|new hires?)\b", re.IGNORECASE)
_SENT_BREAK = re.compile(r"[.;:!?\n]")


def _sentence_before(text: str, start: int) -> str:
    seg = text[max(0, start - 160):start]
    parts = _SENT_BREAK.split(seg)
    return parts[-1] if parts else seg


def _sentence_after(text: str, end: int) -> str:
    seg = text[end:end + 120]
    m = _SENT_BREAK.search(seg)
    return seg[:m.start()] if m else seg


def _negated(text: str, m: re.Match) -> str:
    """The words that rule the match out ("never", "at no cost"), or "" when nothing does. Truthy means cleared."""
    before = " ".join(_sentence_before(text, m.start()).split()[-14:])
    neg = None
    for neg in _NEGATORS.finditer(before):
        pass
    if neg is not None and not _REQUIRE_VERBS.search(before[neg.end():]):
        return neg.group(0)
    after = _AFTER_CUES.search(_sentence_after(text, m.end()))
    return after.group(0) if after else ""


def _post_hire(text: str, m: re.Match) -> str:
    hit = _POST_HIRE.search(text[max(0, m.start() - 120):m.end() + 120])
    return hit.group(0) if hit else ""


# An employer's own safety promise ("At no time will a conversation be moved to an alternative email", "We will
# never ask you to text us") describes the scam in order to rule it out. Added from the Oct 2026 job-board batch.
_DISCLAIMER = re.compile(r"\b(?:at\s+no\s+time|will\s+never|would\s+never|we\s+never|never\s+(?:ask|request|contact|move)|will\s+not\s+ever|won't\s+ever)\b", re.IGNORECASE)


def _disclaimer(text: str, m: re.Match) -> str:
    hit = _DISCLAIMER.search(_sentence_before(text, m.start()))
    return hit.group(0) if hit else ""


_GUARDS = {"negation": _negated, "post_hire": _post_hire, "disclaimer": _disclaimer}


# ---------- rulepack ----------

@dataclass
class Rule:
    id: str
    severity: str
    weight: int
    title: str
    why: str
    patterns: list           # compiled regexes (phrases are compiled into this list too)
    guards: list
    min_matches: int = 1
    bonus: int = 3


class RulepackError(ValueError):
    pass


_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d+,\})")


def _phrase_regex(p: str) -> str:
    return r"\b" + re.escape(p).replace(r"\ ", r"\s+") + r"\b"


def _compile_rule(spec: dict, *, extra: bool) -> Optional[Rule]:
    if spec.get("status", "active") != "active":
        return None
    rid = str(spec.get("id", ""))
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", rid):
        raise RulepackError(f"bad rule id {rid!r}")
    sev = spec.get("severity")
    if sev not in ("critical", "warning", "note"):
        raise RulepackError(f"{rid}: severity must be critical, warning or note")
    weight = int(spec.get("weight", 0))
    if not 1 <= weight <= (30 if extra else 40):
        raise RulepackError(f"{rid}: weight out of range")
    regexes = []
    for ph in spec.get("phrases", []):
        if not isinstance(ph, str) or not ph.strip() or len(ph) > 120:
            raise RulepackError(f"{rid}: bad phrase")
        regexes.append(re.compile(_phrase_regex(ph.lower()), re.IGNORECASE))
    for pat in spec.get("patterns", []):
        if not isinstance(pat, str) or len(pat) > MAX_PATTERN_LEN or _NESTED_QUANT.search(pat):
            raise RulepackError(f"{rid}: pattern too long or has nested quantifiers (ReDoS risk)")
        try:
            regexes.append(re.compile(pat, re.IGNORECASE))
        except re.error as e:
            raise RulepackError(f"{rid}: invalid regex ({e})")
    if not regexes:
        raise RulepackError(f"{rid}: no phrases or patterns")
    guards = [g for g in spec.get("guards", [])]
    for g in guards:
        if g not in _GUARDS:
            raise RulepackError(f"{rid}: unknown guard {g!r}")
    return Rule(rid, sev, weight, str(spec.get("title", rid))[:120], str(spec.get("why", ""))[:600],
                regexes, guards, max(1, int(spec.get("min_matches", 1))), int(spec.get("bonus", 3)))


def load_rulepack(extra_path: Optional[str] = None) -> tuple[list, str]:
    core = json.loads((Path(__file__).parent / "rulepack" / "core.json").read_text(encoding="utf-8"))
    rules = [r for r in (_compile_rule(s, extra=False) for s in core["rules"]) if r]
    version = str(core.get("version", "unknown"))
    extra_path = extra_path or os.environ.get("SCAM_RULEPACK_EXTRA", "")
    if extra_path:
        extra = json.loads(Path(extra_path).read_text(encoding="utf-8"))
        specs = extra.get("rules", [])
        if len(specs) > MAX_RULES:
            raise RulepackError("too many extra rules")
        core_ids = {r.id for r in rules}
        for s in specs:
            rule = _compile_rule(s, extra=True)
            if rule is None:
                continue
            if rule.id in core_ids:
                raise RulepackError(f"extra rule {rule.id!r} would replace a core rule; use a new id")
            rules.append(rule)
        version += "+" + str(extra.get("version", "extra"))
    return rules, version


RULES, RULESET_VERSION = load_rulepack()


def reload_rules(extra_path: Optional[str] = None) -> str:
    """Reload after changing the rulepack (tests and the regression gate use this)."""
    global RULES, RULESET_VERSION
    RULES, RULESET_VERSION = load_rulepack(extra_path)
    return RULESET_VERSION


# ---------- engine ----------

def run_text_rules(text: str, rules: Optional[list] = None) -> List[Finding]:
    text = normalize(text)
    findings: List[Finding] = []
    for rule in (rules if rules is not None else RULES):
        seen: dict[str, str] = {}
        for rx in rule.patterns:
            for m in rx.finditer(text):
                if any(_GUARDS[g](text, m) for g in rule.guards):
                    continue
                key = re.sub(r"\s+", " ", m.group(0).lower()).strip()
                seen.setdefault(key, key)
        if len(seen) >= rule.min_matches:
            weight = rule.weight + min(2 * rule.bonus, rule.bonus * (len(seen) - 1))
            shown = sorted(seen)[:5]
            findings.append(Finding(rule.id, rule.severity, weight, rule.title, rule.why,
                                    [s[:90] for s in shown]))
    return findings


# What cleared a would-be flag. Shown to students in green, framed as "why this wasn't counted", never as "this part is
# safe": scammers copy reassuring lines on purpose, so a cleared phrase lowers nothing beyond the one match it rules out.
GUARD_REASONS = {
    "negation": "It's mentioned only to say it won't happen, so it wasn't counted.",
    "post_hire": "It only comes up after you're hired, which is normal for payroll and tax forms, so it wasn't counted.",
    "disclaimer": "It's part of a safety warning or the employer's own promise, so it wasn't counted.",
    "to_you": "It describes money paid to you, not money you send, so it wasn't counted.",
    "duty": "It describes a job duty or skill, not something they're asking you to do, so it wasn't counted.",
}
MAX_CLEARED = 8


def clause_around(text: str, a: int, b: int) -> str:
    """The words from the clearing cue through the match, trimmed to their sentence, for quoting back."""
    lo = max(0, a)
    while lo > 0 and text[lo - 1] not in ".;!?\n" and a - lo < 120:
        lo -= 1
    hi = min(len(text), b)
    while hi < len(text) and text[hi] not in ".;!?\n" and hi - b < 80:
        hi += 1
    return re.sub(r"\s+", " ", text[lo:hi]).strip(" ,-")


def cue_at(text: str, cue: str, m: re.Match) -> int:
    """Where the clearing words sit: the nearest copy before the match, else the first one after it in the same sentence."""
    low, c = text.lower(), cue.lower()
    i = low.rfind(c, max(0, m.start() - 160), m.end())
    if i >= 0:
        return i if not _SENT_BREAK.search(text[i + len(c):m.start()]) else -1
    i = low.find(c, m.start(), m.end() + 160)
    return i if i >= 0 and not _SENT_BREAK.search(text[m.end():i]) else -1


# A green mark must never land on a real request for money or identity. These cues are too weak to vouch for a clause
# that also names bank, ID, payment-app or crypto details ("For fraud prevention, send your banking login", "To prove you
# are not a scammer, send your SSN"), and a "covered by" / "paid by" cue doesn't clear a clause that goes on to ask for
# payment ("the fee is covered by your first paycheck, so pay it today via Cash App").
_SENSITIVE = re.compile(
    r"\b(?:bank|banking|routing|account\s+number|log-?in|password|ssn|social\s+security|driver'?s?\s+licen[sc]e|passport|"
    r"photo\s+id|id\s+card|gift\s*cards?|zelle|cash\s?app|venmo|paypal|western\s+union|moneygram|wire|bitcoin|btc|crypto\w*|"
    r"usdt|telegram|whats\s?app|signal)\b|\$\s?\d", re.IGNORECASE)
_WEAK_NEGATORS = {"not", "no", "nor", "without", "zero", "neither", "nothing"}
_ASK_VERB = re.compile(r"\b(?:pay|send|transfer|wire|buy|purchase|deposit|reply\s+with|text\s+(?:me|us)|upload|share)\b",
                       re.IGNORECASE)


def show_as_cleared(clause: str, cue: str, guard: str) -> bool:
    """Whether a ruled-out clause is safe to show in green. When in doubt it isn't: no mark beats a green mark on a scam ask."""
    cl, cu = clause.lower(), cue.lower().strip()
    if not cu or cu not in cl:
        return False
    if _SENSITIVE.search(clause) and (guard in ("disclaimer", "to_you", "duty") or cu in _WEAK_NEGATORS):
        return False
    after = clause[cl.find(cu) + len(cu):]
    if _ASK_VERB.search(after) and _SENSITIVE.search(after):
        return False             # "we never ask for fees, just send $200 via Zelle": the clause still makes the ask
    if guard == "negation" and cl.find(cu) > 0 and _ASK_VERB.search(after) and not _NEG_STRONG.search(cu):
        return False
    return True


_NEG_STRONG = re.compile(r"\b(?:never|will\s+not|won't|do\s+not|don't|does\s+not|doesn't|cannot|can't|at\s+no\s+time)\b",
                         re.IGNORECASE)


def cleared_matches(text: str, rules: Optional[list] = None) -> List[dict]:
    """Every place a rule matched but a guard ruled it out: the rule, the clearing words and the clause they sit in."""
    text = normalize(text)
    out: List[dict] = []
    seen = set()
    for rule in (rules if rules is not None else RULES):
        for rx in rule.patterns:
            for m in rx.finditer(text):
                for g in rule.guards:
                    cue = _GUARDS[g](text, m)
                    if not cue:
                        continue
                    ci = cue_at(text, cue, m)
                    if ci < 0:
                        break                      # the clearing words are in another sentence: nothing honest to quote
                    clause = clause_around(text, min(ci, m.start()), max(ci + len(cue), m.end()))
                    key = clause.lower()
                    if key in seen or not show_as_cleared(clause, cue, g):
                        break
                    seen.add(key)
                    out.append({"rule_id": rule.id, "title": rule.title, "guard": g, "cue": cue.strip(),
                                "matched": m.group(0).strip()[:90], "clause": clause[:200], "why": GUARD_REASONS[g]})
                    break
                if len(out) >= MAX_CLEARED:
                    return out
    return out


# ---------- pay that works out to far above market ----------

_PAY = re.compile(r"\$\s?([\d,]+(?:\.\d+)?)\s*(?:(?:per|a|each|/)\s*)?(week|weekly|day|daily)\b", re.IGNORECASE)
_HOURS_DAYS = re.compile(r"(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*hrs?\.?\s*(\d+)\s*days?\s*(?:a|per)\s*week", re.IGNORECASE)
_HOURS = re.compile(r"(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*(?:hrs?|hours?)\s*(?:(?:per|a|/|each)\s*)?(week|weekly|day|daily)?", re.IGNORECASE)
IMPLIED_HOURLY_LIMIT = 60.0


def implied_hourly_finding(text: str) -> Optional[Finding]:
    """Flag 'You can make $650 weekly ... 1-2hrs 3 days a week' (about $108/hr at the top of the range)."""
    text = normalize(text)
    pay = _PAY.search(text)
    if not pay:
        return None
    amount = float(pay.group(1).replace(",", ""))
    per_week = amount * (5 if pay.group(2).lower().startswith("d") else 1)
    hours_week = None
    m = _HOURS_DAYS.search(text)
    if m:
        hours_week = float(m.group(2)) * float(m.group(3))
    else:
        m = _HOURS.search(text)
        if m:
            hours_week = float(m.group(2)) * (5 if (m.group(3) or "").lower().startswith("d") else 1)
    if not hours_week or hours_week <= 0:
        return None
    rate = per_week / hours_week
    if rate < IMPLIED_HOURLY_LIMIT:
        return None
    return Finding(
        "implied_hourly", "warning", 18, "The pay works out to far above market",
        f"{pay.group(0).strip()} for at most about {hours_week:g} hours a week is roughly ${rate:,.0f}/hour. "
        "Real employers do not pay this for casual, no-experience work.",
        [f"{pay.group(0).strip()} / about {hours_week:g} hrs per week"])


# ---------- email domains ----------

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com",
    "proton.me", "mail.com", "yandex.com", "gmx.com", "icloud.com", "live.com", "msn.com",
}


def check_email_domains(text: str, company: str) -> List[Finding]:
    """Flag free-mail addresses used by a named corporate employer."""
    findings: List[Finding] = []
    emails = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", text, re.IGNORECASE))
    domains = {e.split("@")[1].lower().rstrip(".,;:") for e in emails}
    free = sorted(d for d in domains if d in FREE_MAIL)
    if free and company.strip():
        findings.append(Finding(
            "personal_email", "warning", 18, "Recruiter writing from a personal address",
            f"Corporate hiring comes from the company's own domain. Nothing here comes from a "
            f"{company.strip()} address.",
            ["@" + d for d in free],
        ))
    return findings


def extract_domains(text: str) -> List[str]:
    """All distinct domains from emails and URLs, for enrichment lookups."""
    domains = set()
    for e in re.findall(r"[\w.+-]+@([\w-]+\.[\w.-]+)", text, re.IGNORECASE):
        domains.add(e.lower().rstrip(".,;:"))
    for u in re.findall(r"https?://(?:www\.)?([\w-]+\.[\w.-]+)", text, re.IGNORECASE):
        domains.add(u.lower().rstrip("/.,;:"))
    return sorted(d for d in domains if d not in FREE_MAIL)
