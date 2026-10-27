"""
A career center's own allow and block lists, applied to a check after every other finding is in.

    findings = guardrails.apply(findings, rules, text=..., sender=...)
    rules = guardrails.rules_for(school)        # cached; from the store (school_rules)

Trusted domains (an employer the career center verified, e.g. a credit union whose name looks like the school's):
  * findings about that domain's infrastructure are kept but set to weight 0, with a note saying the career center
    trusts it: new_domain, unregistered_domain, no_mail, lookalike_domain. Only when every domain the finding names is
    trusted.
  * the domain is passed to the look-alike check as a protected name, so a domain imitating it gets flagged.
  * nothing else changes. Text rules, confirmed scam contacts, partner reports, template matches, attestation mismatches
    and outside blocklists still count in full: real employer accounts get compromised, and a trusted name is exactly what
    a scammer would borrow.
Blocked domains: a check whose text or sender uses one gets a critical finding naming the career center.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Iterable, List, Optional

from .intel.domains import is_subdomain_of, normalize_host

SOFTEN = {"new_domain", "unregistered_domain", "no_mail", "lookalike_domain"}
_HOST = re.compile(r"(?<![@\w.-])(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE)
_EMAIL_DOMAIN = re.compile(r"[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)
_DOMAIN = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
_IMITATES = re.compile(r"\(imitates [^)]*\)", re.IGNORECASE)
KINDS = ("trusted_domain", "blocked_domain")
TTL = 60.0
_cache: dict = {}
SCHOOLS = Path(__file__).resolve().parent / "schools.json"


def _config() -> dict:
    try:
        return json.loads(SCHOOLS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def school_name(school: str) -> str:
    return (_config().get(school) or {}).get("name", "")


def clean_domain(value: str) -> str:
    """The host exactly as listed (lowercased, no scheme or path). An entry covers that host and its subdomains, never its
    parent: listing careers.example.com doesn't touch example.com, so one page on a shared host can't block the host."""
    d = normalize_host(value or "")
    if not _DOMAIN.match(d):
        raise ValueError(f"not a domain: {value!r}")
    return d


def hosts(text: str) -> set:
    """Hosts named in the text, as links, bare domains or email addresses."""
    found = {m.group(1) for m in _EMAIL_DOMAIN.finditer(text or "")} | {m.group(1) for m in _HOST.finditer(text or "")}
    return {h for h in (normalize_host(x) for x in found) if h}


def covered(host: str, entries: Iterable[str]) -> bool:
    return any(host == e or is_subdomain_of(host, e) for e in entries)


def rules_for(school: str, st=None) -> dict:
    """{"trusted": set, "blocked": set} for a school, cached for TTL seconds. Empty for no school. Never raises."""
    if not school:
        return {"trusted": set(), "blocked": set()}
    hit = _cache.get(school)
    if hit and time.time() - hit[0] < TTL:
        return hit[1]
    try:
        if st is None:
            from .store import get_store
            st = get_store()
        rows = st.school_rules(school)
    except Exception:                                   # noqa: BLE001 - a store outage must not break a check
        rows = []
    configured = set()                                   # schools.json "employer_domains": trusted from the start
    for d in (_config().get(school) or {}).get("employer_domains", []):
        try:
            configured.add(clean_domain(d))
        except ValueError:
            continue
    out = {"trusted": configured | {r["value"] for r in rows if r["kind"] == "trusted_domain"},
           "blocked": {r["value"] for r in rows if r["kind"] == "blocked_domain"}}
    out["trusted"] -= out["blocked"]                    # a block always wins
    _cache[school] = (time.time(), out)
    return out


def clear_cache() -> None:
    _cache.clear()


def apply(findings: List[dict], rules: dict, *, text: str = "", sender: str = "", school_name: str = "") -> List[dict]:
    """The findings with the career center's lists applied. Returns a new list; the input is not changed."""
    trusted, blocked = rules.get("trusted", set()), rules.get("blocked", set())
    if not trusted and not blocked:
        return list(findings)
    who = f"{school_name}'s career center" if school_name else "Your career center"
    out = []
    for f in findings:
        if f.get("rule_id") in SOFTEN and trusted and f.get("weight", 0) > 0:
            # "x.com (imitates fsu.edu: ...)": the finding is about x.com, not the domain it imitates
            named = hosts(" ".join(_IMITATES.sub("", str(m)) for m in f.get("matched", [])))
            if named and all(covered(h, trusted) for h in named):
                f = {**f, "weight": 0, "severity": "note", "softened_by": "trusted_domain",
                     "why": f.get("why", "") + f" {who} has verified {', '.join(sorted(named))} as a real employer, so this "
                                               "doesn't count toward the score. Check the rest of the message as usual."}
        out.append(f)
    used = hosts(" ".join((text or "", sender or "")))
    bad = sorted(h for h in used if covered(h, blocked))
    if bad:
        out.append({"rule_id": "school_blocked_domain", "severity": "critical", "weight": 35,
                    "title": "A domain your career center has blocked",
                    "why": (f"{who} has seen {', '.join(bad)} used against students and blocked it. Don't reply, click "
                            "or send anything; report it to the career center."),
                    "matched": bad})
    return out


def protected(rules: dict) -> tuple:
    """Trusted domains, for intel_findings(protected_extra=...): never looked up as look-alikes, and protected from them."""
    return tuple(sorted(rules.get("trusted", set())))
