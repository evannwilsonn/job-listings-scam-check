"""
Certificate Transparency watch: spot new HTTPS certificates for FSU lookalike domains.

Every publicly trusted TLS certificate is logged in CT logs, and crt.sh indexes them.
A scammer who sets up "fsu-careers.com" with HTTPS almost always gets a certificate,
so new lookalike names often show up here days before anyone reports them.

    find_new_lookalike_certs(["fsu", "seminoles"], since_ts, fetch=None)

Limits:
  - crt.sh is a free community service and is frequently slow or down (502/504,
    timeouts, or an HTML error page instead of JSON). Each term is queried
    separately; a failed term is reported in "errors" and the others still count.
    status is "ok" (all terms answered), "partial", or "unknown" (none answered).
  - "%fsu%" style wildcard queries are broad and heavy; run this from a scheduled
    job, never from a page request. Short terms may time out on crt.sh's side.
  - It only sees domains that got a certificate. Plain-HTTP sites and sites behind
    a CDN's shared certificate may not appear under their own name.
  - "first_seen" is the earliest not_before among the certificates crt.sh returned
    for that name, which approximates when the site went live.
  - A lookalike certificate is a lead to review, not proof of a scam.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Callable, Iterable, Optional, Tuple
from urllib.parse import quote

from .domains import DEFAULT_PROTECTED, OFFICIAL_FSU_DOMAINS, is_subdomain_of, lookalike, normalize_host, registrable_domain

CRT_SH = "https://crt.sh/"
TIMEOUT = 25.0  # crt.sh wildcard queries are slow even when healthy

# A fetch takes a URL and returns (status_code, body_text).
Fetch = Callable[[str], Tuple[int, str]]


def crtsh_url(term: str) -> str:
    """https://crt.sh/?q=%25fsu%25&output=json&exclude=expired (the % wildcard URL-encoded)."""
    return f"{CRT_SH}?q={quote('%' + term.strip() + '%', safe='')}&output=json&exclude=expired"


def _default_fetch(url: str) -> Tuple[int, str]:
    import httpx
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False,
                      headers={"User-Agent": "NoleCareerShield-ct-watch/1.0"}) as c:
        r = c.get(url)
        return r.status_code, r.text


def _to_datetime(value) -> Optional[dt.datetime]:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=dt.timezone.utc)
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
    try:
        d = dt.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def parse_crtsh(body: str) -> list:
    """Return [(hostname, not_before_datetime, issuer), ...] from a crt.sh JSON body."""
    data = json.loads(body)
    if not isinstance(data, list):
        raise ValueError("crt.sh JSON was not a list")
    out = []
    for row in data:
        if not isinstance(row, dict):
            continue
        nb = _to_datetime(row.get("not_before"))
        if nb is None:
            continue
        names = str(row.get("name_value") or "") + "\n" + str(row.get("common_name") or "")
        for raw in names.split("\n"):
            name = normalize_host(raw.strip().lstrip("*.").strip())
            if name and "." in name and " " not in name and "@" not in raw:
                out.append((name, nb, row.get("issuer_name")))
    return out


def find_new_lookalike_certs(protected_terms: Iterable[str], since_ts, fetch: Optional[Fetch] = None,
                             *, extra: Iterable[str] = ()) -> dict:
    """
    Query crt.sh once per term and return lookalike domains first seen at/after since_ts.

    since_ts: datetime, date, epoch seconds, or ISO string.
    extra:    employer domains to treat as protected too (passed to lookalike()).

    Returns {"status": "ok"|"partial"|"unknown", "since": iso,
             "domains": [{"domain", "registrable", "first_seen", "hostnames", "brand", "reason", "detail"}],
             "errors": [{"term", "detail"}]}
    Never raises.
    """
    fetch = fetch or _default_fetch
    since = _to_datetime(since_ts) or dt.datetime.fromtimestamp(0, tz=dt.timezone.utc)
    terms = [t.strip() for t in protected_terms if t and t.strip()]
    extra = tuple(extra)
    protected = tuple(dict.fromkeys([*DEFAULT_PROTECTED, *(t.lower() for t in terms)]))
    errors, answered = [], 0
    first_seen: dict = {}   # hostname -> earliest not_before

    for term in terms:
        url = crtsh_url(term)
        try:
            status, body = fetch(url)
        except Exception as e:  # noqa: BLE001 - timeouts, connection resets
            errors.append({"term": term, "detail": f"crt.sh unreachable ({type(e).__name__})"})
            continue
        if status != 200:
            errors.append({"term": term, "detail": f"crt.sh HTTP {status}"})
            continue
        try:
            rows = parse_crtsh(body or "[]")
        except (ValueError, TypeError) as e:
            errors.append({"term": term, "detail": f"crt.sh returned unreadable data ({type(e).__name__})"})
            continue
        answered += 1
        for name, nb, _issuer in rows:
            if name not in first_seen or nb < first_seen[name]:
                first_seen[name] = nb

    by_reg: dict = {}
    for name, nb in first_seen.items():
        if any(is_subdomain_of(name, o) for o in OFFICIAL_FSU_DOMAINS):
            continue
        hits = lookalike(name, protected, extra)
        if not hits:
            continue
        reg = registrable_domain(name)
        entry = by_reg.get(reg)
        if entry is None:
            entry = by_reg[reg] = {"domain": reg, "registrable": reg, "first_seen": nb, "hostnames": [],
                                   "brand": hits[0]["brand"], "reason": hits[0]["reason"],
                                   "detail": hits[0]["detail"]}
        entry["first_seen"] = min(entry["first_seen"], nb)
        entry["hostnames"].append(name)

    domains = []
    for entry in by_reg.values():
        if entry["first_seen"] >= since:
            entry["first_seen"] = entry["first_seen"].isoformat()
            entry["hostnames"] = sorted(set(entry["hostnames"]))
            domains.append(entry)
    domains.sort(key=lambda e: (e["first_seen"], e["domain"]), reverse=True)

    status = "ok" if answered == len(terms) else ("partial" if answered else "unknown")
    return {"status": status, "since": since.isoformat(), "domains": domains, "errors": errors}
