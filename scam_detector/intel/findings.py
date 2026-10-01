"""
Turn intel lookups into detector findings.

    intel_findings(text, urls, sender, company, *, cache, protected_extra=(), network=True)

Returns a list of dicts in the detector's format:
    {"rule_id", "severity": "critical"|"warning"|"note", "weight", "title", "why", "matched": [...]}

Each rule_id appears at most once (matches are merged), so weights don't stack when
a posting repeats the same bad link.

Offline (always run, network=False runs only these):
  lookalike_domain   critical 35 (FSU brands) / warning 22 (employer domains)
  shortened_link     note 4 (spotting a shortener host is a string check)

Network (network=True):
  shortened_link     plus the expanded destination, which then gets every other check
  new_domain         warning 18 (< 30 days) / warning 10 (30-90 days), via enrichment.domain_age
  no_email_auth      note 6: the employer's email domain has neither SPF nor DMARC
  blocklisted_domain critical 40: URLhaus or Spamhaus DBL lists it
  reported_wallet    critical 35 (verified Chainabuse report) / warning 15 (unverified)
  virtual_number     note 5: Twilio says non-fixed VoIP (weak; real recruiters use Google Voice)

Free-mail domains (gmail.com, ...) are never treated as "the employer's domain", and
official FSU domains and the caller's employer domains are not looked up.
Lookups whose API key isn't configured are simply skipped. Nothing here raises.

Note: scorer.py already emits its own `new_domain` from domain_age for domains in the
text; if both are wired in, keep only one so the weight isn't counted twice.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, List, Optional, Sequence

from ..rules import FREE_MAIL
from .cache import DAY, Cache, cached
from .domains import (OFFICIAL_FSU_DOMAINS, email_auth, lookalike, normalize_host,
                      registrable_domain, split_host)
from .reputation import (chainabuse_wallet, spamhaus_dbl, twilio_line_type, urlhaus_host,
                         urlhaus_url)
from .shortener import expand, is_shortener

MAX_HOSTS = 8
MAX_URLS = 10
MAX_PHONES = 3
MAX_WALLETS = 3

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'()\[\]]+", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)
_COMMON_TLDS = ("com|net|org|edu|gov|io|co|info|biz|us|xyz|top|online|site|app|dev|me|ly|cc|ai|"
                "live|shop|store|click|link|work|jobs|careers|agency|pro|tech|space|website|icu|vip|club")
_BARE_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _COMMON_TLDS + r"))(?![\w-])(?:/[^\s<>\"']*)?",
    re.I)
_PHONE_RE = re.compile(r"(?<![\d\w])(?:\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
_WALLET_RES = (
    re.compile(r"\b0x[a-fA-F0-9]{40}\b"),                         # Ethereum / EVM
    re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b"),                # Bitcoin bech32
    re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),           # Bitcoin legacy
    re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),                 # Tron (USDT-TRC20 scams)
)


def _finding(rule_id, severity, weight, title, why, matched) -> dict:
    return {"rule_id": rule_id, "severity": severity, "weight": weight, "title": title,
            "why": why, "matched": list(dict.fromkeys(matched))}


def _extract(text: str, urls: Sequence[str], sender: str):
    """Return (urls, hosts, email_domains) found in the inputs, in first-seen order."""
    text = text or ""
    all_urls: list = []
    for u in list(urls or []) + _URL_RE.findall(text):
        u = u.strip().rstrip(".,;:!?)")
        if u and u not in all_urls:
            all_urls.append(u)
    hosts: list = []

    def add_host(h):
        h = normalize_host(h)
        if h and "." in h and h not in hosts:
            hosts.append(h)

    for u in all_urls:
        add_host(u)
    email_domains = []
    for d in _EMAIL_RE.findall(text) + ([normalize_host(sender)] if sender and "." in sender else []):
        d = d.lower().rstrip(".")
        if d and d not in email_domains:
            email_domains.append(d)
        add_host(d)
    scrubbed = _URL_RE.sub(" ", text)
    scrubbed = re.sub(r"[\w.+-]+@[\w.-]+", " ", scrubbed)
    for m in _BARE_DOMAIN_RE.finditer(scrubbed):
        add_host(m.group(1))
    # Each email domain costs SPF and DMARC lookups; a message stuffed with hundreds of addresses must not fan out.
    return all_urls, hosts, email_domains[:MAX_HOSTS]


def _phones(text: str) -> list:
    out = []
    for m in _PHONE_RE.findall(text or ""):
        digits = re.sub(r"\D", "", m)
        if digits not in [re.sub(r"\D", "", p) for p in out]:
            out.append(m.strip())
    return out[:MAX_PHONES]


def _wallets(text: str) -> list:
    out = []
    for rx in _WALLET_RES:
        for m in rx.findall(text or ""):
            if m not in out:
                out.append(m)
    return out[:MAX_WALLETS]


def _age(domain: str, cache, age_lookup) -> dict:
    def compute():
        try:
            if age_lookup is not None:
                r = age_lookup(domain)
            else:
                from ..enrichment.domain_age import lookup_domain_age
                r = lookup_domain_age(domain)
            return r.as_dict() if hasattr(r, "as_dict") else dict(r)
        except Exception as e:  # noqa: BLE001
            return {"status": "unknown", "detail": f"age lookup failed ({type(e).__name__})"}
    return cached(cache, f"intel:age:{domain}", DAY, compute)


def intel_findings(text: str, urls: Sequence[str], sender: str, company: str, *,
                   cache: Optional[Cache], protected_extra: Iterable[str] = (), network: bool = True,
                   http_client=None, resolver=None, fetch: Optional[Callable] = None,
                   age_lookup: Optional[Callable] = None) -> List[dict]:
    """
    Run the intel checks that apply to a posting/message and return detector findings.

    text, urls, sender, company: the posting text, any links given separately, the
      sender's email address (or domain), and the claimed company name.
    cache: a Cache (get/set) or None.
    protected_extra: employer domains to protect from lookalikes (and never look up).
    network: False runs only the offline checks.
    http_client / resolver / fetch / age_lookup: injectables for tests (HTTP client for
      the reputation APIs, DNS resolver for SPF/DMARC and Spamhaus, shortener fetch,
      and a domain-age function returning DomainAgeResult or a dict).
    """
    protected_extra = tuple(normalize_host(d) for d in protected_extra if d)
    all_urls, hosts, email_domains = _extract(text, urls, sender)
    findings: List[dict] = []

    # --- shortened links (+ expansion when online) ---
    short_urls = [u for u in all_urls if is_shortener(u)]
    if short_urls:
        matched, dest = [], []
        for u in short_urls[:MAX_URLS]:
            if network:
                r = expand(u, fetch=fetch)
                if r["final_host"] and not is_shortener(r["final_host"]):
                    matched.append(f"{u} -> {r['final_url']}")
                    dest.append(r["final_host"])
                    if r["final_url"] not in all_urls:
                        all_urls.append(r["final_url"])
                    if r["final_host"] not in hosts:
                        hosts.append(r["final_host"])
                else:
                    matched.append(f"{u} (couldn't expand: {r['detail']})")
            else:
                matched.append(u)
        why = ("A link shortener hides where the link really goes. That's common in marketing, "
               "but scammers use it to disguise fake application or payment pages.")
        if dest:
            why += " It actually leads to " + ", ".join(dict.fromkeys(dest)) + "; that site was checked too."
        findings.append(_finding("shortened_link", "note", 4, "A shortened link hides the real destination",
                                 why, matched))

    # --- lookalikes (offline) ---
    fsu_hits, emp_hits = [], []
    for h in hosts:
        if is_shortener(h):
            continue
        for m in lookalike(h, None, protected_extra)[:1]:
            (fsu_hits if m["kind"] == "fsu" else emp_hits).append(m)
    if fsu_hits:
        findings.append(_finding(
            "lookalike_domain", "critical", 35, "A web address pretends to be FSU",
            f"{fsu_hits[0]['detail']}. Real FSU pages end in fsu.edu (like my.fsu.edu or "
            f"careers.fsu.edu). Don't sign in or share anything on this site.",
            [f"{m['domain']} (imitates {m['brand']}: {m['reason']})" for m in fsu_hits]))
    elif emp_hits:
        findings.append(_finding(
            "lookalike_domain", "warning", 22, "A web address imitates the employer's real domain",
            f"{emp_hits[0]['detail']}. Go to the company's site yourself instead of using this link.",
            [f"{m['domain']} (imitates {m['brand']}: {m['reason']})" for m in emp_hits]))

    if not network:
        return findings

    # Registrable domains worth looking up: not free mail, not FSU, not the known employer.
    skip = set(FREE_MAIL) | set(OFFICIAL_FSU_DOMAINS) | {registrable_domain(d) for d in protected_extra}
    regs = []
    for h in hosts:
        if is_shortener(h) or not split_host(h)[2]:
            continue
        reg = registrable_domain(h)
        if reg not in skip and reg not in regs:
            regs.append(reg)
    regs = regs[:MAX_HOSTS]

    # --- domain age ---
    young = []
    for d in regs:
        a = _age(d, cache, age_lookup)
        if a.get("status") == "ok" and isinstance(a.get("age_days"), int) and a["age_days"] < 90:
            young.append((a["age_days"], d))
    if young:
        young.sort()
        youngest = young[0][0]
        weight = 18 if youngest < 30 else 10
        findings.append(_finding(
            "new_domain", "warning", weight, "A website in this posting is brand new",
            f"{young[0][1]} was registered only {youngest} days ago. Scam sites are set up fast and "
            f"thrown away; a real, established employer's site is usually years old.",
            [f"{d}: {n} days old" for n, d in young]))

    # --- blocklists ---
    listed = []
    lookup_hosts = [h for h in hosts if registrable_domain(h) in regs]
    for h in lookup_hosts:
        r = urlhaus_host(h, cache=cache, client=http_client)
        if r.get("status") == "listed":
            listed.append(f"{h}: URLhaus ({r.get('detail')})")
    for u in all_urls[:MAX_URLS]:
        if registrable_domain(normalize_host(u)) not in regs:
            continue
        r = urlhaus_url(u, cache=cache, client=http_client)
        if r.get("status") == "listed":
            listed.append(f"{u}: URLhaus ({r.get('detail')})")
    for d in regs:
        r = spamhaus_dbl(d, cache=cache, resolver=resolver)
        if r.get("status") == "listed":
            listed.append(f"{d}: {r.get('detail')}")
    if listed:
        findings.append(_finding(
            "blocklisted_domain", "critical", 40, "A link is on a security blocklist",
            "Security researchers have already flagged this site for spam, phishing or malware. "
            "Don't open it, and don't enter any login or personal details.", listed))

    # --- SPF / DMARC on the employer's email domain ---
    no_auth = []
    for d in email_domains:
        reg = registrable_domain(d)
        if reg in skip:
            continue
        r = cached(cache, f"intel:emailauth:{reg}", DAY, lambda reg=reg: email_auth(reg, resolver=resolver))
        if r.get("spf", {}).get("status") == "absent" and r.get("dmarc", {}).get("status") == "absent":
            no_auth.append(reg)
    if no_auth:
        who = company.strip() or "the employer"
        findings.append(_finding(
            "no_email_auth", "note", 6, "The email domain isn't set up to prevent spoofing",
            f"{', '.join(no_auth)} publishes no SPF or DMARC records, the basic settings real companies "
            f"use so nobody can fake their email. Small businesses sometimes skip this, so it's only a "
            f"small hint; confirm the offer through {who}'s official website or phone number.",
            no_auth))

    # --- crypto wallets ---
    verified, unverified = [], []
    for w in _wallets(text):
        r = chainabuse_wallet(w, cache=cache, client=http_client)
        if r.get("status") == "reported":
            (verified if r.get("verified") else unverified).append(f"{w}: {r.get('detail')}")
    if verified:
        findings.append(_finding(
            "reported_wallet", "critical", 35, "The crypto wallet here is a confirmed scam wallet",
            "Chainabuse has verified reports of scams using this exact wallet. No real job asks you to "
            "send crypto; don't send money to it.", verified + unverified))
    elif unverified:
        findings.append(_finding(
            "reported_wallet", "warning", 15, "People have reported this crypto wallet as a scam",
            "Chainabuse users have reported this wallet. The reports aren't verified, but a real employer "
            "won't ask you to pay or receive crypto.", unverified))

    # --- phone line type ---
    voip = []
    for p in _phones(text):
        r = twilio_line_type(p, cache=cache, client=http_client)
        if r.get("status") == "ok" and r.get("type") == "nonFixedVoip":
            voip.append(f"{p}: internet phone number" + (f" ({r['carrier']})" if r.get("carrier") else ""))
    if voip:
        findings.append(_finding(
            "virtual_number", "note", 5, "The phone number is an internet (VoIP) number",
            "Numbers from apps like Google Voice or TextNow are free and anonymous, which scammers like. "
            "Plenty of real recruiters use them too, so this alone means very little.", voip))

    return findings
