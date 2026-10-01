"""
URL/flow signals for job postings and application links.

Text rules catch scams that SAY scammy things. This module catches the category
that doesn't: clean-reading postings wrapped in a lead-generation aggregator,
where the tell lives in the URL and the click-path, not the words.

This module reads URLs the USER supplies -- either the one they were given,
or the chain they followed by hand (as in "I clicked apply and ended up at X").
It never fetches or navigates anything itself; it parses strings. Any live
fetch of a company site is done explicitly elsewhere (see scorer.py's use of
web_fetch equivalents), on a URL the user already provided -- never by
clicking through a logged-in platform session.

The signal here is not "is this a redirect" -- legitimate aggregators redirect
too (see the HireFeed -> Joblet.ai example below). The signal is whether each
hop DISCLOSES what it is, versus obscuring it behind tracking and a forced
signup wall. That distinction only comes from a human reading the destination,
which is exactly what the context flags in scorer.py are for. This module
covers the part that's mechanical: parsing the URL/domain structure itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

from ..rules import Finding


# Known job-board / ATS domains that are NOT the employer -- landing here is
# normal and not itself a signal (a real employer's listing lives on one of
# these all the time).
NEUTRAL_JOB_PLATFORMS = {
    "linkedin.com", "indeed.com", "glassdoor.com", "ziprecruiter.com",
    "greenhouse.io", "lever.co", "workday.com", "myworkdayjobs.com",
    "smartrecruiters.com", "jobs.polymer.co", "polymer.co", "ashbyhq.com",
    "icims.com", "taleo.net", "bamboohr.com", "careers-page.com",
}

# Tracking / affiliate parameter names that indicate paid-click or campaign
# routing rather than a direct application.
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_category",
    "cpc", "affiliate", "extra_id_consumer_run", "extra_prev_uid", "extrlint",
}

# Path fragments that indicate a redirect hop or a forced account wall rather
# than a direct listing.
REDIRECT_PATH_MARKERS = ["/away/", "/out/", "/click/", "/redirect/", "/go/"]
SIGNUP_WALL_MARKERS = ["/register", "/signup", "/sign-up", "/apply-with-ai", "/start_google_auth"]


@dataclass
class UrlFinding:
    marker: str
    detail: str


def _domain(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def _name_key(s: str) -> str:
    """Lowercase, letters-only key for loose name matching (company vs domain)."""
    return re.sub(r"[^a-z]", "", s.lower())


def analyze_url_chain(urls: List[str], company: str = "") -> List[Finding]:
    """
    urls: the chain of URLs the user actually followed, in order (as few as
    one). Each is a hop; the LAST one is where "apply" ultimately lands.
    company: the company name claimed on the original listing, if any.

    Returns Findings the scorer can add alongside text/enrichment findings.
    Weights are deliberately modest -- this is one signal among several, and
    legitimate aggregators (disclosed ones) will trip some of these too.
    """
    if not urls:
        return []

    findings: List[Finding] = []
    hits: List[UrlFinding] = []

    for url in urls:
        domain = _domain(url)
        parsed = urlparse(url)
        path = parsed.path.lower()
        params = {k.lower() for k in parse_qs(parsed.query).keys()}

        if any(m in path for m in REDIRECT_PATH_MARKERS):
            hits.append(UrlFinding("redirect_hop", f"{domain}{path} is a redirect/tracking hop"))

        tracked = params & TRACKING_PARAMS
        if tracked:
            hits.append(UrlFinding("tracking_params", f"{domain} URL carries tracking params: {', '.join(sorted(tracked))}"))

        if "cpc" in params or "cpc" in url.lower():
            hits.append(UrlFinding("paid_click", f"{domain} URL contains a cost-per-click parameter -- paid traffic arbitrage"))

        if any(m in path for m in SIGNUP_WALL_MARKERS):
            hits.append(UrlFinding("signup_wall", f"{domain}{path} forces account creation before showing the listing"))

    # Domain-mismatch check: does the FINAL landing domain relate to the
    # claimed company name at all? This is deliberately conservative --
    # skipped entirely if the final domain is a known neutral platform, OR
    # if the chain has more than one hop (a multi-hop chain is common for
    # disclosed aggregators like a jobs feed handing off to a job board;
    # punishing that shape alone produces false positives on legitimate
    # aggregators). It only fires for a SINGLE-hop apply link that claims to
    # be a specific named employer but lands somewhere unrelated -- that
    # combination (one hop, named employer, unrelated domain) is what
    # RemoteHunter showed and what a disclosed aggregator does not do.
    final_domain = _domain(urls[-1])
    single_hop = len(urls) == 1
    if single_hop and company.strip() and final_domain and not any(final_domain.endswith(p) for p in NEUTRAL_JOB_PLATFORMS):
        company_key = _name_key(company)
        domain_key = _name_key(final_domain.split(".")[0])
        if company_key and len(company_key) > 3:
            overlap = company_key[:6] in domain_key or domain_key[:6] in company_key
            if not overlap:
                hits.append(UrlFinding(
                    "domain_mismatch",
                    f"Final application domain ({final_domain}) doesn't match the claimed "
                    f"employer name ({company.strip()}) and isn't a known job platform",
                ))

    if not hits:
        return []

    # Consolidate into findings, capped in weight so this can't alone push a
    # posting to "block" -- it's corroborating evidence, not a verdict.
    by_marker = {}
    for h in hits:
        by_marker.setdefault(h.marker, []).append(h.detail)

    marker_specs = {
        "redirect_hop": ("note", 6, "The apply link passes through a redirect/tracking hop",
                         "A redirect before the real listing is common for legitimate aggregators too, "
                         "but it's worth knowing you're not going straight to the employer."),
        "tracking_params": ("note", 5, "The apply link carries campaign tracking parameters",
                            "UTM and similar tags mean this link is part of a marketing/affiliate campaign, "
                            "not a direct posting from the employer."),
        "paid_click": ("warning", 14, "The apply link is paid-per-click traffic",
                       "A cost-per-click parameter means someone gets paid each time this link is "
                       "clicked, regardless of whether you're hired -- that's an ad, not a job posting."),
        "signup_wall": ("warning", 15, "An account signup is forced before you can see the listing",
                        "Legitimate job boards let you see the posting before asking you to create an "
                        "account. A forced signup wall exists to harvest your email and profile."),
        "domain_mismatch": ("warning", 16, "The apply link doesn't lead to the claimed employer",
                            "The application ultimately goes to a domain unrelated to the company the "
                            "listing named, and it isn't a recognized job platform -- a sign you're "
                            "dealing with a reposting or aggregator, not the employer directly."),
    }

    for marker, details in by_marker.items():
        sev, weight, title, why = marker_specs[marker]
        findings.append(Finding("url_" + marker, sev, weight, title, why, details[:3]))

    return findings
