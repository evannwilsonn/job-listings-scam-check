"""
Compensation plausibility check.

The question we can actually answer: "is the advertised pay wildly above the
national median for work of this kind?" That is the signal that matters for scam
detection, because the bait in most job scams is pay far above market for
low-skill remote work.

Data source: U.S. Bureau of Labor Statistics, Occupational Employment and Wage
Statistics (OEWS/OES), national median wages. This data is free, authoritative,
and public-domain. It updates once a year, so it is bundled here as a static table
rather than fetched per-request. To refresh: download the national OEWS file from
https://www.bls.gov/oes/tables.htm and re-run tools/build_wage_table.py.

Honest limitations, stated plainly:
  - National figures only. Real pay varies a lot by metro; a rate that looks high
    nationally may be normal in San Francisco. We flag "well above national
    median," not "above local market."
  - We map a free-text job title to an occupation with keyword matching. This is
    coarse and will sometimes miss. When we can't map a title, we say so and score
    nothing, rather than guessing.
  - The figures below are BLS OEWS May 2023 national medians (the most recent
    complete release as of this writing). Treat them as approximate and refresh
    annually.

This check produces a *fact* ("advertised $45/hr is ~2.4x the national median for
this occupation"), not a verdict. The scorer decides how much that matters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional, List, Tuple


# occupation_key -> (human label, median annual USD, [title keywords])
# Median annual wages, BLS OEWS May 2023 national data. Refresh annually.
BLS_MEDIAN_ANNUAL = {
    "data_entry":       ("Data Entry Keyers", 37790,
                         ["data entry", "data-entry", "data processor", "typing", "keyer"]),
    "admin_assistant":  ("Secretaries & Administrative Assistants", 46010,
                         ["administrative assistant", "admin assistant", "secretary",
                          "office assistant", "administrative support", "clerical"]),
    "customer_service": ("Customer Service Representatives", 39680,
                         ["customer service", "customer support", "call center",
                          "customer care", "support representative"]),
    "shipping_receiving": ("Shipping, Receiving & Inventory Clerks", 40260,
                         ["shipping", "receiving", "warehouse clerk", "package handler",
                          "reshipping", "shipping coordinator", "logistics coordinator"]),
    "personal_assistant": ("Personal & Executive Assistants", 46010,
                         ["personal assistant", "executive assistant", "virtual assistant"]),
    "bookkeeper":       ("Bookkeeping & Accounting Clerks", 47440,
                         ["bookkeeper", "bookkeeping", "accounting clerk", "accounts payable",
                          "accounts receivable", "payment processor", "payment processing"]),
    "receptionist":     ("Receptionists", 35840,
                         ["receptionist", "front desk"]),
    "general_office":   ("General Office Clerks", 40480,
                         ["office clerk", "general office", "remote assistant",
                          "work from home assistant", "remote worker"]),
    "sales_rep":        ("Sales Representatives (non-technical)", 63230,
                         ["sales representative", "sales rep", "account executive", "inside sales"]),
    "software_dev":     ("Software Developers", 132270,
                         ["software engineer", "software developer", "developer", "programmer",
                          "full stack", "backend engineer", "frontend engineer"]),
    "data_analyst":     ("Data / Operations Analysts", 83640,
                         ["data analyst", "business analyst", "operations analyst"]),
}

HOURS_PER_YEAR = 2080  # 40 hrs/week * 52 weeks, the BLS convention


@dataclass
class CompensationResult:
    status: str                 # "flagged" | "within_range" | "no_pay_found" | "title_unmapped"
    detail: str = ""
    advertised_annual: Optional[float] = None
    matched_occupation: Optional[str] = None
    national_median: Optional[float] = None
    ratio_to_median: Optional[float] = None

    def as_dict(self) -> dict:
        return asdict(self)


def _map_title_to_occupation(title: str, description: str) -> Optional[Tuple[str, str, int]]:
    """Return (key, label, median) for the best keyword match, or None."""
    haystack = f"{title} {description}".lower()
    best = None
    best_len = 0
    for key, (label, median, keywords) in BLS_MEDIAN_ANNUAL.items():
        for kw in keywords:
            if kw in haystack and len(kw) > best_len:
                best = (key, label, median)
                best_len = len(kw)
    return best


def _extract_annualized_pay(text: str) -> List[float]:
    """
    Pull pay figures from text and annualize them. Returns the list of annual
    equivalents found (we test the highest against the median).
    """
    results: List[float] = []
    # $NN(-$NN)? per hour/day/week/month/year, with flexible separators
    pat = re.compile(
        r"\$\s?([\d,]+(?:\.\d+)?)\s*(?:-|–|to|\+)?\s*(?:\$?\s?([\d,]+(?:\.\d+)?))?"
        r"\s*(?:/|per|an?\s)?\s*(hour|hr|day|week|month|year|annum|yr)",
        re.IGNORECASE,
    )
    for m in pat.finditer(text):
        hi = float((m.group(2) or m.group(1)).replace(",", ""))
        unit = m.group(3).lower()
        if unit in ("hour", "hr"):
            results.append(hi * HOURS_PER_YEAR)
        elif unit == "day":
            results.append(hi * 260)          # ~260 working days
        elif unit == "week":
            results.append(hi * 52)
        elif unit == "month":
            results.append(hi * 12)
        else:                                  # year / annum / yr
            results.append(hi)
    return results


def check_compensation(title: str, description: str, flag_ratio: float = 1.8) -> CompensationResult:
    """
    flag_ratio: how many times the national median counts as 'well above market'.
    1.8x is a deliberately conservative default — it catches the blatant bait
    ($45/hr data entry ~= 2.5x) without flagging a genuinely good offer.
    """
    text = f"{title}\n{description}"
    pays = _extract_annualized_pay(text)
    if not pays:
        return CompensationResult(status="no_pay_found",
                                  detail="no parseable pay figure in the posting")

    advertised = max(pays)
    occ = _map_title_to_occupation(title, description)
    if occ is None:
        return CompensationResult(status="title_unmapped", advertised_annual=advertised,
                                  detail="could not map the job title to a known occupation")

    key, label, median = occ
    ratio = advertised / median
    if ratio >= flag_ratio:
        return CompensationResult(
            status="flagged", advertised_annual=advertised, matched_occupation=label,
            national_median=median, ratio_to_median=round(ratio, 2),
            detail=(f"advertised ~${advertised:,.0f}/yr is {ratio:.1f}x the national median "
                    f"of ${median:,.0f} for {label}"),
        )
    return CompensationResult(
        status="within_range", advertised_annual=advertised, matched_occupation=label,
        national_median=median, ratio_to_median=round(ratio, 2),
        detail=(f"advertised ~${advertised:,.0f}/yr is {ratio:.1f}x the national median "
                f"for {label} — within plausible range"),
    )
