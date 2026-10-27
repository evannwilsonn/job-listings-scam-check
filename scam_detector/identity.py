"""
Who sent it: checks on the sender's address, display name and reply-to, offline.

    sender_findings(sender, sender_name="", reply_to="", company="", text="") -> [finding dict, ...]

The text rules judge what a message says. These judge who it comes from, which is what stops the scams whose text
is real: a genuine posting copied from a real company with a fake recruiter attached, or a message sent from a
hacked university account.

  personal_sender         warning 18  claims to be a recruiter, HR or the university but writes from free mail
  reply_to_elsewhere      warning 18  replies go to a different domain than the one it was sent from
                          warning 24  ... and the sender is a .edu address (the hijacked-account pattern)
  sender_company_mismatch note 8      the sender's domain has nothing to do with the company it names
  display_name_spoof      warning 20  the display name names the company, the address doesn't

Weights are deliberately modest: staffing agencies, hiring platforms and small employers legitimately send from
other domains, so these add up with other signs rather than decide on their own. Hiring platforms that send on an
employer's behalf (Greenhouse, Workday, ...) never count as a mismatch. Pure stdlib, no network.
"""

from __future__ import annotations

import re
from typing import List

from .intel.domains import registrable_domain
from .rules import FREE_MAIL

_EMAIL = re.compile(r"[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)
_CLAIMS = re.compile(
    r"\b(?:hr|human\s+resources|recruit(?:er|ing|ment)|talent\s+acquisition|hiring\s+(?:manager|team)|onboarding|"
    r"professor|prof\.|dr\.|department|dept\.?|university|career\s+(?:center|services)|financial\s+aid|faculty)\b", re.I)
# Sends on an employer's behalf, so a different domain is normal.
HIRING_PLATFORMS = frozenset({
    "greenhouse.io", "greenhouse-mail.io", "lever.co", "myworkday.com", "workday.com",
    "ashbyhq.com", "icims.com", "smartrecruiters.com", "jobvite.com", "taleo.net", "successfactors.com",
    "bamboohr.com", "linkedin.com", "indeed.com", "indeedemail.com", "joinhandshake.com", "handshake.com",
    "ziprecruiter.com", "glassdoor.com", "workable.com", "recruitee.com", "paylocity.com", "adp.com",
    "ultipro.com", "ukg.com", "dayforcehcm.com", "breezy.hr", "jazzhr.com", "applytojob.com",
})
_GENERIC = frozenset("""inc llc ltd corp corporation co company companies group holdings services service solutions
international global the and of usa us america american consulting partners associates enterprises technologies
technology tech systems""".split())
_INITIALS_SKIP = frozenset("the and of inc llc ltd co corp".split())


def _domain(addr: str) -> str:
    m = _EMAIL.search(addr or "")
    return m.group(1).lower().rstrip(".") if m else ""


def _finding(rule_id, severity, weight, title, why, matched) -> dict:
    return {"rule_id": rule_id, "severity": severity, "weight": weight, "title": title, "why": why,
            "matched": [m for m in matched if m][:5]}


def _company_words(company: str) -> List[str]:
    words = re.findall(r"[a-z0-9]+", (company or "").lower())
    return [w for w in words if len(w) >= 3 and w not in _GENERIC]


def _relates(domain: str, company: str) -> bool:
    """Whether the domain plausibly belongs to the company: a name word appears in it, or its initials do."""
    words = _company_words(company)
    if not words:
        return True                                  # nothing to compare against: don't flag
    label = re.sub(r"[^a-z0-9]", "", registrable_domain(domain).split(".")[0])
    if any(w in label for w in words):
        return True
    # Initials use every word but filler and legal suffixes: "International Business Machines" -> ibm.
    all_words = [w for w in re.findall(r"[a-z0-9]+", company.lower()) if w not in _INITIALS_SKIP]
    initials = "".join(w[0] for w in all_words)
    return len(initials) >= 2 and label.startswith(initials)


def _is_edu(domain: str) -> bool:
    return domain.endswith(".edu")


def sender_findings(sender: str, sender_name: str = "", reply_to: str = "", company: str = "",
                    text: str = "") -> List[dict]:
    """Findings about who sent the message. Empty when no sender is given. Never raises."""
    sd = _domain(sender)
    if not sd:
        return []
    out: List[dict] = []
    reg = registrable_domain(sd)

    if reg in FREE_MAIL or sd in FREE_MAIL:
        claim = _CLAIMS.search(f"{text}\n{sender_name}")
        if claim:
            out.append(_finding(
                "personal_sender", "warning", 18, "Official-sounding message from a personal account",
                f"It presents itself as {claim.group(0).lower()} but was sent from {sd}. Universities and real "
                f"companies write from their own domain.", ["@" + sd]))

    rd = _domain(reply_to)
    if rd and registrable_domain(rd) != reg and registrable_domain(rd) not in HIRING_PLATFORMS:
        if _is_edu(sd):
            out.append(_finding(
                "reply_to_elsewhere", "warning", 24, "A university address that replies somewhere else",
                f"It was sent from {sd}, but your reply would go to {rd}. That's how messages from hacked "
                f"student and staff accounts work: the real address gets past filters, the replies go to the "
                f"scammer. A genuine .edu address doesn't make it real.", [f"from @{sd}", f"reply-to @{rd}"]))
        else:
            out.append(_finding(
                "reply_to_elsewhere", "warning", 18, "Your reply goes to a different address",
                f"It was sent from {sd}, but your reply would go to {rd}. Check where you're replying before "
                f"you send anything.", [f"from @{sd}", f"reply-to @{rd}"]))

    if (company and reg not in FREE_MAIL and reg not in HIRING_PLATFORMS and not _is_edu(sd)
            and not _relates(sd, company)):
        out.append(_finding(
            "sender_company_mismatch", "note", 8, "The sender's domain doesn't match the company",
            f"It says it's from {company.strip()}, but the address is at {sd}. Agencies and small employers "
            f"sometimes do this; check the company's own website for how it hires.", ["@" + sd]))

    if sender_name and reg not in HIRING_PLATFORMS:
        named = _company_words(company)
        name_l = sender_name.lower()
        if named and any(w in name_l for w in named) and not _relates(sd, company):
            out.append(_finding(
                "display_name_spoof", "warning", 20, "The sender name and the address don't match",
                f"The name shown is \"{sender_name.strip()[:60]}\", but the address is at {sd}. Anyone can set a "
                f"display name.", [sender_name.strip()[:80]]))
    return out
