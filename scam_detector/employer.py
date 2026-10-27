"""
Is the job real, and is the person real? Two checks that don't depend on how the message is written.

    check_job_board(company, title, urls=(), fetch=None) -> dict
    verification_script(company, title="", recruiter="", channel="") -> dict

The most convincing scams copy a real posting from a real company and attach a fake recruiter, so the text passes
every rule. What scammers can't fake is the company's own hiring system. Many employers publish their open jobs
through Greenhouse, Lever or Ashby, which have public read-only APIs. check_job_board finds the company's board (from
a link in the message, or by trying the company name) and looks for the job title.

  status "found"            the job is on the company's own board. The job is real; that still doesn't prove the
                            person who contacted you works there.
  status "not_listed"       the board exists and has no job by that title. A lead for a reviewer, never a verdict:
                            jobs close, and some are only on the company site.
  status "no_public_board"  no board on these three platforms. Says nothing either way: most small employers and
                            every Workday company land here.
  status "unknown"          the lookups failed.

verification_script is the step that turns "maybe" into "no": the student calls the company on a number they found
themselves, not one from the message.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Callable, Iterable, List, Optional, Tuple

Fetch = Callable[[str], Tuple[int, str]]

PROVIDERS = {
    "greenhouse": ("https://boards-api.greenhouse.io/v1/boards/{t}/jobs",
                   re.compile(r"(?:job-)?boards(?:-api)?\.greenhouse\.io/(?:v1/boards/)?([a-z0-9_-]+)", re.I)),
    "lever": ("https://api.lever.co/v0/postings/{t}?mode=json", re.compile(r"jobs\.lever\.co/([a-z0-9_-]+)", re.I)),
    "ashby": ("https://api.ashbyhq.com/posting-api/job-board/{t}", re.compile(r"jobs\.ashbyhq\.com/([a-z0-9_.-]+)", re.I)),
}
MAX_LOOKUPS = 9
MAX_BYTES = 16_000_000                 # Ashby boards include every job description: 13 MB for a large employer
_SKIP_WORDS = frozenset("""inc llc ltd corp corporation co company the and of group holdings""".split())
_TITLE_NOISE = frozenset("""the a an and of for to in at with remote hybrid onsite on site full part time i ii iii iv
senior sr junior jr lead entry level intern internship""".split())


def _default_fetch(url: str) -> Tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "LureCheck job verification (+https://lurecheck.com)",
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read(MAX_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def board_tokens(company: str) -> List[str]:
    words = [w for w in re.findall(r"[a-z0-9]+", (company or "").lower()) if w not in _SKIP_WORDS]
    if not words:
        return []
    return list(dict.fromkeys(["".join(words), "-".join(words), words[0]]))


_PAIR = {
    "greenhouse": re.compile(r'"absolute_url"\s*:\s*"((?:[^"\\]|\\.)*)".{0,4000}?"title"\s*:\s*"((?:[^"\\]|\\.)*)"', re.S),
    "lever": re.compile(r'"text"\s*:\s*"((?:[^"\\]|\\.)*)".{0,20000}?"hostedUrl"\s*:\s*"((?:[^"\\]|\\.)*)"', re.S),
    "ashby": re.compile(r'"title"\s*:\s*"((?:[^"\\]|\\.)*)".{0,400}?"jobUrl"\s*:\s*"((?:[^"\\]|\\.)*)"', re.S),
}


def _salvage(provider: str, body: str) -> List[dict]:
    """Titles from a response cut off at MAX_BYTES, so a huge board still gets checked (partially)."""
    out = []
    for m in _PAIR[provider].finditer(body or ""):
        a, b = (json.loads(f'"{g}"') for g in m.groups())
        url, title = (a, b) if provider == "greenhouse" else (b, a)
        out.append({"title": title, "url": url})
    return out


def _jobs(provider: str, body: str) -> List[dict]:
    try:
        data = json.loads(body or "null")
    except ValueError:
        return _salvage(provider, body)
    if provider == "greenhouse":
        rows = (data or {}).get("jobs", [])
        return [{"title": j.get("title", ""), "url": j.get("absolute_url", "")} for j in rows]
    if provider == "lever":
        rows = data if isinstance(data, list) else []
        return [{"title": j.get("text", ""), "url": j.get("hostedUrl", "")} for j in rows]
    rows = (data or {}).get("jobs", []) if isinstance(data, dict) else []
    return [{"title": j.get("title", ""), "url": j.get("jobUrl", "")} for j in rows]


def _words(title: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]+", (title or "").lower()) if w not in _TITLE_NOISE}


def title_matches(claimed: str, listed: str) -> bool:
    a, b = _words(claimed), _words(listed)
    if not a or not b:
        return False
    return len(a & b) / len(a) >= 0.6


def check_job_board(company: str, title: str, urls: Iterable[str] = (), fetch: Optional[Fetch] = None) -> dict:
    fetch = fetch or _default_fetch
    candidates = []                                     # (provider, token), links in the message first
    for u in urls or ():
        for prov, (_, rx) in PROVIDERS.items():
            m = rx.search(u or "")
            if m:
                candidates.append((prov, m.group(1).lower()))
    for t in board_tokens(company):
        candidates += [(p, t) for p in PROVIDERS]
    candidates = list(dict.fromkeys(candidates))[:MAX_LOOKUPS]
    checked, errors = [], 0
    for prov, token in candidates:
        try:
            status, body = fetch(PROVIDERS[prov][0].format(t=token))
        except Exception:                               # noqa: BLE001 - timeouts, resets
            errors += 1
            continue
        checked.append(f"{prov}:{token}")
        if status != 200:
            continue
        try:
            jobs = _jobs(prov, body)
        except (ValueError, AttributeError, TypeError, KeyError):
            continue
        if not jobs:
            continue
        matches = [j for j in jobs if title_matches(title, j["title"])][:5]
        return {"status": "found" if matches else "not_listed", "provider": prov, "board": token,
                "open_jobs": len(jobs), "matches": matches, "checked": checked}
    status = "unknown" if errors and errors == len(candidates) else "no_public_board"
    return {"status": status, "provider": "", "board": "", "open_jobs": 0, "matches": [], "checked": checked}


def board_finding(result: dict, company: str, title: str) -> Optional[dict]:
    """A reviewer-facing note when the company's own board doesn't list the job. Never more than a note."""
    if result.get("status") != "not_listed":
        return None
    return {"rule_id": "job_not_on_company_board", "severity": "note", "weight": 8,
            "title": "The job isn't on the company's own job board",
            "why": (f"{company.strip()}'s job board on {result['provider'].title()} lists {result['open_jobs']} open jobs "
                    f"and none called \"{title.strip()[:80]}\". Jobs close and some are only on the company's website, "
                    f"so ask for a link to the posting on the company's own careers page before going further."),
            "matched": [f"{result['provider']}:{result['board']}"]}


def verification_script(company: str, title: str = "", recruiter: str = "", channel: str = "") -> dict:
    company = (company or "the company").strip()[:120]
    role = f"the {title.strip()[:100]} role" if title else "this job"
    who = recruiter.strip()[:100] if recruiter else "the person who contacted me"
    how = f" by {channel.strip()[:60]}" if channel else ""
    return {
        "find_the_number": [
            f"Search for {company} yourself and open its official website. Don't use any link, phone number or email "
            f"from the message.",
            "Find the main phone number or the careers or HR contact on that site.",
            "If the company has no website you can find, or the only contact is the one in the message, treat that as a "
            "red flag.",
        ],
        "what_to_say": (f"Hi, I was contacted{how} about {role} by {who}, who said they're with {company}. "
                        f"Can you confirm that this job is open and that this person works in your recruiting team?"),
        "ask": [
            f"Is {role} open, and where is it posted?",
            f"Does {who} work for {company}?",
            "Does your company ever interview by text or chat app, or send checks for equipment?",
        ],
        "real_company_says": "Real recruiters are happy for you to check. They'll confirm the job and the person.",
        "red_flags": [
            "They can't confirm the job or the person.",
            "The recruiter gets upset or pushes you not to call.",
            "The only number that answers is the one from the message.",
        ],
        "after": "Whatever they say, you can tell us with your case code, which helps warn other students.",
    }


SCREEN_VERDICTS = {
    "hold": "Don't approve yet: something here matches a confirmed scam or breaks what the employer told us. Verify "
            "the employer by phone through its own website first.",
    "check": "Needs a closer look before approving. Check the points below with the employer directly.",
    "ok": "No problems found. That isn't proof: approve the way you normally would.",
}


def screen_employer(company: str, contact_email: str = "", website: str = "", title: str = "", description: str = "",
                    run_network: bool = True, fetch: Optional[Fetch] = None, store=None) -> dict:
    """
    One view of an employer for a career-center reviewer at approval time (plan item 17): who is writing, whether the
    job is on the company's own board, what the company attested, whether any contact is already a confirmed scam,
    and what the posting text triggers. It recommends; it never approves or rejects on its own.
    """
    from .attestations import attestation_findings
    from .identity import sender_findings
    from .intel import intel_findings
    from .network import network_findings
    from .scorer import score_posting

    text = "\n".join(x for x in (description, website, contact_email) if x)
    scored = score_posting(title, description or "", company, run_network=run_network) if (description or title) else None
    findings = list(scored.findings) if scored else []
    findings += sender_findings(contact_email, "", "", company, description)
    have = {f["rule_id"] for f in findings}
    findings += [f for f in intel_findings(text, [website] if website else [], contact_email, company, cache=None,
                                           network=run_network) if f["rule_id"] not in have]
    findings += network_findings(text, contact_email, store=store)
    att, att_f = attestation_findings(company, contact_email, description, findings, store=store)
    findings += att_f
    board = check_job_board(company, title, [website] if website else [], fetch=fetch) if (run_network and title) else None
    note = board_finding(board or {}, company, title)
    if note:
        findings.append(note)
    verdict = ("hold" if any(f["severity"] == "critical" for f in findings)
               else "check" if any(f["severity"] == "warning" for f in findings) else "ok")
    return {"verdict": verdict, "advice": SCREEN_VERDICTS[verdict], "findings": findings, "board": board,
            "attested": bool(att), "score": scored.score if scored else 0}
