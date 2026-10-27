"""
Scam alerts timed to the school year, plus alerts when a pattern spikes (plan item 30). Drafts only: career-center
staff decide what to send.

    python -m scam_detector.tools.alerts --ics lurecheck-alerts.ics           # yearly reminders for a staff calendar
    python -m scam_detector.tools.alerts --ics alerts.ics --school fsu --year 2027
    python -m scam_detector.tools.alerts --now                                # what's in season today, with drafts
    python -m scam_detector.tools.alerts --trends                             # patterns rising in the last 14 days

Job scams follow the calendar: students look for campus jobs when a semester starts, for internships in spring, and
for remote summer work in May, and scams aimed at each of those show up then. The calendar file puts a reminder on
the career center's calendar a few days before each season, with a ready-to-edit student email and social post.
Import it once; the events repeat every year. A school can move the dates to fit its academic calendar with
"alert_dates" in scam_detector/schools.json, e.g. {"fall-start": "08-18"}.

Trends come from the follow-up cases (verdict and rule ids only, no text): a scam pattern that flagged at least
3 cases in the last 14 days, at twice its usual rate or more, gets a draft alert naming the pattern.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
SCHOOLS = ROOT / "schools.json"
RULEPACK = ROOT / "rulepack" / "core.json"
LEAD_DAYS = 3                       # reminder lands this many days before the season starts
TREND_DAYS = 14
BASELINE_DAYS = 56
TREND_MIN = 3

# (id, start "MM-DD", end "MM-DD", title, what to watch for, student email draft, social post draft)
SEASONS = [
    ("spring-start", "01-06", "02-10", "Start of spring semester",
     "Fake campus jobs and 'research assistant' offers by email, often sent from a real student or staff account "
     "that was hacked.",
     "Looking for a campus job this semester? Scammers send emails that look like they come from a professor or "
     "department, offering easy remote assistant work. If the job pays by check, asks you to buy gift cards or "
     "equipment, or moves you to text or WhatsApp, it's a scam. Real campus jobs are posted on {portal}. Not sure? "
     "Check it with LureCheck or ask the {career}.",
     "New semester, new job scams. A 'professor' offering remote assistant work by email and paying by check is a "
     "scam. Real campus jobs are on {portal}."),
    ("tax-season", "01-20", "04-15", "Tax season",
     "Requests for your SSN, a W-4, or direct-deposit details 'for payroll' before any real interview.",
     "Tax season is also identity-theft season. A real employer asks for your SSN and bank details only after you've "
     "accepted an offer and are filling out hiring paperwork, usually through its HR system. If someone asks for "
     "them during or before an interview, stop and check with the {career}.",
     "No real employer needs your SSN or bank login before you're hired. Asked for it in an 'interview'? Stop and "
     "check it first."),
    ("internship-hunt", "02-01", "04-30", "Summer internship search",
     "Fake remote internships, offer letters sent after a chat-only 'interview', and 'training' you have to pay for.",
     "Internship offers are coming in. A real offer follows a real interview, comes from the company's own email "
     "domain, and never asks you to pay for training or deposit a check for equipment. Got an offer letter? Paste it "
     "into LureCheck before you sign anything, or bring it to the {career}.",
     "Got an internship offer after a chat-only interview? Check the letter before you sign. Real offers never come "
     "with a check to deposit."),
    ("summer-remote", "05-01", "06-15", "Remote summer work",
     "Work-from-home 'assistant' and package-reshipping jobs, paid tasks that need a deposit first, mystery shopping.",
     "Heading home for the summer and looking for remote work? Watch for jobs that pay you to receive and reship "
     "packages, 'tasks' you have to fund before you're paid, and flat weekly pay for a few hours of work. Those are "
     "the most common summer scams. Check any offer with LureCheck first.",
     "Summer scam check: reshipping packages from home, paid 'tasks' that need a deposit, $500/week for 2 hours a "
     "day. All scams."),
    ("fall-start", "08-10", "09-20", "Start of fall semester",
     "Fake campus jobs and 'research assistant' offers by email (often from hacked university accounts), and "
     "pet-sitting or caregiver jobs that pay by check.",
     "Welcome back. Scammers target students looking for a campus job at the start of every semester. Watch for "
     "emails from a 'professor' or department offering remote assistant work, pet-sitting jobs for a relative who's "
     "'moving to the area', and anything that pays you by check and asks you to send part of it on. Real campus jobs "
     "are on {portal}. Questions? The {career} can help.",
     "Back-to-school scam alert: a 'professor' offering remote work by email, or a pet-sitting job that pays by "
     "check first, is a scam. Check before you reply."),
    ("fall-recruiting", "09-15", "10-31", "Fall recruiting and career fairs",
     "Fake recruiters using big company names, interviews by text only, and offer letters with equipment checks.",
     "It's recruiting season, and scammers pretend to be recruiters from companies you know. Real recruiters write "
     "from the company's own domain or a hiring system, interview you by phone or video, and never send you a check "
     "to buy equipment. If a recruiter texts you out of nowhere, look the company up yourself and apply through its "
     "own site.",
     "A 'recruiter' texting you out of nowhere with an interview over chat? Look the company up yourself. Real "
     "recruiters don't send checks for equipment."),
    ("holiday", "11-01", "12-20", "Holiday season",
     "Reshipping and 'personal shopper' jobs, and work that involves buying gift cards.",
     "Holiday jobs that ask you to receive packages and ship them on, buy gift cards for a boss or client, or act as "
     "a 'personal shopper' with money they send you are scams, and the packages and money are usually stolen. If "
     "you've already started, stop and talk to the {career} or your bank.",
     "Holiday scam alert: no real job has you reship packages from home or buy gift cards for your boss."),
]


def _school(code: str) -> dict:
    try:
        return json.loads(SCHOOLS.read_text(encoding="utf-8")).get(code, {})
    except (OSError, ValueError):
        return {}


def seasons(school: str = "") -> List[dict]:
    """Seasons for a school, with its alert_dates overrides applied."""
    cfg = _school(school)
    moved = cfg.get("alert_dates", {})
    fill = {"career": cfg.get("career", "career center"), "portal": cfg.get("portal", "your school's job board")}
    out = []
    for sid, start, end, title, watch, email, social in SEASONS:
        out.append({"id": sid, "start": moved.get(sid, start), "end": end, "title": title, "watch_for": watch,
                    "email": email.format(**fill), "social": social.format(**fill)})
    return out


def _md(year: int, mmdd: str) -> dt.date:
    m, d = (int(x) for x in mmdd.split("-"))
    return dt.date(year, m, d)


def active(today: dt.date, school: str = "") -> List[dict]:
    """Seasons running on this day."""
    return [s for s in seasons(school) if _md(today.year, s["start"]) <= today <= _md(today.year, s["end"])]


def _ics_text(s: str) -> str:
    return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _fold(line: str) -> List[str]:
    """RFC 5545: lines over 75 octets continue on the next line after a space."""
    out, cur = [], ""
    for ch in line:
        if len((cur + ch).encode("utf-8")) > (75 if not out else 74):
            out.append(cur)
            cur = ""
        cur += ch
    out.append(cur)
    return [out[0]] + [" " + c for c in out[1:]]


def ics(year: int, school: str = "", stamp: Optional[dt.datetime] = None) -> str:
    stamp = (stamp or dt.datetime.now(dt.timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//LureCheck//Scam alerts//EN", "CALSCALE:GREGORIAN",
             "METHOD:PUBLISH", "X-WR-CALNAME:LureCheck scam alerts"]
    for s in seasons(school):
        day = _md(year, s["start"]) - dt.timedelta(days=LEAD_DAYS)
        desc = (f"Season starts {s['start']}, runs to {s['end']}.\nWatch for: {s['watch_for']}\n\n"
                f"Student email draft:\n{s['email']}\n\nSocial post draft:\n{s['social']}")
        ev = ["BEGIN:VEVENT", f"UID:lurecheck-{school or 'all'}-{s['id']}@lurecheck.com", f"DTSTAMP:{stamp}",
              f"DTSTART;VALUE=DATE:{day:%Y%m%d}", f"DTEND;VALUE=DATE:{day + dt.timedelta(days=1):%Y%m%d}",
              "RRULE:FREQ=YEARLY", f"SUMMARY:{_ics_text('Scam alert to send: ' + s['title'])}",
              f"DESCRIPTION:{_ics_text(desc)}", "TRANSP:TRANSPARENT", "END:VEVENT"]
        lines += ev
    lines.append("END:VCALENDAR")
    return "\r\n".join(l for line in lines for l in _fold(line)) + "\r\n"


def trends(cases: List[dict], today: dt.date, rules: dict, school: str = "") -> List[dict]:
    """Rule patterns flagging cases faster than usual. Each row: rule, title, recent, usual (per 14 days), draft."""
    recent_from = today - dt.timedelta(days=TREND_DAYS)
    base_from = recent_from - dt.timedelta(days=BASELINE_DAYS)
    recent, base = Counter(), Counter()
    for c in cases:
        if c.get("band") not in ("review", "block") or (school and c.get("school") != school):
            continue
        try:
            d = dt.date.fromisoformat(str(c.get("date", ""))[:10])
        except ValueError:
            continue
        bucket = recent if recent_from < d <= today else base if base_from < d <= recent_from else None
        if bucket is not None:
            bucket.update(set(c.get("rules", [])))
    out = []
    for rid, n in recent.most_common():
        usual = base[rid] * TREND_DAYS / BASELINE_DAYS
        if n >= TREND_MIN and n >= 2 * usual and rid in rules:
            title = rules[rid].get("title", rid)
            out.append({"rule": rid, "title": title, "recent": n, "usual": round(usual, 1),
                        "draft": f"Scam alert: in the last two weeks, students have been sent messages matching "
                                 f"this pattern: \"{title}\". {rules[rid].get('why', '')} If you got one, don't "
                                 f"reply, and check it with LureCheck or the career center."})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--school", default="")
    ap.add_argument("--year", type=int, default=dt.date.today().year)
    ap.add_argument("--ics", help="write the yearly calendar file here")
    ap.add_argument("--now", action="store_true", help="show the seasons running today")
    ap.add_argument("--trends", action="store_true", help="show patterns rising in the last 14 days")
    a = ap.parse_args(argv)
    if not (a.ics or a.now or a.trends):
        ap.error("pick --ics, --now or --trends")
    if a.ics:
        Path(a.ics).write_text(ics(a.year, a.school), encoding="utf-8", newline="")
        print(f"wrote {a.ics}: {len(SEASONS)} yearly reminders")
    if a.now:
        running = active(dt.date.today(), a.school)
        for s in running:
            print(f"## {s['title']} ({s['start']} to {s['end']})\nWatch for: {s['watch_for']}\n\nEmail:\n{s['email']}"
                  f"\n\nSocial:\n{s['social']}\n")
        if not running:
            print("No seasonal alert is running today.")
    if a.trends:
        from ..store import get_store
        core = json.loads(RULEPACK.read_text(encoding="utf-8"))
        rows = trends(get_store().cases(), dt.date.today(), {r["id"]: r for r in core["rules"]}, a.school)
        for r in rows:
            print(f"- {r['title']}: {r['recent']} flagged in 14 days (usually {r['usual']})\n  Draft: {r['draft']}")
        if not rows:
            print("No pattern is rising faster than usual.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
