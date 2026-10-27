"""
The monthly trends report for a career center: what hit its students this month, how that compares with last month,
and whether the detector is keeping up. Plain Markdown, written to be forwarded upstairs as it is.

    from scam_detector.trends import monthly, render
    print(render(monthly("fsu", "2026-10")))

Everything comes from reviewer-confirmed data (labels, confirmed reports and their indicators) and the anonymous outcome
follow-up. Nothing here names a student. Report text is not needed: the scheme of each confirmed scam is read from its
masked label text, which outlives the report's 30-day text retention.
"""

from __future__ import annotations

import calendar
import datetime as dt
from collections import Counter
from typing import Optional

# Scheme families, first match wins. Rule ids are the rulepack's (scam_detector/rulepack/core.json).
FAMILIES = [
    ("Fake checks and money mule", {"fake_check_funds", "fake_check_es", "money_mule", "mule_recruitment", "reship_home", "crypto_atm"}),
    ("Pay to start (fees, training, equipment)", {"advance_fee", "advance_fee_es", "pay_to_work", "startup_cost",
                                                  "training_sale_perks", "commission_system_pitch"}),
    ("Task, app and review jobs", {"task_scam", "app_boost_task", "review_fraud"}),
    ("Identity and bank-detail harvesting", {"banking_pii", "pii_upfront"}),
    ("Impersonation and threats", {"visa_threat", "authority_impersonation_zh", "brand_recruiter_text"}),
    ("Mystery shopping", {"mystery_shopping"}),
    ("Easy-money assistant offers", {"weekly_stipend", "weekly_pay_few_hours", "remote_weekly_pay", "weekly_pay_assistant",
                                     "student_hardship_bait", "pet_sitter_relative", "earnings_per_day", "income_claim", "too_good"}),
]
OTHER = "Other (no rule recognizes the scheme)"
CHANNELS = {"off_platform": "moved to a messaging app", "personal_channel": "moved to a personal phone or email",
            "text_interview": "interview by text only", "unsolicited_contact": "cold contact from a 'directory'"}
HARM = {"sent_money": "sent money", "deposited_check": "deposited a check", "shared_bank_details": "shared bank details",
        "shared_personal_info": "shared personal information", "shared_login": "shared a login", "gift_cards": "bought gift cards",
        "crypto": "sent crypto", "shipped_packages": "shipped packages", "installed_software": "installed software"}  # recovery.HAPPENED


def month_bounds(month: str) -> tuple[float, float]:
    y, m = (int(x) for x in month.split("-"))
    start = dt.datetime(y, m, 1, tzinfo=dt.timezone.utc)
    end = dt.datetime(y, m, calendar.monthrange(y, m)[1], tzinfo=dt.timezone.utc) + dt.timedelta(days=1)
    return start.timestamp(), end.timestamp()


def previous(month: str) -> str:
    y, m = (int(x) for x in month.split("-"))
    return f"{y - 1}-12" if m == 1 else f"{y}-{m - 1:02d}"


def family(rule_ids: set) -> str:
    for name, ids in FAMILIES:
        if rule_ids & ids:
            return name
    return OTHER


def _ts(iso: str) -> float:
    try:
        return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def _scams(st, school: str, a: float, b: float) -> list[dict]:
    return [l for l in st.labels() if l["label"] == "scam" and l.get("school") == school and a <= (l.get("at") or 0) < b]


def monthly(school: str, month: str, st=None, model=None) -> dict:
    """Everything the report shows, as data."""
    from . import learning
    from .scorer import score_posting
    if st is None:
        from .store import get_store
        st = get_store()
    a, b = month_bounds(month)
    pa, pb = month_bounds(previous(month))
    now_rows, prev_rows = _scams(st, school, a, b), _scams(st, school, pa, pb)
    model = model if model is not None else learning.active_model(st)

    def read(rows):
        fams, chans, caught, misses = Counter(), Counter(), 0, []
        for r in rows:
            res = score_posting(r.get("title", ""), r["description"], r.get("company", ""), run_network=False)
            ids = {f["rule_id"] for f in res.findings}
            fams[family(ids)] += 1
            for k in ids & set(CHANNELS):
                chans[k] += 1
            hit = res.band in ("review", "block")
            if not hit and model is not None:
                hit = model.predict(r.get("title", ""), r["description"], r.get("company", ""), "", res.findings, res.score)["flag"]
            caught += hit
            if not hit:
                misses.append(r)
        return fams, chans, caught, misses

    fams, chans, caught, missed = read(now_rows)
    # the misses grouped by script (copies of one scam show once, with how many there were), biggest first
    groups: list = []
    for r in missed:
        sh = learning._trigrams(r)
        for g in groups:
            if learning._jaccard(sh, g[0]) >= learning.NEAR_COPY:
                g[2] += 1
                break
        else:
            groups.append([sh, r["description"][:140], 1])
    misses = [(text, n) for _, text, n in sorted(groups, key=lambda g: -g[2])]
    prev_fams, _, _, _ = read(prev_rows)
    reports = [r for r in st.confirmed_reports(school=school) if a <= _ts(r.get("reviewed_at") or r.get("received", "")) < b]
    domains = Counter(d for r in reports for d in r.get("indicators", {}).get("domains", []))
    shared = {}
    if domains:
        try:
            shared = {m["value"]: m["schools"] for m in st.confirmed_matches({"domains": list(domains)}) if m["kind"] == "domain"}
        except Exception:                               # noqa: BLE001 - a missing table must not stop the report
            shared = {}
    cases = {c["case"] for c in st.cases() if c.get("school") == school}
    harm = Counter(h for o in st.outcomes() if o["case"] in cases and a <= _ts(o["date"]) < b for h in o["happened"] if h in HARM)
    answered = sum(1 for o in st.outcomes() if o["case"] in cases and a <= _ts(o["date"]) < b)
    runs = [r for r in st.runs(200) if a <= (r.get("started_at") or 0) < b]
    return {
        "school": school, "month": month, "previous": previous(month),
        "confirmed": len(now_rows), "confirmed_prev": len(prev_rows),
        "families": [(name, fams.get(name, 0), prev_fams.get(name, 0)) for name, _ in FAMILIES + [(OTHER, None)]
                     if fams.get(name, 0) or prev_fams.get(name, 0)],
        "caught": caught, "misses": misses[:5], "channels": [(CHANNELS[k], n) for k, n in chans.most_common()],
        "domains": [(d, n, shared.get(d, 0)) for d, n in domains.most_common(8)],
        "harm": [(HARM[k], n) for k, n in harm.most_common()], "followups": answered,
        "retrains": Counter(r["status"] for r in runs), "release": st.release(),
        "real_jobs_labeled": sum(1 for l in st.labels() if l["label"] == "legit" and l.get("school") == school and a <= (l.get("at") or 0) < b),
    }


def _change(now: int, before: int) -> str:
    if before == 0:
        return "new" if now else "-"
    pct = round((now - before) / before * 100)
    return f"{'+' if pct > 0 else ''}{pct}%"


def render(d: dict, school_name: Optional[str] = None) -> str:
    y, m = (int(x) for x in d["month"].split("-"))
    title = f"{school_name or d['school']}: job-scam trends, {calendar.month_name[m]} {y}"
    lines = [f"# {title}", ""]
    if not d["confirmed"] and not d["confirmed_prev"]:
        return "\n".join(lines + ["No confirmed scams this month or last. Reports that reviewers haven't decided yet aren't counted."])
    lines += [f"**{d['confirmed']} confirmed scams** targeted students this month ({d['confirmed_prev']} in "
              f"{calendar.month_name[int(d['previous'][5:])]}, {_change(d['confirmed'], d['confirmed_prev'])}). "
              f"Only scams a reviewer confirmed are counted.", ""]
    if d["families"]:
        lines += ["## What kinds", "", "| Scheme | This month | Last month | Change |", "|---|---|---|---|"]
        lines += [f"| {n} | {a} | {b} | {_change(a, b)} |" for n, a, b in sorted(d["families"], key=lambda x: -x[1])]
        lines.append("")
    if d["confirmed"]:
        pct = round(d["caught"] / d["confirmed"] * 100)
        lines += ["## Is the detector keeping up", "",
                  f"Today's detector flags **{d['caught']} of {d['confirmed']}** ({pct}%) of this month's confirmed scams on its own."]
        if d["misses"]:
            lines += ["The ones it still misses are where the next rules and retrains come from:", ""]
            lines += [f"- \"{t.strip()}...\"" + (f" ({n} copies)" if n > 1 else "") for t, n in d["misses"]]
        lines.append("")
    if d["channels"]:
        lines += ["## How they reached students", ""] + [f"- {n} scams {what}" for what, n in d["channels"]] + [""]
    if d["domains"]:
        lines += ["## Domains reviewers confirmed", "", "| Domain | Reports here | Schools that have seen it |", "|---|---|---|"]
        lines += [f"| {dom} | {n} | {s or '-'} |" for dom, n, s in d["domains"]]
        lines.append("")
    if d["followups"]:
        lines += ["## What students told us happened", "",
                  f"{d['followups']} students answered the follow-up this month." + (" Of those, some had already acted:" if d["harm"] else
                                                                                  " None reported losing money or details.")]
        lines += [f"- {n} {what}" for what, n in d["harm"]]
        lines.append("")
    rt, rel = d["retrains"], d["release"]
    learned = []
    if sum(rt.values()):
        learned.append(f"{sum(rt.values())} retrain attempt{'s' if sum(rt.values()) != 1 else ''} "
                       f"({rt.get('candidate', 0)} passed the gate, {rt.get('refused', 0)} refused)")
    if d["real_jobs_labeled"]:
        learned.append(f"{d['real_jobs_labeled']} real jobs labeled, which keeps false alarms down")
    if rel.get("stage") and rel["stage"] != "none":
        learned.append(f"a new model is in {rel['stage']}")
    if learned:
        lines += ["## What the detector learned", "", "This month: " + "; ".join(learned) + ".", ""]
    lines.append("_Generated by LureCheck from reviewer-confirmed reports. No student is named in this report._")
    return "\n".join(lines)
