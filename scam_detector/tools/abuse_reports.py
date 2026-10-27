"""
Draft takedown requests for confirmed scam domains (plan item 47). Drafts only: a person reads and sends them.

    python -m scam_detector.tools.abuse_reports --out drafts/            # every confirmed domain
    python -m scam_detector.tools.abuse_reports --since 2026-10-01 --out drafts/

For each domain in reviewer-confirmed reports it looks up the registrar and its abuse contact through RDAP (the
public successor to WHOIS, via rdap.org), groups the domains by registrar, and writes one plain-text email per
registrar: the domains, when and how often students reported them, what the scam was, and that each was confirmed
by a named reviewer. Registrars act on reports like these under their abuse policies; a host or platform can be
added the same way.

Nothing is sent from here, and no student data is included: only domains, dates, counts and the reviewer's name.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional, Tuple

Fetch = Callable[[str], Tuple[int, str]]
RDAP = "https://rdap.org/domain/{d}"


def _default_fetch(url: str) -> Tuple[int, str]:
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json", "User-Agent": "LureCheck abuse reports"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(500_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def _vcard_email(entity: dict) -> str:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and item and item[0] == "email":
            return str(item[-1])
    return ""


def registrar_of(domain: str, fetch: Optional[Fetch] = None) -> dict:
    """{"registrar", "abuse_email"} from RDAP; empty strings when unknown. Never raises."""
    try:
        status, body = (fetch or _default_fetch)(RDAP.format(d=domain))
        data = json.loads(body) if status == 200 and body else {}
    except Exception:                                   # noqa: BLE001 - offline, timeouts, bad JSON
        data = {}
    name, abuse = "", ""
    for ent in data.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            vc = (ent.get("vcardArray") or [None, []])[1]
            name = next((str(i[-1]) for i in vc if isinstance(i, list) and i and i[0] == "fn"), name)
            for sub in ent.get("entities", []) or []:
                if "abuse" in (sub.get("roles") or []):
                    abuse = _vcard_email(sub) or abuse
        if "abuse" in (ent.get("roles") or []):
            abuse = _vcard_email(ent) or abuse
    return {"registrar": name, "abuse_email": abuse}


def drafts(reports: list, fetch: Optional[Fetch] = None) -> dict:
    """{registrar: {"abuse_email", "domains": [{domain, reports, first_seen, last_seen, outcomes}], "reviewers"}}"""
    per_domain = defaultdict(lambda: {"reports": 0, "days": [], "outcomes": set(), "reviewers": set()})
    for r in reports:
        for d in r.get("indicators", {}).get("domains", []):
            m = per_domain[d]
            m["reports"] += 1
            m["days"].append(r.get("received", "")[:10])
            if r.get("outcome"):
                m["outcomes"].add(r["outcome"])
            if r.get("reviewer"):
                m["reviewers"].add(r["reviewer"])
    out = {}
    for d, m in sorted(per_domain.items()):
        reg = registrar_of(d, fetch)
        key = reg["registrar"] or "Unknown registrar"
        g = out.setdefault(key, {"abuse_email": reg["abuse_email"], "domains": [], "reviewers": set()})
        g["abuse_email"] = g["abuse_email"] or reg["abuse_email"]
        days = sorted(x for x in m["days"] if x)
        g["domains"].append({"domain": d, "reports": m["reports"], "first_seen": days[0] if days else "",
                             "last_seen": days[-1] if days else "", "outcomes": sorted(m["outcomes"])})
        g["reviewers"] |= m["reviewers"]
    return out


def email_text(registrar: str, group: dict) -> str:
    lines = [f"To: {group['abuse_email'] or '(no abuse contact in RDAP; use the registrar abuse form)'}",
             f"Subject: Abuse report: domains used in employment scams targeting university students", "",
             f"Hello {registrar} abuse team,", "",
             "The domains below were used in job scams aimed at university students. Each was reported by a student "
             "and confirmed by a reviewer before this report. The scams offer fake jobs, then send fake checks, ask for "
             "fees or collect personal and bank details.", ""]
    for d in group["domains"]:
        what = ", ".join(o.replace("_", " ") for o in d["outcomes"]) or "scam contact"
        lines.append(f"- {d['domain']}: {d['reports']} confirmed report(s), {d['first_seen']} to {d['last_seen']}; "
                     f"students reported: {what}")
    lines += ["", "We ask that you suspend these domains under your abuse policy. We can provide the masked message "
              "text for any of them on request.", "",
              f"Confirmed by: {', '.join(sorted(group['reviewers'])) or 'LureCheck reviewers'}", "LureCheck"]
    return "\n".join(lines)


def main(argv=None) -> int:
    from ..store import get_store
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--since", default="")
    ap.add_argument("--school", default="")
    ap.add_argument("--out", required=True, help="folder for the draft emails")
    a = ap.parse_args(argv)
    groups = drafts(get_store().confirmed_reports(a.since, a.school))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, g in groups.items():
        safe = "".join(c if c.isalnum() else "_" for c in name)[:60] or "registrar"
        (out / f"{safe}.txt").write_text(email_text(name, g) + "\n", encoding="utf-8")
    print(f"wrote {len(groups)} draft(s) to {out}; nothing was sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
