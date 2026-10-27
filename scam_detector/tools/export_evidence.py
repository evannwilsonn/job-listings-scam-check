"""
Package reviewer-confirmed reports as evidence for the people who can act on it.

    python -m scam_detector.tools.export_evidence -o evidence.json --summary evidence.md
    python -m scam_detector.tools.export_evidence --since 2026-10-01 --school fsu -o fsu_october.json

Reads only reports a reviewer marked confirmed (tools/review_queue.py) and merges their indicators:

  domains   in the clear, with how many reports and schools named them and when: what a registrar's or host's
            abuse desk needs for a takedown, and what a platform needs to block links
  wallets   in the clear (they're the scammer's): for the exchange and IC3
  email and phone hashes: these stay hashed. They let another LureCheck school, or a partner holding the same salt,
            match a contact it already has; they can't be read back.

The summary is plain text for an abuse desk, a campus bank's fraud team or an IC3 report, and states that each
indicator was confirmed by a named reviewer. It is a reviewer's attestation, not a forensic chain of custody.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import defaultdict

from .review_queue import QUEUE, read


def package(rows: list, since: str = "", school: str = "", now=None) -> dict:
    keep = [r for r in rows if r.get("status") == "confirmed"
            and (not since or r.get("received", "") >= since) and (not school or r.get("school") == school)]
    merged = {k: defaultdict(lambda: {"reports": 0, "schools": set(), "first_seen": "", "last_seen": ""})
              for k in ("domains", "wallets", "email_hashes", "phone_hashes")}
    for r in keep:
        day = r.get("received", "")[:10]
        for kind in merged:
            for v in r.get("indicators", {}).get(kind, []):
                m = merged[kind][v]
                m["reports"] += 1
                if r.get("school"):
                    m["schools"].add(r["school"])
                m["first_seen"] = min(filter(None, [m["first_seen"], day])) if day else m["first_seen"]
                m["last_seen"] = max(m["last_seen"], day)
    indicators = {kind: sorted(({"value": v, "reports": m["reports"], "schools": sorted(m["schools"]),
                                 "first_seen": m["first_seen"], "last_seen": m["last_seen"]}
                                for v, m in vals.items()), key=lambda x: (-x["reports"], x["value"]))
                  for kind, vals in merged.items()}
    return {"generated": (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0).isoformat(),
            "reports": len(keep), "schools": sorted({r.get("school") for r in keep if r.get("school")}),
            "outcomes": dict(sorted(_count(r.get("outcome") for r in keep).items())),
            "indicators": indicators, "attested_by": sorted({r.get("reviewer") for r in keep if r.get("reviewer")})}


def _count(values) -> dict:
    out = defaultdict(int)
    for v in values:
        if v:
            out[v] += 1
    return out


def summary(p: dict) -> str:
    ind = p["indicators"]
    lines = [f"Job-scam indicators confirmed by LureCheck reviewers ({p['generated'][:10]})", "",
             f"{p['reports']} student reports from {len(p['schools']) or 'no named'} school(s), each read and confirmed "
             f"by a reviewer ({', '.join(p['attested_by']) or 'unnamed'}). Student identities are not collected.", ""]
    if ind["domains"]:
        lines.append("Domains used in these scams (for takedown or blocking):")
        lines += [f"  {d['value']}  reports={d['reports']} seen {d['first_seen']}..{d['last_seen']}" for d in ind["domains"]]
        lines.append("")
    if ind["wallets"]:
        lines.append("Cryptocurrency addresses students were told to pay:")
        lines += [f"  {w['value']}  reports={w['reports']}" for w in ind["wallets"]]
        lines.append("")
    if p["outcomes"]:
        lines.append("What students reported had happened: " +
                     ", ".join(f"{k.replace('_', ' ')} ({v})" for k, v in p["outcomes"].items()))
    lines.append(f"Also: {len(ind['email_hashes'])} email addresses and {len(ind['phone_hashes'])} phone numbers, "
                 f"held as salted hashes; available for matching on request.")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--queue", default=str(QUEUE))
    ap.add_argument("--since", default="", help="ISO date; only reports received on or after it")
    ap.add_argument("--school", default="")
    ap.add_argument("-o", "--out", default="")
    ap.add_argument("--summary", default="")
    a = ap.parse_args(argv)
    p = package(read(a.queue), a.since, a.school)
    text = json.dumps(p, indent=1)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text + "\n")
    if a.summary:
        open(a.summary, "w", encoding="utf-8").write(summary(p) + "\n")
    if not a.out and not a.summary:
        print(summary(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
