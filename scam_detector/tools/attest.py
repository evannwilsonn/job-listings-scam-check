"""
Record what a real employer told you about how it recruits (plan item 16).

    python -m scam_detector.tools.attest --company "Acme Corp" --domains acme.com,acmecareers.com \\
        --careers-url https://acme.com/careers --never-text --never-chat-apps --verified-by "E. Wilson" \\
        --contact "Jordan Lee, Talent Acquisition (called main line 2026-10-27)"
    python -m scam_detector.tools.attest --show "Acme Corp"

Only record an attestation after confirming it with the employer through a number or address you found yourself on
the employer's own website, never through a contact that came with a message. A wrong attestation makes LureCheck warn
students about real recruiters, so the reviewer's name is required. Checks and fees are assumed never (real employers
don't send checks or charge applicants); pass --allows-checks or --allows-fees only if the employer says otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from ..attestations import company_key


def main(argv=None) -> int:
    from ..store import get_store
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--company", default="")
    ap.add_argument("--domains", default="", help="comma-separated email domains the recruiters send from")
    ap.add_argument("--careers-url", default="")
    ap.add_argument("--never-text", action="store_true")
    ap.add_argument("--never-chat-apps", action="store_true")
    ap.add_argument("--allows-checks", action="store_true")
    ap.add_argument("--allows-fees", action="store_true")
    ap.add_argument("--contact", default="", help="who confirmed it and how (kept private)")
    ap.add_argument("--verified-by", default="")
    ap.add_argument("--show", default="", metavar="COMPANY")
    a = ap.parse_args(argv)
    store = get_store()
    if a.show:
        print(json.dumps(store.attestation(company_key(a.show)), indent=1, default=str))
        return 0
    domains = [d.strip().lower().lstrip("@") for d in a.domains.split(",") if d.strip()]
    if not a.company or not domains or not a.verified_by.strip():
        print("error: --company, --domains and --verified-by are required", file=sys.stderr)
        return 2
    if not all(re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d) for d in domains):
        print(f"error: not a domain: {domains}", file=sys.stderr)
        return 2
    rec = {"company": a.company.strip(), "company_key": company_key(a.company), "email_domains": domains,
           "careers_url": a.careers_url or None, "never_text": a.never_text, "never_chat_apps": a.never_chat_apps,
           "never_checks": not a.allows_checks, "never_fees": not a.allows_fees, "contact": a.contact or None,
           "verified_by": a.verified_by.strip()}
    store.add_attestation(rec)
    print(f"recorded {rec['company']} ({rec['company_key']}): {', '.join(domains)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
