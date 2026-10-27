"""
A career center's trusted and blocked domains (scam_detector/guardrails.py).

    python -m scam_detector.tools.school_rules list --school fsu
    python -m scam_detector.tools.school_rules trust fsucu.org --school fsu --by "E. Wilson" --reason "FSU Credit Union, verified by phone"
    python -m scam_detector.tools.school_rules block fsu-careers-portal.com --school fsu --by "E. Wilson" --reason "phishing wave, Oct"
    python -m scam_detector.tools.school_rules remove trust fsucu.org --school fsu --by "E. Wilson"

Trust quiets warnings about a domain's infrastructure (new, unregistered, no mail, look-alike) and protects it from
look-alikes. It never overrides scam evidence. Block adds a critical finding to any check that uses the domain. Uses the
database when DATABASE_URL is set, otherwise the development files. Changes reach the API within a minute.
"""

from __future__ import annotations

import argparse
import sys
import time

from ..guardrails import clean_domain

KIND = {"trust": "trusted_domain", "block": "blocked_domain"}


def main(argv=None) -> int:
    from ..store import get_store
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--school", required=True)
    for name in ("trust", "block"):
        p = sub.add_parser(name)
        p.add_argument("domain")
        p.add_argument("--school", required=True)
        p.add_argument("--by", required=True, help="who is adding it")
        p.add_argument("--reason", default="")
    rm = sub.add_parser("remove")
    rm.add_argument("which", choices=list(KIND))
    rm.add_argument("domain")
    rm.add_argument("--school", required=True)
    rm.add_argument("--by", required=True)
    a = ap.parse_args(argv)
    st = get_store()
    try:
        if a.cmd == "list":
            rows = st.school_rules(a.school)
            for r in rows:
                when = time.strftime("%Y-%m-%d", time.gmtime(r["added_at"])) if r.get("added_at") else ""
                print(f"{r['kind']:<15} {r['value']:<32} {when}  {r['added_by']}  {r.get('reason', '')}")
            if not rows:
                print("no entries")
            return 0
        domain = clean_domain(a.domain)
        if a.cmd == "remove":
            if not st.remove_school_rule(a.school, KIND[a.which], domain, a.by):
                print(f"{domain} isn't on the {a.which} list", file=sys.stderr)
                return 1
            print(f"removed {domain} from the {a.which} list")
        else:
            st.add_school_rule(a.school, KIND[a.cmd], domain, a.by, a.reason)
            print(f"{a.cmd}ed {domain} for {a.school}")
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
