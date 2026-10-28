"""
Reviewer accounts for the review page (/review). The only way accounts are made: there is no sign-up on the web.

    python -m scam_detector.tools.reviewers add --email jdoe@fsu.edu --name "J. Doe" --school fsu
    python -m scam_detector.tools.reviewers add --email you@example.com --name "Evan" --school ""   # every school
    python -m scam_detector.tools.reviewers list
    python -m scam_detector.tools.reviewers reset jdoe@fsu.edu        # new temporary password, logs out everywhere
    python -m scam_detector.tools.reviewers disable jdoe@fsu.edu      # or enable

add and reset print a temporary password once. Send it to the person by a different channel from the page link and ask
them to change it under Password after logging in. Uses DATABASE_URL when set, files otherwise.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys


def main(argv=None) -> int:
    from .. import guardrails
    from .. import reviewers as acct
    from ..store import get_store
    ap = argparse.ArgumentParser(description="Reviewer accounts for the review page")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("--email", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--school", required=True, help='a school code from schools.json, or "" for every school')
    sub.add_parser("list")
    for c in ("reset", "disable", "enable"):
        sub.add_parser(c).add_argument("email")
    args = ap.parse_args(argv)
    st = get_store()

    if args.cmd == "add":
        if args.school and args.school not in guardrails._config():
            print(f"error: unknown school {args.school!r} (add it to scam_detector/schools.json first)", file=sys.stderr)
            return 2
        pw = acct.temp_password()
        try:
            st.add_reviewer(acct.normalize_email(args.email), args.name, args.school, acct.hash_password(pw))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"added {acct.normalize_email(args.email)} for {args.school or 'every school'}")
        print(f"temporary password (shown once): {pw}")
        return 0

    if args.cmd == "list":
        for r in st.reviewers():
            last = dt.datetime.fromtimestamp(r["last_login"]).strftime("%Y-%m-%d") if r.get("last_login") else "never"
            print(f"{r['email']:40} {r['name']:24} {r['school'] or '(every school)':16} "
                  f"{'active' if r['active'] else 'DISABLED':9} last login {last}")
        return 0

    r = st.reviewer_by_email(acct.normalize_email(args.email))
    if r is None:
        print(f"error: no account for {args.email}", file=sys.stderr)
        return 1
    if args.cmd == "reset":
        pw = acct.temp_password()
        st.set_reviewer(r["email"], pw_hash=acct.hash_password(pw))
        st.drop_sessions(r["id"])
        print(f"reset {r['email']}; logged out everywhere")
        print(f"temporary password (shown once): {pw}")
        return 0
    st.set_reviewer(r["email"], active=(args.cmd == "enable"))
    if args.cmd == "disable":
        st.drop_sessions(r["id"])
    print(f"{args.cmd}d {r['email']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
