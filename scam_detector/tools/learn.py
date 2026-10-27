"""
Run and watch the learning loop (scam_detector/learning.py).

    python -m scam_detector.tools.learn status              # release stage, what's due, drift, recent runs
    python -m scam_detector.tools.learn tick                # the scheduled job: move the release along, retrain when due
    python -m scam_detector.tools.learn retrain             # retrain now (same gate); --trigger fast for the fast lane
    python -m scam_detector.tools.learn release next        # with MODEL_AUTO_RELEASE=0: take the next step by hand
    python -m scam_detector.tools.learn release stop        # discard the candidate
    python -m scam_detector.tools.learn release rollback    # restore the previous model

Schedule `tick` every 30 minutes wherever DATABASE_URL and LURECHECK_DATA (the labeled corpora) are available.
Rollback is always automatic; the buttons here are for a person who has seen something the checks haven't.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from .. import learning


def _when(t) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(t)) if t else "-"


def status(st) -> str:
    rel = st.release()
    ok, why, trig = learning.due(st)
    d = learning.drift_status(st)
    lines = [f"Release: {rel['stage']}" + (f" ({rel['lane']} lane)" if rel["stage"] != "none" else "")
             + (f", {rel['pct']}% of checks" if rel["stage"] == "rollout" else ""),
             f"  active model: {rel.get('active_version') or 'the one shipped with the code'}",
             f"  candidate: {rel.get('candidate_version') or '-'}   previous: {rel.get('previous_version') or '-'}",
             f"  {rel.get('note') or ''}",
             f"Retrain: {'due now (' + trig + ')' if ok else 'not due'}: {why}",
             f"Drift: {d['level']}: {d['why']}"]
    if rel["stage"] in ("shadow", "rollout"):
        n, cr, ar = learning.compared_traffic(rel, st)
        lines.append(f"  compared on {n} checks: candidate flags {cr:.0%}, active {ar:.0%}")
    lines.append("Recent runs:")
    lines += [f"  {_when(r['started_at'])}  {r['trigger']:<9} {r['status']:<11} {r.get('version') or '':<13} {r.get('train_rows', 0)} rows"
              for r in st.runs(8)] or ["  none yet"]
    lines.append("Release log:")
    lines += [f"  {_when(l['at'])}  {l['event']:<12} {l.get('version') or '':<13} {l.get('detail', '')[:100]}"
              for l in st.release_log(8)] or ["  nothing yet"]
    return "\n".join(lines)


def main(argv=None) -> int:
    from ..store import get_store
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("tick")
    r = sub.add_parser("retrain")
    r.add_argument("--trigger", default="manual", choices=["manual", "fast"])
    rel = sub.add_parser("release")
    rel.add_argument("action", choices=["next", "stop", "rollback"])
    rel.add_argument("--who", default="")
    a = ap.parse_args(argv)
    st = get_store()
    if a.cmd == "status":
        print(status(st))
    elif a.cmd == "tick":
        print(json.dumps(learning.learn_tick(st), indent=1))
    elif a.cmd == "retrain":
        res = learning.run_retrain(a.trigger, force=True, st=st)
        print(json.dumps(res, indent=1))
        return 0 if res["status"] in ("candidate", "refused") else 1
    else:
        cur = st.release()
        if a.action == "next":
            if cur["stage"] == "shadow":
                learning.start_rollout(who=a.who, st=st)
            elif cur["stage"] == "rollout":
                nxt = [p for p in learning.STAGES if p > int(cur["pct"])]
                if not nxt or nxt[0] >= 100:
                    learning.promote(st)
                else:
                    learning.start_rollout(nxt[0], a.who, st)
            else:
                print("nothing to advance", file=sys.stderr)
                return 1
        elif a.action == "stop":
            if cur["stage"] not in ("shadow", "rollout"):
                print("no candidate in release", file=sys.stderr)
                return 1
            learning.discard(f"stopped by {a.who or 'a person'}", st=st)
        elif not learning.rollback(f"restored by {a.who or 'a person'}", st):
            print("nothing to roll back", file=sys.stderr)
            return 1
        print(status(st))
    return 0


if __name__ == "__main__":
    sys.exit(main())
