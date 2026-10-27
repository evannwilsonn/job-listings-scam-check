"""
Weekly look-alike domain watch for every subscribing school.

    python -m scam_detector.tools.ct_watch_run                      # all schools in schools.json, last 8 days
    python -m scam_detector.tools.ct_watch_run --days 30 --school fsu
    python -m scam_detector.tools.ct_watch_run --out ct_report.json --markdown ct_report.md

Reads scam_detector/schools.json ({"fsu": {"name": ..., "terms": [...], "employer_domains": [...]}}), asks the public
certificate-transparency logs (crt.sh) for certificates issued since --days ago to names containing each school's
terms, and reports the ones that look like the school. A certificate is issued before a phishing site goes live, so
this often finds the site before the first student does.

The report is for a reviewer: a domain found here is a lead, not a confirmed indicator. Exit code is always 0 unless
the config can't be read, so a scheduled run never fails just because crt.sh was slow.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from ..intel.ct_watch import find_new_lookalike_certs

CONFIG = Path(__file__).resolve().parent.parent / "schools.json"


def run(config: dict, days: int, only: str = "", fetch=None) -> dict:
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    out = {"since": since.replace(microsecond=0).isoformat(), "schools": {}}
    for key, school in sorted(config.items()):
        if only and key != only:
            continue
        r = find_new_lookalike_certs(school.get("terms", []), since, fetch=fetch,
                                     extra=school.get("employer_domains", []))
        out["schools"][key] = {"name": school.get("name", key), **r}
    return out


def markdown(report: dict) -> str:
    lines = [f"# Look-alike domain watch (certificates since {report['since'][:10]})", ""]
    for key, r in report["schools"].items():
        lines.append(f"## {r['name']}: {len(r.get('domains', []))} new, status {r.get('status')}")
        for d in r.get("domains", []):
            lines.append(f"- `{d['domain']}` first seen {str(d.get('first_seen'))[:10]}: {d.get('detail') or d.get('reason')}")
        for e in r.get("errors", []):
            lines.append(f"- (couldn't check `{e['term']}`: {e['detail']})")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--config", default=str(CONFIG))
    ap.add_argument("--days", type=int, default=8)
    ap.add_argument("--school", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--markdown", default="")
    a = ap.parse_args(argv)
    try:
        config = json.loads(Path(a.config).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"can't read {a.config}: {e}", file=sys.stderr)
        return 2
    report = run(config, a.days, a.school)
    text = json.dumps(report, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
    if a.markdown:
        Path(a.markdown).write_text(markdown(report) + "\n", encoding="utf-8")
    if not a.out:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
