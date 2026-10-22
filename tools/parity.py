#!/usr/bin/env python3
"""
Parity gate: the browser engine must score every fixture exactly like the Python engine.

    python tools/parity.py                # diff both engines over tests/fixtures/parity_cases.jsonl
    python tools/parity.py --show fake_check   # print both results for one case

The two engines are separate implementations of the same spec (rules.py / scorer.py / leadgen.py /
compensation.py / url_flow.py on one side, web/engine.js on the other). They share the rulepack as data,
but the normalizer, guards, scorer and lead-gen heuristics are code in both places and will drift unless
something checks. This is that check. It compares, per case:

  score, band
  findings: rule_id, severity, weight and the matched evidence, in scorer order
  lead_gen: points, flag, level and the reason strings

Network enrichment (domain age, MX) is skipped on the Python side because the browser has none.
Message-mode checks (sender / link findings) exist only in the browser engine and are not compared.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "tests" / "fixtures" / "parity_cases.jsonl"
RUNNER = ROOT / "web" / "parity_runner.js"

sys.path.insert(0, str(ROOT))
from scam_detector.scorer import score_posting  # noqa: E402


def load_cases(path: Path = CASES) -> list[dict]:
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cases.append(json.loads(line))
    ids = [c["id"] for c in cases]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SystemExit(f"duplicate case ids: {sorted(dupes)}")
    return cases


def python_results(cases: list[dict]) -> list[dict]:
    out = []
    for c in cases:
        r = score_posting(c.get("title", ""), c.get("description", ""), c.get("company", ""),
                          run_network=False, url_chain=c.get("urls") or [])
        out.append({
            "id": c["id"], "score": r.score, "band": r.band,
            "findings": [{"rule_id": f["rule_id"], "severity": f["severity"], "weight": f["weight"],
                          "matched": f["matched"]} for f in r.findings],
            "lead_gen": {"points": r.lead_gen["points"], "flag": r.lead_gen["flag"], "level": r.lead_gen["level"],
                         "reasons": [x["reason"] for x in r.lead_gen["reasons"]]},
        })
    return out


def js_results(cases: list[dict]) -> list[dict]:
    node = shutil.which("node")
    if not node:
        raise SystemExit("node is required for the parity check (https://nodejs.org)")
    payload = "\n".join(json.dumps(c, ensure_ascii=False) for c in cases)
    proc = subprocess.run([node, str(RUNNER)], input=payload, capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"web/parity_runner.js failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def diff(py: list[dict], js: list[dict]) -> list[str]:
    problems = []
    by_id = {r["id"]: r for r in js}
    for p in py:
        j = by_id.get(p["id"])
        if j is None:
            problems.append(f"{p['id']}: missing from JS output")
            continue
        for key in ("score", "band"):
            if p[key] != j[key]:
                problems.append(f"{p['id']}: {key} python={p[key]!r} js={j[key]!r}")
        if p["findings"] != j["findings"]:
            p_ids = [f["rule_id"] for f in p["findings"]]
            j_ids = [f["rule_id"] for f in j["findings"]]
            if p_ids != j_ids:
                problems.append(f"{p['id']}: findings python={p_ids} js={j_ids}")
            else:
                for pf, jf in zip(p["findings"], j["findings"]):
                    if pf != jf:
                        problems.append(f"{p['id']}: {pf['rule_id']} python={pf} js={jf}")
        if p["lead_gen"] != j["lead_gen"]:
            problems.append(f"{p['id']}: lead_gen python={p['lead_gen']} js={j['lead_gen']}")
    return problems


def run(cases: list[dict] | None = None) -> list[str]:
    cases = cases if cases is not None else load_cases()
    return diff(python_results(cases), js_results(cases))


def main() -> int:
    ap = argparse.ArgumentParser(description="Diff the Python and browser engines over the parity fixtures.")
    ap.add_argument("--show", metavar="CASE_ID", help="print both engines' results for one case")
    args = ap.parse_args()
    cases = load_cases()
    if args.show:
        cases = [c for c in cases if c["id"] == args.show]
        if not cases:
            raise SystemExit(f"no case named {args.show!r}")
        print("python:", json.dumps(python_results(cases)[0], indent=2))
        print("js:    ", json.dumps(js_results(cases)[0], indent=2))
        return 0
    problems = run(cases)
    if problems:
        print(f"{len(problems)} parity failure(s) over {len(cases)} cases:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 1
    print(f"parity ok: {len(cases)} cases agree between Python and JS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
