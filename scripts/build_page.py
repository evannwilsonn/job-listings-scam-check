"""
Copy the detector's data into the browser page.

index.html carries its own copy of the rulepack and the learned model so it works as one
file with no server. This script writes the current scam_detector/rulepack/core.json and
scam_detector/models/scam_model.json into the page, so the page never runs older data
than the Python engine.

    python scripts/build_page.py            # update index.html
    python scripts/build_page.py --check    # exit 1 if index.html is out of date (CI)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "index.html"
RULEPACK = ROOT / "scam_detector" / "rulepack" / "core.json"
MODEL = ROOT / "scam_detector" / "models" / "scam_model.json"

BLOCK = re.compile(r'<script id="lurecheck-data">.*?</script>', re.S)

# Model fields the browser needs. drift_ref and holdout are for the training tools only.
MODEL_KEYS = ("format", "version", "threshold", "rule_scale", "rule_ids", "rule_coef", "vocab", "cvocab",
              "shape_coef", "shape_scale", "intercept", "conformal", "trained_at")


def _json(obj) -> str:
    # "</" can't appear inside a <script> element; escaping the slash keeps the JSON identical once parsed.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")


def data_block() -> str:
    rulepack = json.loads(RULEPACK.read_text(encoding="utf-8"))
    spec = json.loads(MODEL.read_text(encoding="utf-8"))
    model = {k: spec[k] for k in MODEL_KEYS if k in spec}
    model["trained_on"] = {"rows": spec.get("trained_on", {}).get("rows")}
    return ('<script id="lurecheck-data">\n'
            f"window.LURECHECK_RULEPACK = {_json(rulepack)};\n"
            f"window.LURECHECK_MODEL = {_json(model)};\n"
            "</script>")


def build(page: str) -> str:
    if not BLOCK.search(page):
        raise SystemExit('index.html has no <script id="lurecheck-data"> block to replace')
    return BLOCK.sub(lambda _: data_block(), page, count=1)


def main(argv: list[str]) -> int:
    page = PAGE.read_text(encoding="utf-8")
    new = build(page)
    if "--check" in argv:
        if new != page:
            print("index.html is out of date with the rulepack or model. Run: python scripts/build_page.py", file=sys.stderr)
            return 1
        print("index.html matches the rulepack and model.")
        return 0
    if new != page:
        PAGE.write_text(new, encoding="utf-8")
        print("index.html updated.")
    else:
        print("index.html already up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
