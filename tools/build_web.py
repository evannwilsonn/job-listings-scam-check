#!/usr/bin/env python3
"""
Build index.html from its parts.

    python tools/build_web.py          # write index.html
    python tools/build_web.py --check  # exit 1 if index.html is stale (CI drift guard)

index.html is a build output. The page keeps its one-file, no-server form (open it from disk or
serve it with GitHub Pages) but nothing in it is hand-written: the rulepack comes from
scam_detector/rulepack/core.json, the engine from web/engine.js and the markup from web/page.html.
Edit those, rebuild, commit all of it together.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULEPACK = ROOT / "scam_detector" / "rulepack" / "core.json"
MODEL = ROOT / "scam_detector" / "models" / "scam_model.json"
# Model fields the browser needs. drift_ref and holdout are for the training tools only.
MODEL_KEYS = ("format", "version", "threshold", "rule_scale", "rule_ids", "rule_coef", "vocab", "cvocab",
              "shape_coef", "shape_scale", "intercept", "conformal", "trained_at")
ENGINE = ROOT / "web" / "engine.js"
PAGE = ROOT / "web" / "page.html"
OUT = ROOT / "index.html"


def public_rulepack(core: dict) -> dict:
    """The rulepack as shipped to the browser: active rules only, change history stripped.

    The history entries carry superseded regexes that the engine never runs; leaving them out keeps the
    page smaller and keeps the shipped artifact equal to what the engine actually evaluates. Rule order
    is preserved because the scorer's sort is stable on weight ties.
    """
    rules = []
    for spec in core["rules"]:
        if spec.get("status", "active") != "active":
            continue
        rules.append({k: v for k, v in spec.items() if k != "history"})
    return {"version": str(core.get("version", "unknown")), "rules": rules}


def public_model() -> dict | None:
    """The learned model as shipped to the browser, or None when there is no model file (rules only)."""
    if not MODEL.exists():
        return None
    spec = json.loads(MODEL.read_text(encoding="utf-8"))
    model = {k: spec[k] for k in MODEL_KEYS if k in spec}
    model["trained_on"] = {"rows": spec.get("trained_on", {}).get("rows")}
    return model


def _json(obj) -> str:
    # </script> inside a JSON string would end the script tag early; JSON-escape the slash.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def render() -> str:
    core = json.loads(RULEPACK.read_text(encoding="utf-8"))
    pack = public_rulepack(core)
    page = PAGE.read_text(encoding="utf-8")
    engine = ENGINE.read_text(encoding="utf-8").rstrip("\n")
    pack_json = _json(pack)
    if "</script" in engine.lower():
        raise SystemExit("web/engine.js must not contain the text '</script'")
    subs = {
        "{{RULEPACK_VERSION}}": pack["version"],
        "{{RULE_COUNT}}": str(len(pack["rules"])),
        "{{RULEPACK_JSON}}": pack_json,
        "{{MODEL_JSON}}": _json(public_model()),
        "{{ENGINE_JS}}": engine,
    }
    for key, val in subs.items():
        if key not in page:
            raise SystemExit(f"web/page.html is missing the {key} placeholder")
        page = page.replace(key, val)
    if "{{" in page:
        raise SystemExit("unreplaced placeholder left in index.html")
    return page


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail instead of writing when index.html is stale")
    args = ap.parse_args()
    html = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != html:
            print("index.html is stale: run `python tools/build_web.py` and commit the result", file=sys.stderr)
            return 1
        print("index.html is up to date")
        return 0
    OUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(html):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
