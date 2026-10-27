"""
The browser page (index.html) must run the same detector as the Python engine.

* Its embedded rulepack and model must be the current ones (scripts/build_page.py --check).
* Its JavaScript port of ml.py must give the same probability as ml.py on the same input.
* Its rules must fire the same rules as rules.py on the same text.

The JavaScript checks run the page's script in Node and are skipped where Node isn't installed.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from scam_detector import ml
from scam_detector.scorer import score_posting

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "index.html"

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")

# Hand-written cases covering what the model reads: money, chat apps, look-alike letters, emoji, non-ASCII,
# headers and redaction placeholders, a plain legitimate posting and an empty one.
EXTRA = [
    {"title": "Remote Personal Assistant", "description": "We are hiring a part-time personal assistant to work from home. You will be paid $650 weekly for 1-2 hrs a day, 3 days a week. No experience needed, you are hired immediately after a short interview on Telegram. You will receive a check to purchase office equipment from our approved vendor; deposit it and send the balance by Zelle."},
    {"title": "", "description": "Hello Student, the department is recruiting a research assistant. Pay is $400 every 7 days and the job is flexible. Text me on WhatsApp at wa.me/10000000000 with your full name, address and bank name to get started.\nCareer Services <careerservices.dept@gmail.com>"},
    {"title": "Software Engineer II", "company": "Acme Corp", "description": "Acme Corp, Inc. is an equal opportunity employer. Requirements: bachelor's degree in computer science and 3 years of experience with Python. Benefits include health insurance, dental, vision and a 401k match. Apply on our careers page.", "url": "https://careers.acme.com/jobs/123"},
    {"title": "Data entry", "description": "K i n d l y reply with your wh@tsapp number!!! URGENT hiring today 💼💰 earn $$$ from home, no prior experience needed. Contact our HR department."},
    {"title": "", "description": "From: Dr. [NAME REDACTED]\nSubject: Assistant needed\nI am a professor at the university and need an assistant for errands. Weekly pay of 500 dollars. Reply with your cell and personal email (not your .edu)."},
    {"title": "Étudiant job", "description": "Trabajo para estudiantes: café, résumé, naïve façade — pago semanal. Contacte por Signal."},
    {"title": "", "description": ""},
]


def _test_texts() -> list[dict]:
    """Long string literals from the other test files, used as extra postings."""
    out = []
    for f in sorted((ROOT / "tests").glob("test_*.py")):
        if f.name == "test_page.py":
            continue
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 60:
                out.append({"title": "", "description": node.value})
    seen, uniq = set(), []
    for c in out:
        if c["description"] not in seen:
            seen.add(c["description"])
            uniq.append(c)
    return uniq[:80]


CASES = EXTRA + _test_texts()


def _page_scripts() -> str:
    """The data block and the detector engine, without the page UI (which needs a DOM)."""
    html = PAGE.read_text(encoding="utf-8")
    data = re.search(r'<script id="lurecheck-data">(.*?)</script>', html, re.S).group(1)
    engine = next(s for s in re.findall(r"<script>(.*?)</script>", html, re.S) if "function createEngine" in s)
    return (data.replace("window.", "globalThis.") + "\n" + engine +
            "\nconst LureCheck = createEngine(globalThis.LURECHECK_RULEPACK, globalThis.LURECHECK_MODEL || null);\n")


def _run_node(cases: list[dict]) -> list[dict]:
    js = _page_scripts() + r"""
const cases = JSON.parse(require("fs").readFileSync(0, "utf8"));
const out = cases.map(c => {
  const url = c.url || "";
  const p = LureCheck.modelPredict(c.title || "", c.description || "", c.company || "", url, c.findings, c.score);
  const s = LureCheck.scorePosting(c.title || "", c.description || "", c.company || "", url ? [url] : []);
  return {p: p.probability, flag: p.flag, shape: LureCheck.shapeFeatures([c.title, c.company, c.description, url].filter(Boolean).join("\n")),
          rules: s.findings.map(f => f.rule_id).filter(r => r !== "model_second_look").sort(), score: s.score};
});
process.stdout.write(JSON.stringify(out));
"""
    with tempfile.TemporaryDirectory() as d:          # the script is too long to pass with node -e
        script = Path(d) / "page_check.js"
        script.write_text(js, encoding="utf-8")
        res = subprocess.run([NODE, str(script)], input=json.dumps(cases), capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr[-2000:]
    return json.loads(res.stdout)


def _python(case: dict) -> dict:
    url = case.get("url", "")
    r = score_posting(case.get("title", ""), case.get("description", ""), case.get("company", ""),
                      run_network=False, url_chain=[url] if url else None)
    return {"findings": r.findings, "score": r.score}


def test_page_data_is_current():
    res = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_page.py"), "--check"], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


@needs_node
def test_page_model_matches_python():
    model = ml.load(ml.MODEL_PATH)
    assert model is not None
    cases = []
    for c in CASES:
        py = _python(c)
        cases.append(dict(c, findings=[{"rule_id": f["rule_id"]} for f in py["findings"]], score=py["score"]))
    js = _run_node(cases)
    private = _private_rules()
    for c, j in zip(cases, js):
        if private & {f["rule_id"] for f in c["findings"]}:
            continue                # server-only rules never fire in the page, and the page's model leaves them out
        text = ml.posting_text(c.get("title", ""), c.get("description", ""), c.get("company", ""), c.get("url", ""))
        assert j["shape"] == pytest.approx(ml.shape_features(text), abs=1e-9), c["description"][:80]
        pred = model.predict(c.get("title", ""), c.get("description", ""), c.get("company", ""), c.get("url", ""),
                             c["findings"], c["score"])
        assert j["p"] == pytest.approx(pred["probability"], abs=1e-4), c["description"][:80]
        assert j["flag"] == pred["flag"], c["description"][:80]


@needs_node
def _private_rules() -> set:
    core = json.loads((ROOT / "scam_detector" / "rulepack" / "core.json").read_text(encoding="utf-8"))
    return {r["id"] for r in core["rules"] if r.get("private")}


def test_page_rules_match_python():
    """The page runs every rule except the server-only ("private") ones, so it must agree on all the others."""
    private = _private_rules()
    js = _run_node([dict(c, findings=[], score=0) for c in CASES])
    for c, j in zip(CASES, js):
        py = _python(c)
        fired = {f["rule_id"] for f in py["findings"]}
        assert j["rules"] == sorted(fired - private), c["description"][:80]
        if not fired & private:
            assert j["score"] == py["score"], c["description"][:80]


def test_private_rules_are_not_shipped_in_the_page():
    html = PAGE.read_text(encoding="utf-8")
    data = re.search(r'<script id="lurecheck-data">(.*?)</script>', html, re.S).group(1)
    pack = json.loads(re.search(r"window\.LURECHECK_RULEPACK = (\{.*?\});\n", data, re.S).group(1))
    assert _private_rules() and not _private_rules() & {r["id"] for r in pack["rules"]}
