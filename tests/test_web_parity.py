"""The browser build must stay a faithful, up-to-date port of the Python engine.

Two guards:
  - index.html is generated from web/page.html + web/engine.js + the rulepack; a stale build fails.
  - every fixture in tests/fixtures/parity_cases.jsonl must score identically in both engines.
The JS half needs Node; when it is missing the parity test is skipped, not failed, so a Python-only
environment can still run the rest of the suite.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True)


def test_index_html_is_built_from_its_parts():
    proc = _run("tools/build_web.py", "--check")
    assert proc.returncode == 0, proc.stderr or proc.stdout


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_browser_engine_matches_python_engine():
    proc = _run("tools/parity.py")
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_parity_fixtures_cover_every_active_rule_family():
    """Every active rule id should fire in at least one fixture, or the gate can't catch its drift."""
    sys.path.insert(0, str(ROOT))
    from scam_detector import rules
    from tools.parity import load_cases, python_results
    fired = {f["rule_id"] for r in python_results(load_cases()) for f in r["findings"]}
    missing = sorted(r.id for r in rules.RULES if r.id not in fired)
    assert not missing, f"rules with no parity fixture: {missing}"
