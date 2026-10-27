"""
Build the browser page. Kept as an alias: the build lives in tools/build_web.py, which assembles
index.html from web/page.html, web/engine.js, the rulepack and the learned model.

    python scripts/build_page.py            # update index.html
    python scripts/build_page.py --check    # exit 1 if index.html is out of date (CI)
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.argv[0] = str(Path(__file__).resolve().parent.parent / "tools" / "build_web.py")
    runpy.run_path(sys.argv[0], run_name="__main__")
