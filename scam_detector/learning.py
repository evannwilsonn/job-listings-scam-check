"""
The learning loop: reviewer decisions teach the detector, a gate decides what ships, and a staged release gets it to
students without ever letting a worse model through.

    python -m scam_detector.tools.learn status      # where the release stands, what's due, drift
    python -m scam_detector.tools.learn tick        # run this every 30 minutes (cron, a scheduled job, a GitHub Action)

What it learns from
  * Only labels a reviewer made: confirming a report (scam), or dismissing it as a real job (`review_queue --real`).
    A student's own opinion never becomes a label, so nobody can teach the model by spamming reports.
  * Every label gets a permanent place the first time it is used: about 1 in 3 go to the live holdout (never trained on),
    the rest to training. Copies of the same script share their first copy's place, so a scam wave is trained on or held
    out as a whole. A model has to handle this month's scams, not only the frozen holdouts.

Two speeds
  * Template memory (memory.py), at once: confirming a report stores a sketch of its wording; the next copy of that script
    is flagged on the next check (`confirmed_scam_template`, `confirmed_scam_copy`). Labeling the same text real forgets it.
  * Retraining: monthly once RETRAIN_MIN_NEW distinct new labels exist; early at RETRAIN_EVIDENCE_MIN, or when live
    traffic has drifted from the training data; in the fast lane within hours when RETRAIN_FAST_MIN new labels include a
    scam the current detector misses. Never more often than RETRAIN_MIN_GAP_DAYS (RETRAIN_FAST_GAP_HOURS for the fast lane).

What ships
  1. tools/train_model.py's own gate (frozen holdouts, hard-legit set, no new false alarm).
  2. The release gate, candidate against the active model: recent confirmed scams in the live holdout, false alarms on
     every legitimate row (at most RELEASE_FP_MAX_RATE and none the active model doesn't make), older techniques, unusual
     but real employers, red-team regression variants.
  3. Shadow (scores every check, nothing shown), then rollout to a stable slice of checks (RELEASE_STAGES), then active
     with the previous model kept. Each step needs labels the candidate never saw showing it isn't worse; rollback is
     automatic. The fast lane uses the same checks on a shorter clock.

Where it keeps its state: the store (Postgres in production; files in development). Model files live in the store too,
so the API and the retrain job can run on different machines. Training needs scikit-learn and the labeled corpora in
LURECHECK_DATA; serving needs neither.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import math
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from . import memory, ml
from .scorer import score_posting

log = logging.getLogger("lurecheck.learning")


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


DATA = Path(_env("LURECHECK_DATA", str(Path(__file__).resolve().parent / "data")))
HOLDOUT_EVERY = 3
NEAR_COPY = 0.6                     # word-trigram overlap that counts as the same script (tools/train_model.py's NEAR_COPY)
RETRAIN_DAYS = float(_env("RETRAIN_DAYS", "30"))
RETRAIN_MIN_NEW = int(_env("RETRAIN_MIN_NEW", "20"))
EVIDENCE_MIN_NEW = int(_env("RETRAIN_EVIDENCE_MIN", "30"))
MIN_GAP_DAYS = float(_env("RETRAIN_MIN_GAP_DAYS", "3"))
FAST_ON = _env("RETRAIN_FAST", "on").lower() not in ("0", "off", "false", "no")
FAST_MIN_NEW = int(_env("RETRAIN_FAST_MIN", "5"))
FAST_GAP_HOURS = float(_env("RETRAIN_FAST_GAP_HOURS", "12"))
FAST_AFTER_WATCH_DAYS = float(_env("RETRAIN_FAST_AFTER_WATCH_DAYS", "2"))

SHADOW_DAYS = float(_env("RELEASE_SHADOW_DAYS", "7"))
STAGE_DAYS = float(_env("RELEASE_STAGE_DAYS", "3"))
WATCH_DAYS = float(_env("RELEASE_WATCH_DAYS", "14"))
FAST_SHADOW_DAYS = float(_env("RELEASE_FAST_SHADOW_DAYS", "1"))
FAST_STAGE_DAYS = float(_env("RELEASE_FAST_STAGE_DAYS", "1"))
FAST_WATCH_DAYS = float(_env("RELEASE_FAST_WATCH_DAYS", "7"))
STAGES = [int(x) for x in _env("RELEASE_STAGES", "10,50,100").split(",")]
FRESH_MIN = int(_env("RELEASE_FRESH_MIN", "5"))
TRAFFIC_MIN = int(_env("RELEASE_TRAFFIC_MIN", "30"))
FP_MAX_RATE = float(_env("RELEASE_FP_MAX_RATE", "0.02"))
RECENT_DAYS = 120

DRIFT_WINDOW_DAYS = float(_env("DRIFT_WINDOW_DAYS", "7"))
DRIFT_MIN_CHECKS = int(_env("DRIFT_MIN_CHECKS", "50"))
PSI_WATCH, PSI_ALERT = 0.1, float(_env("DRIFT_PSI_ALERT", "0.25"))
NOVELTY_ALERT = float(_env("DRIFT_NOVELTY_ALERT", "0.15"))
TRAFFIC_KEEP_DAYS = 120


def auto() -> bool:
    return _env("MODEL_AUTO_RELEASE", "1").lower() not in ("0", "false", "no", "off")


def _store(st=None):
    if st is not None:
        return st
    from .store import get_store
    return get_store()


# ---------------------------------------------------------------- labels

def split_of(label_id: str) -> str:
    """The place for a label that copies no earlier one: about 1 in 3 is held out, derived from its id."""
    return "holdout" if int(hashlib.sha256(f"label:{label_id}".encode()).hexdigest()[:8], 16) % HOLDOUT_EVERY == 0 else "train"


def _trigrams(r: dict) -> set:
    t = ml.tokens(ml.posting_text(r.get("title", ""), r.get("description", ""), r.get("company", "")))
    return {" ".join(t[i:i + 3]) for i in range(max(1, len(t) - 2))}


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def assign_splits(labels: list[dict]) -> dict:
    """{label id: split} for labels without a place yet: a copy of a placed label takes its place, otherwise split_of()."""
    placed = [(_trigrams(r), r["split"]) for r in labels if r.get("split")]
    out = {}
    for r in labels:
        if r.get("split"):
            continue
        sh = _trigrams(r)
        best = max(((j, sp) for j, sp in ((_jaccard(sh, s2), sp) for s2, sp in placed) if j >= NEAR_COPY), default=None)
        split = best[1] if best else split_of(r["id"])
        out[r["id"]] = split
        placed.append((sh, split))
    return out


def labeled_rows(st=None) -> list[dict]:
    """Every reviewer label, in the corpus format train_model.py reads, with its permanent split (assigned here on first use)."""
    s = _store(st)
    labels = [r for r in s.labels() if r["label"] in ("scam", "legit", "lead_gen")]
    new = assign_splits(labels)
    if new:
        s.set_label_splits(new)
    return [{"id": f"live-{r['id']}", "label": r["label"], "title": r.get("title", ""), "company": r.get("company", ""),
             "description": r["description"], "url": "", "context_flags": [], "split": r.get("split") or new[r["id"]],
             "at": r.get("at") or 0.0, "school": r.get("school", ""), "text_key": memory.text_key(r["description"]),
             "notes": f"reviewer label by {r.get('reviewer', '')} ({r.get('source', '')})"}
            for r in labels]


def _distinct(rows: list[dict]) -> int:
    """Labels on the same text count once, so one script labeled many times can't trigger a retrain."""
    return len({r["text_key"] for r in rows})


# ---------------------------------------------------------------- evaluation

def _rules(r: dict) -> dict:
    if "_rules" not in r:
        res = score_posting(r.get("title", ""), r.get("description", ""), r.get("company", ""), run_network=False)
        r["_rules"] = {"findings": res.findings, "score": res.score, "flag": res.band in ("review", "block")}
    return r["_rules"]


def flags(model: Optional[ml.Model], rows: list[dict]) -> list[bool]:
    """What a check does: the rules flag it, or the model does (the model can only add)."""
    out = []
    for r in rows:
        ru = _rules(r)
        f = ru["flag"]
        if not f and model is not None:
            f = model.predict(r.get("title", ""), r.get("description", ""), r.get("company", ""), r.get("url") or "",
                              ru["findings"], ru["score"])["flag"]
        out.append(bool(f))
    return out


def tally(rows: list[dict], fl: list[bool]) -> dict:
    t = {"scam": 0, "scam_total": 0, "legit_flagged": 0, "legit_total": 0}
    for r, f in zip(rows, fl):
        if r["label"] == "scam":
            t["scam_total"] += 1
            t["scam"] += f
        elif r["label"] == "legit":
            t["legit_total"] += 1
            t["legit_flagged"] += f
    return t


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


# ---------------------------------------------------------------- models

_model_cache: dict = {}


def model_for(version: Optional[str], st=None) -> Optional[ml.Model]:
    """A model by version from the store; None means the one shipped with the code."""
    if not version:
        return ml.load(ml.MODEL_PATH)
    if version not in _model_cache:
        spec = _store(st).get_model(version)
        if spec is None:
            return None
        _model_cache[version] = ml.Model(spec)
    return _model_cache[version]


def active_model(st=None) -> Optional[ml.Model]:
    return model_for(_store(st).release().get("active_version"), st)


# ---------------------------------------------------------------- template memory

_tm: dict = {"at": 0.0, "mem": None}
TM_TTL = 60.0


def remember(text: str, *, title: str = "", school: str = "", report_id: str = "", st=None) -> Optional[str]:
    sk = memory.sketch(text)
    if len(sk) < memory.MIN_SHINGLES:
        return None
    key = memory.text_key(text)
    _store(st).add_template({"key": key, "sketch": sk, "kid": memory.key_id(memory.current_key()), "title": (title or "")[:80],
                             "when": time.strftime("%Y-%m-%d"), "source": "reviewer", "note": "", "school": school,
                             "report_id": report_id})
    _tm["at"] = 0.0
    return key


def forget(text: str, st=None) -> None:
    _store(st).forget_template(memory.text_key(text))
    _tm["at"] = 0.0


def template_finding(text: str, st=None) -> Optional[dict]:
    """The template-memory finding for a check, or None. Never raises."""
    try:
        if _tm["mem"] is None or time.time() - _tm["at"] > TM_TTL:
            _tm.update({"mem": memory.TemplateMemory(_store(st).templates()), "at": time.time()})
        return _tm["mem"].finding(text)
    except Exception:                                   # noqa: BLE001 - a failed lookup must never break a check
        log.exception("template memory lookup failed")
        return None


def after_decision(record: dict, decision: str, real: bool = False, st=None) -> None:
    """What a reviewer's decision teaches at once (the store already wrote the training label)."""
    text = record.get("text_masked") or ""
    if not text:
        return
    if decision == "confirmed":
        remember(text, title=text[:60], school=record.get("school", ""), report_id=str(record.get("id", "")), st=st)
    elif real:
        forget(text, st)


# ---------------------------------------------------------------- serving: which model answers, and what is recorded

_route_cache: dict = {"at": 0.0, "rel": None}
_other: contextvars.ContextVar = contextvars.ContextVar("lurecheck_other_pred", default=None)
ROUTE_TTL = 60.0


def _release_cached(st=None) -> dict:
    if _route_cache["rel"] is None or time.time() - _route_cache["at"] > ROUTE_TTL:
        _route_cache.update({"rel": _store(st).release(), "at": time.time()})
    return _route_cache["rel"]


def bucket(key: str) -> int:
    return int(key[:8], 16) % 100


def route(key: str, shipped: ml.Model):
    """(model to serve, model to score alongside or None). During rollout a stable slice of checks (by text hash) gets the
    candidate; in shadow the candidate is scored alongside and never shown."""
    rel = _release_cached()
    active = model_for(rel.get("active_version")) or shipped
    cand = model_for(rel["candidate_version"]) if rel["stage"] in ("shadow", "rollout") and rel.get("candidate_version") else None
    if cand is None:
        return active, None
    if rel["stage"] == "rollout" and bucket(key) < int(rel.get("pct") or 0):
        return cand, active
    return active, cand


def observe(key, served, pred, other, other_pred) -> None:
    _other.set((other, other_pred) if other else None)


def monitor(key: str, pred: dict, novelty: float) -> None:
    other = _other.get()
    _other.set(None)
    try:
        rec = {"key": key, "served": pred.get("version", ""), "p": float(pred["probability"]), "flag": bool(pred["flag"]),
               "novelty": float(novelty)}
        if other:
            rec.update({"other": other[0], "other_p": float(other[1]["probability"]), "other_flag": bool(other[1]["flag"])})
        _store().add_traffic(rec)
    except Exception:                                   # noqa: BLE001
        log.exception("could not record model traffic")


def configure_serving() -> None:
    """Point ml.second_look at the store's active model and candidate, and record what it sees. Called once by the API.
    LEARN_TRAFFIC=off stops the recording (the routing stays)."""
    ml.ROUTE, ml.OBSERVE = route, observe
    ml.MONITOR = monitor if _env("LEARN_TRAFFIC", "on").lower() not in ("0", "off", "false", "no") else None


# ---------------------------------------------------------------- drift

def histogram(values, bins: int = 10) -> list[float]:
    counts = [0] * bins
    for v in values:
        counts[min(bins - 1, max(0, int(float(v) * bins)))] += 1
    n = max(1, len(values))
    return [c / n for c in counts]


def psi(live: list[float], ref: list[float], eps: float = 1e-4) -> float:
    return round(sum((max(a, eps) - max(b, eps)) * math.log(max(a, eps) / max(b, eps)) for a, b in zip(live, ref)), 4)


def drift_status(st=None, model: Optional[ml.Model] = None) -> dict:
    s = _store(st)
    m = model or active_model(s)
    ref = (m.spec.get("drift_ref") if m else None) or {}
    rows = s.traffic(time.time() - DRIFT_WINDOW_DAYS * 86400)
    out = {"checks": len(rows), "measured": False, "level": "ok", "why": "", "psi_score": None, "psi_novelty": None,
           "flag_rate": None, "novelty_mean": None, "ref_flag_rate": ref.get("flag_rate"), "ref_novelty_mean": ref.get("novelty_mean")}
    if not rows:
        out["why"] = "no checks recorded yet"
        return out
    out["flag_rate"] = round(sum(bool(r["flag"]) for r in rows) / len(rows), 4)
    out["novelty_mean"] = round(sum(r["novelty"] for r in rows) / len(rows), 4)
    if not ref:
        out["why"] = "the active model has no training reference (retrain to add one)"
        return out
    if len(rows) < DRIFT_MIN_CHECKS:
        out["why"] = f"{len(rows)} checks in the window; {DRIFT_MIN_CHECKS} needed before the comparison means anything"
        return out
    out["measured"] = True
    out["psi_score"] = psi(histogram([r["p"] for r in rows]), ref.get("score_hist", []))
    out["psi_novelty"] = psi(histogram([r["novelty"] for r in rows]), ref.get("novelty_hist", []))
    reasons = []
    if out["psi_score"] >= PSI_ALERT:
        reasons.append(f"the spread of model scores has moved (PSI {out['psi_score']:.2f})")
    if out["psi_novelty"] >= PSI_ALERT:
        reasons.append(f"the wording being checked has moved away from the training set (PSI {out['psi_novelty']:.2f})")
    if out["novelty_mean"] - float(ref.get("novelty_mean", 0.0)) >= NOVELTY_ALERT:
        reasons.append(f"{out['novelty_mean']:.0%} of words are new to the model, against {float(ref.get('novelty_mean', 0)):.0%} in training")
    if reasons:
        out["level"], out["why"] = "drift", "; ".join(reasons)
    elif max(out["psi_score"], out["psi_novelty"]) >= PSI_WATCH:
        out["level"], out["why"] = "watch", "a small shift; nothing to do yet"
    else:
        out["why"] = "traffic looks like the training data"
    return out


# ---------------------------------------------------------------- when to retrain

def misses(rows: list[dict], model: Optional[ml.Model]) -> int:
    """Distinct confirmed scams among `rows` that the rules and this model would let through."""
    scams = [r for r in rows if r["label"] == "scam"]
    return len({r["text_key"] for r, f in zip(scams, flags(model, scams)) if not f})


def due(st=None) -> tuple[bool, str, str]:
    """(due, why, trigger)."""
    s = _store(st)
    rel = s.release()
    last = s.last_run()
    since = last["started_at"] if last else 0.0
    elapsed = (time.time() - since) / 86400 if last else 1e9
    new_rows = [r for r in labeled_rows(s) if r["at"] > since]
    new = _distinct(new_rows)
    if rel["stage"] == "rollout":
        return False, "a model release is rolling out; retraining waits until it settles", ""
    watching = rel["stage"] == "watch"
    fast_ok = (FAST_ON and new >= FAST_MIN_NEW and elapsed * 24 >= FAST_GAP_HOURS
               and not (watching and (time.time() - (rel["stage_started"] or time.time())) / 86400 < FAST_AFTER_WATCH_DAYS))
    if fast_ok:
        missed = misses(new_rows, active_model(s))
        if missed:
            return True, f"fast lane: {missed} confirmed scam{'s' if missed != 1 else ''} the detector misses; {new} new labels", "fast"
    if watching:
        return False, "a new model is being watched; only the fast lane can retrain now", ""
    if elapsed >= MIN_GAP_DAYS:
        if new >= EVIDENCE_MIN_NEW:
            return True, f"{new} new distinct labels (early retrain at {EVIDENCE_MIN_NEW})", "evidence"
        d = drift_status(s)
        if d["level"] == "drift" and new >= RETRAIN_MIN_NEW:
            return True, f"model drift ({d['why']}); {new} new distinct labels", "drift"
    if elapsed < RETRAIN_DAYS:
        days_left = int((since + RETRAIN_DAYS * 86400 - time.time()) // 86400) + 1
        return False, f"next scheduled retrain in about {days_left} day{'s' if days_left != 1 else ''} ({new} new labels so far)", ""
    if new < RETRAIN_MIN_NEW:
        return False, f"waiting for labels: {new} new of the {RETRAIN_MIN_NEW} needed", ""
    return True, f"{new} new distinct labels", "schedule"


# ---------------------------------------------------------------- the release gate

def suites(st=None) -> dict:
    from .tools import redteam
    live = [r for r in labeled_rows(st) if r["label"] in ("scam", "legit")]
    cutoff = time.time() - RECENT_DAYS * 86400
    return {
        "recent": [r for r in live if r["split"] == "holdout" and r["at"] > cutoff],
        "older": [r for f in ("field_2026_09_holdout.jsonl", "field_2026_10_holdout.jsonl") for r in _load_jsonl(DATA / f)],
        "hard_legit": _load_jsonl(DATA / "stress_legit.jsonl"),
        "redteam": _load_jsonl(Path(redteam.REGRESSION)),
        "live_holdout": [r for r in live if r["split"] == "holdout"],
    }


def gate(candidate: ml.Model, active: Optional[ml.Model], st=None) -> tuple[bool, list[dict]]:
    """Candidate against the active model on data neither trained on. Returns (passed, [{name, passed, detail}])."""
    s = suites(st)
    checks = []

    def both(rows):
        return tally(rows, flags(candidate, rows)), tally(rows, flags(active, rows))

    c, a = both(s["recent"])
    if not c["scam_total"]:
        checks.append({"name": "Recent confirmed scams", "passed": False,
                       "detail": "No recent confirmed scams in the live holdout to test on, so it can't show an improvement."})
    else:
        checks.append({"name": "Recent confirmed scams", "passed": c["scam"] > a["scam"] or c["scam"] == a["scam"] == a["scam_total"],
                       "detail": f"candidate {c['scam']}/{c['scam_total']}, active {a['scam']}/{a['scam_total']}"})
    seen, legit = set(), []
    for r in s["recent"] + s["older"] + s["hard_legit"] + s["live_holdout"]:
        k = r.get("id") or r.get("description", "")[:80]
        if r["label"] == "legit" and k not in seen:
            seen.add(k)
            legit.append(r)
    cl, al = both(legit)
    rate = cl["legit_flagged"] / cl["legit_total"] if cl["legit_total"] else 0.0
    checks.append({"name": "False alarms on legitimate items", "passed": rate <= FP_MAX_RATE and cl["legit_flagged"] <= al["legit_flagged"],
                   "detail": f"candidate {cl['legit_flagged']}/{cl['legit_total']} ({rate:.1%}, limit {FP_MAX_RATE:.0%}), "
                             f"active {al['legit_flagged']}/{al['legit_total']}"})
    c, a = both(s["older"])
    checks.append({"name": "Older scam techniques (frozen holdouts)", "passed": c["scam"] >= a["scam"],
                   "detail": f"candidate {c['scam']}/{c['scam_total']}, active {a['scam']}/{a['scam_total']}"})
    c, a = both(s["hard_legit"])
    checks.append({"name": "Legitimate but unusual employers", "passed": c["legit_flagged"] <= a["legit_flagged"],
                   "detail": f"candidate flags {c['legit_flagged']}/{c['legit_total']}, active {a['legit_flagged']}/{a['legit_total']}"})
    c, a = both(s["redteam"])
    checks.append({"name": "Red-team regression variants", "passed": c["scam"] >= a["scam"],
                   "detail": f"candidate {c['scam']}/{c['scam_total']}, active {a['scam']}/{a['scam_total']}" if c["scam_total"]
                   else "no regression variants saved yet"})
    return all(x["passed"] for x in checks), checks


# ---------------------------------------------------------------- retraining

_lock = threading.Lock()


def run_retrain(trigger: str = "manual", force: bool = False, st=None) -> dict:
    """Retrain once. Returns {"status": candidate | refused | skipped | busy | unavailable | error, ...}."""
    s = _store(st)
    if not _lock.acquire(blocking=False):
        return {"status": "busy"}
    try:
        if not force:
            ok, why, trig = due(s)
            if not ok:
                return {"status": "skipped", "why": why}
            trigger = trig or trigger
        elif s.release()["stage"] == "rollout":
            return {"status": "skipped", "why": "a model release is rolling out"}
        rows = labeled_rows(s)
        run_id = s.start_run(trigger, len(rows))
        try:
            from .tools import train_model
        except (ImportError, SystemExit):
            s.finish_run(run_id, status="unavailable", report="scikit-learn isn't installed here, so it can't retrain.")
            return {"status": "unavailable", "run": run_id}
        rel = s.release()
        with tempfile.TemporaryDirectory(prefix="lurecheck-retrain-") as tmp:
            d = Path(tmp)
            train_f, hold_f, cand_f, cur_f = d / "live_train.jsonl", d / "live_holdout.jsonl", d / "candidate.json", d / "current.json"
            train_f.write_text("".join(json.dumps(r) + "\n" for r in rows if r["split"] == "train"))
            held = [r for r in rows if r["split"] == "holdout"]
            hold_f.write_text("".join(json.dumps(r) + "\n" for r in held))
            current = active_model(s)
            argv = ["--extra", str(train_f), "--out", str(cand_f), "--report-dir", str(d)]
            if current is not None:
                cur_f.write_text(json.dumps(current.spec))
                argv += ["--current", str(cur_f)]
            if held:
                argv += ["--holdout-extra", str(hold_f)]
            try:
                train_model.main(argv)
            except Exception as e:                      # noqa: BLE001 - a failed retrain must never take anything down
                log.exception("retrain failed")
                s.finish_run(run_id, status="error", report=f"Training failed: {type(e).__name__}: {e}")
                return {"status": "error", "run": run_id}
            res = dict(train_model.LAST_RESULT)
            report = res.get("report", "")
            if not res.get("written") or not cand_f.exists():
                s.finish_run(run_id, status="refused", version=res.get("version"), train_rows=res.get("rows", 0), report=report)
                return {"status": "refused", "run": run_id}
            spec = json.loads(cand_f.read_text())
        candidate = ml.Model(spec)
        passed, checks = gate(candidate, active_model(s), s)
        report += "\n\n## Release gate (candidate vs the active model)\n\n| Check | Result | Detail |\n|---|---|---|\n" + "".join(
            f"| {c['name']} | {'pass' if c['passed'] else 'FAIL'} | {c['detail']} |\n" for c in checks)
        if not passed:
            s.finish_run(run_id, status="refused", version=spec["version"], train_rows=res.get("rows", 0), report=report)
            return {"status": "refused", "run": run_id, "version": spec["version"]}
        s.save_model(spec)
        begin_shadow(spec["version"], run_id, "passed the release gate", lane="fast" if trigger == "fast" else "full", st=s,
                     was=rel)
        s.finish_run(run_id, status="candidate", version=spec["version"], train_rows=res.get("rows", 0),
                     report=report + "\nPassed. It now scores alongside the active model before any student sees it.")
        return {"status": "candidate", "run": run_id, "version": spec["version"]}
    finally:
        _lock.release()


# ---------------------------------------------------------------- the release

def days(rel: dict, stage: str) -> float:
    fast = (rel.get("lane") or "full") == "fast"
    return {"shadow": FAST_SHADOW_DAYS if fast else SHADOW_DAYS, "rollout": FAST_STAGE_DAYS if fast else STAGE_DAYS,
            "watch": FAST_WATCH_DAYS if fast else WATCH_DAYS}[stage]


def _set(s, **kw) -> None:
    s.set_release(**kw)
    _route_cache["at"] = 0.0


def begin_shadow(version: str, run_id, report: str = "", lane: str = "full", st=None, was: Optional[dict] = None) -> None:
    s = _store(st)
    rel = was or s.release()
    if rel["stage"] == "shadow" and rel.get("candidate_version"):
        s.log_release("replaced", rel["candidate_version"], f"replaced in shadow by {version}")
    if rel["stage"] == "watch":
        s.log_release("settled", rel.get("active_version"), "a fast-lane candidate takes over the watch")
    now = time.time()
    _set(s, stage="shadow", lane=lane if lane in ("full", "fast") else "full", candidate_version=version, run_id=run_id, pct=0,
         created_at=now, stage_started=now, note="scoring alongside the active model" + (" (fast lane)" if lane == "fast" else ""))
    s.log_release("shadow", version, ("[fast lane] " if lane == "fast" else "") + report)


def discard(why: str, event: str = "rejected", st=None) -> None:
    s = _store(st)
    rel = s.release()
    s.log_release(event, rel.get("candidate_version"), why)
    _set(s, stage="none", pct=0, candidate_version=None, note=why)


def start_rollout(pct: Optional[int] = None, who: str = "", st=None) -> None:
    s = _store(st)
    rel = s.release()
    pct = pct or STAGES[0]
    _set(s, stage="rollout", pct=pct, stage_started=time.time(), note=f"serving {pct}% of checks")
    s.log_release("rollout", rel["candidate_version"], f"{pct}% of checks" + (f" (started by {who})" if who else ""))


def promote(st=None) -> None:
    s = _store(st)
    rel = s.release()
    _set(s, stage="watch", pct=100, stage_started=time.time(), previous_version=rel.get("active_version"),
         active_version=rel["candidate_version"], candidate_version=None,
         note="active; the previous model is kept for rollback")
    s.log_release("promoted", rel["candidate_version"], "now serving every check")


def rollback(why: str, st=None) -> bool:
    """Drop a candidate mid-release, or restore the previous model after a promotion."""
    s = _store(st)
    rel = s.release()
    if rel["stage"] in ("shadow", "rollout"):
        discard(why, "rolled_back" if rel["stage"] == "rollout" else "rejected", s)
        return True
    if rel["stage"] != "watch":
        return False
    bad = rel.get("active_version")
    _set(s, stage="none", pct=0, active_version=rel.get("previous_version"), previous_version=None,
         note=f"restored the previous model: {why}")
    s.log_release("rolled_back", bad, why)
    return True


def fresh(since: float, first: Optional[ml.Model], second: Optional[ml.Model], st=None) -> dict:
    """Both models on labels made after `since` (neither trained on them)."""
    rows = [r for r in labeled_rows(st) if r["label"] in ("scam", "legit") and r["at"] > since]
    return {"n": len(rows), "first": tally(rows, flags(first, rows)), "second": tally(rows, flags(second, rows))}


def worse(fr: dict) -> str:
    a, b = fr["first"], fr["second"]
    if a["scam"] < b["scam"]:
        return f"caught fewer new confirmed scams ({a['scam']} vs {b['scam']} of {a['scam_total']})"
    if a["legit_flagged"] > b["legit_flagged"]:
        return f"flagged more new confirmed-real items ({a['legit_flagged']} vs {b['legit_flagged']} of {a['legit_total']})"
    return ""


def compared_traffic(rel: dict, st=None) -> tuple[int, float, float]:
    """(checks scored by both, candidate flag rate, active flag rate) since the stage began."""
    cv = rel.get("candidate_version")
    rows = [r for r in _store(st).traffic(rel.get("stage_started") or 0) if r.get("other")]
    n = len(rows)
    if not n:
        return 0, 0.0, 0.0
    cf = sum(bool(r["flag"] if r["served"] == cv else r["other_flag"]) for r in rows)
    af = sum(bool(r["other_flag"] if r["served"] == cv else r["flag"]) for r in rows)
    return n, cf / n, af / n


def tick(now: Optional[float] = None, st=None) -> str:
    """Advance, hold or roll back the release by what the evidence says."""
    s = _store(st)
    now = now or time.time()
    rel = s.release()
    stage = rel["stage"]
    if stage == "none":
        return "nothing in release"
    age = (now - (rel.get("stage_started") or now)) / 86400
    active = active_model(s)
    if stage in ("shadow", "rollout"):
        cand = model_for(rel.get("candidate_version"), s)
        if cand is None:
            discard("the candidate model is missing", st=s)
            return "discarded"
        fr = fresh(rel.get("created_at") or 0, cand, active, s)
        why = worse(fr) if fr["n"] else ""
        n, cr, ar = compared_traffic(rel, s)
        if not why and n >= TRAFFIC_MIN and cr > max(2 * ar, ar + 0.05):
            why = f"flags {cr:.0%} of real checks against the active model's {ar:.0%}"
        if why:
            rollback(why, s)
            return f"stopped: {why}"
        need = days(rel, stage)
        if age < need:
            doing = "scoring alongside" if stage == "shadow" else f"serving {int(rel['pct'])}%"
            _set(s, note=f"{doing}: day {int(age) + 1} of {need:g}" + (" (fast lane)" if rel.get("lane") == "fast" else ""))
            return "waiting: time"
        if fr["n"] < FRESH_MIN or (stage == "shadow" and n < TRAFFIC_MIN):
            _set(s, note=f"waiting for evidence: {fr['n']}/{FRESH_MIN} new labels, {n}/{TRAFFIC_MIN} checks compared")
            return "waiting: evidence"
        if not auto():
            _set(s, note="ready for the next step: run `learn release next` (automatic release is off)")
            return "ready"
        if stage == "shadow":
            start_rollout(st=s)
            return "rollout started"
        nxt = [p for p in STAGES if p > int(rel["pct"])]
        if not nxt or nxt[0] >= 100:
            promote(s)
            return "promoted"
        start_rollout(nxt[0], st=s)
        return f"rollout {nxt[0]}%"
    if stage == "watch":
        prev = model_for(rel.get("previous_version"), s)
        fr = fresh(rel.get("stage_started") or 0, active, prev, s)
        why = worse(fr) if fr["n"] else ""
        if why:
            rollback("after release, the new model " + why, s)
            return "rolled back"
        if age >= days(rel, "watch"):
            _set(s, stage="none", note="release complete")
            s.log_release("settled", rel.get("active_version"), f"no problems in {days(rel, 'watch'):g} days")
            return "settled"
        return "watching"
    return ""


def learn_tick(st=None) -> dict:
    """The scheduled job: move the release along, retrain when due, prune old traffic."""
    s = _store(st)
    out = {"release": tick(st=s)}
    s.prune_traffic(time.time() - TRAFFIC_KEEP_DAYS * 86400)
    ok, why, trig = due(s)
    out["due"] = why
    if ok:
        out["retrain"] = run_retrain(trig, st=s)
    return out
