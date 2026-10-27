"""The learning loop (scam_detector/learning.py) on the file-backed store: reviewer decisions become labels and template
memory, retraining is triggered by evidence (fastest when the detector misses a confirmed scam), and a candidate reaches
students only through the gate, shadow, staged rollout and watch, with automatic rollback."""

import json
import time

import pytest

from scam_detector import learning, memory, ml
from scam_detector.reports import make_report

SCAM = ("Hello student, our department needs a remote personal assistant. $450 weekly, flexible hours, no experience needed. "
        "You will receive a check to buy office equipment from our vendor and keep the rest. Kindly reply with your personal email.")
RENAMED = SCAM.replace("$450", "$500").replace("personal assistant", "admin assistant").replace("Kindly", "Please")
_WORDS = ("alder birch cedar dogwood elm fir ginkgo hazel ironwood juniper larch maple oak pine quince redwood spruce teak walnut "
          "yew aspen beech cypress holly linden magnolia olive poplar rowan sumac willow").split()


class _Real(str):
    """REAL.format(i=n): distinct wording per n (digits are folded, so a number alone wouldn't make it a new text)."""
    def format(self, i):                                    # noqa: A003
        return str(self).replace("{i}", " ".join(_WORDS[int(d)] for d in f"{i:03d}") + f" {_WORDS[i % len(_WORDS)]}")


# A scam the rules and the shipped model both let through: what the fast lane exists for.
QUIET = _Real("Hi, are you open to a quick part-time role helping our small team with errands this month? Reply here and I "
              "will share the details and the schedule. {i}")
REAL = _Real("Campus library needs a student assistant, $13/hour, 10 hours a week, apply through the university jobs site. Ref {i}.")


@pytest.fixture(autouse=True)
def _fresh_caches():
    learning._model_cache.clear()
    learning._tm.update({"at": 0.0, "mem": None})
    learning._route_cache.update({"at": 0.0, "rel": None})
    yield
    learning._route_cache.update({"at": 0.0, "rel": None})
    learning.configure_serving()


def _spec(version, threshold=None):
    s = json.loads(ml.MODEL_PATH.read_text())
    s["version"] = version
    if threshold is not None:
        s["threshold"] = threshold
    return s


def _label(st, text, label="scam"):
    st.add_label({"label": label, "description": text, "source": "test", "reviewer": "T"})


def _run(st, hours_ago, status="refused"):
    rid = st.start_run("test")
    st.finish_run(rid, status=status)
    runs = [json.loads(l) for l in st._p("runs.jsonl").read_text().splitlines()]
    runs[int(rid)]["started_at"] = time.time() - hours_ago * 3600
    st._rewrite(st._p("runs.jsonl"), runs)


def _client():
    from fastapi.testclient import TestClient
    from scam_detector import api
    return TestClient(api.app)


# ---------------------------------------------------------------- reviewer decisions

def test_confirming_a_report_labels_it_and_the_next_copy_is_flagged(_isolated_store):
    st = _isolated_store
    c = _client()
    before = c.post("/analyze", json={"description": RENAMED, "run_network": False}).json()
    assert not any(f["rule_id"].startswith("confirmed_scam") for f in before["findings"])
    rid = st.add_report(make_report(SCAM, school="fsu"))
    rec = st.decide_report(rid, "confirmed", "E. Wilson")
    learning.after_decision(rec, "confirmed", st=st)
    assert [l["label"] for l in st.labels()] == ["scam"]
    after = c.post("/analyze", json={"description": RENAMED, "run_network": False}).json()
    hit = [f for f in after["findings"] if f["rule_id"] in ("confirmed_scam_template", "confirmed_scam_copy")]
    assert hit and after["score"] >= before["score"]


def test_a_real_job_becomes_a_legit_label_and_forgets_the_template(_isolated_store):
    st = _isolated_store
    learning.remember(SCAM, st=st)
    rid = st.add_report(make_report(SCAM, school="fsu"))
    rec = st.decide_report(rid, "dismissed", "E. Wilson", real=True)
    learning.after_decision(rec, "dismissed", real=True, st=st)
    assert [l["label"] for l in st.labels()] == ["legit"]
    assert learning.template_finding(RENAMED, st) is None
    with pytest.raises(ValueError):
        st.decide_report(rid, "confirmed", "E. Wilson")      # already decided


def test_review_queue_real_flag(_isolated_store):
    from scam_detector.tools import review_queue
    st = _isolated_store
    rid = st.add_report(make_report(REAL.format(i=1), school="fsu"))
    assert review_queue.main(["--set", rid, "confirmed", "--real", "--reviewer", "T"]) == 2
    assert review_queue.main(["--set", rid, "dismissed", "--real", "--reviewer", "T"]) == 0
    assert st.labels()[0]["label"] == "legit"


def test_splits_are_permanent_about_one_in_three_and_waves_stay_together(_isolated_store):
    splits = [learning.split_of(str(i)) for i in range(600)]
    assert 150 < splits.count("holdout") < 250
    st = _isolated_store
    for i in range(12):                                      # one scam wave, twelve copies
        _label(st, SCAM.replace("$450", f"${450 + i}").replace("Kindly", "Kindly " + _WORDS[i]))
    for i in range(12):
        _label(st, REAL.format(i=i), "legit")
    first = {r["id"]: r["split"] for r in learning.labeled_rows(st)}
    assert len({first[f"live-{i}"] for i in range(12)}) == 1                # the wave shares one place
    assert first == {r["id"]: r["split"] for r in learning.labeled_rows(st)}   # and nothing moves later
    assert all(l["split"] for l in st.labels())


# ---------------------------------------------------------------- when to retrain

def test_fast_lane_needs_a_scam_the_detector_misses(_isolated_store):
    st = _isolated_store
    _run(st, 13)
    for i in range(5):
        _label(st, REAL.format(i=i), "legit")
    assert learning.due(st)[2] != "fast"
    _label(st, SCAM)                                         # caught already: not a miss
    assert learning.due(st)[2] != "fast"
    _label(st, QUIET.format(i=0))
    ok, why, trig = learning.due(st)
    assert ok and trig == "fast" and "1 confirmed scam the detector misses" in why
    _run(st, 2)
    assert learning.due(st)[2] != "fast"                     # retrained two hours ago


def test_rollout_blocks_and_early_watch_blocks_except_after_two_days(_isolated_store):
    st = _isolated_store
    _run(st, 13)
    for i in range(4):
        _label(st, REAL.format(i=i), "legit")
    _label(st, QUIET.format(i=0))
    st.set_release(stage="rollout", stage_started=time.time())
    assert not learning.due(st)[0]
    st.set_release(stage="watch", stage_started=time.time() - 0.5 * 86400)
    assert not learning.due(st)[0]
    st.set_release(stage="watch", stage_started=time.time() - 3 * 86400)
    assert learning.due(st)[2] == "fast"


def test_evidence_and_repeated_labels_count_once(_isolated_store, monkeypatch):
    st = _isolated_store
    monkeypatch.setattr(learning, "FAST_ON", False)
    monkeypatch.setattr(learning, "EVIDENCE_MIN_NEW", 3)
    _run(st, 5 * 24)
    for i in range(3):
        _label(st, REAL.format(i=i), "legit")
    assert learning.due(st)[2] == "evidence"
    for _ in range(5):                                       # the same text labeled again counts once
        _label(st, REAL.format(i=0), "legit")
    monkeypatch.setattr(learning, "EVIDENCE_MIN_NEW", 4)
    assert learning.due(st)[2] != "evidence"


# ---------------------------------------------------------------- retraining

def test_retrain_runs_the_gate_and_starts_a_shadow(_isolated_store, monkeypatch):
    from pathlib import Path
    from scam_detector.tools import train_model
    st = _isolated_store

    def fake_main(argv):
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(_spec("cand1")))
        train_model.LAST_RESULT.clear()
        train_model.LAST_RESULT.update({"written": True, "version": "cand1", "rows": 9, "report": "trained"})
        return 0
    monkeypatch.setattr(train_model, "main", fake_main)
    monkeypatch.setattr(learning, "gate", lambda c, a, s=None: (True, [{"name": "x", "passed": True, "detail": ""}]))
    res = learning.run_retrain("fast", force=True, st=st)
    assert res["status"] == "candidate" and st.get_model("cand1")
    rel = st.release()
    assert rel["stage"] == "shadow" and rel["lane"] == "fast" and rel["candidate_version"] == "cand1"
    monkeypatch.setattr(learning, "gate", lambda c, a, s=None: (False, [{"name": "x", "passed": False, "detail": "no"}]))
    res = learning.run_retrain("manual", force=True, st=st)
    assert res["status"] == "refused" and st.runs(1)[0]["status"] == "refused"


def test_gate_refuses_a_flag_happy_candidate(_isolated_store):
    st = _isolated_store
    for i in range(30):
        _label(st, REAL.format(i=i), "legit")
    for i in range(12):
        _label(st, SCAM.replace("$450", f"${450 + i}"))
    ok, checks = learning.gate(ml.Model(_spec("bad", threshold=0.0)), learning.active_model(st), st)
    assert not ok and not next(c for c in checks if c["name"] == "False alarms on legitimate items")["passed"]


# ---------------------------------------------------------------- serving and release

def test_routing_serves_a_stable_slice_and_records_both_opinions(_isolated_store):
    st = _isolated_store
    st.save_model(_spec("cand2", threshold=0.0))
    learning.begin_shadow("cand2", None, "x", st=st)
    learning.configure_serving()
    ml.second_look("Assistant", REAL.format(i=1))
    t = st.traffic()
    assert len(t) == 1 and t[0]["other"] == "cand2" and t[0]["served"] != "cand2"   # shadow: never shown
    learning.start_rollout(100, st=st)
    f = ml.second_look("Assistant", REAL.format(i=1))
    assert st.traffic()[-1]["served"] == "cand2" and f is not None                    # serving the candidate now


def test_fast_release_promotes_then_rolls_back_a_model_that_turns_out_worse(_isolated_store):
    st = _isolated_store
    st.save_model(_spec("active0"))
    st.save_model(_spec("cand3"))
    st.set_release(active_version="active0")
    learning.begin_shadow("cand3", None, "x", lane="fast", st=st)
    st.set_release(created_at=time.time() - 2 * 86400, stage_started=time.time() - 1.2 * 86400)
    for i in range(40):
        st.add_traffic({"key": f"{i:064x}", "served": "active0", "p": 0.1, "flag": False, "novelty": 0.4,
                        "other": "cand3", "other_p": 0.1, "other_flag": False})
    assert learning.tick(st=st) == "waiting: evidence"
    for i in range(3):
        _label(st, SCAM.replace("$450", f"${600 + i}"))
        _label(st, REAL.format(i=100 + i), "legit")
    assert learning.tick(st=st) == "rollout started"
    st.set_release(stage_started=time.time() - 0.5 * 86400)
    assert learning.tick(st=st) == "waiting: time"          # one day per step in the fast lane, not three
    for expect in ("rollout 50%", "promoted"):
        st.set_release(stage_started=time.time() - 1.1 * 86400)
        assert learning.tick(st=st) == expect
    rel = st.release()
    assert rel["active_version"] == "cand3" and rel["previous_version"] == "active0" and rel["stage"] == "watch"
    # the new model turns out to flag real jobs: the previous one comes back by itself
    st.save_model(_spec("cand3-bad", threshold=0.0))
    st.set_release(active_version="cand3-bad", stage_started=time.time() - 60)
    for i in range(3):
        _label(st, REAL.format(i=200 + i), "legit")
    assert learning.tick(st=st) == "rolled back"
    assert st.release()["active_version"] == "active0"
    assert [l["event"] for l in st.release_log(10)][:4] == ["rolled_back", "promoted", "rollout", "rollout"]


def test_a_traffic_spike_stops_a_shadow_candidate(_isolated_store):
    st = _isolated_store
    st.save_model(_spec("cand4"))
    learning.begin_shadow("cand4", None, "x", st=st)
    for i in range(40):
        st.add_traffic({"key": f"{i:064x}", "served": "x", "p": 0.1, "flag": False, "novelty": 0.4,
                        "other": "cand4", "other_p": 0.9, "other_flag": True})
    assert learning.tick(st=st).startswith("stopped: flags 100%")
    assert st.release()["stage"] == "none"


def test_drift_is_measured_against_the_training_reference(_isolated_store, monkeypatch):
    st = _isolated_store
    monkeypatch.setattr(learning, "DRIFT_MIN_CHECKS", 20)
    assert not learning.drift_status(st)["measured"]
    for i in range(30):
        st.add_traffic({"key": f"{i:064x}", "served": "x", "p": 0.5, "flag": False, "novelty": 0.97})
    d = learning.drift_status(st)
    assert d["measured"] and d["level"] == "drift"


def test_cli_status_and_manual_steps(_isolated_store, capsys):
    from scam_detector.tools import learn
    st = _isolated_store
    st.save_model(_spec("cand5"))
    learning.begin_shadow("cand5", None, "x", st=st)
    assert learn.main(["release", "next", "--who", "E"]) == 0 and st.release()["stage"] == "rollout"
    assert learn.main(["release", "stop"]) == 0 and st.release()["stage"] == "none"
    assert learn.main(["release", "rollback"]) == 1
    assert learn.main(["status"]) == 0 and "Release: none" in capsys.readouterr().out
