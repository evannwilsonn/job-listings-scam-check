"""Recovery plans, outcome follow-up, the employer job-board check and call script, review and evidence export."""

import json

from scam_detector.employer import board_tokens, check_job_board, title_matches, verification_script
from scam_detector.followup import load, open_case, record_outcome
from scam_detector.recovery import HAPPENED, PLAN, STEPS, next_step, recovery_plan


# ---------------------------------------------------------------- recovery

def test_every_situation_has_a_plan_and_every_step_exists():
    assert set(HAPPENED) == set(PLAN)
    assert all(s in STEPS for steps in PLAN.values() for s in steps)


def test_money_that_can_still_be_stopped_comes_first():
    steps = [s["id"] for s in recovery_plan(["shared_personal_info", "deposited_check"])["steps"]]
    assert steps[0] == "stop_contact"
    assert steps.index("call_bank_check") < steps.index("freeze_credit") < steps.index("report_ftc")
    assert len(steps) == len(set(steps))


def test_unknown_input_still_gets_basic_steps():
    plan = recovery_plan(["teleported"])
    assert plan["unknown"] == ["teleported"] and [s["id"] for s in plan["steps"]][0] == "stop_contact"
    assert "not legal advice" in plan["note"]


def test_next_step_is_the_urgent_action():
    assert "bank" in next_step("deposited_check")
    assert next_step("nonsense") == ""


# ---------------------------------------------------------------- follow-up

def test_case_keeps_no_text_and_no_code(tmp_path):
    cases = tmp_path / "cases.jsonl"
    result = {"band": "review", "score": 52, "findings": [{"rule_id": "fake_check_funds"}, {"rule_id": "model_second_look"}]}
    code = open_case(result, "FSU", path=cases)
    rec = load(cases)[0]
    assert code not in cases.read_text() and rec["rules"] == ["fake_check_funds"] and rec["model_flag"]
    assert rec["school"] == "fsu" and "text" not in rec


def test_outcome_validation(tmp_path):
    out = tmp_path / "outcomes.jsonl"
    assert record_outcome("abc12345", ["deposited_check"], "job_fake", path=out)
    assert not record_outcome("abc12345", ["teleported"], "", path=out)
    assert not record_outcome("abc12345", ["nothing"], "maybe", path=out)
    assert len(load(out)) == 1


def test_outcome_report_finds_misses_and_false_alarms(tmp_path):
    from scam_detector.tools.outcome_report import summarize
    cases, outs = tmp_path / "c.jsonl", tmp_path / "o.jsonl"
    a = open_case({"band": "clear", "score": 5, "findings": [{"rule_id": "student_bait"}]}, "fsu", path=cases)
    b = open_case({"band": "block", "score": 80, "findings": []}, "fsu", path=cases)
    c = open_case({"band": "review", "score": 40, "findings": []}, "fsu", path=cases)
    record_outcome(a, ["sent_money"], "job_fake", path=outs)
    record_outcome(b, ["nothing"], "job_fake", path=outs)
    record_outcome(c, ["nothing"], "job_real", path=outs)
    s = summarize(load(cases), load(outs))
    assert len(s["misses"]) == 1 and s["missed_rule_counts"] == {"student_bait": 1}
    assert len(s["false_alarms"]) == 1 and s["by_band"]["block"]["verified_fake"] == 1


# ---------------------------------------------------------------- employer

GH = json.dumps({"jobs": [{"title": "Software Engineer, Payments", "absolute_url": "https://boards.greenhouse.io/acme/jobs/1"},
                          {"title": "Data Analyst", "absolute_url": "https://boards.greenhouse.io/acme/jobs/2"}]})


def fake_fetch(boards):
    def fetch(url):
        for key, body in boards.items():
            if key in url:
                return 200, body
        return 404, ""
    return fetch


def test_tokens_and_title_matching():
    assert board_tokens("Acme Corp, Inc.") == ["acme"]
    assert board_tokens("Blue Ridge Labs") == ["blueridgelabs", "blue-ridge-labs", "blue"]
    assert title_matches("Remote Data Analyst (Entry Level)", "Data Analyst")
    assert not title_matches("Personal Assistant", "Data Analyst")


def test_job_found_on_board():
    r = check_job_board("Acme Corp", "Data Analyst", fetch=fake_fetch({"boards/acme/": GH}))
    assert r["status"] == "found" and r["provider"] == "greenhouse" and r["matches"][0]["title"] == "Data Analyst"


def test_job_not_listed_is_a_note_only():
    from scam_detector.employer import board_finding
    r = check_job_board("Acme", "Remote Personal Assistant", fetch=fake_fetch({"boards/acme/": GH}))
    assert r["status"] == "not_listed"
    f = board_finding(r, "Acme", "Remote Personal Assistant")
    assert f["severity"] == "note" and f["weight"] <= 10


def test_link_in_message_is_tried_first_and_no_board_is_neutral():
    lever = json.dumps([{"text": "Field Technician", "hostedUrl": "https://jobs.lever.co/zeta/1"}])
    r = check_job_board("Zeta Inc", "Field Technician", urls=["https://jobs.lever.co/zeta/1"],
                        fetch=fake_fetch({"postings/zeta": lever}))
    assert r["status"] == "found" and r["checked"][0] == "lever:zeta"
    assert check_job_board("Nobody LLC", "Clerk", fetch=lambda u: (404, ""))["status"] == "no_public_board"


def test_lookup_errors_are_unknown_not_a_verdict():
    def boom(url):
        raise TimeoutError
    assert check_job_board("Acme", "Analyst", fetch=boom)["status"] == "unknown"


def test_script_never_uses_message_contacts():
    s = verification_script("Acme", "Data Analyst", "Jordan Lee", "text")
    assert "Don't use any link, phone number or email" in s["find_the_number"][0]
    assert "Jordan Lee" in s["what_to_say"] and "by text" in s["what_to_say"]


# ---------------------------------------------------------------- review and evidence

def _queue(tmp_path):
    from scam_detector.reports import append_report, make_report
    q = tmp_path / "q.jsonl"
    append_report(make_report("Pay via https://fast-jobs.example and bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                              school="fsu", outcome="crypto"), q)
    append_report(make_report("Real job at https://realco.example, apply on site", school="fsu"), q)
    return q


def test_only_confirmed_reports_are_exported(tmp_path):
    from scam_detector.tools.export_evidence import package, summary
    from scam_detector.tools.review_queue import decide, read, write
    q = _queue(tmp_path)
    rows = read(q)
    decide(rows, 0, "confirmed", "E. Wilson", "crypto wave")
    decide(rows, 1, "dismissed", "E. Wilson")
    write(q, rows)
    p = package(read(q))
    assert p["reports"] == 1 and p["attested_by"] == ["E. Wilson"]
    assert [d["value"] for d in p["indicators"]["domains"]] == ["fast-jobs.example"]
    assert p["indicators"]["wallets"][0]["value"].startswith("bc1q")
    assert "fast-jobs.example" in summary(p) and "confirmed by a reviewer" in summary(p)


def test_review_needs_a_reviewer_and_a_valid_decision(tmp_path):
    import pytest
    from scam_detector.tools.review_queue import decide, read
    rows = read(_queue(tmp_path))
    with pytest.raises(ValueError):
        decide(rows, 0, "confirmed", " ")
    with pytest.raises(ValueError):
        decide(rows, 0, "approved", "E. Wilson")


# ---------------------------------------------------------------- API

def test_api_recovery_outcome_and_follow_up(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from scam_detector import api, followup
    monkeypatch.setattr(followup, "CASES", tmp_path / "c.jsonl")
    monkeypatch.setattr(followup, "OUTCOMES", tmp_path / "o.jsonl")
    c = TestClient(api.app)
    plan = c.post("/recovery", json={"happened": ["sent_money"]}).json()
    assert plan["steps"][1]["id"] == "call_bank_payment"
    out = c.post("/analyze", json={"description": "Deposit the check we mail you and send the rest to our vendor.",
                                   "run_network": False, "second_look": False, "follow_up": True, "school": "fsu"}).json()
    code = out["case_code"]
    assert out["follow_up_after"] and code
    r = c.post("/outcome", json={"case_code": code, "happened": ["deposited_check"], "verified": "job_fake"}).json()
    assert r["recorded"] and r["recovery"]["steps"]
    assert c.post("/outcome", json={"case_code": code, "happened": ["teleported"]}).status_code == 422


def test_api_verify_job_without_board_lookup():
    from fastapi.testclient import TestClient
    from scam_detector import api
    c = TestClient(api.app)
    out = c.post("/verify-job", json={"company": "Deloitte", "title": "Analyst", "recruiter_email": "hr@quick-hire.net",
                                      "check_board": False}).json()
    assert out["board"] is None and out["script"]["what_to_say"]
    assert "sender_company_mismatch" in {f["rule_id"] for f in out["findings"]}


def test_cut_off_board_response_is_still_checked():
    from scam_detector.employer import _jobs
    body = json.dumps({"jobs": [{"title": "Data Analyst", "jobUrl": "https://jobs.ashbyhq.com/x/1", "descriptionHtml": "a" * 50},
                                {"title": "Field Tech", "jobUrl": "https://jobs.ashbyhq.com/x/2"}]})
    cut = body[: body.index("x/2") + 4]           # cut off mid-object, after the second URL
    assert [j["title"] for j in _jobs("ashby", cut)] == ["Data Analyst", "Field Tech"]
