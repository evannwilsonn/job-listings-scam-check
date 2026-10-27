"""Sender identity, the thread and report endpoints, the CT-watch runner and the public-report importer."""

import json

from scam_detector.identity import sender_findings
from scam_detector.reports import ftc_summary, hash_identifier, make_report, mask


def ids(findings):
    return {f["rule_id"] for f in findings}


# ---------------------------------------------------------------- identity

def test_free_mail_recruiter_is_flagged():
    f = sender_findings("talent.team.hr@gmail.com", text="I'm a recruiter with Acme's HR department.")
    assert "personal_sender" in ids(f)


def test_free_mail_without_a_claim_is_not():
    assert sender_findings("jane.doe@gmail.com", text="Hi, are you still selling the couch?") == []


def test_hijacked_edu_reply_to_is_flagged_harder():
    f = sender_findings("prof.smith@cs.example.edu", reply_to="prof.smith.office@gmail.com",
                        text="I need a research assistant.")
    r = [x for x in f if x["rule_id"] == "reply_to_elsewhere"]
    assert r and r[0]["weight"] == 24 and ".edu" in r[0]["why"]


def test_reply_to_same_domain_or_hiring_platform_is_fine():
    assert "reply_to_elsewhere" not in ids(sender_findings("a@acme.com", reply_to="jobs@careers.acme.com"))
    assert "reply_to_elsewhere" not in ids(sender_findings("a@acme.com", reply_to="no-reply@greenhouse.io"))


def test_company_mismatch_is_a_note_and_skips_platforms_and_matches():
    f = sender_findings("hr@quick-hire-now.com", company="Deloitte")
    m = [x for x in f if x["rule_id"] == "sender_company_mismatch"]
    assert m and m[0]["severity"] == "note"
    assert sender_findings("recruiting@deloitte.com", company="Deloitte LLP") == []
    assert sender_findings("no-reply@myworkday.com", company="Deloitte") == []
    assert sender_findings("jobs@ibm.com", company="International Business Machines") == []


def test_display_name_spoof():
    f = sender_findings("hiring@careers-portal.net", sender_name="Amazon Recruiting", company="Amazon")
    assert "display_name_spoof" in ids(f)


# ---------------------------------------------------------------- reports

def test_report_masks_text_and_hashes_contacts():
    text = "Text me at (850) 555-0134 or email hr.team@gmail.com. Pay to 0x" + "a" * 40 + " via https://fast-jobs.example/apply"
    r = make_report(text, sender="hr.team@gmail.com", school="FSU!", outcome="deposited_check")
    assert "555" not in r["text_masked"] and "gmail" not in r["text_masked"] and "[wallet]" in r["text_masked"]
    assert r["school"] == "fsu" and r["outcome"] == "deposited_check" and r["status"] == "reported"
    ind = r["indicators"]
    assert ind["phone_hashes"] == [hash_identifier("8505550134")]
    assert ind["email_hashes"] == [hash_identifier("hr.team@gmail.com")]
    assert "fast-jobs.example" in ind["domains"] and "gmail.com" not in ind["domains"]
    assert ind["wallets"] == ["0x" + "a" * 40]


def test_unknown_outcome_is_dropped_and_ftc_summary_carries_the_text():
    assert make_report("x" * 80, outcome="nonsense")["outcome"] == ""
    s = ftc_summary("They sent me a check to buy equipment.", "a@b.com", "deposited_check")
    assert "deposited check" in s and "a@b.com" in s and "check to buy equipment" in s


def test_mask_leaves_ordinary_text():
    assert mask("Pay is $18 per hour, 20 hours a week.") == "Pay is $18 per hour, 20 hours a week."


# ---------------------------------------------------------------- API

def test_analyze_adds_sender_findings_and_rescores():
    from fastapi.testclient import TestClient
    from scam_detector import api
    c = TestClient(api.app)
    body = {"title": "Research Assistant", "description": "I am a professor and need a research assistant.",
            "run_network": False, "second_look": False,
            "sender": "prof.lee@bio.example.edu", "reply_to": "prof.lee.lab@gmail.com"}
    out = c.post("/analyze", json=body).json()
    assert "reply_to_elsewhere" in ids(out["findings"])
    assert out["score"] == min(100, sum(f["weight"] for f in out["findings"]))


def test_analyze_thread_endpoint():
    from fastapi.testclient import TestClient
    from scam_detector import api
    c = TestClient(api.app)
    thread = ("Them: Hi, I'm a recruiter. Are you open to a remote assistant role?\n"
              "Me: Yes, tell me more.\n"
              "Them: Great. Please add me on WhatsApp so we can continue the interview there.\n"
              "Them: I'll mail you a check to buy your equipment. Deposit it and send the rest to our vendor.")
    out = c.post("/analyze-thread", json={"thread": thread}).json()
    assert out["turns"] and out["furthest_stage"]


def test_report_endpoint_queues_masked_record(_isolated_store):
    from fastapi.testclient import TestClient
    from scam_detector import api
    q = _isolated_store.reports_path
    c = TestClient(api.app)
    out = c.post("/report", json={"text": "Email me at boss.hr@gmail.com and deposit the check we send you today.",
                                  "school": "fsu", "outcome": "deposited_check"}).json()
    assert out["queued"] and out["ftc_url"].startswith("https://reportfraud.ftc.gov") and "bank" in out["next_step"]
    rec = json.loads(q.read_text().splitlines()[0])
    assert "gmail" not in rec["text_masked"] and rec["status"] == "reported"


# ---------------------------------------------------------------- tools

def test_ct_watch_run_with_fake_logs():
    from scam_detector.tools.ct_watch_run import markdown, run
    body = json.dumps([{"name_value": "fsu-careers-portal.com", "not_before": "2030-01-02T00:00:00", "issuer_name": "x"}])
    rep = run({"fsu": {"name": "Florida State University", "terms": ["fsu"]}}, days=8, fetch=lambda url: (200, body))
    found = [d["domain"] for d in rep["schools"]["fsu"]["domains"]]
    assert any("fsu-careers-portal.com" in d for d in found)
    assert "Florida State University" in markdown(rep)


def test_import_reports_masks_dedups_and_marks_for_review(tmp_path):
    from scam_detector.tools.import_reports import read_blocks, to_rows
    p = tmp_path / "saved.txt"
    report = "They offered me a remote assistant job, then sent a check and told me to text 850-555-0199 after deposit."
    p.write_text(f"{report}\n\n{report}\n\ntoo short\n")
    rows = to_rows(read_blocks(p), "r/scams")
    assert len(rows) == 1 and rows[0]["needs_review"] and "[phone]" in rows[0]["description"]
