"""Basic checks that the standalone detector scores postings the way the full system does."""
from scam_detector.scorer import score_posting


def band(title, text, company=""):
    r = score_posting(title, text, company)
    return r["band"] if isinstance(r, dict) else r.band


def test_fake_check_scam_is_blocked():
    assert band("Remote Assistant", "You will be paid $650 weekly for 1-2 hrs a day. Interview on Telegram. "
                "We send a check, deposit it and send the balance by Zelle.") == "block"


def test_fee_to_start_is_flagged():
    assert band("Data Entry", "Start today! You must pay a $90 training fee before your first shift.") in ("review", "block")


def test_negated_fee_is_not_flagged():
    assert band("Barista", "We will never ask you for a training fee. $15/hr, weekends, apply in store.", "Bean Co") == "clear"


def test_ssn_for_payroll_after_hire_is_fine():
    assert band("Cashier", "Your Social Security number is collected for payroll upon hire. $14/hr.", "Corner Market") == "clear"


def test_ordinary_posting_is_clear():
    assert band("Marketing Intern", "Help plan campus events and write social posts. 15 hours a week, $16/hr. "
                "Apply through our careers page.", "Acme") == "clear"
