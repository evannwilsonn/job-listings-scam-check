"""Offer letters, screenshots, the school-year alert calendar, and the browser extension build."""

import base64
import datetime as dt
import io
import json
import shutil

import pytest
from fastapi.testclient import TestClient

from scam_detector.api import app
from scam_detector.offer import offer_findings, pdf_text
from scam_detector.tools.alerts import active, ics, seasons, trends

client = TestClient(app)

SCAM_OFFER = """OFFER OF EMPLOYMENT
Dear Candidate,
Following your interview, we are pleased to offer you the position of Remote Administrative Assistant with Deloitte.
Please reply to hr.deloitte.onboarding@gmail.com with your acceptance.
Regards,
Hiring Team"""

LEGIT_OFFER = """Acme Robotics, Inc.
1200 Innovation Way, Tallahassee, FL 32304
Dear Jordan Lee,
We are pleased to offer you the position of Software Engineering Intern at Acme Robotics.
Your start date is May 18, 2027 and your pay will be $32.00 per hour, paid bi-weekly.
This offer is contingent upon a background check and completion of Form I-9. Employment with Acme is at-will.
Questions? Contact recruiting@acmerobotics.com or visit https://careers.acmerobotics.com.
Sincerely,
Dana Morales
University Recruiting Manager"""


def _ids(findings):
    return {f["rule_id"] for f in findings}


# ---------------------------------------------------------------- offer letters

def test_scam_offer_letter_findings():
    assert _ids(offer_findings(SCAM_OFFER)) == {"offer_freemail_contact", "offer_missing_basics"}


def test_real_offer_letter_is_clean():
    assert offer_findings(LEGIT_OFFER) == []


def test_offer_contacts_from_another_company():
    text = LEGIT_OFFER.replace("recruiting@acmerobotics.com", "onboarding@talentbridge-hr.net")
    f = {x["rule_id"]: x for x in offer_findings(text)}
    assert set(f) == {"offer_company_mismatch"} and f["offer_company_mismatch"]["matched"] == ["talentbridge-hr.net"]
    # hiring systems send for the employer: never a mismatch
    assert offer_findings(LEGIT_OFFER.replace("recruiting@acmerobotics.com", "no-reply@greenhouse.io")) == []


def test_not_an_offer_letter_gets_no_offer_findings():
    assert offer_findings("Text me on WhatsApp for a remote job, reply to jobs4u@gmail.com") == []


def _pdf(text):
    canvas = pytest.importorskip("reportlab.pdfgen.canvas")
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    y = 780
    for line in text.splitlines():
        c.drawString(40, y, line[:110])
        y -= 18
    c.save()
    return buf.getvalue()


def test_offer_pdf_through_the_api():
    r = client.post("/analyze-offer", json={"pdf_base64": base64.b64encode(_pdf(SCAM_OFFER)).decode(), "run_network": False})
    j = r.json()
    assert r.status_code == 200 and j["is_offer_letter"] and "deloitte" in j["text_read"].lower()
    assert {"offer_freemail_contact", "offer_missing_basics"} <= _ids(j["findings"]) and j["band"] == "caution"     # contact + thin letter alone: be careful
    legit = client.post("/analyze-offer", json={"text": LEGIT_OFFER, "run_network": False}).json()
    assert legit["band"] == "clear" and legit["is_offer_letter"]


def test_bad_offer_uploads_get_a_plain_reason():
    assert client.post("/analyze-offer", json={"pdf_base64": base64.b64encode(b"hello").decode()}).json()["detail"] \
        == "That isn't a PDF file."
    assert client.post("/analyze-offer", json={}).status_code == 422
    assert client.post("/analyze-offer", json={"pdf_base64": "%%%"}).json()["detail"] == "The file wasn't valid base64."
    with pytest.raises(ValueError):
        pdf_text(b"%PDF-1.4 garbage")


# ---------------------------------------------------------------- screenshots

def _png(lines):
    from PIL import Image, ImageDraw, ImageFont
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 22)
    except OSError:
        font = ImageFont.load_default(size=22)
    img = Image.new("RGB", (760, 60 + 50 * len(lines)), "white")
    d = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        d.text((20, 20 + 50 * i), line, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


@pytest.mark.skipif(not shutil.which("tesseract"), reason="tesseract-ocr not installed")
def test_screenshot_is_read_and_checked():
    png = _png(["We will mail you a check to buy equipment", "from our vendor. Text me on WhatsApp."])
    r = client.post("/analyze-image", json={"image_base64": base64.b64encode(png).decode(), "run_network": False})
    j = r.json()
    assert r.status_code == 200 and "check" in j["text_read"].lower()
    assert "fake_check_funds" in _ids(j["findings"]) and j["band"] == "block"


def test_screenshot_rejects_other_files():
    r = client.post("/analyze-image", json={"image_base64": base64.b64encode(b"GIF89a" + b"x" * 40).decode()})
    assert r.status_code == 422 and "PNG, JPEG and WebP" in r.json()["detail"]


def test_uploads_get_a_bigger_body_limit_than_text():
    big = "A" * 200_000
    assert client.post("/analyze", json={"description": big}).status_code == 413
    assert client.post("/analyze-image", json={"image_base64": big}).status_code == 422   # read, then refused as not an image


# ---------------------------------------------------------------- alert calendar

def test_seasons_cover_the_year_and_fill_school_details():
    s = {x["id"]: x for x in seasons("fsu")}
    assert {"fall-start", "spring-start", "internship-hunt", "summer-remote", "holiday"} <= set(s)
    assert "FSU Career Center" in s["fall-start"]["email"] and "{" not in s["fall-start"]["email"]
    assert [x["id"] for x in active(dt.date(2026, 8, 25), "fsu")] == ["fall-start"]
    assert active(dt.date(2026, 7, 4), "fsu") == []


def test_calendar_file_is_valid_and_repeats_yearly():
    text = ics(2027, "fsu", stamp=dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc))
    lines = text.split("\r\n")
    assert lines[0] == "BEGIN:VCALENDAR" and text.endswith("END:VCALENDAR\r\n")
    assert all(len(l.encode()) <= 75 for l in lines)
    assert text.count("BEGIN:VEVENT") == len(seasons()) and text.count("RRULE:FREQ=YEARLY") == len(seasons())
    assert "DTSTART;VALUE=DATE:20270807" in text            # fall-start 08-10, three days ahead
    unfolded = text.replace("\r\n ", "")
    assert "Scam alert to send: Start of fall semester" in unfolded


def test_trend_alert_on_a_spike():
    rules = {"reship_home": {"title": "Receive and re-ship packages from home", "why": "It's laundering."}}
    today = dt.date(2026, 11, 20)
    spike = [{"date": "2026-11-15", "band": "block", "rules": ["reship_home"]} for _ in range(4)]
    usual = [{"date": "2026-10-01", "band": "block", "rules": ["reship_home"]}]
    rows = trends(spike + usual, today, rules)
    assert len(rows) == 1 and rows[0]["recent"] == 4 and "re-ship packages" in rows[0]["draft"]
    steady = [{"date": f"2026-10-{d:02d}", "band": "block", "rules": ["reship_home"]} for d in range(1, 29)]
    assert trends(spike + steady, today, rules) == []


# ---------------------------------------------------------------- extension

def test_extension_is_built_from_the_public_rulepack():
    from pathlib import Path
    from tools.build_web import render_extension
    root = Path(__file__).resolve().parent.parent / "extension"
    manifest = json.loads((root / "manifest.json").read_text())
    assert manifest["manifest_version"] == 3 and "host_permissions" not in manifest
    assert set(manifest["permissions"]) == {"contextMenus", "storage"}       # no network, no page access
    files = render_extension()
    assert all(p.read_text(encoding="utf-8") == text for p, text in files.items())
    data = (root / "lurecheck-data.js").read_text()
    assert "remote_weekly_pay" not in data and "weekly_pay_few_hours" not in data
    assert "innerHTML" not in (root / "popup.js").read_text()
