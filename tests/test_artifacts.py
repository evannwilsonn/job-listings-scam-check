"""Attachment analysis: offer-letter PDFs, check images, QR codes (scam_detector/artifacts.py)."""
import io
import re
import struct
import zlib
from datetime import datetime, timedelta, timezone

import pytest

from scam_detector import artifacts as A


# ------------------------------------------------------------------ helpers

def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(lines, metadata=None, password=None, pages=1) -> bytes:
    """Build a real text PDF in memory with pypdf (Helvetica, one line per Tj)."""
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    w = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                             NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    font_ref = w._add_object(font)
    for _ in range(pages):
        page = w.add_blank_page(612, 792)
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})})
        ops = ["BT", "/F1 11 Tf", "14 TL", "72 740 Td"]
        for ln in lines:
            ops.append(f"({_pdf_escape(ln)}) Tj T*")
        ops.append("ET")
        stream = DecodedStreamObject()
        stream.set_data("\n".join(ops).encode("latin-1"))
        page[NameObject("/Contents")] = w._add_object(stream)
    if metadata:
        w.add_metadata(metadata)
    if password:
        w.encrypt(user_password=password, owner_password=password)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def make_png(width=4, height=4) -> bytes:
    """Minimal valid grayscale PNG, no Pillow needed."""
    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def pdfdate(dt: datetime) -> str:
    return dt.strftime("D:%Y%m%d%H%M%SZ")


def ids(res):
    return {f["rule_id"] for f in res["findings"]}


def all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from all_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from all_strings(v)


CHECK_TEXT = """Brightline Logistics LLC
1200 Commerce Way, Dallas TX 75201
Date: 09/20/2026
PAY TO THE ORDER OF Jordan Student $2,950.00
Two thousand nine hundred fifty and 00/100 DOLLARS
Wells Fargo Bank, N.A.
Memo: equipment
Routing: 021000021 Account: 123456789012
"""


# ------------------------------------------------------------------ ABA / masking

@pytest.mark.parametrize("rtn", ["021000021", "011000015", "121000358", "026009593"])
def test_aba_checksum_valid(rtn):
    assert A.aba_checksum_ok(rtn)


@pytest.mark.parametrize("rtn", ["021000022", "123456789", "011000016", "000000000", "12345678", "02100002a", ""])
def test_aba_checksum_invalid(rtn):
    assert not A.aba_checksum_ok(rtn)


def test_mask_number_keeps_only_last_four():
    assert A.mask_number("123456789012") == "********9012"
    assert A.mask_number("1234 5678 9012") == "********9012"
    assert A.mask_number("9012") == "9012"


def test_account_numbers_never_returned_in_full():
    res = A.analyze_text(CHECK_TEXT, claimed_company="Seminole Data Co")
    blob = repr(res)
    assert "123456789012" not in blob
    assert "********9012" in res["accounts"]
    assert any(r["routing"] == "021000021" and r["checksum_ok"] for r in res["routing_numbers"])
    red = A.redact_accounts(CHECK_TEXT)
    assert "123456789012" not in red and "9012" in red
    assert "021000021" in red              # public routing number left intact


def test_micr_line_routing_and_account():
    text = "PAY TO THE ORDER OF Jane Doe $1,500.00\n⑆021000021⑆ 4455667788⑈ 1042"
    res = A.analyze_text(text)
    assert any(r["source"] == "micr" and r["checksum_ok"] for r in res["routing_numbers"])
    assert "******7788" in res["accounts"]
    assert "4455667788" not in repr(res)


def test_invalid_routing_is_reported_not_trusted():
    res = A.analyze_text("Routing number: 123456789")
    assert res["routing_numbers"] == [{"routing": "123456789", "checksum_ok": False, "source": "labeled"}]
    assert not res["is_check"] and not res["findings"]


# ------------------------------------------------------------------ check findings

def test_check_image_finding():
    res = A.analyze_text(CHECK_TEXT)
    f = next(f for f in res["findings"] if f["rule_id"] == "check_image")
    assert f["severity"] == "critical" and f["weight"] == 30
    assert "before you start" in f["why"] and "equipment" in f["why"]
    assert "valid routing number does not mean" in f["why"].lower()
    assert not any("123456789012" in m for m in f["matched"])


def test_no_check_finding_for_ordinary_offer_text():
    text = "We are pleased to offer you the position of Analyst. Your annual salary is $55,000.00."
    assert A.analyze_text(text)["findings"] == []


def test_check_payer_mismatch():
    res = A.analyze_text(CHECK_TEXT, claimed_company="Seminole Data Co")
    f = next(f for f in res["findings"] if f["rule_id"] == "check_payer_mismatch")
    assert f["severity"] == "warning"
    assert any("Brightline" in m for m in f["matched"])
    assert "Brightline Logistics LLC" in res["payers"]
    assert any("Wells Fargo" in b for b in res["banks"])


def test_check_payer_matches_claimed_company():
    res = A.analyze_text(CHECK_TEXT, claimed_company="Brightline Logistics")
    assert "check_payer_mismatch" not in ids(res)
    assert "check_image" in ids(res)        # still a check sent to deposit


def test_payer_label_is_used():
    text = "Remitter: Globex Holdings Inc\nPAY TO THE ORDER OF Sam $900.00"
    res = A.analyze_text(text, claimed_company="Initech")
    assert "check_payer_mismatch" in ids(res)


# ------------------------------------------------------------------ PDFs

def test_pdf_text_and_metadata_extracted():
    data = make_pdf(["Offer of Employment", "Dear Candidate,"],
                    metadata={"/Producer": "pypdf test", "/Author": "HR"})
    res = A.analyze_upload(data, "offer.pdf", "application/pdf")
    assert res["kind"] == "pdf"
    assert "Offer of Employment" in res["text"]
    assert res["meta"]["pdf"]["producer"] == "pypdf test"
    assert res["meta"]["pdf"]["author"] == "HR"
    assert res["meta"]["pdf"]["pages"] == 1


def test_pdf_page_cap(monkeypatch):
    monkeypatch.setattr(A, "MAX_PDF_PAGES", 2)
    res = A.analyze_upload(make_pdf(["page text"], pages=4), "x.pdf", "application/pdf")
    assert res["text"].count("page text") == 2
    assert any("first 2 pages" in n for n in res["notes"])


def test_doc_edited_after_creation():
    now = datetime.now(timezone.utc)
    data = make_pdf(["Hello"], metadata={"/CreationDate": pdfdate(now - timedelta(days=900)),
                                         "/ModDate": pdfdate(now - timedelta(days=3))})
    res = A.analyze_upload(data, "offer.pdf", "application/pdf")
    f = next(f for f in res["findings"] if f["rule_id"] == "doc_edited_after_creation")
    assert f["severity"] == "note"


def test_doc_consumer_tool_needs_big_company_claim():
    lines = ["Amazon", "Offer of Employment", "We are pleased to offer you the position of Remote Data Clerk."]
    data = make_pdf(lines, metadata={"/Producer": "Microsoft® Word for Microsoft 365"})
    res = A.analyze_upload(data, "offer.pdf", "application/pdf")
    f = next(f for f in res["findings"] if f["rule_id"] == "doc_consumer_tool")
    assert f["severity"] == "note" and f["weight"] <= 3

    small = make_pdf(["Tallahassee Tutoring", "Offer of Employment"],
                     metadata={"/Producer": "Microsoft® Word for Microsoft 365"})
    assert "doc_consumer_tool" not in ids(A.analyze_upload(small, "offer.pdf", "application/pdf"))


def test_doc_consumer_tool_uses_claimed_company():
    data = make_pdf(["Offer of Employment", "Start date: soon"], metadata={"/Creator": "Canva"})
    res = A.analyze_upload(data, "o.pdf", "application/pdf", claimed_company="Deloitte")
    assert "doc_consumer_tool" in ids(res)


def test_doc_future_date():
    future = datetime.now(timezone.utc) + timedelta(days=400)
    res = A.analyze_upload(make_pdf(["Hi"], metadata={"/CreationDate": pdfdate(future)}), "a.pdf", "application/pdf")
    assert "doc_future_or_mismatched_date" in ids(res)


def test_doc_mismatched_date():
    data = make_pdf(["March 3, 2021", "Offer of Employment"],
                    metadata={"/CreationDate": "D:20260915100000Z", "/ModDate": "D:20260915100000Z"})
    res = A.analyze_upload(data, "a.pdf", "application/pdf")
    f = next(f for f in res["findings"] if f["rule_id"] == "doc_future_or_mismatched_date")
    assert "March 3, 2021" in f["why"]
    ok = make_pdf(["September 14, 2026"], metadata={"/CreationDate": "D:20260915100000Z"})
    assert "doc_future_or_mismatched_date" not in ids(A.analyze_upload(ok, "a.pdf", "application/pdf"))


def test_parse_pdf_date_with_offset():
    dt = A.parse_pdf_date("D:20240101120000-05'00'")
    assert dt == datetime(2024, 1, 1, 17, 0, tzinfo=timezone.utc)
    assert A.parse_pdf_date("garbage") is None
    assert A.parse_pdf_date(None) is None


def test_check_inside_pdf_masks_account_in_text_and_meta():
    data = make_pdf(CHECK_TEXT.strip().splitlines(), metadata={"/Author": "acct 99887766554433"})
    res = A.analyze_upload(data, "check.pdf", "application/pdf", claimed_company="Seminole Data Co")
    assert {"check_image", "check_payer_mismatch"} <= ids(res)
    for s in all_strings(res):
        assert "123456789012" not in s and "99887766554433" not in s
    assert "********9012" in res["text"]


def test_encrypted_pdf_is_handled():
    data = make_pdf(["secret offer"], password="hunter2")
    res = A.analyze_upload(data, "locked.pdf", "application/pdf")
    assert res["kind"] == "pdf"
    assert res["meta"]["pdf"]["encrypted"] is True
    assert res["text"] == ""
    assert any("password" in n.lower() for n in res["notes"])


def test_encrypted_pdf_with_empty_password_is_read():
    data = make_pdf(["open offer"], password="")
    res = A.analyze_upload(data, "o.pdf", "application/pdf")
    assert "open offer" in res["text"]


@pytest.mark.parametrize("blob", [
    b"%PDF-1.7\n this is not really a pdf \x00\xff",
    b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF",
    b"not a pdf at all",
])
def test_garbage_pdf_is_handled(blob):
    res = A.analyze_upload(blob, "bad.pdf", "application/pdf")
    assert res["kind"] == "pdf"
    assert res["findings"] == []
    assert res["notes"]


def test_truncated_real_pdf():
    data = make_pdf(["Offer"])[:200]
    res = A.analyze_upload(data, "cut.pdf", "application/pdf")
    assert res["kind"] == "pdf" and isinstance(res["text"], str)


# ------------------------------------------------------------------ images / OCR / QR

def test_image_ocr_unavailable(monkeypatch):
    monkeypatch.setattr(A, "HAS_OCR", False)
    monkeypatch.setattr(A, "HAS_QR", False)
    res = A.analyze_upload(make_png(), "check.png", "image/png")
    assert res["kind"] == "image"
    assert res["meta"]["ocr"] == "unavailable"
    assert res["text"] == ""
    assert any("Paste the text from the image" in n for n in res["notes"])


def test_image_without_pillow(monkeypatch):
    monkeypatch.setattr(A, "HAS_PIL", False)
    monkeypatch.setattr(A, "HAS_OCR", False)
    monkeypatch.setattr(A, "HAS_QR", False)
    res = A.analyze_upload(make_png(7, 5), "x.png", "image/png")
    assert res["meta"]["image"]["width"] == 7 and res["meta"]["image"]["height"] == 5
    assert res["meta"]["ocr"] == "unavailable"


def test_qr_fallback_when_no_decoder(monkeypatch):
    monkeypatch.setattr(A, "HAS_QR", False)
    monkeypatch.setattr(A, "HAS_OCR", False)
    res = A.analyze_upload(make_png(), "qr.png", "image/png")
    assert res["meta"]["qr"] == "unavailable"
    assert res["urls"] == []
    assert any("QR" in n for n in res["notes"])


def test_qr_payload_url_is_listed(monkeypatch):
    monkeypatch.setattr(A, "HAS_OCR", False)
    monkeypatch.setattr(A, "HAS_QR", True)
    monkeypatch.setattr(A, "_decode_qr", lambda data, img: ["https://Onboard-Portal.example/start?id=1", "WIFI:S:x;;"])
    res = A.analyze_upload(make_png(), "qr.png", "image/png")
    assert res["urls"] == ["https://Onboard-Portal.example/start?id=1"]
    f = next(f for f in res["findings"] if f["rule_id"] == "qr_link")
    assert f["severity"] == "note" and f["matched"] == ["onboard-portal.example"]
    assert "WIFI:S:x;;" in res["meta"]["qr_payloads"]


def test_real_qr_decode_if_available():
    if not A.HAS_QR or not A.HAS_CV2:
        pytest.skip("no QR decoder here")
    cv2 = pytest.importorskip("cv2")
    if not hasattr(cv2, "QRCodeEncoder"):
        pytest.skip("cv2 has no QR encoder")
    qr = cv2.QRCodeEncoder.create().encode("https://pay-deposit.example/x")
    qr = cv2.resize(qr, (qr.shape[1] * 8, qr.shape[0] * 8), interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, png = cv2.imencode(".png", qr)
    assert ok
    res = A.analyze_upload(png.tobytes(), "qr.png", "image/png")
    assert "https://pay-deposit.example/x" in res["urls"]
    assert "qr_link" in ids(res)


def test_real_ocr_if_available():
    if not A.HAS_OCR:
        pytest.skip("tesseract not available here")
    from PIL import Image, ImageDraw, ImageFont
    try:
        font = ImageFont.load_default(size=36)
    except TypeError:
        pytest.skip("old Pillow without scalable default font")
    img = Image.new("RGB", (1400, 260), "white")
    d = ImageDraw.Draw(img)
    d.text((30, 30), "PAY TO THE ORDER OF Jordan $2,950.00", fill="black", font=font)
    d.text((30, 130), "Routing: 021000021", fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    res = A.analyze_upload(buf.getvalue(), "check.png", "image/png")
    assert res["meta"]["ocr"] == "ok"
    assert re.search(r"(?i)order", res["text"])
    assert "check_image" in ids(res)


# ------------------------------------------------------------------ limits / kinds

def test_size_limit():
    res = A.analyze_upload(b"%PDF-1.4" + b"0" * (A.MAX_BYTES + 1), "big.pdf", "application/pdf")
    assert res["meta"]["rejected"] == "too_large"
    assert res["findings"] == [] and res["text"] == ""
    assert any("8 MB" in n for n in res["notes"])


def test_pixel_limit_rejects_before_decoding():
    # Header claims 50000x50000; body is bogus. Must be rejected without decoding.
    png = make_png()
    huge = png[:16] + struct.pack(">II", 50000, 50000) + png[24:]
    res = A.analyze_upload(huge, "huge.png", "image/png")
    assert res["meta"]["image"]["rejected"] == "too_many_pixels"
    assert res["meta"]["ocr"] == "skipped"


def test_image_dimensions_jpeg_header():
    sof = b"\xff\xc0\x00\x11\x08" + struct.pack(">HH", 480, 640) + b"\x03" + b"\x00" * 9
    jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + sof
    assert A.image_dimensions(jpg) == (640, 480)


def test_unsupported_and_empty():
    res = A.analyze_upload(b"PK\x03\x04zipdata", "offer.docx", "application/octet-stream")
    assert res["kind"] == "unsupported" and res["notes"]
    assert A.analyze_upload(b"", "x.pdf", "application/pdf")["notes"]


def test_result_shape():
    res = A.analyze_upload(make_pdf(["See https://apply-now.example/form for details"]), "a.pdf", "application/pdf")
    assert set(res) == {"kind", "text", "findings", "meta", "notes", "urls"}
    assert "https://apply-now.example/form" in res["urls"]
    for f in A.analyze_text(CHECK_TEXT, "Other Co")["findings"]:
        assert set(f) == {"rule_id", "severity", "weight", "title", "why", "matched"}
        assert f["severity"] in ("critical", "warning", "note")


def test_nothing_written_to_disk(monkeypatch):
    import builtins
    real_open = builtins.open

    def guarded(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            raise AssertionError(f"artifacts tried to write {file!r}")
        return real_open(file, mode, *a, **k)
    pdf = make_pdf(CHECK_TEXT.splitlines())
    png = make_png(200, 60)
    monkeypatch.setattr(builtins, "open", guarded)
    import tempfile
    monkeypatch.setattr(tempfile, "mkstemp", lambda *a, **k: (_ for _ in ()).throw(AssertionError("mkstemp")))
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", lambda *a, **k: (_ for _ in ()).throw(AssertionError("tmp")))
    A.analyze_upload(pdf, "c.pdf", "application/pdf", "Acme")
    res = A.analyze_upload(png, "c.png", "image/png")
    if A.HAS_OCR:
        assert res["meta"]["ocr"] == "ok"      # OCR ran without touching the disk
