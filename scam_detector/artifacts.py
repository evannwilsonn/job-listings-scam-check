"""Attachment analysis: offer-letter PDFs, check photos, QR codes.

Scams are moving into attachments. This module takes an uploaded file's bytes
(plus its filename and content type) and returns extracted text and findings
in the detector's usual dict format:

    {"rule_id", "severity" ("critical"|"warning"|"note"), "weight",
     "title", "why", "matched": [...]}

Public API
    analyze_upload(data, filename, content_type, claimed_company="") -> dict
    analyze_text(text, claimed_company="") -> dict

Design rules
- Nothing is written to disk. Everything happens on in-memory bytes.
- Optional dependencies (Pillow, pytesseract + tesseract binary, pyzbar,
  OpenCV) are detected at runtime. Without them the result degrades to a
  user-facing note ("Paste the text from the image") instead of failing.
  pypdf is the only library the PDF path needs.
- Full bank account numbers never leave this module: they are masked to the
  last 4 digits in findings, in the returned text and in meta.
"""
from __future__ import annotations

import importlib
import importlib.util
import io
import re
import shutil
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------- limits

MAX_BYTES = 8 * 1024 * 1024          # reject uploads over 8 MB
MAX_PDF_PAGES = 10                   # only read this many pages
MAX_TEXT = 20000                     # cap on returned / scanned text
MAX_PAGE_TEXT = 8000                 # cap per PDF page before joining
MAX_IMAGE_PIXELS = 40_000_000        # refuse to decode bigger images
MAX_IMAGE_SIDE = 12000               # refuse absurd single dimensions
OCR_MAX_SIDE = 3000                  # downscale before OCR
OCR_TIMEOUT_S = 20
EDIT_GAP = timedelta(days=30)        # "much later" for ModDate vs CreationDate
DATE_MISMATCH_GAP = timedelta(days=180)


# ------------------------------------------------- optional dependency flags
# Plain module-level booleans so callers/tests can monkeypatch them. Detection
# uses find_spec (cheap, nothing heavy is imported until actually needed).

def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


HAS_PIL = _has_module("PIL")
HAS_PYPDF = _has_module("pypdf")
HAS_OCR = bool(HAS_PIL and _has_module("pytesseract") and shutil.which("tesseract"))
HAS_PYZBAR = _has_module("pyzbar")
HAS_CV2 = _has_module("cv2")
HAS_QR = bool(HAS_PYZBAR or HAS_CV2)

NOTE_PASTE_TEXT = ("We couldn't read text from this image here. Paste the text from the image "
                   "(the letter, message or check wording) into the checker instead.")
NOTE_QR_UNAVAILABLE = ("QR codes in images can't be decoded here. If the image has a QR code, "
                       "don't scan it; ask the employer for a normal link you can check first.")


# ------------------------------------------------------------ small helpers

def _finding(rule_id: str, severity: str, weight: int, title: str, why: str,
             matched: Optional[List[str]] = None) -> dict:
    return {"rule_id": rule_id, "severity": severity, "weight": weight,
            "title": title, "why": why, "matched": list(matched or [])[:10]}


def mask_number(digits: str) -> str:
    """Mask all but the last 4 digits: '123456789012' -> '********9012'."""
    d = re.sub(r"\D", "", digits or "")
    if len(d) <= 4:
        return d
    return "*" * (len(d) - 4) + d[-4:]


_LONG_DIGITS = re.compile(r"\d(?:[ -]?\d){7,}")


def _mask_long_digit_runs(s: str) -> str:
    """Mask any run of 8+ digits (with optional single spaces/dashes), except a
    bare 9-digit number that passes the ABA checksum (routing numbers are public)."""
    def _m(m):
        raw = m.group(0)
        if re.fullmatch(r"\d{9}", raw) and aba_checksum_ok(raw):
            return raw
        return mask_number(raw)
    return _LONG_DIGITS.sub(_m, s)


def _scrub(obj):
    """Recursively mask long digit runs in every string of a meta structure."""
    if isinstance(obj, str):
        return _mask_long_digit_runs(obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_scrub(v) for v in obj]
    return obj


# ------------------------------------------------------------ ABA / checks

def aba_checksum_ok(rtn: str) -> bool:
    """ABA routing-number checksum: 3(d1+d4+d7) + 7(d2+d5+d8) + (d3+d6+d9) = 0 mod 10."""
    if not isinstance(rtn, str) or not re.fullmatch(r"\d{9}", rtn):
        return False
    d = [int(c) for c in rtn]
    if not any(d):
        return False
    total = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return total % 10 == 0


# MICR transit/on-us symbols as they show up in text or OCR output.
_MICR_SYM = "⑆⑇⑈⑉"
_ROUTING_CTX = re.compile(
    r"(?i)\b(?:routing|rtn|r/t|aba|transit)\b(?:\s*(?:no\.?|number|num|#|code))?[\s:#.\-]{0,6}(\d{9})\b")
_MICR_ROUTING = re.compile(
    r"(?:[" + _MICR_SYM + r"]|\|:|:\||\bT)\s?(\d{9})\s?(?:[" + _MICR_SYM + r"]|\|:|:\||T\b)")
_ACCOUNT_CTX = re.compile(
    r"(?i)\b(?:account|acct|a/c|acc)\b(?:\s*(?:no\.?|number|num|#))?[\s:#.\-]{0,6}(\d(?:[ -]?\d){4,16})\b")
# On-us field after the routing number in a MICR line: digits followed by ⑈ (or 'U'/'"' in OCR).
_MICR_ACCOUNT = re.compile(r"[" + _MICR_SYM + r"]\s?\d{9}\s?[" + _MICR_SYM + r"]\s?(\d[\d ]{3,19}\d)\s?[⑈⑉]")
_DOLLAR = re.compile(r"(?i)(?:\$\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*\.\d{2}\s*(?:usd|dollars)\b"
                     r"|\b(?:one|two|three|four|five|six|seven|eight|nine|ten|hundred|thousand)\b[\w\s-]{0,60}\bdollars\b)")
_PAY_ORDER = re.compile(r"(?i)\bpay\s+to\s+the\s+order\s+of\b|\bpay\s+to\s+the\s+order\b")
_CHECK_WORDS = re.compile(r"(?i)\b(?:void\s+after|memo|cashier'?s\s+check|certified\s+check|"
                          r"authorized\s+signature|check\s+(?:no|number|#))\b")
_BANK_NAME = re.compile(
    r"\b((?:[A-Z][A-Za-z&.'\-]*[ \t]+){0,5}(?:Bank|Bancorp|Credit[ \t]+Union|Savings(?:[ \t]+Bank)?|Trust[ \t]+Company)"
    r"(?:[ \t]+of[ \t]+[A-Z][A-Za-z]+(?:[ \t]+[A-Z][A-Za-z]+)?)?(?:,?[ \t]+N\.?A\.?)?)")
_PAYER_LABEL = re.compile(r"(?im)^\s*(?:payer|drawer|remitter|issued\s+by|from|purchaser)\s*[:\-]\s*(.{2,80})$")
_CORP_SUFFIX = re.compile(r"(?i)\b(?:inc|llc|l\.l\.c|corp|corporation|co|company|ltd|limited|lp|llp|plc|"
                          r"group|holdings|enterprises|solutions|services|partners)\b\.?")


def _find_routing(text: str) -> List[Tuple[str, bool, str]]:
    """Return [(routing, checksum_ok, source)] for context/MICR hits, de-duplicated."""
    out: Dict[str, Tuple[str, bool, str]] = {}
    for m in _ROUTING_CTX.finditer(text):
        r = m.group(1)
        out.setdefault(r, (r, aba_checksum_ok(r), "labeled"))
    for m in _MICR_ROUTING.finditer(text):
        r = m.group(1)
        if r not in out or out[r][2] != "micr":
            out[r] = (r, aba_checksum_ok(r), "micr")
    return list(out.values())


def _find_accounts(text: str) -> List[str]:
    """Raw account-number digit strings (never returned; only used to mask)."""
    found = []
    for rx in (_ACCOUNT_CTX, _MICR_ACCOUNT):
        for m in rx.finditer(text):
            d = re.sub(r"\D", "", m.group(1))
            if 4 <= len(d) <= 17 and d not in found:
                found.append(d)
    return found


def redact_accounts(text: str) -> str:
    """Mask detected account numbers (and any other 10+ digit run that isn't a
    valid routing number) in free text so the returned text is safe to store."""
    if not text:
        return text
    for acct in sorted(_find_accounts(text), key=len, reverse=True):
        if len(acct) <= 4:
            continue
        pat = r"(?<!\d)" + r"[ -]?".join(re.escape(c) for c in acct) + r"(?!\d)"
        text = re.sub(pat, mask_number(acct), text)

    def _long(m):
        d = re.sub(r"\D", "", m.group(0))
        if len(d) == 9 and aba_checksum_ok(d):
            return m.group(0)
        return mask_number(d)
    return re.sub(r"(?<!\d)\d{10,19}(?!\d)", _long, text)


def _norm_company(name: str) -> str:
    n = (name or "").lower()
    n = re.sub(r"[^a-z0-9& ]+", " ", n)
    n = _CORP_SUFFIX.sub(" ", n)
    n = re.sub(r"\b(?:the|of|and|&)\b", " ", n)
    return re.sub(r"\s+", " ", n).strip()


def _same_company(a: str, b: str) -> bool:
    na, nb = _norm_company(a), _norm_company(b)
    if not na or not nb:
        return False
    if na in nb or nb in na:
        return True
    ta = {t for t in na.split() if len(t) >= 3}
    tb = {t for t in nb.split() if len(t) >= 3}
    return bool(ta & tb)


def _looks_like_name_line(line: str) -> bool:
    s = line.strip()
    if not (3 <= len(s) <= 70):
        return False
    if sum(c.isalpha() for c in s) < 3 or sum(c.isdigit() for c in s) > 4:
        return False
    low = s.lower()
    skip = ("pay to", "order of", "date", "memo", "void", "dollars", "signature", "check",
            "routing", "account", "amount", "street", " st.", " ave", "suite", "p.o.", "po box",
            "dear", "congratulations", "sincerely", "regards")
    if any(k in low for k in skip):
        return False
    if _BANK_NAME.search(s):
        return False
    return True


def _extract_payers(text: str) -> Tuple[List[str], List[str]]:
    """Best-effort (payers, banks) on a check. Payer = the account holder that issues it."""
    payers: List[str] = []
    for m in _PAYER_LABEL.finditer(text):
        payers.append(m.group(1).strip())
    banks = []
    for m in _BANK_NAME.finditer(text):
        b = re.sub(r"\s+", " ", m.group(1)).strip()
        if b.lower() not in {x.lower() for x in banks}:
            banks.append(b)
    lines = text.splitlines()
    pay_idx = next((i for i, l in enumerate(lines) if _PAY_ORDER.search(l)), None)
    if pay_idx is not None and not payers:
        region = [l for l in lines[max(0, pay_idx - 12):pay_idx] if l.strip()]
        corp = [l.strip() for l in region if _CORP_SUFFIX.search(l) and _looks_like_name_line(l)]
        if corp:
            payers.append(corp[0])
        else:
            named = [l.strip() for l in region if _looks_like_name_line(l)]
            if named:
                payers.append(named[0])
    return payers[:3], banks[:3]


def analyze_text(text: str, claimed_company: str = "") -> dict:
    """Check/bank-detail analysis on any extracted text (PDF, OCR or pasted).

    Returns {"findings": [...], "routing_numbers": [...], "accounts": [masked],
             "payers": [...], "banks": [...], "is_check": bool}.
    """
    text = (text or "")[:MAX_TEXT]
    findings: List[dict] = []
    routing = _find_routing(text)
    valid_rtns = [r for r, ok, _ in routing if ok]
    accounts_masked = [mask_number(a) for a in _find_accounts(text)]
    has_pay_order = bool(_PAY_ORDER.search(text))
    dollars = [m.group(0).strip() for m in _DOLLAR.finditer(text)][:5]
    micr_valid = any(ok and src == "micr" for _, ok, src in routing)
    check_words = bool(_CHECK_WORDS.search(text))

    is_check = (has_pay_order and bool(valid_rtns or dollars)) or \
               (micr_valid and bool(dollars) and check_words)
    payers, banks = _extract_payers(text) if (has_pay_order or micr_valid) else ([], [])

    evidence = []
    if has_pay_order:
        evidence.append("pay to the order of")
    evidence += [f"routing {r} (valid ABA checksum)" for r in valid_rtns]
    evidence += [f"account {a}" for a in accounts_masked]
    evidence += dollars[:2]

    if is_check:
        findings.append(_finding(
            "check_image", "critical", 30,
            "This looks like a check sent to you to deposit",
            "The text reads like a check made out to you (payee line plus a routing number or dollar "
            "amount). Real employers don't mail or email checks before you start, and they never ask "
            "you to deposit one and then buy equipment, pay a 'vendor' or send part of it back. That is "
            "the fake-check scam: the check bounces days later and you owe the bank the full amount. "
            "A valid routing number does NOT mean the check is real; scammers print real banks' routing "
            "numbers on counterfeit checks. Don't deposit it.",
            evidence))

    if claimed_company and payers and (is_check or has_pay_order or micr_valid):
        mismatched = [p for p in payers if not _same_company(p, claimed_company)]
        if mismatched and not any(_same_company(p, claimed_company) for p in payers):
            findings.append(_finding(
                "check_payer_mismatch", "warning", 15,
                "The check is from a different company than the one hiring you",
                f"The job is with {claimed_company!s}, but the check appears to be issued by "
                f"{mismatched[0]!s}. A check drawn on some other business's account is the classic "
                "fake-check tell: scammers use stolen or counterfeit checks from unrelated companies. "
                "A valid routing number doesn't make it genuine.",
                [f"payer: {p}" for p in mismatched] + [f"bank: {b}" for b in banks]
                + [f"claimed employer: {claimed_company}"]))

    return {
        "findings": findings,
        "routing_numbers": [{"routing": r, "checksum_ok": ok, "source": src} for r, ok, src in routing],
        "accounts": accounts_masked,
        "payers": payers,
        "banks": banks,
        "is_check": is_check,
    }


# ------------------------------------------------------------ PDF analysis

# Large, frequently impersonated employers. An offer "from" one of these made
# in a consumer tool is a weak signal only.
LARGE_COMPANIES = (
    "Amazon", "Google", "Alphabet", "Microsoft", "Apple Inc", "Meta Platforms", "Facebook", "Netflix",
    "Walmart", "Target Corporation", "Costco", "Home Depot", "Lowe's", "CVS Health", "Walgreens", "Publix",
    "Deloitte", "PwC", "PricewaterhouseCoopers", "Ernst & Young", "KPMG", "Accenture", "IBM", "Oracle",
    "Salesforce", "Adobe", "Intel", "Cisco", "NVIDIA", "Nvidia", "Tesla", "JPMorgan", "JP Morgan",
    "Bank of America", "Wells Fargo", "Citigroup", "Goldman Sachs", "Morgan Stanley", "Fidelity",
    "Vanguard", "Pfizer", "Johnson & Johnson", "UnitedHealth", "Humana", "Lockheed Martin", "Raytheon",
    "Boeing", "Disney", "Comcast", "AT&T", "Verizon", "T-Mobile", "FedEx", "UPS", "Coca-Cola", "PepsiCo",
    "Procter & Gamble", "Nike", "Starbucks", "McDonald's", "Uber", "Airbnb", "PayPal", "Mastercard",
    "American Express", "ExxonMobil", "Chevron", "General Electric", "General Motors", "Ford Motor",
)
_CONSUMER_TOOL = re.compile(
    r"(?i)\b(microsoft(?:®|\(r\))?\s*(?:office\s*)?word|word\s+for\s+(?:microsoft\s*365|office\s*365|mac)|"
    r"canva|google\s+docs|libreoffice\s+writer|wps\s+(?:office|writer)|smallpdf|ilovepdf|"
    r"pdf24|sejda|online2pdf|pdfcandy|sodapdf|soda\s+pdf|convertio|zamzar|cloudconvert|"
    r"freepdfconvert|pdf2go|hipdf|docfly|pdffiller|dochub|pdfescape|lightpdf|wondershare|"
    r"microsoft:\s*print\s+to\s+pdf|microsoft\s+print\s+to\s+pdf)\b")
_OFFER_WORDS = re.compile(r"(?i)\b(offer\s+(?:of\s+employment|letter)|pleased\s+to\s+offer|job\s+offer|"
                          r"start\s+date|annual\s+salary|compensation|position\s+of|onboarding|"
                          r"employment\s+agreement|welcome\s+to\s+the\s+team)\b")

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
_TEXT_DATE_PATTERNS = [
    # January 5, 2026 / Jan. 5 2026
    (re.compile(r"(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(20\d{2}|19\d{2})\b"),
     lambda m: (int(m.group(3)), _MONTHS[m.group(1).lower()[:3]], int(m.group(2)))),
    # 5 January 2026
    (re.compile(r"(?i)\b(\d{1,2})(?:st|nd|rd|th)?\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?,?\s+(20\d{2}|19\d{2})\b"),
     lambda m: (int(m.group(3)), _MONTHS[m.group(2).lower()[:3]], int(m.group(1)))),
    # 2026-01-05
    (re.compile(r"\b(20\d{2}|19\d{2})-(\d{1,2})-(\d{1,2})\b"),
     lambda m: (int(m.group(1)), int(m.group(2)), int(m.group(3)))),
    # 01/05/2026 (US order)
    (re.compile(r"\b(\d{1,2})/(\d{1,2})/(20\d{2}|19\d{2})\b"),
     lambda m: (int(m.group(3)), int(m.group(1)), int(m.group(2)))),
]


def _text_dates(text: str, limit: int = 20) -> List[Tuple[int, datetime, str]]:
    """Dates found in text as [(position, datetime, raw)] sorted by position."""
    out = []
    for rx, conv in _TEXT_DATE_PATTERNS:
        for m in rx.finditer(text[:MAX_TEXT]):
            try:
                y, mo, d = conv(m)
                out.append((m.start(), datetime(y, mo, d, tzinfo=timezone.utc), m.group(0)))
            except (ValueError, KeyError):
                continue
    out.sort(key=lambda t: t[0])
    return out[:limit]


_PDF_DATE = re.compile(r"(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?\s*([Zz+\-])?\s*(\d{2})?'?(\d{2})?")


def parse_pdf_date(value) -> Optional[datetime]:
    """Parse a PDF date string ("D:20240101120000Z", "D:20240101120000-05'00'") to aware UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if s.startswith("D:"):
        s = s[2:]
    m = _PDF_DATE.match(s)
    if not m:
        return None
    try:
        y = int(m.group(1))
        mo = int(m.group(2) or 1)
        d = int(m.group(3) or 1)
        hh, mi, ss = int(m.group(4) or 0), int(m.group(5) or 0), int(m.group(6) or 0)
        dt = datetime(y, mo, d, hh, mi, min(ss, 59))
        sign = m.group(7)
        off = timedelta(0)
        if sign in ("+", "-") and m.group(8):
            off = timedelta(hours=int(m.group(8)), minutes=int(m.group(9) or 0))
            if sign == "-":
                off = -off
        return (dt - off).replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def _meta_str(md, key: str) -> str:
    try:
        v = md.get(key) if md is not None else None
    except Exception:
        return ""
    if v is None:
        return ""
    try:
        return str(v)[:200]
    except Exception:
        return ""


def _claims_large_company(text: str, claimed_company: str) -> Optional[str]:
    """Name of a large employer the document claims to be from, if any.
    claimed_company matches case-insensitively; the text match is case-sensitive
    to avoid ordinary words ("target", "apple") triggering it."""
    low_claim = (claimed_company or "").lower()
    head = (text or "")[:4000]
    for name in LARGE_COMPANIES:
        pat = r"(?<![A-Za-z])" + re.escape(name) + r"(?![A-Za-z])"
        if low_claim and re.search(pat, claimed_company, re.I):
            return claimed_company
    for name in LARGE_COMPANIES:
        if re.search(r"(?<![A-Za-z])" + re.escape(name) + r"(?![A-Za-z])", head):
            return name
    return None


def _pdf_findings(meta: dict, text: str, claimed_company: str, now: datetime) -> List[dict]:
    findings = []
    created = parse_pdf_date(meta.get("creation_date_raw"))
    modified = parse_pdf_date(meta.get("mod_date_raw"))

    if created and modified and modified - created > EDIT_GAP:
        gap = (modified - created).days
        findings.append(_finding(
            "doc_edited_after_creation", "note", 3,
            "The document was edited long after it was created",
            f"The PDF's metadata says it was created on {created.date()} and last modified {gap} days "
            f"later, on {modified.date()}. That can be innocent (a reused template), but fake offer "
            "letters are often made by editing an old real document. Weak signal on its own.",
            [f"CreationDate {created.date()}", f"ModDate {modified.date()}"]))

    tool = " / ".join(x for x in (meta.get("producer"), meta.get("creator")) if x)
    tm = _CONSUMER_TOOL.search(tool) if tool else None
    big = _claims_large_company(text, claimed_company) if tm else None
    if tm and big and _OFFER_WORDS.search(text or ""):
        findings.append(_finding(
            "doc_consumer_tool", "note", 2,
            "Offer letter from a large company made with a consumer tool",
            f"The letter presents itself as coming from {big}, but the PDF was produced with "
            f"{tm.group(0).strip()}. Large employers usually send offers through an HR system "
            "(Workday, Greenhouse, DocuSign and the like). Plenty of real letters are made in Word, "
            "so treat this as a weak hint and verify the offer through the company's official site.",
            [f"producer/creator: {tool[:120]}", f"claims to be: {big}"]))

    dates = [d for d in (created, modified) if d]
    future = [d for d in dates if d > now + timedelta(days=2)]
    tdates = _text_dates(text or "")
    if future:
        findings.append(_finding(
            "doc_future_or_mismatched_date", "note", 2,
            "The document's dates don't add up",
            f"The PDF metadata carries a date in the future ({future[0].date()}). Real documents "
            "can't be created after today, so the file was likely generated by a tool with a wrong "
            "clock or its metadata was tampered with.",
            [f"metadata date {d.date()}" for d in future]))
    elif created and tdates:
        _, letter_date, raw = tdates[0]           # the first date is usually the letter date
        if abs(letter_date - created) > DATE_MISMATCH_GAP:
            gap = abs((letter_date - created).days)
            order = "before" if letter_date < created else "after"
            findings.append(_finding(
                "doc_future_or_mismatched_date", "note", 2,
                "The document's dates don't add up",
                f"The letter is dated {raw}, {gap} days {order} the PDF file itself was created "
                f"({created.date()}). A mismatch like this can mean the letter was back-dated, "
                "or copied and edited from an older document.",
                [f"text date: {raw}", f"CreationDate {created.date()}"]))
    return findings


def _analyze_pdf(data: bytes, claimed_company: str, result: dict, now: datetime) -> None:
    meta = result["meta"]
    pdf_meta: dict = {"encrypted": False, "pages": None}
    meta["pdf"] = pdf_meta
    if not HAS_PYPDF:
        result["notes"].append("PDF reading isn't available right now. Paste the text of the document instead.")
        return
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data), strict=False)
    except Exception:
        pdf_meta["error"] = "unreadable"
        result["notes"].append("This PDF looks damaged or isn't a real PDF, so we couldn't read it. "
                               "Paste the text of the document instead.")
        return

    try:
        if reader.is_encrypted:
            pdf_meta["encrypted"] = True
            ok = False
            try:
                ok = bool(reader.decrypt(""))
            except Exception:
                ok = False
            if not ok:
                result["notes"].append("This PDF is password-protected, so we couldn't read it. Paste the "
                                       "text instead. Be careful with 'secure' documents that make you "
                                       "enter details to open them.")
                return
    except Exception:
        pdf_meta["error"] = "unreadable"
        result["notes"].append("We couldn't open this PDF. Paste the text of the document instead.")
        return

    try:
        md = reader.metadata
    except Exception:
        md = None
    pdf_meta.update({
        "producer": _meta_str(md, "/Producer"),
        "creator": _meta_str(md, "/Creator"),
        "author": _meta_str(md, "/Author"),
        "creation_date_raw": _meta_str(md, "/CreationDate"),
        "mod_date_raw": _meta_str(md, "/ModDate"),
    })
    for k_raw, k in (("creation_date_raw", "creation_date"), ("mod_date_raw", "mod_date")):
        dt = parse_pdf_date(pdf_meta[k_raw])
        pdf_meta[k] = dt.isoformat() if dt else ""

    parts: List[str] = []
    total = 0
    try:
        n_pages = len(reader.pages)
    except Exception:
        n_pages = 0
        pdf_meta["error"] = "no_pages"
    pdf_meta["pages"] = n_pages
    for i in range(min(n_pages, MAX_PDF_PAGES)):
        if total >= MAX_TEXT:
            break
        try:
            t = reader.pages[i].extract_text() or ""
        except Exception:
            continue
        t = t[:MAX_PAGE_TEXT]
        parts.append(t)
        total += len(t)
    if n_pages > MAX_PDF_PAGES:
        result["notes"].append(f"Only the first {MAX_PDF_PAGES} pages were checked.")
    text = "\n".join(parts)[:MAX_TEXT]
    if not text.strip() and n_pages:
        result["notes"].append("This PDF has no selectable text (it may be a scanned image). "
                               "Paste the text of the document instead.")
    result["text"] = text
    result["findings"].extend(_pdf_findings(pdf_meta, text, claimed_company, now))
    pdf_meta.pop("creation_date_raw", None)   # raw strings replaced by the ISO dates above
    pdf_meta.pop("mod_date_raw", None)


# ------------------------------------------------------------ image analysis

def image_dimensions(data: bytes) -> Optional[Tuple[int, int]]:
    """Read (width, height) from PNG/JPEG/WebP headers without decoding pixels."""
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
            return struct.unpack(">II", data[16:24])
        if data[:3] == b"\xff\xd8\xff":
            i, n = 2, len(data)
            while i + 9 < n:
                if data[i] != 0xFF:
                    i += 1
                    continue
                marker = data[i + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return w, h
                i += 2 + seg_len
            return None
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            chunk = data[12:16]
            if chunk == b"VP8X" and len(data) >= 30:
                w = 1 + int.from_bytes(data[24:27], "little")
                h = 1 + int.from_bytes(data[27:30], "little")
                return w, h
            if chunk == b"VP8 " and len(data) >= 30:
                w, h = struct.unpack("<HH", data[26:30])
                return w & 0x3FFF, h & 0x3FFF
            if chunk == b"VP8L" and len(data) >= 25:
                b = data[21:25]
                w = 1 + (((b[1] & 0x3F) << 8) | b[0])
                h = 1 + (((b[3] & 0x0F) << 10) | (b[2] << 2) | ((b[1] & 0xC0) >> 6))
                return w, h
    except (struct.error, IndexError):
        return None
    return None


def _open_pil(data: bytes, result: dict):
    """Open with Pillow (if present) after enforcing the pixel cap. None on failure."""
    if not HAS_PIL:
        return None
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))           # lazy: reads header only
        w, h = img.size
        if w * h > MAX_IMAGE_PIXELS or max(w, h) > MAX_IMAGE_SIDE:
            result["meta"]["image"]["rejected"] = "too_many_pixels"
            return None
        img.load()
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        return img
    except Exception:
        return None


def _ocr(img) -> Optional[str]:
    """OCR via the tesseract binary, piping PNG bytes through stdin/stdout.

    pytesseract's own helpers write the image to a temp file; we only use it to
    locate the configured binary, so nothing touches the disk."""
    try:
        pytesseract = importlib.import_module("pytesseract")
        cmd = getattr(getattr(pytesseract, "pytesseract", None), "tesseract_cmd", None) or "tesseract"
        work = img
        if max(img.size) > OCR_MAX_SIDE:
            scale = OCR_MAX_SIDE / max(img.size)
            work = img.resize((max(1, int(img.size[0] * scale)), max(1, int(img.size[1] * scale))))
        buf = io.BytesIO()
        work.save(buf, "PNG")
        proc = subprocess.run([cmd, "stdin", "stdout", "--psm", "3"], input=buf.getvalue(),
                              capture_output=True, timeout=OCR_TIMEOUT_S, check=False)
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace")[:MAX_TEXT]
    except Exception:
        return None


def _decode_qr(data: bytes, img) -> Optional[List[str]]:
    """Decoded QR payloads, or None if no decoder could run."""
    if HAS_PYZBAR and img is not None:
        try:
            pyzbar = importlib.import_module("pyzbar.pyzbar")
            out = []
            for sym in pyzbar.decode(img):
                if getattr(sym, "type", "QRCODE") in ("QRCODE", "QR"):
                    out.append(sym.data.decode("utf-8", "replace"))
            return out
        except Exception:
            pass
    if HAS_CV2:
        try:
            cv2 = importlib.import_module("cv2")
            np = importlib.import_module("numpy")
            if img is not None:
                arr = np.array(img.convert("RGB"))[:, :, ::-1].copy()
            else:
                arr = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
            if arr is None:
                return None
            det = cv2.QRCodeDetector()
            out: List[str] = []
            try:
                ok, decoded, _, _ = det.detectAndDecodeMulti(arr)
                if ok:
                    out = [d for d in decoded if d]
            except Exception:
                pass
            if not out:
                val, _, _ = det.detectAndDecode(arr)
                if val:
                    out = [val]
            return out
        except Exception:
            return None
    return None


def _analyze_image(data: bytes, result: dict) -> None:
    meta = result["meta"]
    img_meta: dict = {}
    meta["image"] = img_meta
    dims = image_dimensions(data)
    if dims:
        img_meta["width"], img_meta["height"] = dims
        if dims[0] * dims[1] > MAX_IMAGE_PIXELS or max(dims) > MAX_IMAGE_SIDE:
            img_meta["rejected"] = "too_many_pixels"
            meta["ocr"] = "skipped"
            meta["qr"] = "skipped"
            result["notes"].append("This image is too large to check. Crop it or paste the text from the image.")
            return

    img = _open_pil(data, result)
    if img_meta.get("rejected"):
        meta["ocr"] = meta["qr"] = "skipped"
        result["notes"].append("This image is too large to check. Crop it or paste the text from the image.")
        return
    if img is not None:
        img_meta["width"], img_meta["height"] = img.size

    # OCR
    if not HAS_OCR:
        meta["ocr"] = "unavailable"
        result["notes"].append(NOTE_PASTE_TEXT)
    elif img is None:
        meta["ocr"] = "failed"
        result["notes"].append("We couldn't open this image (HEIC photos often need converting). " + NOTE_PASTE_TEXT)
    else:
        text = _ocr(img)
        if text is None:
            meta["ocr"] = "failed"
            result["notes"].append(NOTE_PASTE_TEXT)
        else:
            meta["ocr"] = "ok"
            result["text"] = text
            if not text.strip():
                result["notes"].append("No readable text was found in the image. " + NOTE_PASTE_TEXT)

    # QR
    payloads = _decode_qr(data, img) if HAS_QR else None
    if payloads is None:
        meta["qr"] = "unavailable"
        if not HAS_QR:
            result["notes"].append(NOTE_QR_UNAVAILABLE)
        return
    meta["qr"] = "ok"
    _add_qr_payloads(payloads, result)


def _add_qr_payloads(payloads: List[str], result: dict) -> None:
    clean = [_mask_long_digit_runs(p[:2000]) for p in payloads][:10]
    result["meta"]["qr_payloads"] = clean
    for p in clean:
        s = p.strip()
        if re.match(r"(?i)^(?:https?://|www\.)", s):
            url = s if s.lower().startswith("http") else "http://" + s
            host = (urlparse(url).hostname or "").lower()
            if url not in result["urls"]:
                result["urls"].append(url)
            result["findings"].append(_finding(
                "qr_link", "note", 1,
                "The image contains a QR code link",
                f"A QR code in this image points to {host or 'a web address'}. QR codes hide where a link "
                "goes, which is why scammers use them for fake 'onboarding' and payment pages. We list the "
                "link so it can be checked; don't scan it with your phone until it has been.",
                [host or url]))


# ------------------------------------------------------------ entry point

_IMAGE_TYPES = ("image/png", "image/jpeg", "image/jpg", "image/pjpeg", "image/webp",
                "image/heic", "image/heif")
_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".webp", ".heic", ".heif", ".jfif")


def _sniff_kind(data: bytes, filename: str, content_type: str) -> str:
    head = data[:1024]
    if b"%PDF-" in head:
        return "pdf"
    if (data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff"
            or (data[:4] == b"RIFF" and data[8:12] == b"WEBP")
            or (data[4:8] == b"ftyp" and data[8:12] in (b"heic", b"heix", b"hevc", b"heim", b"heis",
                                                         b"mif1", b"msf1", b"avif"))):
        return "image"
    ct = (content_type or "").split(";")[0].strip().lower()
    fn = (filename or "").lower()
    if ct == "application/pdf" or fn.endswith(".pdf"):
        return "pdf"          # claims PDF but no header: let the PDF path report it as malformed
    if ct in _IMAGE_TYPES or fn.endswith(_IMAGE_EXT):
        return "image"
    return "unsupported"


def analyze_upload(data: bytes, filename: str, content_type: str, claimed_company: str = "") -> dict:
    """Analyze an uploaded attachment held in memory.

    Returns {"kind": "pdf"|"image"|"unsupported", "text": str, "findings": [...],
             "meta": {...}, "notes": [str], "urls": [str]}.
    Never raises on bad input; never writes to disk.
    """
    data = data if isinstance(data, (bytes, bytearray)) else b""
    data = bytes(data)
    result = {"kind": "unsupported", "text": "", "findings": [], "notes": [], "urls": [],
              "meta": {"filename": (filename or "")[:200], "content_type": (content_type or "")[:100],
                       "size": len(data)}}
    if len(data) > MAX_BYTES:
        result["meta"]["rejected"] = "too_large"
        result["notes"].append(f"This file is over {MAX_BYTES // (1024 * 1024)} MB, so it wasn't checked. "
                               "Paste the text from it instead.")
        return _finish(result)
    if not data:
        result["notes"].append("The file is empty.")
        return _finish(result)

    kind = _sniff_kind(data, filename, content_type)
    result["kind"] = kind
    now = datetime.now(timezone.utc)
    try:
        if kind == "pdf":
            _analyze_pdf(data, claimed_company, result, now)
        elif kind == "image":
            _analyze_image(data, result)
        else:
            result["notes"].append("This file type can't be checked. Upload a PDF or an image, "
                                   "or paste the text instead.")
    except Exception:  # defensive: an attachment must never break the checker
        result["notes"].append("Something went wrong reading this file. Paste the text from it instead.")

    if result["text"]:
        ta = analyze_text(result["text"], claimed_company)
        result["findings"].extend(ta["findings"])
        result["meta"]["check"] = {k: ta[k] for k in ("routing_numbers", "accounts", "payers", "banks", "is_check")}
        for m in re.finditer(r"(?i)\bhttps?://[^\s<>\"')\]]+", result["text"]):
            u = m.group(0).rstrip(".,;:")
            if u not in result["urls"] and len(result["urls"]) < 20:
                result["urls"].append(u)
    return _finish(result)


def _finish(result: dict) -> dict:
    result["text"] = redact_accounts((result.get("text") or "")[:MAX_TEXT])
    for f in result["findings"]:
        f["matched"] = [_mask_long_digit_runs(str(x)) for x in f.get("matched", [])]
    result["meta"] = _scrub(result["meta"])
    return result


__all__ = ["analyze_upload", "analyze_text", "aba_checksum_ok", "mask_number", "redact_accounts",
           "parse_pdf_date", "image_dimensions", "MAX_BYTES"]
