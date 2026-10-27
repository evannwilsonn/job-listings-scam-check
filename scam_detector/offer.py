"""
Checks for a job offer letter (plan item 34): the document a student gets after a fake "interview", usually as a
PDF, that makes the scam feel official right before the check or the equipment purchase.

    pdf_text(data: bytes) -> str                    # text layer, or OCR of the first pages when it's a scan
    offer_findings(text, company="") -> [finding]   # added on top of the normal /analyze checks

The text rules already catch what a letter asks for (fees, checks, equipment, bank details). These look at what a
real offer letter has and a fake one usually doesn't:

  offer_freemail_contact   warning 18  the HR or onboarding contact in the letter is a free email address
  offer_company_mismatch   warning 16  the letter's email addresses or links belong to a different company
  offer_missing_basics     note 10     it reads as an offer but has few of: start date, pay, a named signer with a
                                       title, a street address, the usual conditions (background check, I-9, at-will)

Weights are modest on purpose: small employers write thin letters, so these add up with other signs. Pure stdlib
apart from pypdf for PDFs.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List

from .identity import HIRING_PLATFORMS, _relates, _finding
from .intel.domains import registrable_domain
from .rules import FREE_MAIL

MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PAGES = 6

OFFER_CUE = re.compile(
    r"\b(?:offer\s+letter|offer\s+of\s+employment|employment\s+(?:offer|agreement|contract)|"
    r"(?:pleased|happy|delighted|excited)\s+to\s+(?:offer|extend|inform)|we\s+are\s+offering\s+you|"
    r"accept(?:ance)?\s+of\s+(?:this|the)\s+offer|you\s+have\s+been\s+(?:selected|hired|offered))\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.I)
_URL = re.compile(r"\bhttps?://([a-z0-9.-]+\.[a-z]{2,})", re.I)
_COMPANY = re.compile(
    r"\b(?:position|role|job|employment|career|internship|team|offer)\b[^.\n]{0,80}?\s(?:at|with)\s+"
    r"([A-Z][\w&.'-]*(?:\s+(?:&\s+)?[A-Z][\w&.'-]*){0,3})")

BASICS = {
    "start date": re.compile(r"\bstart(?:ing)?\s+date\b|\bfirst\s+day\b|\b(?:begin|start|commence)\w*\s+"
                             r"(?:work\w*\s+|employment\s+)?on\b", re.I),
    "pay": re.compile(r"\$\s?\d[\d,]*(?:\.\d{2})?\s*(?:/|per|an?|each)?\s*(?:hour|hr|year|yr|annum|annually|week|"
                      r"month|bi-?weekly)|\b(?:annual|base)\s+salary\b|\bsalary\s+of\b", re.I),
    "signer": re.compile(r"\n\s*[A-Z][a-z'.-]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z'-]+\s*[,\n|]\s*[^\n]{0,40}"
                         r"\b(?:manager|director|recruiter|officer|president|partner|lead|specialist|coordinator|"
                         r"vp|head|generalist|business\s+partner|founder|owner)\b", re.I),
    "address": re.compile(r"\b\d{2,6}\s+(?:[NSEW]\.?\s+)?[A-Z][\w.]*(?:\s+[A-Z][\w.]*){0,4}\s+(?:St|Street|Ave|"
                          r"Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Way|Lane|Ln|Pkwy|Parkway|Ct|Court|Pl|Place|Hwy|"
                          r"Highway|Plaza|Circle|Cir|Square|Sq)\b\.?"),
    "conditions": re.compile(r"\bbackground\s+(?:check|screen)|\bdrug\s+(?:test|screen)|\bI-9\b|\bemployment\s+"
                             r"eligibility|\bat[\s-]will\b|\bcontingent\s+(?:up)?on\b|\bconditional\s+(?:up)?on\b",
                             re.I),
}


def pdf_text(data: bytes) -> str:
    """The PDF's text, or OCR of its first pages when it has none (a scanned or image-only letter).

    Raises ValueError (not a PDF, too big, unreadable) or ocr.OcrError (a scan that can't be read here)."""
    if not data.startswith(b"%PDF-"):
        raise ValueError("That isn't a PDF file.")
    if len(data) > MAX_PDF_BYTES:
        raise ValueError("That PDF is over 5 MB.")
    from pypdf import PdfReader
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise ValueError("That PDF is password-protected. Take a screenshot of the letter instead.")
        text = "\n".join((p.extract_text() or "") for p in reader.pages[:MAX_PAGES])
    except ValueError:
        raise
    except Exception as exc:                     # noqa: BLE001 - malformed PDFs raise many kinds of errors
        raise ValueError("That PDF couldn't be read. Take a screenshot of the letter instead.") from exc
    if len(text.strip()) >= 40:
        return text[:20000]
    return _ocr_pdf(data)


def _ocr_pdf(data: bytes) -> str:
    from .ocr import OcrUnavailable, image_text
    exe = shutil.which("pdftoppm")
    if not exe:
        raise OcrUnavailable("That PDF is a scanned image. Take a screenshot of the letter instead.")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "in.pdf"
        src.write_bytes(data)
        try:
            subprocess.run([exe, "-png", "-r", "150", "-f", "1", "-l", "3", str(src), str(Path(tmp) / "p")],
                           capture_output=True, timeout=30, check=True)
        except (subprocess.SubprocessError, OSError) as exc:
            raise ValueError("That PDF couldn't be read. Take a screenshot of the letter instead.") from exc
        pages = sorted(Path(tmp).glob("p*.png"))
        return "\n".join(image_text(p.read_bytes()) for p in pages)[:20000]


def is_offer(text: str) -> bool:
    return bool(OFFER_CUE.search(text or ""))


def _claimed_company(text: str, company: str) -> str:
    if company:
        return company
    m = _COMPANY.search(text)
    return m.group(1) if m else ""


def offer_findings(text: str, company: str = "") -> List[dict]:
    """Findings about the letter itself. Empty unless the text reads as an offer. Never raises."""
    text = text or ""
    if not is_offer(text):
        return []
    out = []
    emails = [(m.group(0), m.group(1).lower()) for m in _EMAIL.finditer(text)]
    free = [addr for addr, dom in emails if registrable_domain(dom) in FREE_MAIL]
    if free:
        out.append(_finding(
            "offer_freemail_contact", "warning", 18, "The offer's contact is a personal email address",
            "Companies send offer letters from their own email domain, or through a hiring system. A letter that "
            "tells you to reply to a Gmail, Outlook or Yahoo address didn't come from the company's HR team. Look "
            "the company up yourself and ask its HR team whether this offer is real.", free))

    name = _claimed_company(text, company)
    domains = {registrable_domain(d) for _, d in emails} | {registrable_domain(m.group(1)) for m in _URL.finditer(text)}
    foreign = sorted(d for d in domains
                     if d and d not in FREE_MAIL and d not in HIRING_PLATFORMS and not _relates(d, name))
    if name and foreign:
        out.append(_finding(
            "offer_company_mismatch", "warning", 16, f"The letter's addresses don't belong to {name[:60]}",
            f"The letter is for a job with {name[:60]}, but its email addresses or links go to {', '.join(foreign[:3])}. "
            "Scammers copy a real company's name and logo onto a letter and give their own contact details. "
            "Find the company's website yourself and check that the domain matches.", foreign))

    have = [k for k, rx in BASICS.items() if rx.search(text)]
    missing = [k for k in BASICS if k not in have]
    if len(missing) >= 3:
        out.append(_finding(
            "offer_missing_basics", "note", 10, "The offer is missing what real offer letters include",
            "Real offer letters usually state a start date and the pay, are signed by a named person with a job "
            "title, give the company's address, and mention conditions like a background check or the I-9 form. "
            f"This one is missing: {', '.join(missing)}. On its own that can just be a small employer, but check "
            "the rest of the letter carefully.", missing))
    return out
