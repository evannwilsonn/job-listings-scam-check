"""
Anonymous one-tap reports from students.

    make_report(text, sender="", school="", outcome="", now=None) -> dict    the record to queue
    append_report(record, path) -> None                                     one JSON line, never raises on read errors
    ftc_summary(record) -> str                                               text to paste into reportfraud.ftc.gov

A report is a lead for a reviewer, never a verdict: nothing in it reaches the cross-school network or training until a
person confirms it. What is kept, and what isn't:

  * no name, no IP address, no device data, no account;
  * the message text with every email address, phone number and wallet replaced by a placeholder;
  * the identifiers themselves, separately, so a reviewer can confirm them: email addresses and phone numbers as
    salted SHA-256 hashes (a reviewer can match a known one, not read them), domains and wallet addresses in the clear
    (a domain is not personal data and is what takedown requests need; a scam wallet is the scammer's);
  * what the student says happened (outcome), from a fixed list.

The FTC form wants the details in plain text, so ftc_summary() is built on the student's device from what they pasted
and is never stored.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Optional

from .intel.domains import registrable_domain
from .recovery import HAPPENED
from .rules import FREE_MAIL

OUTCOMES = ("not_replied",) + tuple(HAPPENED)
MAX_TEXT = 8000

_EMAIL = re.compile(r"[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)
_PHONE = re.compile(r"(?<![\d\w])(?:\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
_WALLET = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|"
                     r"T[1-9A-HJ-NP-Za-km-z]{33})\b")
_URL_HOST = re.compile(r"\bhttps?://(?:[^@/\s]*@)?([a-z0-9.-]+\.[a-z]{2,})", re.I)


def _salt() -> bytes:
    return os.environ.get("REPORT_HASH_SALT", "lurecheck-dev-salt").encode()


def hash_identifier(value: str) -> str:
    """Salted SHA-256 of a normalised email or phone number."""
    v = value.strip().lower()
    if not _EMAIL.fullmatch(v):
        v = re.sub(r"\D", "", v)[-10:]
    return hashlib.sha256(_salt() + v.encode()).hexdigest()


def _indicators(text: str, sender: str) -> dict:
    blob = f"{text}\n{sender}"
    emails = sorted({m.group(0).lower() for m in _EMAIL.finditer(blob)})
    phones = sorted({re.sub(r"\D", "", m.group(0))[-10:] for m in _PHONE.finditer(blob)})
    wallets = sorted({m.group(0) for m in _WALLET.finditer(blob)})
    domains = {registrable_domain(m.group(1).lower()) for m in _EMAIL.finditer(blob)}
    domains |= {registrable_domain(m.group(1).lower()) for m in _URL_HOST.finditer(blob)}
    domains = sorted(d for d in domains if d and d not in FREE_MAIL)
    return {"email_hashes": [hash_identifier(e) for e in emails],
            "free_mail_senders": sorted({e.split("@")[1] for e in emails if e.split("@")[1] in FREE_MAIL}),
            "phone_hashes": [hash_identifier(p) for p in phones],
            "domains": domains, "wallets": wallets}


def mask(text: str) -> str:
    text = _WALLET.sub("[wallet]", text or "")
    text = _EMAIL.sub("[email]", text)
    return _PHONE.sub("[phone]", text)


def make_report(text: str, sender: str = "", school: str = "", outcome: str = "",
                now: Optional[dt.datetime] = None) -> dict:
    text = (text or "")[:MAX_TEXT]
    now = now or dt.datetime.now(dt.timezone.utc)
    return {
        "received": now.replace(microsecond=0).isoformat(),
        "school": re.sub(r"[^a-z0-9_-]", "", (school or "").lower())[:40],
        "outcome": outcome if outcome in OUTCOMES else "",
        "text_masked": mask(text),
        "indicators": _indicators(text, sender),
        "status": "reported",                    # a reviewer moves it to confirmed or dismissed
    }


def append_report(record: dict, path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")




def ftc_summary(text: str, sender: str = "", outcome: str = "") -> str:
    """Plain-text summary for the student to paste into reportfraud.ftc.gov. Built from what they pasted; not stored."""
    lines = ["Job scam: someone offered me a job that I believe is fake."]
    if sender:
        lines.append(f"It came from: {sender.strip()[:200]}")
    if outcome in OUTCOMES and outcome != "not_replied":
        lines.append("What happened: " + outcome.replace("_", " ") + ".")
    lines.append("Their message:")
    lines.append((text or "").strip()[:3000])
    return "\n".join(lines)
