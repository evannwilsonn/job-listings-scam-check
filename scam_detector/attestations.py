"""
Employer attestations: what a real employer told us about how it recruits.

    company_key(name) -> str
    attestation_findings(company, sender="", text="", findings=(), channel="", store=None) -> (attestation, [finding])

A message that names an attested employer is checked against what the employer said:

  attested_domain_mismatch   warning 26   sent from a domain the employer doesn't use
  attested_channel_mismatch  warning 26   by text or a chat app, when the employer says it never recruits that way
  attested_money_mismatch    critical 40  a check, equipment money or a fee, when the employer says it never does that

Only attestations a reviewer verified are stored (db/migrations/002_attestations.sql), so this can't be gamed by a
scammer "attesting" for a real company. With no attestation for the company, nothing happens.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

from .intel.domains import registrable_domain

_LEGAL = re.compile(r"\b(?:inc|llc|ltd|corp|corporation|co|company|plc|lp|llp)\b\.?", re.I)
_EMAIL = re.compile(r"[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)
_CHAT = re.compile(r"\b(?:whats\s?app|telegram|signal|wechat|wickr|kik|discord|line\s+app)\b", re.I)
_SMS = re.compile(r"\b(?:text\s+(?:me|us)|send\s+(?:me|us)\s+a\s+text|sms)\b", re.I)
MONEY_RULES = {"fake_check_funds": "never_checks", "money_mule": "never_checks", "startup_cost": "never_checks",
               "advance_fee": "never_fees", "pay_to_work": "never_fees"}


def company_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _LEGAL.sub("", (name or "").lower()))


def _store(store):
    if store is None:
        from .store import get_store
        store = get_store()
    return store


def _f(rule_id, severity, weight, title, why, matched) -> dict:
    return {"rule_id": rule_id, "severity": severity, "weight": weight, "title": title, "why": why,
            "matched": [m for m in matched if m][:5]}


def attestation_findings(company: str, sender: str = "", text: str = "", findings: Iterable[dict] = (),
                         channel: str = "", store=None) -> Tuple[Optional[dict], List[dict]]:
    key = company_key(company)
    if not key:
        return None, []
    try:
        att = _store(store).attestation(key)
    except Exception:                                    # noqa: BLE001 - never break a check over this
        return None, []
    if not att:
        return None, []
    name, out = att["company"], []
    domains = {registrable_domain(d.lower().lstrip("@")) for d in att["email_domains"]}

    m = _EMAIL.search(sender or "")
    if m and registrable_domain(m.group(1).lower()) not in domains:
        out.append(_f("attested_domain_mismatch", "warning", 26, f"{name} doesn't send from this address",
                      f"{name} has told LureCheck its recruiters only email from "
                      f"{', '.join('@' + d for d in sorted(domains))}. This came from @{m.group(1).lower()}.",
                      ["@" + m.group(1).lower()]))

    ch = (channel or "").lower()
    chat = _CHAT.search(text or "")
    if att.get("never_chat_apps") and (chat or ch in ("whatsapp", "telegram", "signal", "chat")):
        out.append(_f("attested_channel_mismatch", "warning", 26, f"{name} doesn't recruit on chat apps",
                      f"{name} has told LureCheck it never recruits through WhatsApp, Telegram, Signal or similar.",
                      [chat.group(0) if chat else ch]))
    elif att.get("never_text") and (_SMS.search(text or "") or ch in ("text", "sms")):
        out.append(_f("attested_channel_mismatch", "warning", 26, f"{name} doesn't recruit by text message",
                      f"{name} has told LureCheck it never recruits by text message.", [ch or "text message"]))

    fired = {f.get("rule_id") for f in findings}
    broken = sorted({r for r, flag in MONEY_RULES.items() if r in fired and att.get(flag, True)})
    if broken:
        out.append(_f("attested_money_mismatch", "critical", 40, f"{name} never asks for this",
                      f"{name} has told LureCheck it never sends checks, asks you to buy equipment, or charges a fee. "
                      f"This message does, so it isn't from {name}.", broken))
    return att, out
