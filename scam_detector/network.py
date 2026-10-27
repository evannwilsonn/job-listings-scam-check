"""
The cross-school network: has this contact already been confirmed as a scam somewhere?

    network_findings(text, sender="", store=None) -> [finding]       for /analyze: a critical finding per match
    lookup(value, store=None) -> dict                                 for /lookup: one phone, email, domain or wallet

Only indicators a reviewer confirmed are ever matched. A report alone never warns anyone, so nobody can make a real
employer's domain look like a scam by reporting it. Phone numbers and emails are compared as salted hashes (the same
hash reports.py stores), so a lookup never needs the raw contact to be stored.
"""

from __future__ import annotations

import re
from typing import List

from .intel.domains import registrable_domain
from .reports import _indicators, hash_identifier
from .rules import FREE_MAIL

_LABEL = {"domain": "This website", "wallet": "This crypto wallet", "email": "This email address",
          "phone": "This phone number", "handle": "This account"}
_EMAIL = re.compile(r"^[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$", re.I)
_WALLET = re.compile(r"^(?:0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|"
                     r"T[1-9A-HJ-NP-Za-km-z]{33})$")


def _store(store):
    if store is None:
        from .store import get_store
        store = get_store()
    return store


def _shown(m: dict) -> str:
    return m["value"] if m["kind"] in ("domain", "wallet") else _LABEL[m["kind"]].split(" ", 1)[1]


def _sentence(m: dict) -> str:
    schools = f" at {m['schools']} school{'s' if m['schools'] != 1 else ''}" if m.get("schools") else ""
    week = f", {m['schools_7d']} of them this week" if m.get("schools_7d") else ""
    return (f"{_LABEL[m['kind']]} was in {m['reports']} scam report{'s' if m['reports'] != 1 else ''} confirmed by "
            f"reviewers{schools}{week}, most recently {m['last_seen']}.")


def network_findings(text: str, sender: str = "", store=None) -> List[dict]:
    """One critical finding listing every confirmed indicator in the message. Empty when nothing matches."""
    try:
        matches = _store(store).confirmed_matches(_indicators(text or "", sender or ""))
    except Exception:                                    # noqa: BLE001 - the network is extra; never break a check
        return []
    if not matches:
        return []
    matches.sort(key=lambda m: (-m["reports"], m["kind"]))
    return [{"rule_id": "confirmed_scam_indicator", "severity": "critical", "weight": 40,
             "title": "Already confirmed as a scam",
             "why": " ".join(_sentence(m) for m in matches[:3]) + " Don't reply, pay or share anything.",
             "matched": [_shown(m) for m in matches][:5]}]


def normalize(value: str) -> tuple:
    """(kind, stored value) for something a student pastes, or ("", "") if it isn't recognisable."""
    v = (value or "").strip()
    if _EMAIL.match(v):
        return "email", hash_identifier(v)
    if _WALLET.match(v):
        return "wallet", v
    digits = re.sub(r"\D", "", v)
    if 10 <= len(digits) <= 11 and re.fullmatch(r"[\d\s().+-]+", v):
        return "phone", hash_identifier(digits[-10:])
    host = re.sub(r"^https?://", "", v.lower()).split("/")[0].split("@")[-1].strip(".")
    if "." in host and re.fullmatch(r"[a-z0-9.-]+", host):
        reg = registrable_domain(host)
        return ("domain", reg) if reg not in FREE_MAIL else ("", "")
    return "", ""


def lookup(value: str, store=None) -> dict:
    kind, stored = normalize(value)
    if not kind:
        return {"found": False, "kind": "", "message": "Paste one phone number, email address, website or wallet."}
    key = {"email": "email_hashes", "phone": "phone_hashes", "domain": "domains", "wallet": "wallets"}[kind]
    matches = _store(store).confirmed_matches({key: [stored]})
    if not matches:
        return {"found": False, "kind": kind,
                "message": "No confirmed scam reports for this yet. That isn't proof it's safe: check the employer "
                           "yourself before sharing anything."}
    m = matches[0]
    return {"found": True, "kind": kind, "reports": m["reports"], "schools": m["schools"],
            "first_seen": m["first_seen"], "last_seen": m["last_seen"], "message": _sentence(m)}
