"""
Tactic-level "asks": what a message asks the student to DO.

Scam wording mutates constantly ("paycheck for office supplies", "funds for your equipment", "cover the
expenses for these softwares"), but the action requested is stable: deposit a check, pay a vendor on Zelle,
buy gift cards, top up an account to unlock earnings, reship parcels, hand over bank or ID details. This module
names those actions so the rest of the detector (and conversation.py) can reason about the tactic instead of
the phrasing.

    extract_asks(text) -> [{"ask": id, "label": plain English, "evidence": matched span,
                            "money": bool, "start": offset}, ...]

Precision matters more than recall: legitimate postings describe the same things in order to rule them out
("we will never ask you to pay a training fee", "background check paid by us", "direct deposit after hire",
"you will never be asked to deposit checks"). Every ask carries guards for negation, employer disclaimers /
scam warnings, and (for bank and ID details) post-hire context. tests/test_conversation.py runs this over every
labeled row in scam_detector/data and fails if legitimate postings trigger money asks more than rarely.

Pure stdlib, deterministic, bounded regexes only.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List

from .rules import normalize

__all__ = ["ASKS", "ASK_LABELS", "MONEY_ASKS", "DATA_ASKS", "extract_asks", "ask_ids"]

_F = re.IGNORECASE

# ---------------------------------------------------------------- guards

_SENT_BREAK = re.compile(r"[.;!?\n]")
_NEGATORS = re.compile(
    r"\b(?:no|never|not|without|zero|nor|neither|free of|isn't|aren't|doesn't|won't|don't|do not|"
    r"does not|will not|cannot|can't|nothing)\b", _F)
# "no experience needed, you must pay a $50 fee" -> the negator does not govern the ask.
_REQUIRE_AFTER_NEG = re.compile(
    r"\b(?:must|need to|needs to|have to|has to|required to|you will|you'll|you pay|but|however|then|just|only)\b", _F)
_AFTER_CUES = re.compile(
    r"^[^.;!?\n]{0,60}\b(?:at no (?:cost|charge)|no cost|free of charge|for free|is free|are free|free to you|"
    r"covered by|paid for by|paid by (?:us|the|our)|we (?:pay|cover)|is waived|are waived|is not required|"
    r"are not required|is never required|will never be)\b", _F)
# An employer's own safety promise or a scam warning describes the tactic in order to rule it out.
_DISCLAIMER = re.compile(
    r"\b(?:at\s+no\s+(?:time|point)|will\s+never|would\s+never|we\s+never|never\s+(?:ask|request|require|contact|"
    r"move|be\s+asked)|will\s+not\s+ever|won't\s+ever|we\s+(?:do\s+not|don't)\s+(?:ask|request|require|charge|"
    r"conduct)|scams?\b|scammers?|fraud\w*|phishing|beware|red\s+flags?|be\s+(?:wary|cautious|careful)|"
    r"legitimate\s+(?:employers?|companies|recruiters?)|report\s+(?:it|them|this))", _F)
_POST_HIRE = re.compile(
    r"\b(?:upon\s+(?:hire|hiring|being\s+hired|acceptance|accepting|your\s+start)|"
    r"after\s+(?:you(?:'re|\s+are)\s+|being\s+|an?\s+|your\s+|the\s+)?(?:hired|hire|offer|accept\w*|acceptance|"
    r"start\s+date|first\s+(?:day|shift|completed)|orientation)|"
    r"once\s+(?:you(?:'re|\s+are)\s+)?(?:hired|onboarded|you\s+accept)|new[- ]hires?\b|pre-employment|"
    r"i-?9\b|w-?4\b|payroll\s+portal|(?:on|during)\s+(?:your\s+)?(?:first\s+day|orientation)|"
    r"(?:signed|accept(?:ed)?)\s+(?:the\s+|your\s+|our\s+)?offer(?:\s+letter)?)", _F)


def _sentence_before(text: str, start: int) -> str:
    seg = text[max(0, start - 200):start]
    parts = _SENT_BREAK.split(seg)
    return parts[-1] if parts else seg


def _sentence_after(text: str, end: int) -> str:
    seg = text[end:end + 160]
    m = _SENT_BREAK.search(seg)
    return seg[:m.start()] if m else seg


def _g_negation(text: str, m: re.Match) -> bool:
    before = " ".join(_sentence_before(text, m.start()).split()[-10:])
    last = None
    for last in _NEGATORS.finditer(before):
        pass
    if last is not None and not _REQUIRE_AFTER_NEG.search(before[last.end():]):
        return True
    return bool(_AFTER_CUES.search(_sentence_after(text, m.end())))


def _g_disclaimer(text: str, m: re.Match) -> bool:
    sentence = _sentence_before(text, m.start()) + m.group(0) + _sentence_after(text, m.end())
    return bool(_DISCLAIMER.search(sentence))


def _g_post_hire(text: str, m: re.Match) -> bool:
    return bool(_POST_HIRE.search(text[max(0, m.start() - 140):m.end() + 140]))


# Payment flowing TO the student ("we pay you via PayPal", "you'll be paid via Zelle") is not an ask.
_TO_YOU = re.compile(r"\b(?:pay|send|transfer|wire|sent|paid|remit)\w*\s+(?:to\s+)?you\b|\b(?:paid|payments?|pay|salary|"
                     r"compensation|wages?|earnings?|stipend|bonus(?:es)?)\b[^.]{0,25}$", _F)
# "I will send the money via PayPal" / "we wire your pay": the sender is them, not the student.
_THEY_SEND = re.compile(r"\b(?:i|we|they|he|she|employer|company)(?:'ll|'d|\s+will|\s+would|\s+can|\s+shall)?\s*"
                        r"(?:\w+ly\s+)?$", _F)


def _g_to_you(text: str, m: re.Match) -> bool:
    if _TO_YOU.search(m.group(0)[:60]):
        return True
    before = " ".join(_sentence_before(text, m.start()).split()[-4:])
    return bool(_THEY_SEND.search(before + " " if before and not before.endswith(" ") else before))


# A job duty or requirement ("must have a valid driver's license", "verify routing numbers") is not an ask.
_DUTY = re.compile(r"\b(?:verify|verifies|verifying|process(?:es|ing)?|reconcil\w+|audit\w*|maintain\w*|review\w*|"
                   r"experience\s+(?:with|in)|knowledge\s+of|familiar\w*)\b", _F)


def _g_duty(text: str, m: re.Match) -> bool:
    before = " ".join(_sentence_before(text, m.start()).split()[-6:])
    return bool(_DUTY.search(before))


_GUARDS: Dict[str, Callable[[str, re.Match], bool]] = {
    "negation": _g_negation, "disclaimer": _g_disclaimer, "post_hire": _g_post_hire,
    "to_you": _g_to_you, "duty": _g_duty,
}

# ---------------------------------------------------------------- taxonomy

_MONEY_WORDS = r"(?:zelle|cash\s?app|venmo|western\s+union|moneygram|wire\s+transfer|paypal)"
_CRYPTO = r"(?:bitcoin|btc|usdt|usdc|tether|ethereum|crypto(?:currency|currencies)?)"
_CARD_BRANDS = r"(?:apple|itunes|google\s+play|amazon|steam|target|walmart|visa|ebay|sephora|vanilla|best\s+buy|razer)"

_SPECS = [
    # --- money asks -------------------------------------------------------------------------------
    {"id": "pay_fee", "label": "Pay a fee for training, registration, a background check or a starter kit",
     "money": True, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:training|registration|application|processing|onboarding|background[- ]check|certification|enrol?lment|"
         r"administrative|admin|visa(?:\s+processing)?|installation|sign[- ]?up|commitment|membership|activation|"
         r"website|placement|clearance|verification)\s+(?:fees?|charges?|costs?)\b",
         r"\b(?:pay|paying|cover|send)\s+(?:a\s+|an\s+|the\s+|your\s+|our\s+)?(?:small\s+|one[- ]time\s+|refundable\s+|"
         r"upfront\s+|up-front\s+)?(?:\$\s?\d[\d,]*(?:\.\d\d)?\s+)?(?:fee|deposit)\b",
         r"\$\s?\d[\d,]*(?:\.\d\d)?\s+(?:[a-z]+\s+)?(?:fee|deposit)\b",
         r"\$\s?\d[\d,]*(?:\.\d\d)?\s+(?:paid\s+)?(?:certification|training|course|mentorship|enrol?lment|starter\s+kit)\b",
         r"\b(?:training|course|program|starter\s+kit|kit)\b[^.\n]{0,20}\b(?:costs?|for\s+only|price\s+of)\s+\$\s?\d",
         r"\brefundable\s+(?:deposit|fee)\b",
         r"\b(?:one[- ]time\s+)?enrol?lment\s+investment\b",
         r"\b(?:training|program)\s+with\s+a\s+fee\b",
         r"\$\s?\d[\d,]*[^.\n]{0,25}\b(?:out\s+of\s+pocket|start-?up\s+cost)\b",
         r"\b(?:buy|purchase|pay\s+for)\s+(?:your\s+|a\s+|the\s+)?starter\s+kit\b",
     ]},
    {"id": "buy_equipment", "label": "Buy equipment or supplies from a vendor they name",
     "money": True, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:purchase|buy)\w*\s+(?:the\s+|your\s+|our\s+|all\s+|some\s+|any\s+)?(?:required\s+|necessary\s+|home[- ]office\s+|"
         r"office\s+|work\s+)?(?:equipment|supplies|softwares?|laptop|macbook|office\s+items|devices?)\b[^.\n]{0,50}\b"
         r"(?:vendor|supplier|from\s+(?:us|our|my|the\s+(?:vendor|supplier|store\s+we))|we\s+(?:recommend|provide|send))\b",
         r"\b(?:purchase|buy)\w*\s+(?:our|the)\s+required\s+(?:software|equipment|kit)\b",
         r"\b(?:pay|send\s+money\s+to)\s+(?:the|our|my|an?)\s+(?:approved\s+|designated\s+|preferred\s+|certified\s+)?"
         r"(?:equipment\s+)?(?:vendor|supplier)\b",
         r"\b(?:approved|designated|preferred|certified)\s+(?:equipment\s+)?(?:vendor|supplier)\b[^.\n]{0,40}\b(?:pay|purchase|buy)\b",
         r"\bcover\s+the\s+(?:expenses|costs?)\b[^.\n]{0,30}\bfor\s+(?:these|the)\s+(?:softwares?|equipment|supplies)\b",
         r"\b(?:purchase|buy)\s+(?:gifts?|gift\s+items|items)\s+(?:and\s+items\s+)?for\s+(?:some|the|my)\b",
         r"\buse\s+the\s+(?:rest|remainder|balance)\s+to\s+(?:purchase|buy)\b",
     ]},
    {"id": "deposit_check", "label": "Deposit or mobile-deposit a check they send",
     "money": True, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:mobile[- ])?deposit\s+(?:the|this|a|your|that)\s+(?:pay)?(?:check|cheque)\b",
         r"\bmobile\s+deposit\b(?!\s+limit)",
         r"\bcash\s+(?:the|this)\s+(?:pay)?(?:check|cheque)\b",
         r"\b(?:send|mail|issue|email|deliver|give|courier)\w*\s+you\s+(?:an?\s+)?(?:official\s+|onboarding\s+|cashier'?s\s+|"
         r"certified\s+)?(?:pay)?(?:check|cheque)\b[^.\n]{0,90}\b(?:deposit|purchase|equipment|supplies|expenses|software|vendor|keep)\b",
         r"\b(?:send|mail|issue|email|deliver)\w*\s+you\s+(?:an?\s+|the\s+)?(?:official|onboarding|cashier'?s|certified)\s+"
         r"(?:pay)?(?:check|cheque)\b",
         r"\b(?:pay)?(?:check|cheque)\s+(?:for|to\s+cover)\s+(?:the\s+|your\s+)?(?:office\s+|home[- ]office\s+|equipment\s+)?"
         r"(?:supplies|equipment|expenses|purchases?|items|setup)\b",
         r"\b(?:attached|enclosed)\s+is\s+(?:the|your|a)\s+(?:pay)?(?:check|cheque)\b",
         r"\b(?:onboarding|equipment)\s+(?:check|cheque)\b",
         r"\b(?:provide|send|give|issue)\w*\s+you\s+(?:with\s+)?(?:the\s+)?funds?\b[^.\n]{0,40}\b(?:to|for)\s+(?:purchase|buy|handle|cover|"
         r"the\s+(?:shipping|equipment|supplies|office))\b",
         r"\bpaid\s+in\s+advance\s+for\s+(?:all\s+)?(?:tasks\s+and\s+)?purchases\b",
         r"\ballocate\s+(?:the\s+)?(?:necessary\s+)?(?:finances|funds)\s+for\s+the\s+(?:acquisition|purchase)\b",
         r"\bcashier'?s\s+check\b[^.\n]{0,60}\b(?:deposit|cash|you)\b",
     ]},
    {"id": "send_money_on", "label": "Send or forward money by Zelle, Cash App, Venmo or wire",
     "money": True, "guards": ["negation", "disclaimer", "to_you"], "patterns": [
         r"\b(?:forward|wire|transfer|send|remit|return)\w*\s+(?:the\s+)?(?:remaining\s+|excess\s+|leftover\s+)?"
         r"(?:balance|remainder|rest|excess|remaining\s+(?:balance|funds|amount|money))\b",
         r"\b(?:forward|wire|transfer|send|remit|return)\w*\s+(?:the\s+)?(?:funds|money)\b[^.\n]{0,30}\b(?:back|to\s+(?:our|my|the)\s+"
         r"(?:vendor|supplier|agent|partner|client|manager))\b",
         r"\bmake\s+(?:a\s+)?payment\b[^.\n]{0,30}\bto\s+(?:the\s+|our\s+|my\s+)?(?:\w+\s+)?(?:" + _MONEY_WORDS + r"|vendor|supplier|agent)\b",
         r"\b(?:pay|send|transfer|wire|remit)\b[^.\n]{0,60}\b(?:via|through|by|on|using|with|to\s+(?:my|our|the))\s+"
         + _MONEY_WORDS + r"\b",
         r"\b" + _MONEY_WORDS + r"\s+(?:information|info|details|handle|tag|account)\s+(?:below|above|i\s+(?:sent|gave))\b",
         r"\bwire\s+(?:the\s+)?(?:money|funds|payment|it)\b",
     ]},
    {"id": "gift_cards", "label": "Buy gift cards",
     "money": True, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:buy|purchase|pick\s+up|get\s+me|grab)\w*\s+(?:me\s+|us\s+)?(?:\d+\s+|some\s+|a\s+few\s+|several\s+|the\s+)?"
         r"(?:\(?\$\s?\d+\)?\s+)?(?:" + _CARD_BRANDS + r"\s+)?(?:gift|store|prepaid)\s*cards?\b",
         r"\bgift\s*cards?\b[^.\n]{0,40}\b(?:scratch|send\s+(?:me|us)\s+the\s+(?:codes?|pictures?|photos?)|codes?\s+(?:to|back))\b",
         r"\b(?:return|pay|send|reimburse|refund|remit)\w*\b[^.\n]{0,40}\b(?:via|with|in|using)\s+(?:" + _CARD_BRANDS + r"\s+)?gift\s*cards?\b",
         r"\bsend\s+(?:me|us)\s+(?:the\s+)?(?:card\s+)?codes\b",
     ]},
    {"id": "crypto", "label": "Buy, send or deposit crypto, or visit a Bitcoin ATM",
     "money": True, "guards": ["negation", "disclaimer", "duty"], "patterns": [
         r"\b(?:bitcoin|btc|crypto(?:currency)?)\s+atms?\b",
         r"\b(?:buy|purchase|send|deposit|transfer|top\s?up|recharge|convert|load|fund)\w*\s+(?:(?:it|the\s+(?:money|funds|cash))\s+"
         r"(?:in|into|to)\s+)?(?:\$\s?\d[\d,]*\s+(?:(?:in|of|worth\s+of)\s+)?)?(?:your\s+|some\s+|the\s+)?" + _CRYPTO + r"\b",
         r"\b(?:with|in|using|into)\s+(?:\$?\s?\d[\d,.]*\s+)?" + _CRYPTO + r"\b(?![^.\n]{0,30}\b(?:markets?|industry|nodes?|exchange|infrastructure|space|"
         r"experience|projects?|platform)\b)",
         r"\b(?:wallet\s+address|crypto\s+wallet|scan\s+the\s+qr\s+code)\b",
     ]},
    {"id": "reship", "label": "Receive packages at home and re-ship them",
     "money": True, "guards": ["negation", "disclaimer"], "patterns": [
         r"\breshipp?(?:ing|er|ers)?\b|\bre-ship\w*\b",
         r"\b(?:relabel|re-label|repack|re-pack|repackag)\w*\b",
         r"\b(?:parcels?|packages?|packs|goods|items|shipments?|boxes)\b[^.\n]{0,60}\b(?:delivered|sent|shipped|mailed)\s+"
         r"(?:directly\s+)?to\s+your\s+(?:home|house|address|residence|apartment|residential)\b",
         r"\b(?:receive|accept|inspect)\w*\s+(?:the\s+)?(?:parcels?|packages?|shipments?|boxes|goods|correspondence)\b[^.\n]{0,80}"
         r"\b(?:your\s+(?:home|residential|residence|address)|at\s+home|residential\s+address)\b",
         r"\b(?:forward|ship|send)\w*\s+(?:the\s+)?(?:parcels?|packages?|boxes)\b[^.\n]{0,40}\b(?:overseas|abroad|on\s+to|our\s+customers|"
         r"prepaid|label)\b",
         r"\bprepares?\s+goods\s+for\s+forwarding\b|\bpackage\s+forwarding\b",
         r"\baddress\s+to\s+send\s+(?:packs|packages|parcels)\b",
         r"\b(?:outgoing|prepaid)\s+shipping\s+labels?\b",
     ]},
    {"id": "receive_transfers", "label": "Receive payments into your account and pass them on for a cut",
     "money": True, "guards": ["negation", "disclaimer"], "patterns": [
         r"\breceiv\w*\s+(?:client\s+|customer\s+)?(?:funds|payments?|money|transfers?|deposits?)\s+(?:in|into|to|on)\s+your\s+"
         r"(?:personal\s+|own\s+)?(?:bank\s+)?account\b",
         r"\b(?:customers?|clients?|buyers?|people)\s+(?:will\s+)?(?:pay|send|deposit|transfer)\w*\s+(?:money\s+|funds\s+)?(?:into|to)\s+"
         r"your\s+(?:personal\s+|own\s+)?(?:bank\s+)?account\b",
         r"\bkeep(?:ing)?\s+(?:a\s+|the\s+)?(?:\d{1,2}\s?%|percentage|portion|cut)\b",
         r"\bkeep(?:ing)?\s+\$\s?\d[\d,]*[^.\n]{0,30}\bcommission\b",
         r"\b(?:transfer|send|wire|forward|remit)\w*\b[^.\n]{0,30}\b\d{1,3}\s?%[^.\n]{0,30}\b(?:partner|to\s+us|our|company|account)\b",
         r"\bprocess(?:ing)?\s+payments?\s+on\s+behalf\s+of\b",
         r"\bpayment\s+processing\s+agent\b|\bmoney\s+transfer\s+agent\b|\bfinancial\s+(?:agent|representative)\s+to\s+receive\b",
         r"\buse\s+your\s+(?:bank\s+)?account\s+to\s+(?:receive|accept|process)\b",
     ]},
    {"id": "task_deposit", "label": "Deposit or \"recharge\" to unlock tasks, commissions or earnings",
     "money": True, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:top\s?up|top-up|recharge|reload|refill|fund)\w*\s+(?:your\s+|the\s+)?(?:work\s+|task\s+|platform\s+)?(?:account|balance|wallet)\b",
         r"\bunlock\s+(?:your\s+|the\s+)?(?:withdrawal|earnings|commissions?|tasks?|bonus|funds|profits?|salary)\b",
         r"\bwithdraw\w*\b[^.\n]{0,50}\b(?:top\s?up|recharge|deposit|unlock|upgrade|pay\s+(?:the|a)\s+(?:tax|fee))\b",
         r"\b(?:negative|insufficient)\s+balance\b|\b(?:combination|combo|lucky|merge[d]?|premium)\s+(?:order|task)s?\b",
         r"\bfailure\s+to\s+withdraw\b",
         r"\bdeposit\b[^.\n]{0,40}\b(?:to|before\s+you\s+can)\s+(?:continue|unlock|withdraw|complete\s+(?:the\s+)?(?:set|task))\b",
     ]},
    {"id": "bank_details", "label": "Bank name, account/routing number or online banking login",
     "money": True, "guards": ["negation", "disclaimer", "post_hire", "duty"], "patterns": [
         r"\b(?:provide|send|share|give|text|email|include|need|require|submit|write|confirm|furnish)\w*\b[^.\n]{0,60}"
         r"\b(?:routing|(?:bank\s+)?account)\s+(?:and\s+(?:routing|account)\s+)?numbers?\b",
         r"\byour\s+(?:bank(?:ing)?\s+)?(?:account\s+(?:and\s+routing\s+)?number|routing\s+(?:and\s+account\s+)?number)\b",
         r"(?:^|\n)[\s*\-•]*(?:bank\s+name|bank\s+address|account\s+number|routing\s+number|account\s+holder'?s?\s+name|account\s+type)\s*[:.]",
         r"\bname\s+of\s+your\s+(?:financial\s+institution|bank)\b",
         r"\byour\s+name\s+(?:just\s+)?as\s+it\s+appears\s+on\s+your\s+(?:financial\s+institution|bank)",
         r"\bonline\s+banking\s+(?:login|log-in|username|user\s*name|password|credentials|details|access)\b|\bbank(?:ing)?\s+login\b",
         r"\bmobile\s+deposit\s+limit\b",
         r"\bvalid\s+(?:u\.?s\.?\s+)?bank\s+account\s+for\s+payment\b",
         r"\bvoided\s+check\b",
         r"\b(?:what|which)\s+bank\s+do\s+you\s+(?:use|bank\s+with|have)\b|\bwho\s+do\s+you\s+bank\s+with\b|"
         r"\bwhat\s+bank\s+(?:are\s+you\s+with|is\s+your\s+account)\b",
         r"\b(?:age|address|phone\s+number|email)\s*,\s*bank\s+name\b",
         r"\bdo\s+you\s+have\s+(?:a\s+)?(?:mobile|online)\s+banking\b",
     ]},
    {"id": "identity_docs", "label": "SSN, driver's license or ID photo, or date of birth before an offer",
     "money": True, "guards": ["negation", "disclaimer", "post_hire"], "patterns": [
         r"\b(?:send|provide|share|text|email|upload|scan|snap|attach|submit|give|need|require)\w*\b[^.\n]{0,50}\b(?:ssn|social\s+security|"
         r"driver'?s?\s+licen[sc]e|passport|photo\s+id|id\s+card|state\s+id|government[- ]issued\s+(?:id|identification)|"
         r"(?:copy|photo|picture|scan)\s+of\s+(?:your\s+)?(?:any\s+)?(?:id|identification|document\s+of\s+identification))\b",
         r"\b(?:copy|photo|picture|scan|image|front\s+and\s+back(?:\s+photo)?)\s+of\s+(?:your\s+|any\s+|a\s+)?(?:any\s+)?"
         r"(?:driver'?s?\s+licen[sc]e|id\b|identification|government[- ]issued|passport|state\s+id|ssn|social\s+security\s+card|"
         r"document\s+of\s+identification)",
         r"\byour\s+(?:ssn|social\s+security\s+number)\b",
         r"\bvalid\s+(?:u\.?s\.?\s+)?(?:identification\s+or\s+)?social\s+security\s+number\b",
         r"\bdate\s+of\s+birth\b|(?:^|\n)[\s*\-•]*dob\s*[:.]|\bdob\b(?=\s*[,\n])",
         r"\bverify\s+(?:your\s+)?identi(?:ty|fy)\s+on\s+(?:the\s+)?app\b|\byou\s+need\s+your\s+id\s+to\s+verify\b",
     ]},
    # --- non-money asks ---------------------------------------------------------------------------
    {"id": "move_off_platform", "label": "Move the conversation to WhatsApp, Telegram, Signal, text or personal email",
     "money": False, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:whats\s?app|telegram|wickr|google\s+hangouts|hangouts\s+app|kik\b|line\s+app|wechat)\b",
         r"\b(?:on|via|add\s+(?:me|us)\s+on|through)\s+signal\b|\bsignal\s+(?:app|messenger)\b",
         r"\b(?:text|sms|txt)\s+(?:me|us|him|her|them|our\s+\w+)\b",
         r"\b(?:send|drop)\s+(?:a\s+|me\s+a\s+)?text(?:\s+message)?\s+to\b|\bvia\s+(?:text|sms)(?:\s+message)?\b|\bby\s+text\s+message\b",
         r"\btext\s+(?:your|me\s+your|us\s+your)\s+(?:full\s+)?name\b|\btext\s+\"",
         r"\b(?:add|message|contact|reach)\s+(?:me|us|our\s+(?:manager|hr|recruiter|employer))\s+on\s+(?:instagram|facebook|messenger|"
         r"snapchat|teams)\b|\binstagram\b[^.\n]{0,40}\bmessage\s+only\b",
         r"\b(?:provide|send|share)\s+(?:us\s+|me\s+)?your\s+(?:microsoft\s+)?teams\s+(?:contact|id|email|username|handle|details|"
         r"information)\b|\bteams\s+for\s+(?:direct\s+)?communication\b",
         r"\b(?:message|contact|reach)\s+(?:me|us)\s+at\s+my\s+(?:personal\s+)?email\b",
         r"\bdrop\s+your\s+(?:phone|cell|mobile)\s+number\b",
     ]},
    {"id": "personal_email_reply", "label": "Reply from your personal email instead of your school email",
     "money": False, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:using|with|from|via|to)\s+(?:only\s+)?your\s+(?:alternative|alternate|personal|private|non[- ]?school|non[- ]?edu)\s+"
         r"e-?mail(?:\s+address)?\b",
         r"\b(?:alternative|alternate|non[- ]?school|non[- ]?edu)\s+e-?mail(?:\s+address)?\b",
         r"\bnot\s+(?:your|the|with\s+your)\s+(?:\.?edu|school|university|student|campus|work/school|work\s+or\s+school)\s+e-?mail\b",
         r"\bpersonal\s+e-?mail\s+address\s*\(\s*(?:gmail|yahoo|hotmail)",
         r"\b(?:send|provide|reply\s+with|email\s+back\s+with)\b[^.\n]{0,40}\b(?:gmail|personal\s+e-?mail)\b",
     ]},
    {"id": "urgency", "label": "Respond within hours or lose a limited slot",
     "money": False, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:respond|reply|answer|confirm|get\s+back)\w*\b[^.\n]{0,30}\bwithin\s+(?:the\s+next\s+)?(?:\d{1,2}|an?|one|two|few)\s*"
         r"(?:-\s*\d+\s*)?(?:hours?|hrs?|minutes?|mins?)\b",
         r"\b(?:limited|few)\s+(?:slots|positions|spots|openings|vacancies)\b|\bslots\s+are\s+limited\b",
         r"\bfirst[- ]come,?\s+first[- ]serve[d]?\b",
         r"\boffer\s+(?:expires|ends|closes)\s+(?:soon|today|tonight|in)\b",
         r"\b(?:urgent(?:ly)?\s+(?:hiring|needs?|required|requires)|needed\s+urgently|hiring\s+urgently)\b",
         r"\b(?:complete|finish|do)\s+(?:it|this|the\s+task|the\s+payment|the\s+deposit)\s+(?:today|now|asap|immediately|right\s+away)\b",
         r"\b(?:as\s+soon\s+as\s+possible|asap)\b[^.\n]{0,40}\b(?:deposit|pay|send|purchase|complete)\b",
         r"\b(?:today|tonight)\s+only\b",
     ]},
    {"id": "no_interview", "label": "Hired without an interview, or a text/chat \"interview\"",
     "money": False, "guards": ["negation", "disclaimer"], "patterns": [
         r"\bno\s+interview\b|\bwithout\s+(?:an?\s+|any\s+)?interview\b",
         r"\bhired\s+on\s+the\s+spot\b|\bhired\s+the\s+same\s+day\b",
         r"\b(?:chat|text|written|im|instant\s+message)\s+interview\b|\binterview\b[^.\n]{0,40}\b(?:via|on|through|over|by)\s+"
         r"(?:whats\s?app|telegram|signal|text(?:\s+message)?|chat|sms|hangouts|google\s+chat|im)\b",
         r"\binterview\s+(?:will\s+be\s+)?conducted\s+(?:via|by|through|over)\s+(?:chat|text|whats\s?app|telegram)\b",
         r"\bregular\s+im\s+session\b",
         r"\byou(?:'ve|\s+have)\s+been\s+(?:hired|accepted)\b|\b(?:application|resume)\s+(?:is\s+|was\s+|has\s+been\s+)?"
         r"(?:successful|approved|accepted)\b|\bdeemed\s+qualified\b|\bcongratulations,?\s+you(?:'re|\s+are)\s+hired\b",
     ]},
    {"id": "install_app", "label": "Download an app or remote-access tool",
     "money": False, "guards": ["negation", "disclaimer"], "patterns": [
         r"\b(?:download|install)\w*\s+(?:the\s+|our\s+|this\s+|an?\s+)?(?:\w+\s+){0,2}(?:app|application|apk|software)\b"
         r"(?![^.\n]{0,20}\b(?:development|developer|testing)\b)",
         r"\b(?:anydesk|teamviewer|ultraviewer|quick\s?support|rustdesk|logmein|screenconnect|supremo)\b",
         r"\bremote\s+(?:access|desktop|control)\s+(?:app|tool|software|session)\b",
     ]},
]

ASKS = []
for _s in _SPECS:
    ASKS.append({
        "id": _s["id"], "label": _s["label"], "money": _s["money"], "guards": list(_s["guards"]),
        "patterns": [re.compile(p, _F) for p in _s["patterns"]],
    })

ASK_LABELS = {a["id"]: a["label"] for a in ASKS}
MONEY_ASKS = frozenset(a["id"] for a in ASKS if a["money"])
# Asks that are about personal data rather than moving money; conversation.py stages these as data_grab.
DATA_ASKS = frozenset({"bank_details", "identity_docs"})


def ask_ids() -> List[str]:
    return [a["id"] for a in ASKS]


def extract_asks(text: str) -> List[dict]:
    """Return one entry per ask found in `text`, ordered by where it first appears."""
    norm = normalize(text or "")
    out = []
    for spec in ASKS:
        best = None
        for rx in spec["patterns"]:
            for m in rx.finditer(norm):
                if any(_GUARDS[g](norm, m) for g in spec["guards"]):
                    continue
                if best is None or m.start() < best.start():
                    best = m
                break
        if best is not None:
            out.append({"ask": spec["id"], "label": spec["label"], "evidence": best.group(0).strip()[:160],
                        "money": spec["money"], "start": best.start()})
    out.sort(key=lambda a: a["start"])
    return out
