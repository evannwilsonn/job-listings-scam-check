"""
"I already responded": what to do now, for what already happened.

    recovery_plan(happened: list[str]) -> {"steps": [...], "happened": [...], "unknown": [...], "note": str}
    next_step(happened: str) -> str      the single most urgent action

A verdict is no help to the student who already deposited the check. This turns what they tell us happened into an
ordered list of steps, most urgent first (money that can still be stopped comes before paperwork). Each step says
what to do, why now, and where. Steps shared by several situations appear once.

Everything here is US-specific and points only at official or primary sources (the student's own bank, the credit
bureaus, the FTC, the FBI's IC3, USPS Postal Inspection, the IRS). It is general guidance, not legal advice, and
says so.
"""

from __future__ import annotations

from typing import Dict, List

HAPPENED = {
    "replied": "I replied or talked to them",
    "shared_personal_info": "I gave them my SSN, ID, date of birth or address",
    "shared_bank_details": "I gave them my bank account or card details",
    "shared_login": "I gave them a password or a login code",
    "deposited_check": "I deposited a check they sent",
    "sent_money": "I sent them money (bank transfer, Zelle, Cash App, Venmo, PayPal)",
    "gift_cards": "I bought gift cards for them",
    "crypto": "I sent cryptocurrency or used a crypto ATM",
    "shipped_packages": "I received or reshipped packages for them",
    "installed_software": "I installed an app or let them connect to my computer",
}

# id: (title, what to do, why now, urgency: lower runs first)
STEPS: Dict[str, tuple] = {
    "stop_contact": ("Stop replying", "Don't answer, don't send anything else, and don't click their links. Block the "
                     "number or account after you've saved screenshots of the conversation.",
                     "Scammers come back with new reasons to pay, and anyone 'helping you recover the money' later is "
                     "usually the same people.", 0),
    "call_bank_check": ("Call your bank about the check", "Call your bank at the number on the back of your card, say "
                        "the check may be fake, and ask them to put a hold on it. Don't spend or send any of that money.",
                        "Your bank may show the money as available, but a fake check can come back weeks later and you "
                        "owe the bank the full amount.", 1),
    "call_bank_payment": ("Call your bank or payment app now", "Report the payment as fraud and ask them to stop or "
                          "reverse it. For Zelle, call your own bank; for Cash App, Venmo or PayPal, use the app's "
                          "help center.", "Some transfers can still be stopped if you report them within hours.", 1),
    "card_issuer": ("Call the gift card company", "Call the number on the back of each card, give the card numbers and "
                    "receipts, and ask them to freeze the balance.", "If the money hasn't been spent yet it can "
                    "sometimes be frozen.", 1),
    "crypto_report": ("Report it to the exchange or ATM operator", "Contact the exchange or crypto ATM company with the "
                      "transaction ID and wallet address, then report it at ic3.gov.", "Crypto can't be reversed, "
                      "but exchanges can sometimes freeze funds that land on their platform.", 2),
    "stop_shipping": ("Stop shipping anything", "Don't send any more packages. Keep every label, receipt and message, "
                      "and report it to the U.S. Postal Inspection Service at uspis.gov.",
                      "Reshipping moves goods bought with stolen cards. Stopping now and reporting it protects you.", 1),
    "disconnect": ("Disconnect and remove their access", "Uninstall the app they had you install, restart, run your "
                   "computer's security scan, and change your important passwords from a different device.",
                   "Remote-access tools let them see your screen and accounts while connected.", 1),
    "bank_accounts": ("Lock down your bank account", "Call your bank's fraud line, tell them the details were shared, "
                      "and ask about a new account number and alerts on every transaction.",
                      "Shared account details are used to move stolen money through your account.", 2),
    "passwords": ("Change your passwords", "Change the password you shared and anywhere you reuse it, and turn on "
                  "two-step sign-in. Start with email and banking.", "Your email account resets every other "
                  "password, so it goes first.", 2),
    "freeze_credit": ("Freeze your credit (free)", "Freeze your credit at Equifax, Experian and TransUnion, each on "
                      "its own website or by phone.", "A freeze stops anyone opening new accounts in your name. You "
                      "can lift it any time.", 3),
    "identitytheft_gov": ("Get a recovery plan at identitytheft.gov", "Report what was shared at identitytheft.gov. "
                          "It builds a step-by-step plan and the official report you can show to banks.",
                          "That report is what lets you dispute accounts someone opens in your name.", 4),
    "irs_pin": ("Get an IRS Identity Protection PIN", "If you shared your SSN, request an IP PIN at irs.gov/ippin.",
                "It stops someone filing a tax return in your name to take your refund.", 4),
    "report_ftc": ("Report it to the FTC", "Report it at reportfraud.ftc.gov. LureCheck can fill in a summary for you.",
                   "Reports are how scams get tracked and shut down, and they're kept confidential.", 5),
    "report_ic3": ("Report it to the FBI's IC3", "If you lost money, also report it at ic3.gov with dates, amounts and "
                   "account or wallet details.", "IC3 reports are how the FBI links your case to others from the same "
                   "group.", 5),
    "tell_school": ("Tell your career center", "Let your school's career center know, especially if it came through "
                    "the school's job board or email.", "They can warn other students the same day.", 6),
}

PLAN: Dict[str, List[str]] = {
    "replied": ["stop_contact", "report_ftc", "tell_school"],
    "shared_personal_info": ["stop_contact", "freeze_credit", "identitytheft_gov", "irs_pin", "report_ftc", "tell_school"],
    "shared_bank_details": ["stop_contact", "bank_accounts", "identitytheft_gov", "report_ftc", "tell_school"],
    "shared_login": ["stop_contact", "passwords", "bank_accounts", "report_ftc", "tell_school"],
    "deposited_check": ["stop_contact", "call_bank_check", "report_ftc", "report_ic3", "tell_school"],
    "sent_money": ["stop_contact", "call_bank_payment", "report_ftc", "report_ic3", "tell_school"],
    "gift_cards": ["stop_contact", "card_issuer", "report_ftc", "tell_school"],
    "crypto": ["stop_contact", "crypto_report", "report_ftc", "report_ic3", "tell_school"],
    "shipped_packages": ["stop_contact", "stop_shipping", "report_ftc", "tell_school"],
    "installed_software": ["disconnect", "stop_contact", "passwords", "bank_accounts", "report_ftc", "tell_school"],
}

DISCLAIMER = "General guidance, not legal advice. If you're unsure, your bank's fraud line is the first call."


def recovery_plan(happened: List[str]) -> dict:
    happened = list(happened or [])
    known = [h for h in dict.fromkeys(happened) if h in PLAN]
    unknown = [h for h in happened if h not in PLAN]
    ids = list(dict.fromkeys(s for h in known for s in PLAN[h])) or ["stop_contact", "report_ftc", "tell_school"]
    ids.sort(key=lambda s: STEPS[s][3])                     # stable: keeps plan order within the same urgency
    steps = [{"id": s, "title": STEPS[s][0], "do": STEPS[s][1], "why": STEPS[s][2]} for s in ids]
    return {"happened": known, "unknown": unknown, "steps": steps, "note": DISCLAIMER}


def next_step(happened: str) -> str:
    """The single most urgent action besides 'stop replying', for short replies (the report endpoint)."""
    if happened not in PLAN:
        return ""
    plan = recovery_plan([happened])["steps"]
    first = next((s for s in plan if s["id"] != "stop_contact"), plan[0])
    return first["do"]
