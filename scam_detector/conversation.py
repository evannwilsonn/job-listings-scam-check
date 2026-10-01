"""
Multi-message thread analysis.

A single scam message can look harmless; the thread gives it away. Job scams follow a playbook:

    hook -> legitimacy (name-drop a professor, the career center, a brand) -> channel switch (text, WhatsApp,
    personal email) -> onboarding ("job details", forms, first task) -> data grab (bank, ID) -> the ask
    (deposit a check, pay a vendor, top up, reship) -> pressure

This module splits a pasted or forwarded thread into turns, stages each of the other side's turns, matches the
sequence to a small table of known scripts and predicts the next move. The point is EARLY warning: a thread
that has reached onboarding or a data grab along a known script is flagged before any money is asked for.

    split_turns(thread_text, me=None) -> [{"speaker": "them"|"me"|"unknown", "text": ..., "who": ...}, ...]
    stage_of(turn_text)               -> {"stages": [...], "asks": [...], "evidence": {stage: span}}
    analyze_thread(thread_text, me=None) -> {"turns", "trajectory", "furthest_stage", "risk", "warning",
                                             "next_step", "script", "findings"}

Findings use the detector's Finding dict format (rule_id, severity, weight, title, why, matched).
Pure stdlib, deterministic.
"""

from __future__ import annotations

import email.utils
import re
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Union

from .asks import DATA_ASKS, MONEY_ASKS, _GUARDS, extract_asks
from .rules import Finding, normalize

__all__ = ["STAGES", "SCRIPTS", "split_turns", "stage_of", "analyze_thread"]

_F = re.IGNORECASE
MAX_THREAD = 60000

STAGES = ["hook", "legitimacy", "channel_switch", "onboarding", "data_grab", "ask", "pressure"]
_STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}

# ====================================================================== turn splitting

_ME_WORDS = {"me", "you", "i", "myself", "self", "student", "applicant (me)", "me (student)"}
_THEM_WORDS = {"them", "they", "recruiter", "hr", "scammer", "employer", "manager", "hiring manager", "sender",
               "boss", "professor", "prof", "company", "agent", "recruiter (them)", "him", "her", "other"}
_NOT_SPEAKERS = {"subject", "from", "to", "cc", "bcc", "date", "sent", "position", "pay", "hours", "hrs", "type",
                 "style", "name", "full name", "address", "email", "phone", "note", "nb", "ps", "p.s", "re",
                 "requirements", "duties", "benefits", "salary", "location", "title", "job", "schedule", "opening",
                 "important", "attachment", "http", "https", "responsibilities", "qualifications", "compensation",
                 "reference number", "job type", "pay rate", "time", "tel", "cell", "mobile", "website", "www"}

# WhatsApp exports: Android "10/12/26, 3:04 PM - Name: msg"; iOS "[10/12/26, 3:04:05 PM] Name: msg".
_WA_PREFIX = (r"^‎?\[?(?P<date>\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}),?\s+(?P<time>\d{1,2}:\d{2}(?::\d{2})?"
              r"(?:\s?[AaPp]\.?\s?[Mm]\.?)?)\]?\s*(?:-\s*)?")
_WA_MSG = re.compile(_WA_PREFIX + r"(?P<name>[^:\n]{1,40}?):\s(?P<msg>.*)$")
_WA_SYSTEM = re.compile(_WA_PREFIX + r"(?P<msg>.*)$")
# Chat copies with a bare time: "[9:41 AM] Name: msg" or "[9:41 AM] msg".
_TS_MSG = re.compile(r"^\[(?P<time>\d{1,2}:\d{2}(?::\d{2})?\s?(?:[AaPp]\.?[Mm]\.?)?)\]\s*"
                     r"(?:(?P<name>[A-Za-z][^:\n\[\]]{0,39}?):\s*)?(?P<msg>.*)$")
_LABEL = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9 .'&()\-]{0,39}?)\s*:\s+(?P<msg>\S.*)$")

_ORIG = re.compile(r"^-{2,}\s*(?:original\s+message|reply\s+message)\s*-{2,}\s*$", _F)
_FWD = re.compile(r"^(?:-{2,}\s*forwarded\s+message\s*-{2,}|begin\s+forwarded\s+message:?)\s*$", _F)
_WROTE = re.compile(r"^On\s+(?P<inner>.{3,200}?)\s+wrote:\s*$", _F)
_HEADER = re.compile(r"^(?P<key>from|sent|date|to|cc|bcc|subject|reply-to)\s*:\s*(?P<val>.*)$", _F)
_QUOTE = re.compile(r"^((?:\s*>)+)\s?")
_ADDR = re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+")


def _quote_depth(line: str) -> tuple:
    m = _QUOTE.match(line)
    if not m:
        return 0, line
    return m.group(1).count(">"), line[m.end():]


def _parse_date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
        if d is not None:
            return d.replace(tzinfo=None)
    except (TypeError, ValueError, IndexError):
        pass
    t = re.sub(r"\s+at\s+", " ", s)
    t = re.sub(r"\s*\((?:[^)]*)\)|\s+[A-Z]{2,4}$|\s+[+\-]\d{4}$", "", t)
    t = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", t.replace(",", " "))
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"(\d)([AaPp][Mm])$", r"\1 \2", t)
    for fmt in ("%a %b %d %Y %I:%M %p", "%A %B %d %Y %I:%M %p", "%a %B %d %Y %I:%M %p", "%A %b %d %Y %I:%M %p",
                "%b %d %Y %I:%M %p", "%B %d %Y %I:%M %p", "%m/%d/%Y %I:%M %p", "%m/%d/%y %I:%M %p",
                "%a %b %d %Y %I:%M:%S %p", "%A %B %d %Y %I:%M:%S %p", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S",
                "%a %b %d %Y %H:%M", "%A %B %d %Y %H:%M", "%m/%d/%Y %H:%M", "%d %b %Y %H:%M", "%a %d %b %Y %H:%M:%S",
                "%a %b %d %Y", "%A %B %d %Y", "%b %d %Y", "%B %d %Y", "%m/%d/%Y", "%m/%d/%y"):
        try:
            return datetime.strptime(t, fmt)
        except ValueError:
            continue
    return None


def _who_from_header(val: str) -> str:
    val = val.strip()
    addr = _ADDR.search(val)
    name = re.sub(r"<[^>]*>|\[mailto:[^\]]*\]|\"", "", val).strip()
    name = _ADDR.sub("", name).strip(" <>()[]")
    return (name + (" <" + addr.group(0).lower() + ">" if addr else "")).strip()


def _split_wrote(inner: str) -> tuple:
    """'Tue, Oct 20, 2026 at 4:10 PM Evan Wilson <e@x.edu>' -> (who, date)."""
    last = None
    for last in re.finditer(r"\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AaPp]\.?[Mm]\.?)?|\b\d{4}\b", inner):
        pass
    if last is not None:
        who = inner[last.end():].strip(" ,")
        if who:
            return _who_from_header(who), inner[:last.end()].strip(" ,")
    parts = inner.rsplit(",", 1)
    if len(parts) == 2:
        return _who_from_header(parts[1]), parts[0]
    return _who_from_header(inner), ""


def _email_like(lines: List[str]) -> bool:
    quoted = 0
    for i, ln in enumerate(lines):
        s = ln.strip()
        if _ORIG.match(s) or _FWD.match(s) or _WROTE.match(s):
            return True
        if s.lower().startswith("from:"):
            window = lines[i + 1:i + 6]
            if any(_HEADER.match(w.strip()) for w in window):
                return True
        if _QUOTE.match(ln):
            quoted += 1
    return quoted >= 1


def _split_email(lines: List[str]) -> tuple:
    # Re-join Gmail's wrapped attribution line: "On Tue, ... Name <\naddr> wrote:"
    joined: List[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        depth, content = _quote_depth(ln)
        if (content.strip().lower().startswith("on ") and not content.rstrip().endswith("wrote:")
                and i + 1 < len(lines)):
            d2, nxt = _quote_depth(lines[i + 1])
            if d2 == depth and nxt.rstrip().endswith("wrote:") and len(content) + len(nxt) < 260:
                joined.append((">" * depth + " " if depth else "") + content.rstrip() + " " + nxt.strip())
                i += 2
                continue
        joined.append(ln)
        i += 1

    segments: List[dict] = []
    history_markers = False

    def new(depth, who=None, date=None, subject=None):
        return {"depth": depth, "who": who, "date": date, "subject": subject, "lines": []}

    def flush(seg):
        body = "\n".join(seg["lines"]).strip()
        if seg["subject"] and body:
            body = seg["subject"].strip() + "\n\n" + body
        if body:
            segments.append({"who": seg["who"], "date": seg["date"], "text": body})

    cur = new(0)
    i = 0
    while i < len(joined):
        depth, content = _quote_depth(joined[i])
        s = content.strip()
        if _ORIG.match(s) or _FWD.match(s):
            history_markers = True
            flush(cur)
            cur = new(None)
            i += 1
            continue
        m = _WROTE.match(s)
        if m:
            history_markers = True
            flush(cur)
            who, date = _split_wrote(m.group("inner"))
            cur = new(None, who or None, date or None)
            i += 1
            continue
        h = _HEADER.match(s)
        if h and h.group("key").lower() == "from":
            nxt = [(_quote_depth(x)[1]).strip() for x in joined[i + 1:i + 6]]
            if any(_HEADER.match(x) for x in nxt) or not "".join(cur["lines"]).strip():
                if "".join(cur["lines"]).strip():
                    flush(cur)
                    cur = new(depth)
                elif cur["depth"] is None:
                    cur["depth"] = depth
                while i < len(joined):
                    d, c = _quote_depth(joined[i])
                    hh = _HEADER.match(c.strip())
                    if not hh:
                        break
                    key, val = hh.group("key").lower(), hh.group("val")
                    if key == "from":
                        cur["who"] = _who_from_header(val)
                    elif key in ("sent", "date"):
                        cur["date"] = val
                    elif key == "subject":
                        cur["subject"] = val
                    i += 1
                continue
        if cur["depth"] is None:
            if s:
                cur["depth"] = depth
        elif depth != cur["depth"] and s:
            flush(cur)
            cur = new(depth)
            if depth > 0:
                history_markers = True
        cur["lines"].append(content)
        i += 1
    flush(cur)

    dates = [_parse_date(sg["date"]) for sg in segments]
    if segments and all(d is not None for d in dates):
        order = sorted(range(len(segments)), key=lambda k: (dates[k], -k))
        segments = [segments[k] for k in order]
    elif history_markers:
        segments.reverse()
    return segments


def _split_labeled(lines: List[str]) -> Optional[List[dict]]:
    cands = []
    for i, ln in enumerate(lines):
        m = _LABEL.match(ln.strip())
        if m and m.group("name").strip().lower() not in _NOT_SPEAKERS:
            cands.append((i, m.group("name").strip(), m.group("msg")))
    counts: dict = {}
    for _, n, _ in cands:
        counts[n.lower()] = counts.get(n.lower(), 0) + 1
    # A label mid-paragraph ("Note: ...") only starts a turn when that speaker name recurs or is a known role word;
    # after a blank line any label does.
    starts = [(i, n, msg) for i, n, msg in cands
              if i == 0 or not lines[i - 1].strip() or n.lower() in _ME_WORDS or n.lower() in _THEM_WORDS or counts[n.lower()] >= 2]
    if len(starts) < 2:
        return None
    names = [n.lower() for _, n, _ in starts]
    known = any(n in _ME_WORDS or n in _THEM_WORDS for n in names)
    repeated = any(names.count(n) >= 2 for n in set(names))
    if not (known or (repeated and len(set(names)) >= 2)):
        return None
    turns: List[dict] = []
    first = starts[0][0]
    pre = "\n".join(lines[:first]).strip()
    if pre:
        turns.append({"who": None, "date": None, "text": pre})
    for k, (i, name, msg) in enumerate(starts):
        end = starts[k + 1][0] if k + 1 < len(starts) else len(lines)
        body = "\n".join([msg] + lines[i + 1:end]).strip()
        turns.append({"who": name, "date": None, "text": body})
    return turns


def _split_prefixed(lines: List[str], rx: re.Pattern, system: Optional[re.Pattern]) -> Optional[List[dict]]:
    turns: List[dict] = []
    hits = 0
    for ln in lines:
        m = rx.match(ln.strip())
        if m:
            hits += 1
            name = (m.groupdict().get("name") or "").strip() or None
            turns.append({"who": name, "date": None, "text": m.group("msg")})
            continue
        if system is not None and system.match(ln.strip()):
            hits += 1
            continue                       # "Messages and calls are end-to-end encrypted", "X joined"...
        if turns:
            turns[-1]["text"] += "\n" + ln
        elif ln.strip():
            turns.append({"who": None, "date": None, "text": ln})
    if hits < 2 or sum(1 for t in turns if t["who"] or rx is _TS_MSG) < 2:
        return None
    for t in turns:
        t["text"] = t["text"].strip()
    return [t for t in turns if t["text"] and t["text"] not in ("<Media omitted>", "This message was deleted")]


def _identity_matches(who: str, me: Iterable[str]) -> bool:
    w = who.lower()
    return any(m and m.lower() in w for m in me)


def _resolve_speakers(raw: List[dict], me: Optional[Union[str, Iterable[str]]]) -> List[dict]:
    if isinstance(me, str):
        me = [me]
    me = [m for m in (me or []) if m and m.strip()]
    key = lambda w: (_ADDR.search(w).group(0).lower() if _ADDR.search(w) else w.strip().lower()) if w else None
    ids: Dict[str, str] = {}
    order: List[str] = []
    for t in raw:
        k = key(t.get("who"))
        if k and k not in ids:
            ids[k] = "unknown"
            order.append(k)
    display = {key(t["who"]): t["who"] for t in raw if t.get("who")}

    for k in order:
        name = display[k].lower()
        bare = re.sub(r"<[^>]*>", "", name).strip()
        if me and _identity_matches(display[k], me):
            ids[k] = "me"
        elif bare in _ME_WORDS:
            ids[k] = "me"
        elif bare in _THEM_WORDS or (me and not _identity_matches(display[k], me)):
            ids[k] = "them"
    unresolved = [k for k in order if ids[k] == "unknown"]
    if unresolved:
        has_me = "me" in ids.values()
        has_them = "them" in ids.values()
        if has_me:
            for k in unresolved:
                ids[k] = "them"
        elif has_them and len(unresolved) == 1:
            ids[unresolved[0]] = "me"
        else:
            score = {k: 0 for k in unresolved}
            for t in raw:
                k = key(t.get("who"))
                if k in score:
                    st = stage_of(t["text"])
                    score[k] += len(st["stages"]) + 2 * len(st["asks"])
            top = max(unresolved, key=lambda k: (score[k], -order.index(k)))
            for k in unresolved:
                if k == top:
                    ids[k] = "them"
                elif len(order) == 2 or score[k] == 0:
                    ids[k] = "me"
                else:
                    ids[k] = "them"

    out = []
    for t in raw:
        k = key(t.get("who"))
        out.append({"speaker": ids[k] if k else "unknown", "text": t["text"], "who": t.get("who"),
                    "date": t.get("date")})
    # Two-party thread: an unlabeled turn (e.g. the top reply of an email chain) belongs to the other party.
    if {"me", "them"} <= {o["speaker"] for o in out}:
        for i, o in enumerate(out):
            if o["speaker"] != "unknown":
                continue
            prev = next((out[j]["speaker"] for j in range(i - 1, -1, -1) if out[j]["speaker"] != "unknown"), None)
            nxt = next((out[j]["speaker"] for j in range(i + 1, len(out)) if out[j]["speaker"] != "unknown"), None)
            ref = prev or nxt
            if ref:
                o["speaker"] = "them" if ref == "me" else "me"
    return out


def split_turns(thread_text: str, me: Optional[Union[str, Iterable[str]]] = None) -> List[dict]:
    """Split a pasted/forwarded thread into chronological turns: {"speaker", "text", "who", "date"}.

    `me` optionally names the student (display name, email address or chat name) so their turns are labeled "me".
    """
    text = (thread_text or "")[:MAX_THREAD].replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return []
    lines = text.split("\n")
    raw = (_split_prefixed(lines, _WA_MSG, _WA_SYSTEM)
           or _split_prefixed(lines, _TS_MSG, None)
           or (_split_email(lines) if _email_like(lines) else None)
           or _split_labeled(lines))
    if not raw:
        raw = [{"who": None, "date": None, "text": text}]
    return _resolve_speakers(raw, me)


# ====================================================================== staging

def _rx(patterns):
    return [re.compile(p, _F) for p in patterns]


_STAGE_PATTERNS = {
    "hook": _rx([
        r"\byou(?:'ve|\s+have)\s+been\s+(?:selected|chosen|shortlisted|pre-?selected|recommended)\b",
        r"\b(?:got|obtained|received|found|saw)\s+your\s+(?:contact|info\w*|resume|cv|email|e-mail|number|details|profile)\s+"
        r"(?:through|from|via|on|in|at)\b",
        r"\bcame\s+across\s+your\s+(?:cv|resume|profile)\b|\brecommended\s+by\s+(?:several|multiple)\b",
        r"\b(?:sorry|apologi[sz]e)\s+(?:to|for)\s+(?:interrupt|bother|disturb)\w*\b",
        r"\b(?:are\s+you|would\s+you\s+be)\s+(?:interested|looking)\s+(?:in|for)\s+(?:a\s+)?(?:remote|part[- ]time|flexible|side|"
        r"extra|online)?\s*(?:job|work|position|opportunity|gig|income)\b",
        r"\$\s?\d{3,}[\d,]*(?:\.\d\d)?\s*(?:usd\s*)?(?:per\s+|a\s+|/\s*|each\s+|every\s+)?(?:week|weekly|day|daily)\b",
        r"\$\s?\d{2,3}\s*(?:-|to|–)\s*\$?\s?\d{3,}[\d,]*\s*(?:per\s+|a\s+|/\s*)?(?:day|daily)\b",
        r"\bno\s+(?:prior\s+)?(?:work\s+)?experience\s+(?:or\s+skill\s+)?(?:is\s+)?(?:required|needed|necessary)\b",
        r"\b(?:student\s+empowerment|part[- ]time\s+job\s+offer|job\s+offer\s+has\s+been\s+approved|dear\s+(?:selected|chosen)|"
        r"greetings,?\s+chosen|without\s+affecting\s+your)\b",
    ]),
    "legitimacy": _rx([
        r"\b(?:prof\.?|professor|dr\.)\s+(?:\[|[a-z]+\b)",
        r"\bcareer\s+(?:center|centre|services|development\s+(?:center|office))\b|\bcareer\s+fair\b",
        r"\b(?:department|dept\.?)\s+of\s+[a-z]+",
        r"\bschool'?s?\s+(?:recruiting|directory|database|admin\w*)\b|\buniversity\s+recruiting\b|"
        r"\bstudent\s+(?:services|employment)\b|\bjob\s+placement\b|\bstudent\s+directory\b",
        r"\b(?:hr|human\s+resources?)\s+(?:manager|department|representative|rep|consultant|specialist|team|officer|director)\b|"
        r"\bhead\s+of\s+recruitment\b|\b(?:talent|hiring)\s+(?:manager|acquisition|partner)\b|\bpayroll\s+(?:department|office)\b|"
        r"\baccount(?:s|ing)\s+(?:and\s+payroll\s+)?department\b|\bfinancial\s+advis[eo]r\b",
        r"\b(?:i'?m|i\s+am)\s+(?:a|an|the)\s+(?:\w+\s+)?recruit\w*\b|\brecruit(?:er|ment\s+assistant|ing\s+(?:coordinator|specialist))\s+"
        r"(?:at|from|with|for)\b|\bi'?m\s+from\s+(?:the\s+)?[a-z]+",
        r"\bon\s+behalf\s+of\b|\bauthori[sz]ed\s+representative\b|\bassisting\s+\w+\s+with\s+(?:its|their)\s+recruitment\b",
    ]),
    "channel_switch": _rx([
        r"\b(?:reach\s+out|contact|message|text|call)\w*\s+(?:to\s+)?you\s+(?:on|via|through|over)\s+(?:whats\s?app|telegram|signal|"
        r"text|sms|hangouts|teams)\b",
        r"\b(?:continue|move|switch|talk|chat)\w*\s+(?:this\s+|the\s+conversation\s+|our\s+conversation\s+)?(?:on|to|over|via)\s+"
        r"(?:whats\s?app|telegram|signal|text|sms|hangouts)\b",
        r"\bsave\s+my\s+number\b|\bmy\s+(?:personal|cell|direct)\s+(?:number|line)\b",
    ]),
    "onboarding": _rx([
        r"\bjob\s+(?:details|description)\b",
        r"\b(?:fill|complete)\w*\s+(?:out\s+)?(?:the|this|our|a)\s+(?:\w+\s+)?(?:form|questionnaire|survey)\b",
        r"\b(?:provide|send|reply\s+with|respond\s+with|confirm|include)\b[^.\n]{0,50}\b(?:following\s+(?:information|details)|"
        r"full\s+name|mailing\s+address|home\s+address|physical\s+address|phone\s+number|cell\s+phone|contact\s+(?:details|information))\b",
        r"\b(?:first|next)\s+(?:task|assignment)\b|\bemployment\s+agreement\b|\bquestionnaire\b",
        r"(?:^|\n)[\s*\-•\d.]*(?:full\s+name|mailing\s+address|home\s+address|phone\s+number|cell\s+#?)\s*[:.…]",
        r"\b(?:training|onboarding)\s+(?:session|materials?|starts?|link)\b|\bset\s+up\s+your\s+(?:account|profile)\b",
        r"\bpayroll\s+(?:interval|method)\b|\bprice\s+(?:inquiry|details|information|list)\b|\bregister\s+(?:in|on|with)\b",
        r"\byour\s+mentor\b|\bwill\s+train\s+you\b",
    ]),
    "data_grab": _rx([
        r"\b(?:what|which)\s+bank\b|\bdo\s+you\s+have\s+(?:a\s+)?(?:checking|bank|savings)\s+account\b",
        r"\b(?:your\s+)?bank(?:ing)?\s+(?:details|information|info)\b",
        r"\bmobile\s+(?:banking|deposit)\s+(?:app|limit)\b",
    ]),
    "pressure": _rx([
        r"\byou(?:'ll|\s+will)\s+be\s+(?:charged|reported|penali[sz]ed|terminated|blacklisted|sued|held\s+(?:responsible|liable))\b",
        r"\blegal\s+action\b|\blast\s+(?:chance|warning|reminder)\b",
        r"\b(?:complete|finish|do|make|send)\s+(?:it|this|the\s+\w+)\s+(?:today|now|asap|immediately|tonight|right\s+away)\b",
        r"\b(?:as\s+soon\s+as\s+possible|asap|right\s+away|without\s+delay)\b",
        r"\b(?:why|how\s+come)\s+(?:haven'?t|didn'?t|aren'?t)\s+you\b|\bare\s+you\s+done\b",
        r"\bhave\s+you\s+(?:made|completed|sent|done|received)\s+(?:the|it|your)\b",
        r"\b(?:account|funds?|earnings?|commissions?)\s+(?:will\s+be\s+)?(?:frozen|locked|forfeited|lost|suspended)\b",
        r"\bfailure\s+to\s+(?:comply|complete|respond|pay|deposit)\b|\bwaiting\s+(?:for|on)\s+(?:your|the)\s+"
        r"(?:confirmation|payment|response|receipt)\b",
    ]),
}
_STAGE_GUARDS = {"hook": [], "legitimacy": [], "channel_switch": ["negation", "disclaimer"],
                 "onboarding": ["disclaimer"], "data_grab": ["negation", "disclaimer", "post_hire"],
                 "pressure": ["negation", "disclaimer"]}
_ASK_STAGE = {"move_off_platform": "channel_switch", "personal_email_reply": "channel_switch",
              "bank_details": "data_grab", "identity_docs": "data_grab", "urgency": "pressure",
              "no_interview": "hook", "install_app": "onboarding"}


def stage_of(turn_text: str) -> dict:
    """Stages for one of the other side's messages, from asks.py plus a few stage-specific patterns."""
    norm = normalize(turn_text or "")
    asks = extract_asks(turn_text or "")
    evidence: Dict[str, str] = {}
    for a in asks:
        st = "ask" if a["ask"] in MONEY_ASKS and a["ask"] not in DATA_ASKS else _ASK_STAGE.get(a["ask"])
        if st and st not in evidence:
            evidence[st] = a["evidence"]
    for st, pats in _STAGE_PATTERNS.items():
        if st in evidence:
            continue
        for rx in pats:
            hit = next((m for m in rx.finditer(norm)
                        if not any(_GUARDS[g](norm, m) for g in _STAGE_GUARDS[st])), None)
            if hit is not None:
                evidence[st] = hit.group(0).strip()[:160]
                break
    stages = [s for s in STAGES if s in evidence]
    return {"stages": stages, "asks": asks, "evidence": evidence}


# ====================================================================== scripts

_OBS = {
    "move_off_platform": None,  # filled from the channel
    "personal_email_reply": "asked you to reply from a personal email",
    "no_interview": "skipped the interview",
    "install_app": "had you install an app",
    "bank_details": "asked about your bank",
    "identity_docs": "asked for your ID or SSN",
    "urgency": "rushed you",
    "pay_fee": "asked you to pay a fee",
    "buy_equipment": "told you to buy equipment from their vendor",
    "deposit_check": "sent you a check to deposit",
    "send_money_on": "asked you to send money on",
    "gift_cards": "asked you to buy gift cards",
    "crypto": "asked you to move money into crypto",
    "reship": "asked you to receive and re-ship packages",
    "receive_transfers": "asked you to pass payments through your account",
    "task_deposit": "asked you to deposit money to unlock earnings",
}

SCRIPTS = [
    {"id": "fake_check", "name": "fake-check",
     "key": {"deposit_check": 6, "buy_equipment": 6, "send_money_on": 3},
     "early": {"no_interview": 2, "move_off_platform": 1, "personal_email_reply": 2, "bank_details": 3, "legitimacy": 1},
     "cues": [r"\bresearch\s+assistant\b", r"\bpersonal\s+assistant\b", r"\b(?:professor|prof\.)", r"\boffice\s+(?:supplies|equipment|items)\b",
              r"\bprices?\s+(?:of|for|inquiry|details|list)\b|\bcheck\s+(?:online\s+)?(?:and\s+get\s+(?:me\s+)?)?the\s+prices?\b",
              r"\bfirst\s+task\b", r"\bout\s+of\s+town\b", r"\berrands?\b", r"\bmobile\s+(?:banking|deposit)\b", r"\bwhat\s+bank\b",
              r"\blaptop\b|\bprinter\b"],
     "next_step": "a check to deposit (usually by mobile deposit) and a 'vendor' to pay by Zelle or Cash App for your equipment. "
                  "The check bounces days later and your bank takes the full amount back from you.",
     "advice": "Don't deposit anything and don't send money.",
     "after": "the check bouncing within days. Your bank reverses it, anything you sent their 'vendor' is gone, and you owe the bank the difference; expect pressure to send more before that happens."},
    {"id": "task_scam", "name": "task-scam",
     "key": {"task_deposit": 6, "crypto": 3},
     "early": {"move_off_platform": 2, "hook": 1, "onboarding": 1},
     "cues": [r"\boptimi[sz]ation\b", r"\b(?:product|app|hotel|music|merchant)\s+(?:tasks?|data|ratings?|reviews?|views|downloads)\b",
              r"\bcommissions?\b", r"\bmerchants?\b", r"\bplay\s+counts?\b", r"\bmentor\b", r"\bwithdraw\w*\b",
              r"\bsets?\s+of\s+tasks\b|\btasks?\s+(?:per|a)\s+day\b", r"\b(?:boost|increase)\w*\s+(?:ratings?|views|downloads|rankings?)\b",
              r"\bproduct\s+tester\b|\b\d{2,3}\s*(?:-|to)\s*\d{2,3}\s+minutes\s+(?:a|per)\s+day\b"],
     "next_step": "a small first payout to build trust, then a 'combination order' or negative balance you must top up "
                  "(usually in crypto) before you can withdraw. The deposits never come back.",
     "advice": "Don't deposit or top up anything.",
     "after": "another 'combination order' demanding a bigger top-up, then fees or 'taxes' to release the withdrawal. None of it comes back."},
    {"id": "reshipping", "name": "reshipping",
     "key": {"reship": 6},
     "early": {"identity_docs": 2, "onboarding": 1},
     "cues": [r"\bpackages?\b|\bparcels?\b", r"\bshipping\b|\blogistics\b", r"\bquality\s+control\s+inspector\b|\bpackage\s+handler\b",
              r"\blabels?\b", r"\bforward\w*\b"],
     "next_step": "packages bought with stolen cards arriving at your address, with prepaid labels to relabel and ship them "
                  "overseas. The pay never arrives and the shipments trace back to you.",
     "advice": "Don't accept or forward packages, and don't send your ID.",
     "after": "packages bought with stolen cards arriving at your home with labels to reship; when the fraud surfaces the shipments trace to your address and the promised salary never arrives."},
    {"id": "gift_card_boss", "name": "gift-card boss",
     "key": {"gift_cards": 6},
     "early": {"move_off_platform": 1, "legitimacy": 1},
     "cues": [r"\bare\s+you\s+(?:available|free|around)\b", r"\bquick\s+(?:favou?r|task|errand)\b", r"\bin\s+a\s+(?:meeting|conference)\b",
              r"\bcan'?t\s+(?:talk|take\s+calls)\b", r"\b(?:client|staff|kids?|employee)\s+gifts?\b", r"\bsurprise\b"],
     "next_step": "an urgent request to buy gift cards 'for clients' and text photos of the codes, with a promise of "
                  "reimbursement that never comes.",
     "advice": "Don't buy gift cards for anyone; call the person on a number you already know.",
     "after": "requests for more cards, then silence once the codes are drained. The reimbursement never comes."},
    {"id": "crypto_recruiter", "name": "crypto recruiter",
     "key": {"crypto": 6},
     "early": {"move_off_platform": 1, "hook": 1},
     "cues": [r"\bbitcoin\b|\bbtc\b", r"\bcrypto\w*\b", r"\bwallet\b", r"\bcoinbase\b|\bbinance\b", r"\batms?\b", r"\bevaluator\b"],
     "next_step": "money or a check sent to you, with instructions to feed it into a Bitcoin ATM or wallet they control. "
                  "The deposit reverses and the crypto is gone.",
     "advice": "Don't deposit money for anyone or use a Bitcoin ATM on their instructions.",
     "after": "more money to route through the ATM; the original deposit reverses and you owe it back."},
    {"id": "advance_fee_training", "name": "advance-fee training",
     "key": {"pay_fee": 6},
     "early": {"no_interview": 1, "hook": 1},
     "cues": [r"\btraining\b", r"\bcertification\b|\bcertificate\b", r"\bcourse\b|\bmentorship\b", r"\benrol\w*\b",
              r"\bstarter\s+kit\b", r"\bbackground\s+check\b"],
     "next_step": "a fee for training, certification, a background check or a starter kit before you can start. "
                  "The job never materializes.",
     "advice": "Don't pay anything to get a job.",
     "after": "another fee (equipment, a background check, an 'exam'), then the recruiter disappears."},
    {"id": "identity_harvest", "name": "identity-harvest",
     "key": {},
     "early": {"identity_docs": 4, "bank_details": 2, "onboarding": 1, "personal_email_reply": 1, "move_off_platform": 1},
     "cues": [r"\bverify\s+your\s+identity\b", r"\bssn\b|\bsocial\s+security\b", r"\bdriver'?s?\s+licen[sc]e\b",
              r"\bdate\s+of\s+birth\b|\bdob\b", r"\bid\.me\b|\bw-?2\b|\btax\s+(?:form|return)\b"],
     "next_step": "requests for your SSN, a photo of your ID and your bank login 'for payroll', which is enough to open "
                  "accounts or file taxes in your name.",
     "advice": "Don't send ID or bank details until you've verified the employer yourself and hold a real offer.",
     "after": "your details being used to open accounts, take loans or file tax refunds in your name, often followed by a bank-login request to 'verify payroll'."},
    {"id": "money_mule", "name": "money-mule",
     "key": {"receive_transfers": 6, "send_money_on": 2},
     "early": {"bank_details": 2, "move_off_platform": 1},
     "cues": [r"\bpayment\s+processing\b|\bprocess\s+payments\b", r"\bon\s+behalf\s+of\s+(?:our\s+)?(?:international\s+)?clients\b",
              r"\bcommission\b", r"\bfinancial\s+agent\b|\btransfer\s+agent\b"],
     "next_step": "money landing in your account that you're told to forward on for a cut. That is laundering, and the "
                  "account holder (you) is who the bank and police come after.",
     "advice": "Don't let anyone move money through your account.",
     "after": "more transfers through your account until the bank freezes it, leaving you liable for the stolen funds."},
]
_SCRIPT_BY_ID = {s["id"]: s for s in SCRIPTS}
for _s in SCRIPTS:
    _s["_cues"] = [re.compile(c, _F) for c in _s["cues"]]

# Signals that legitimate recruiting threads essentially never produce; a script only matches on early stages when
# at least one is present, so a normal recruiter thread (hook, name-drop, forms) can't trip the early warning.
_SCAM_SIGNALS = set(MONEY_ASKS) | {"move_off_platform", "personal_email_reply", "no_interview", "install_app"}


def _channel_name(evidence: str) -> str:
    e = (evidence or "").lower()
    for k, v in (("whatsapp", "WhatsApp"), ("whats app", "WhatsApp"), ("telegram", "Telegram"), ("signal", "Signal"),
                 ("hangouts", "Google Hangouts"), ("teams", "Microsoft Teams"), ("instagram", "Instagram"),
                 ("wickr", "Wickr"), ("wechat", "WeChat")):
        if k in e:
            return v
    if "mail" in e:
        return "a personal email"
    return "text"


def _join(items: List[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _match_script(signals: set, them_text: str) -> tuple:
    best, best_score = None, 0
    for sc in SCRIPTS:
        key_hit = any(k in signals for k, w in sc["key"].items() if w >= 6)
        score = sum(w for k, w in sc["key"].items() if k in signals)
        early = sum(w for k, w in sc["early"].items() if k in signals)
        cues = sum(1 for rx in sc["_cues"] if rx.search(them_text))
        score += early + 2 * min(cues, 3)
        eligible = key_hit or (early >= 3 and signals & _SCAM_SIGNALS) or \
            (sum(w for k, w in sc["key"].items() if k in signals) > 0 and early + cues >= 3)
        if eligible and score > best_score:
            best, best_score = sc, score
    return best, best_score


def analyze_thread(thread_text: str, me: Optional[Union[str, Iterable[str]]] = None) -> dict:
    turns = split_turns(thread_text, me=me)
    out_turns = []
    trajectory: List[str] = []
    signals: set = set()
    ask_evidence: Dict[str, str] = {}
    channel_turn = data_turn_after = None
    first_late = None          # first turn with a data grab or money ask
    late_pressure = False      # pressure at/after that turn (urgency in the opening pitch is just part of the hook)
    them_texts = []
    for idx, t in enumerate(turns):
        if t["speaker"] == "me":
            out_turns.append({**t, "stages": [], "asks": [], "stage_evidence": {}})
            continue
        st = stage_of(t["text"])
        them_texts.append(normalize(t["text"]))
        out_turns.append({**t, "stages": st["stages"], "asks": st["asks"], "stage_evidence": st["evidence"]})
        for s in st["stages"]:
            if s not in trajectory:
                trajectory.append(s)
            signals.add(s)
        for a in st["asks"]:
            signals.add(a["ask"])
            ask_evidence.setdefault(a["ask"], a["evidence"])
        if first_late is None and ({"ask", "data_grab"} & set(st["stages"])):
            first_late = idx
        if "pressure" in st["stages"] and first_late is not None:
            late_pressure = True
        if "channel_switch" in st["stages"] and channel_turn is None:
            channel_turn = idx
        if "data_grab" in st["stages"] and channel_turn is not None and data_turn_after is None:
            data_turn_after = idx

    has_ask = "ask" in signals
    has_data = "data_grab" in signals
    core = [s for s in trajectory if s != "pressure" or late_pressure]
    furthest = max(core, key=lambda s: _STAGE_INDEX[s]) if core else None

    script, _score = _match_script(signals, "\n".join(them_texts))
    reached_early = bool(signals & {"channel_switch", "onboarding", "data_grab"})

    findings: List[Finding] = []
    evidence_list = [f"{a}: {e}" for a, e in ask_evidence.items()][:5]
    observations: List[str] = []
    for a in ask_evidence:
        if a == "urgency":
            continue
        if a == "move_off_platform":
            ct = next((t["text"] for t in out_turns if any(x["ask"] == a for x in t["asks"])), "")
            ev = ask_evidence[a]
            chan = _channel_name(ev) if re.search(r"text|sms|txt|mail|app|gram|signal|hangouts|teams|wickr|chat", ev, _F) \
                else _channel_name(ct)
            observations.append("moved you to " + chan)
        elif a == "send_money_on":
            e = (ask_evidence[a] + " " + next((t["text"] for t in out_turns
                                                if any(x["ask"] == a for x in t["asks"])), "")).lower()
            chan = next((v for k, v in (("zelle", "Zelle"), ("cash app", "Cash App"), ("cashapp", "Cash App"),
                                        ("venmo", "Venmo"), ("western union", "Western Union"), ("moneygram", "MoneyGram"),
                                        ("paypal", "PayPal"), ("wire", "wire")) if k in e), None)
            observations.append("asked you to send money" + (" by " + chan if chan else " on to someone else"))
        elif a in _OBS and _OBS[a]:
            observations.append(_OBS[a])
    if "channel_switch" in signals and "move_off_platform" not in ask_evidence and "personal_email_reply" not in ask_evidence:
        observations.insert(0, "moved you to another channel")
    if "data_grab" in signals and not (signals & DATA_ASKS):
        observations.append("asked about your bank")
    if late_pressure:
        observations.append("pressured you to act fast")
    observations = list(dict.fromkeys(observations))

    if script is not None and has_ask:
        why = (f"This follows the {script['name']} script: they {_join(observations)}. "
               f"What usually comes next: {script['after']} {script['advice']}")
        findings.append(Finding("conversation_script", "critical", 35, f"Thread follows the {script['name']} scam script",
                                why, evidence_list or [furthest or ""]))
    elif script is not None and reached_early:
        why = (f"This follows the {script['name']} script: they {_join(observations)}. "
               f"The next step is usually {script['next_step']} {script['advice']}")
        findings.append(Finding("conversation_script", "warning", 22,
                                f"Early warning: thread is tracking the {script['name']} script", why,
                                evidence_list or [furthest or ""]))
    if data_turn_after is not None:
        dg = out_turns[data_turn_after]["stage_evidence"].get("data_grab", "")
        cs = out_turns[channel_turn]["stage_evidence"].get("channel_switch", "")
        findings.append(Finding(
            "channel_switch_then_data", "warning", 20, "Moved you off-platform, then asked for bank or ID details",
            "Real employers collect banking and ID details through their HR or payroll system after a written offer, "
            "not over text or chat after moving you off the job board.", [s for s in (cs, dg) if s][:5]))

    non_money_scam = signals & {"move_off_platform", "personal_email_reply", "no_interview"}
    if has_ask or any(f.severity == "critical" for f in findings) or data_turn_after is not None:
        risk = "high"
    elif findings or has_data or non_money_scam or ("install_app" in signals and len(signals & _SCAM_SIGNALS) >= 2):
        risk = "medium"
    else:
        risk = "low"

    if findings and findings[0].rule_id == "conversation_script":
        warning = findings[0].why
    elif risk != "low":
        warning = (f"This thread has warning signs: they {_join(observations) or 'showed known scam patterns'}. "
                   "Verify the employer through its official website or your career center before sharing anything else.")
    else:
        warning = ("Nothing in this thread matches a known scam script. Still verify the employer through its official "
                   "site, and never deposit a check, buy anything or pay a fee to get a job.")

    order = {"critical": 0, "warning": 1, "note": 2}
    findings.sort(key=lambda f: (order[f.severity], -f.weight))
    return {
        "turns": out_turns,
        "trajectory": trajectory,
        "furthest_stage": furthest,
        "risk": risk,
        "warning": warning,
        "next_step": (script["after"] if has_ask else script["next_step"]) if script else None,
        "script": script["id"] if script else None,
        "findings": [f.as_dict() for f in findings],
    }
