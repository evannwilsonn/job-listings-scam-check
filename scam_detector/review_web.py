"""
The review page: where career-center staff decide what students reported, in a browser.

    GET  /review                         home: what needs attention, and this month's numbers for the school
    GET  /review/queue?tab=waiting       the queue (tabs: waiting, acted, close, decided), riskiest first
    POST /review/decide                  it's a scam / it's a real job / aggregator / not enough to tell
    GET  /review/settings, POST          the school's trusted and blocked domains (guardrails.py)
    GET  /review/trends                  the monthly trends report (trends.py)
    GET  /review/login, POST /review/login, POST /review/logout, GET|POST /review/password

Each report card shows what the detector says about it today: a 0-100 risk gauge, every red flag with its plain
explanation, aggregator / lead-gen signals, and cross-school evidence (links and contacts other schools' reviewers
confirmed, and confirmed scam scripts it matches). Decisions go through store.decide_report and
learning.after_decision, exactly like tools/review_queue.py; the reviewer's name comes from their account.

Security: accounts are made with tools/reviewers.py only. The session cookie is HttpOnly, SameSite=Strict, scoped to
/review and Secure unless REVIEW_COOKIE_SECURE=0 (local http only); the store keeps only its SHA-256. Every form carries
a CSRF token bound to the session. Login is rate limited per IP. Pages run no scripts (CSP). A reviewer sees and changes
only their own school; an account with no school (the LureCheck operator) sees every school.
"""

from __future__ import annotations

import datetime as dt
import html
import os
import re
import time
from urllib.parse import parse_qs, quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import guardrails, reviewers as acct
from .security import RateLimiter, client_key

router = APIRouter()
COOKIE = "lc_review"
login_limiter = RateLimiter(max_attempts=10, window_seconds=900)
QUEUE_MAX = 50
HARM = {"sent_money": "sent money", "deposited_check": "deposited a check", "shared_bank_details": "shared bank details",
        "shared_personal_info": "shared personal information", "shared_login": "shared a login",
        "gift_cards": "bought gift cards", "crypto": "sent crypto", "shipped_packages": "shipped packages",
        "installed_software": "installed software"}
BAND = {"block": "likely scam", "review": "needs a person", "caution": "be careful", "clear": "no scam signs"}
TAG_AGGREGATOR = "[aggregator]"
TAG_UNCLEAR = "[unclear]"
MIN_RATE = 10                                         # below this many confirmed scams a percentage means little
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
FONTS = ("https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT@9..144,500..700,0..100"
         "&family=Martian+Mono:wdth,wght@75..100,400..600&family=Plus+Jakarta+Sans:wght@400..700&display=swap")
HEADERS = {"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
                                      "font-src https://fonts.gstatic.com; form-action 'self'; frame-ancestors 'none'; "
                                      "base-uri 'none'",
           "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}
e = html.escape


def _store():
    from .store import get_store
    return get_store()


def _secure() -> bool:
    return os.environ.get("REVIEW_COOKIE_SECURE", "1") != "0"


async def _form(request: Request) -> dict:
    body = (await request.body()).decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}


def _who(request: Request):
    """(reviewer, token) for a valid session, else (None, "")."""
    token = request.cookies.get(COOKIE, "")
    if not token or len(token) > 200:
        return None, ""
    try:
        r = _store().session_reviewer(acct.token_hash(token))
    except Exception:                                   # noqa: BLE001 - a store outage reads as logged out
        r = None
    return (r, token) if r else (None, "")


def _school_label(code: str) -> str:
    return guardrails.school_name(code) or code or "Every school"


def _day(iso: str) -> str:
    try:
        d = dt.datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
        return f"{d:%b} {d.day}, {d.year}"
    except ValueError:
        return iso or ""


# ---------------------------------------------------------------- what the detector says about a report today

def assess(r: dict, st) -> dict:
    """Score the masked text the way /analyze would, plus what other schools' reviewers already confirmed."""
    from . import learning, ml
    from .scorer import _band, score_posting
    text = r.get("text_masked") or ""
    out = {"score": 0, "band": "clear", "flags": [], "lead_gen": {}, "network": [], "model": None}
    if not text:
        return out
    try:
        # The report's own links stand in for the apply chain: they only feed the aggregator / lead-gen axis
        # (tracking parameters, signup walls), never the scam score.
        res = score_posting(title="", description=text, company="", run_network=False, url_chain=_URL.findall(text)[:3])
    except Exception:                                   # noqa: BLE001
        return out
    flags = [f for f in res.findings if f.get("weight", 0) > 0]
    tm = learning.template_finding(text, st=st)
    if tm:
        flags.append(tm)
    try:
        matches = st.confirmed_matches(r.get("indicators") or {})
    except Exception:                                   # noqa: BLE001
        matches = []
    if matches:
        flags.append({"rule_id": "confirmed_scam_indicator", "severity": "critical", "weight": 40,
                      "title": "Uses a link or contact reviewers already confirmed as a scam",
                      "why": "Reviewers confirmed it in an earlier report. Details below."})
    school = r.get("school", "")
    rules = guardrails.rules_for(school)                # the school's own trusted / blocked lists, as students see them
    if rules["trusted"] or rules["blocked"]:
        flags = [f for f in guardrails.apply(flags, rules, text=text, school_name=guardrails.school_name(school))
                 if f.get("weight", 0) > 0]
    try:
        look = ml.second_look("", text, "", findings=flags, score=min(100, sum(f.get("weight", 0) for f in flags)))
    except Exception:                                   # noqa: BLE001
        look = None
    score = min(100, sum(f.get("weight", 0) for f in flags))
    band, _ = _band(score, any(f.get("severity") == "critical" for f in flags))
    model = (look or {}).get("model")
    p = model["probability"] if model else None
    # A wide gap between the rule score and the trained model is the case a person should read most carefully,
    # and the one where pre-selecting an answer would bias the label.
    disagree = p is not None and ((p >= 0.8 and score < 50) or (p <= 0.2 and score >= 75))
    out.update({"score": score, "band": band, "flags": flags, "lead_gen": res.lead_gen or {}, "network": matches,
                "template": tm, "model": model, "disagree": disagree})
    return out


def _zone(score: int) -> int:
    return 0 if score < 25 else 1 if score < 50 else 2 if score < 75 else 3


def _gauge(score: int, band: str) -> str:
    """The one place a card states its risk: a small instrument, the number, and the band in words."""
    z = _zone(score)
    return (f'<div class="gauge z{z}" role="img" aria-label="Risk {score} of 100, {e(BAND.get(band, band))}">'
            f'<div class="g-track"><i></i><i></i><i></i><i></i><b style="left:{max(0, min(100, score))}%"></b></div>'
            f'<span class="g-num">{score}</span><span class="g-band">{e(BAND.get(band, band))}</span></div>')


_GREETING = re.compile(r"^\s*(?:hello|hi|hey|dear|good (?:morning|afternoon|evening))\b[^.!?,\n]{0,40}[.!?,\n]+\s*", re.I)


def _headline(text: str) -> str:
    """What the report is about, in one line: its first real sentence."""
    t = _GREETING.sub("", (text or "").strip())
    first = re.split(r"(?<=[.!?])\s+|\n", t, maxsplit=1)[0].strip() or t[:90]
    first = first[:1].upper() + first[1:]
    return first if len(first) <= 96 else first[:93].rsplit(" ", 1)[0] + "…"


def _matched_in(text: str, f: dict) -> list:
    """The phrases a flag matched, as the student's message actually wrote them."""
    low, out = (text or "").lower(), []
    for m in f.get("matched") or []:
        if isinstance(m, str) and len(m.strip()) >= 3 and m.lower() in low:
            i = low.index(m.lower())
            out.append(text[i:i + len(m)])
    return out


def _spans(text: str, f: dict) -> list:
    low, out = text.lower(), []
    for m in _matched_in(text, f):
        i = low.find(m.lower())
        while i != -1:
            out.append((i, i + len(m)))
            i = low.find(m.lower(), i + len(m))
    return out


def _flag_groups(text: str, flags: list) -> list:
    """Flags whose matched words overlap in the message, merged into one line led by the strongest."""
    spans = [_spans(text, f) for f in flags]
    parent = list(range(len(flags)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    for i in range(len(flags)):
        for j in range(i + 1, len(flags)):
            if any(a < d and c < b for a, b in spans[i] for c, d in spans[j]):
                parent[root(j)] = root(i)
    groups: dict = {}
    for i, f in enumerate(flags):
        groups.setdefault(root(i), []).append(f)
    out = [sorted(g, key=lambda f: -f.get("weight", 0)) for g in groups.values()]
    return sorted(out, key=lambda g: -sum(f.get("weight", 0) for f in g))


def _highlight(text: str, flags: list) -> str:
    """The message with every phrase a red flag matched marked in place, so the evidence is read, not described."""
    low, spans = text.lower(), []
    for f in flags:
        for m in _matched_in(text, f):
            start = low.find(m.lower())
            while start != -1:
                spans.append((start, start + len(m)))
                start = low.find(m.lower(), start + len(m))
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    out, pos = [], 0
    for a, b in merged:
        out.append(e(text[pos:a]) + f"<mark>{e(text[a:b])}</mark>")
        pos = b
    return "".join(out) + e(text[pos:])


# ---------------------------------------------------------------- page shell

CSS = """
:root{--paper:#F6F5F1;--card:#FFFFFF;--ink:#0B1424;--soft:#4A5568;--dim:#7A8597;--line:#E3E1DA;--line2:#D3D0C6;
--navy:#0B1424;--navy2:#13213A;--gold:#C99B45;--gold-hi:#E2BE6A;
--g:#2F9E6E;--y:#D6981F;--o:#E2702F;--r:#D2343B;--g-t:#E5F4EC;--y-t:#FBF1DC;--o-t:#FCE9DD;--r-t:#FBE3E3;--b-t:#E8EEF8;--b:#2C5AA0;--v:#6A4C9C;--v-t:#F0EBF8;--v-l:#CDBFE6;
--display:'Fraunces',Georgia,serif;--sans:'Plus Jakarta Sans',system-ui,-apple-system,Segoe UI,sans-serif;--mono:'Martian Mono',ui-monospace,Menlo,monospace}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font:15px/1.55 var(--sans);background:var(--paper);color:var(--ink)}
a{color:var(--b)}
header{background:var(--navy);color:#E8ECF4;padding:0 16px}
.hd{max-width:1040px;margin:0 auto;display:flex;flex-wrap:wrap;gap:10px 22px;align-items:center;min-height:60px;padding:8px 0}
.brand{display:flex;align-items:center;gap:9px;font:700 20px var(--display);font-variation-settings:'SOFT' 60;color:#fff;text-decoration:none}
.brand small{font:600 10px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--gold-hi);border:1px solid #ffffff2a;border-radius:999px;padding:2px 8px}
.mark{width:22px;height:22px}
nav.main{display:flex;gap:4px;flex-wrap:wrap;flex:1}
nav.main a{color:#C9D2E3;text-decoration:none;padding:6px 10px;border-radius:7px;font-weight:600;font-size:14px}
nav.main a.on{background:#ffffff1a;color:#fff}
.me{display:flex;align-items:center;gap:10px;font-size:13px;color:#C9D2E3}
.me form{margin:0}.me button{background:none;border:1px solid #ffffff3a;color:#fff;border-radius:7px;padding:5px 10px;font:600 13px var(--sans);cursor:pointer}
main{max-width:1040px;margin:0 auto;padding:22px 16px 48px}
h1{font:700 28px/1.2 var(--display);font-variation-settings:'SOFT' 60;margin:4px 0 6px}
h2{font:700 19px/1.25 var(--display);margin:0 0 10px}
.sub{color:var(--soft);margin:0 0 18px;max-width:720px}
.kick{font:600 11px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:0 0 14px}
.tabs{display:flex;gap:2px;flex-wrap:wrap;border-bottom:1px solid var(--line2);margin:0 0 16px}
.tabs a{display:flex;align-items:baseline;gap:7px;padding:10px 14px 9px;text-decoration:none;color:var(--soft);font-weight:600;font-size:14px;border-bottom:3px solid transparent;margin-bottom:-1px}
.tabs a b{font:600 18px var(--mono);color:var(--ink)}.tabs a.on{color:var(--ink);border-color:var(--gold)}.tabs a.urgent b{color:var(--r)}
.r-head{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;justify-content:space-between;margin-bottom:8px}
.r-id{font:500 12px var(--mono);color:var(--dim)}
.pill{display:inline-flex;align-items:center;gap:6px;font:600 11.5px var(--mono);letter-spacing:.02em;border-radius:999px;padding:3px 10px;white-space:nowrap}
.p0{background:var(--g-t);color:#1E7350}.p1{background:var(--y-t);color:#8A5B00}.p2{background:var(--o-t);color:#9A4310}.p3{background:var(--r-t);color:#A1222A}
.tag{display:inline-block;font:600 12px var(--sans);border-radius:6px;padding:2px 8px;background:#EEF0F3;color:var(--soft)}
.tag.harm{background:var(--r-t);color:#A1222A}.tag.close{background:var(--y-t);color:#8A5B00}.tag.agg{background:var(--v-t);color:var(--v)}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px}
.gauge{display:flex;align-items:center;gap:8px;margin:2px 0 12px;max-width:520px}
.g-end{font:500 11px var(--mono);color:var(--dim)}.g-num{font:700 16px var(--mono);min-width:3ch}
.g-track{position:relative;flex:1;height:6px;margin:0 9px;display:grid;grid-template-columns:repeat(4,1fr);gap:2px}
.g-track i:nth-child(1){background:var(--g);border-radius:999px 0 0 999px}.g-track i:nth-child(2){background:var(--y)}
.g-track i:nth-child(3){background:var(--o)}.g-track i:nth-child(4){background:var(--r);border-radius:0 999px 999px 0}
.g-track b{position:absolute;top:50%;width:16px;height:16px;margin:-8px 0 0 -8px;border-radius:50%;background:#fff;border:3px solid var(--mk);box-shadow:0 1px 3px #0003}
.z0{--mk:var(--g)}.z1{--mk:var(--y)}.z2{--mk:var(--o)}.z3{--mk:var(--r)}.z0 .g-num{color:var(--g)}.z1 .g-num{color:var(--y)}.z2 .g-num{color:var(--o)}.z3 .g-num{color:var(--r)}
.flags{list-style:none;margin:0 0 12px;padding:0}
.flags li{border-left:3px solid var(--mk,var(--o));padding:2px 0 2px 11px;margin:0 0 9px}
.flags li.crit{--mk:var(--r)}.flags li.warn{--mk:var(--o)}.flags li.note{--mk:var(--line2)}
.flags b{display:block;font-size:14px}.flags span{display:block;color:var(--soft);font-size:13.5px}
.text{white-space:pre-wrap;word-break:break-word;background:#FAFAF8;border:1px solid var(--line);border-radius:9px;padding:11px 13px;font-size:14.5px;max-height:320px;overflow:auto;margin:0 0 12px}
.net{background:var(--b-t);border:1px solid #CFDCF0;border-radius:9px;padding:10px 13px;margin:0 0 12px;font-size:13.5px}
.net strong{display:block;font-size:12px;font-family:var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--b);margin-bottom:4px}
.net ul{margin:0;padding-left:18px}
.meta{font-size:13px;color:var(--dim);margin:0 0 10px}
form.decide{display:flex;flex-wrap:wrap;gap:8px;align-items:center;border-top:1px solid var(--line);padding-top:12px;margin-top:4px}
form.decide input[type=text]{flex:1 1 200px;min-width:0;padding:9px 11px;border:1px solid var(--line2);border-radius:8px;font:inherit;background:#fff}
.btn{border:1px solid transparent;border-radius:8px;padding:9px 14px;font:700 14px var(--sans);cursor:pointer;background:#EEF0F3;color:var(--ink)}
.btn.scam{background:var(--r);color:#fff}.btn.real{background:var(--g);color:#fff}.btn.agg{background:#fff;border-color:var(--v-l);color:var(--v)}
.btn.skip{background:#fff;border-color:var(--line2);color:var(--soft)}.btn.dark{background:var(--navy);color:#fff}
.flash{background:var(--g-t);border:1px solid #BFE3CF;border-radius:10px;padding:11px 14px;margin:0 0 16px}
.err{background:var(--r-t);border:1px solid #F2C2C2;border-radius:10px;padding:11px 14px;margin:0 0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:0 0 18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;text-decoration:none;color:inherit;display:block}
.stat b{display:block;font:700 30px/1.1 var(--mono);margin:4px 0 2px}.stat span{color:var(--soft);font-size:13.5px}
.stat.urgent b{color:var(--r)}.stat.ok b{color:var(--g)}
.two{display:grid;grid-template-columns:1.2fr 1fr;gap:14px}@media(max-width:760px){.two{grid-template-columns:1fr}}
.list{list-style:none;margin:0;padding:0}.list li{display:flex;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid var(--line);font-size:14px}.list li:last-child{border:0}
.bar{height:8px;border-radius:999px;background:#EEF0F3;overflow:hidden;margin:6px 0 2px}.bar i{display:block;height:100%;background:var(--g)}
table.rules{width:100%;border-collapse:collapse;font-size:14px}table.rules td,table.rules th{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
table.rules th{font:600 11px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--dim)}
.inline{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.inline input,.inline select{padding:9px 11px;border:1px solid var(--line2);border-radius:8px;font:inherit;background:#fff}
.inline input[name=value]{flex:1 1 220px}.inline input[name=reason]{flex:2 1 240px}
.login{max-width:400px;margin:40px auto}.login label{display:block;margin:12px 0 4px;font-weight:600}
.login input{width:100%;padding:10px 11px;border:1px solid var(--line2);border-radius:8px;font:inherit}.login .btn{margin-top:16px;width:100%}
.report{white-space:pre-wrap;font:13px/1.6 var(--mono)}
.empty{color:var(--soft);text-align:center;padding:28px 16px}
select{font:inherit}
/* Interaction: crisp and fast for a tool used every day. Presses answer at once, hovers only where a mouse exists,
   nothing animates that staff see dozens of times a day except the press itself. */
:root{--ease-out:cubic-bezier(.23,1,.32,1);--ease-in-out:cubic-bezier(.77,0,.175,1);
--shadow:0 1px 1px rgb(11 20 36/.03),0 2px 8px -3px rgb(11 20 36/.08);--ring:0 0 0 3px rgb(201 155 69/.32)}
body{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
::selection{background:#F3E3BC;color:var(--ink)}
.card,.stat{border-color:#E7E5DF;box-shadow:var(--shadow)}
.stat b,.tabs a b,.g-num,.r-id,.pill,.list b{font-variant-numeric:tabular-nums}
.btn,.me button,nav.main a,.tabs a,a.stat{-webkit-tap-highlight-color:transparent;touch-action:manipulation}
.btn,.me button{transition:transform 160ms var(--ease-out),background-color 150ms ease,border-color 150ms ease}
.btn:active,.me button:active{transform:scale(.97)}
a.stat{transition:transform 160ms var(--ease-out),border-color 150ms ease}a.stat:active{transform:scale(.985)}
nav.main a,.tabs a{transition:background-color 150ms ease,color 150ms ease}
input,select{transition:border-color 150ms ease,box-shadow 150ms ease}
input:focus,select:focus{outline:none;border-color:var(--gold);box-shadow:var(--ring)}
a:focus-visible,.btn:focus-visible,.me button:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
@media (hover:hover) and (pointer:fine){
nav.main a:hover{background:#ffffff12;color:#fff}.tabs a:hover{color:var(--ink)}
.btn.scam:hover{background:#BC2A31}.btn.real:hover{background:#278A5F}.btn.agg:hover{background:var(--v-t)}
.btn.skip:hover{background:#F7F7F4;border-color:#C4C0B4}.btn.dark:hover{background:var(--navy2)}.me button:hover{border-color:#ffffff70}
a.stat:hover{border-color:var(--line2)}}
.flash,.err{transition:opacity 220ms var(--ease-out),transform 220ms var(--ease-out)}
@starting-style{.flash,.err{opacity:0;transform:translateY(-4px)}}
@media (prefers-reduced-motion:reduce){.btn:active,.me button:active,a.stat:active{transform:none}
@starting-style{.flash,.err,.stub{transform:none}}}
/* Type in four steps: 12 labels, 14 secondary, 16 reading, 22/30 headings. */
body{font-size:16px}h1{font-size:30px}h2{font-size:22px}
.kick,.r-id,.tag,table.rules th,.g-band{font-size:12px}
.sub,.meta,.btn,nav.main a,.tabs a,.me,.stat span,.list li,.flags p,.flags q,.why-t,table.rules{font-size:14px}
.text,.flags b,.c-title,.tabs a b,.g-num{font-size:16px}.stat b{font-size:30px}
/* The card reads top to bottom the way a reviewer decides: what is it, the evidence, the flags, the answer. */
.c-head{display:flex;flex-wrap:wrap;gap:8px 20px;align-items:flex-start;justify-content:space-between;margin-bottom:10px}
.c-head>div:first-child{min-width:0;flex:1 1 320px}
.c-title{font-family:var(--sans);font-weight:700;line-height:1.35;margin:3px 0 0;text-wrap:balance}
.gauge{margin:2px 0 0;max-width:none;flex:0 0 auto;gap:9px}.g-track{flex:none;width:112px;margin:0 8px 0 0}
.g-band{font-family:var(--mono);font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--soft)}
.text mark{background:#FDE6A8;color:inherit;border-radius:3px;padding:0 2px;-webkit-box-decoration-break:clone;box-decoration-break:clone}
.flags li{padding:3px 0 3px 11px;margin:0 0 6px}
.flags q{display:block;color:var(--soft);font-family:var(--sans);quotes:"“" "”"}
.whys{margin:-4px 0 12px}.whys summary{cursor:pointer;color:var(--b);font-weight:600;font-size:14px;width:fit-content}
.whys[open] summary{color:var(--dim)}.whys p{margin:6px 0 0;color:var(--soft);font-size:14px;max-width:72ch}.whys p b{color:var(--ink)}
.agg-h{margin:0 0 6px;font:600 12px var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--v)}
.agg-h span{color:var(--dim);text-transform:none;letter-spacing:0;font-family:var(--sans)}.flags.agg li{--mk:var(--v-l)}
.split{margin:0 0 10px;padding:9px 12px;border-radius:9px;background:#EEF0F3;border-left:3px solid var(--navy);font-size:14px;color:var(--soft)}
.split b{color:var(--ink)}
.nw{white-space:nowrap}
.card.done{padding:0}.card.done>details>summary{list-style:none;cursor:pointer;padding:13px 18px;display:grid;
grid-template-columns:auto minmax(0,1fr) auto;gap:2px 12px;align-items:baseline}
.card.done>details>summary::-webkit-details-marker{display:none}
.d-title{font-weight:700;font-size:16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.d-v{font:600 12px var(--mono);letter-spacing:.04em;text-transform:uppercase}.v-scam{color:var(--r)}.v-real{color:#1E7350}
.v-aggregator{color:var(--v)}.v-not{color:var(--dim)}
.d-meta{grid-column:2/4;font-size:14px;color:var(--dim)}.d-meta em{font-style:normal;color:#1E7350;font-weight:600}
.card.done details[open]>summary{border-bottom:1px solid var(--line)}.d-body{padding:14px 18px 16px}
.d-body .c-head{justify-content:flex-start}.d-body .c-head>div:first-child{display:none}
.tag.seen{background:var(--b-t);color:var(--b);font-weight:700}
.btn{display:inline-flex;align-items:center;gap:8px}.btn i{width:8px;height:8px;border-radius:50%;flex:none}
.btn.primary{background:var(--navy);color:#fff}.btn.ghost{background:#fff;border-color:var(--line2);color:var(--ink)}
.stub{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;justify-content:space-between;background:var(--g-t);border-color:#BFE3CF;box-shadow:none}
.stub p{margin:0;flex:1 1 360px}.stub form{margin:0}
.stub{transition:opacity 220ms var(--ease-out),transform 220ms var(--ease-out)}@starting-style{.stub{opacity:0;transform:translateY(-4px)}}
.stat.static{background:transparent;box-shadow:none;border-style:dashed}
.also{display:block;grid-column:1;color:var(--dim);font-size:14px}
.flags details p+p{margin-top:6px}
.impact{margin:8px 0 0;font-size:14px;color:#1E7350;font-weight:600}
.impact-card{border-color:#CFE7DA}.impact-card b{font-family:var(--mono)}
kbd{font:600 12px var(--mono);border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;padding:0 5px;background:#fff;color:var(--ink)}
.kb{margin:-8px 0 14px}.kb-help .list li{font-size:14px}
article.card.kb-focus{outline:2px solid var(--gold);outline-offset:3px}
article.card:focus{outline:none}article.card.kb-focus:focus{outline:2px solid var(--gold)}
.doc-bar{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:space-between;margin:0 0 12px}.doc-bar p{margin:0}
.doc{padding:22px 26px;max-width:760px}.doc h2{font-size:22px;margin:0 0 12px}.doc h3{font:700 16px var(--sans);margin:20px 0 6px}
.doc p,.doc li{font-size:16px;max-width:68ch}.doc ul{padding-left:20px;margin:0}
.doc table{border-collapse:collapse;margin:6px 0 4px;font-size:14px;font-variant-numeric:tabular-nums}
.doc th,.doc td{text-align:left;padding:7px 14px 7px 0;border-bottom:1px solid var(--line)}
.doc th{font:600 12px var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--dim)}
.doc em{color:var(--dim);font-style:normal;font-size:14px}
.mnav{display:none}
@media (max-width:720px){
.hd{flex-wrap:nowrap;min-height:56px}nav.main,.hd>.me{display:none}
.mnav{display:block;margin-left:auto;position:relative}
.mnav summary{list-style:none;cursor:pointer;color:#fff;font:600 14px var(--sans);border:1px solid #ffffff3a;border-radius:8px;padding:7px 12px}
.mnav summary::-webkit-details-marker{display:none}.mnav summary::after{content:" ▾";color:var(--gold-hi)}
.mnav-body{position:absolute;right:0;top:calc(100% + 8px);z-index:5;min-width:240px;display:flex;flex-direction:column;gap:2px;
background:var(--navy2);border:1px solid #ffffff22;border-radius:12px;padding:8px;box-shadow:0 12px 32px -8px rgb(0 0 0/.45)}
.mnav-body a{color:#E8ECF4;text-decoration:none;padding:9px 10px;border-radius:7px;font-weight:600;font-size:14px}
.mnav-body a.on{background:#ffffff1a}.mnav-body .me{flex-direction:column;align-items:flex-start;gap:8px;padding:10px;border-top:1px solid #ffffff1a;margin-top:4px}
.tabs{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch}.tabs::-webkit-scrollbar{display:none}
.tabs a{white-space:nowrap;padding:10px 12px 9px}
.doc{padding:18px}.kb,#kb-help{display:none}
.grid{grid-template-columns:1fr 1fr;gap:10px}.stat{padding:12px 14px}.stat b{font-size:24px}
.card.done>details>summary{grid-template-columns:auto minmax(0,1fr);padding:12px 14px}.d-v{grid-column:2;grid-row:2}
.d-meta{grid-column:2}.d-body{padding:12px 14px 14px}}
@media (hover:hover) and (pointer:fine){.btn.primary:hover{background:var(--navy2)}.btn.ghost:hover{background:#F7F7F4;border-color:#C4C0B4}
.whys summary:hover,.card.done>details>summary:hover .d-title{text-decoration:underline;text-decoration-color:var(--line2);text-underline-offset:3px}}
"""
MARK = ('<svg class="mark" viewBox="0 0 40 40" aria-hidden="true"><path d="M20 3 L34 8 V19 C34 28 28 34 20 37 C12 34 6 28 6 19 V8 Z" '
        'fill="#13213A" stroke="#E2BE6A" stroke-width="2"/><path d="M20 11 L22.4 17.6 L29 20 L22.4 22.4 L20 29 L17.6 22.4 L11 20 '
        'L17.6 17.6 Z" fill="#E2BE6A"/></svg>')


def _page(title: str, body: str, who=None, token: str = "", status: int = 200, on: str = "") -> HTMLResponse:
    nav = ""
    if who:
        links = [("home", "/review", "Home"), ("queue", "/review/queue", "Reports"), ("trends", "/review/trends", "Trends"),
                 ("settings", "/review/settings", "School settings"), ("password", "/review/password", "Password")]
        items = "".join(f'<a href="{h}"{" class=on" if k == on else ""}>{t}</a>' for k, h, t in links)
        me = (f'<div class="me"><span>{e(who["name"])} · {e(_school_label(who["school"]))}</span>'
              f'<form method="post" action="/review/logout"><input type="hidden" name="csrf" value="{acct.csrf_for(token)}">'
              f'<button>Log out</button></form></div>')
        current = next((t for k, _, t in links if k == on), "Menu")
        nav = (f'<nav class="main">{items}</nav>{me}'
               f'<details class="mnav"><summary>{e(current)}</summary><div class="mnav-body">{items}{me}</div></details>')
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
           f'initial-scale=1"><title>{e(title)} · LureCheck for career centers</title>'
           f'<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
           f'<link rel="stylesheet" href="{FONTS}"><style>{CSS}</style><script src="/review/assets/review.js" defer></script></head><body>'
           f'<header><div class="hd"><a class="brand" href="/review">{MARK}LureCheck<small>Staff</small></a>{nav}</div></header>'
           f'<main>{body}</main></body></html>')
    return HTMLResponse(doc, status_code=status, headers=HEADERS)


def _to(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303, headers=HEADERS)


def _expired(who, token) -> HTMLResponse:
    return _page("Expired", '<div class="err">That form expired. Go back and try again.</div>', who, token, 403)


# ---------------------------------------------------------------- login

def _login_page(error: str = "", status: int = 200) -> HTMLResponse:
    err = f'<div class="err">{e(error)}</div>' if error else ""
    return _page("Log in", f'<div class="login card"><p class="kick">Career-center staff</p><h1>Log in</h1>'
                           f'<p class="sub">Ask the LureCheck operator for an account.</p>{err}<form method="post" action="/review/login">'
                           f'<label for="em">Email</label><input id="em" name="email" type="email" autocomplete="username" required>'
                           f'<label for="pw">Password</label><input id="pw" name="password" type="password" '
                           f'autocomplete="current-password" required><button class="btn dark">Log in</button></form></div>',
                 status=status)


_SCRIPT = os.path.join(os.path.dirname(__file__), "static", "review.js")


@router.get("/review/assets/review.js")
def review_script():
    from fastapi.responses import Response
    with open(_SCRIPT, "rb") as fh:
        return Response(fh.read(), media_type="application/javascript", headers={"Cache-Control": "no-cache"})


@router.get("/review/login", response_class=HTMLResponse)
def login_form(request: Request):
    who, _ = _who(request)
    return _to("/review") if who else _login_page()


@router.post("/review/login")
async def login(request: Request):
    key = client_key(request, "review-login")
    allowed, retry = login_limiter.check(key)
    if not allowed:
        return _login_page(f"Too many attempts. Try again in {retry // 60 + 1} minutes.", 429)
    login_limiter.hit(key)
    f = await _form(request)
    st = _store()
    r = st.reviewer_by_email(acct.normalize_email(f.get("email", "")))
    ok = acct.verify_password(f.get("password", ""), r["pw_hash"] if r else acct.DUMMY_HASH)
    if not (r and ok and r.get("active")):
        return _login_page("That email and password don't match an active reviewer account.", 401)
    token, h = acct.new_session()
    st.add_session(h, r["id"], time.time() + acct.SESSION_HOURS * 3600)
    st.touch_login(r["id"])
    resp = _to("/review")
    resp.set_cookie(COOKIE, token, max_age=acct.SESSION_HOURS * 3600, path="/review", httponly=True,
                    secure=_secure(), samesite="strict")
    return resp


@router.post("/review/logout")
async def logout(request: Request):
    who, token = _who(request)
    f = await _form(request)
    if who and acct.csrf_ok(token, f.get("csrf", "")):
        _store().drop_session(acct.token_hash(token))
    resp = _to("/review/login")
    resp.delete_cookie(COOKIE, path="/review")
    return resp


# ---------------------------------------------------------------- the queue

UNDO_SECONDS = 120
TABS = ("waiting", "acted", "close", "decided")


def _groups(rows: list) -> dict:
    pending = [r for r in rows if r.get("status") == "reported"]
    return {"waiting": pending, "acted": [r for r in pending if r.get("outcome") in HARM],
            "close": [r for r in pending if r.get("kind") == "borderline"],
            "decided": [r for r in rows if r.get("status") != "reported"]}


def _ordered(st, who, tab: str):
    """(groups, [(report, assessment)]) for a tab, in the order staff see it."""
    g = _groups(st.list_reports("", who["school"]))
    rows = g[tab]
    if tab == "decided":
        rows = sorted(rows, key=lambda r: r.get("reviewed_at") or "", reverse=True)[:QUEUE_MAX]
        return g, [(r, assess(r, st)) for r in rows]
    scored = [(r, assess(r, st)) for r in rows]
    scored.sort(key=lambda x: (x[0].get("outcome") not in HARM, -x[1]["score"], x[0].get("received", "")))
    return g, scored[:QUEUE_MAX]


def _tabs(g: dict, on: str) -> str:
    names = [("waiting", "Waiting"), ("acted", "Students who acted"), ("close", "Close calls"), ("decided", "Decided")]
    out = []
    for k, label in names:
        cls = " ".join(c for c in ("on" if k == on else "", "urgent" if k == "acted" and g[k] else "") if c)
        attr = f' class="{cls}"' if cls else ""
        out.append(f'<a href="/review/queue?tab={k}"{attr}><b>{len(g[k])}</b>{label}</a>')
    return '<nav class="tabs">' + "".join(out) + "</nav>"


def _seen_stamp(a: dict) -> str:
    schools = max([m.get("schools") or 0 for m in a["network"]] or [0])
    if schools:
        return f'<span class="tag seen">Confirmed as a scam at {schools} school{"s" if schools != 1 else ""} before</span>'
    tm = a.get("template") or {}
    if tm.get("rule_id") == "peer_scam_template":
        return '<span class="tag seen">Same script confirmed at another school</span>'
    if tm:
        return '<span class="tag seen">Same script confirmed here before</span>'
    return ""


def _network_why(a: dict) -> str:
    word = {"wallet": "A crypto wallet", "email": "An email address", "phone": "A phone number"}
    bits = []
    for m in a["network"]:
        what = m["value"] if m["kind"] == "domain" else word.get(m["kind"], "A contact")
        n, sc = m.get("reports") or 0, m.get("schools") or 0
        bits.append(f"{what} was confirmed as a scam in {n} earlier report{'s' if n != 1 else ''}"
                    f"{f' at {sc} school' + ('s' if sc != 1 else '') if sc else ''}, last seen {_day(m.get('last_seen', ''))}.")
    return " ".join(bits)


DOT = {"scam": "var(--r)", "real": "var(--g)", "aggregator": "var(--v)", "unclear": "var(--dim)"}


def _verdict(r: dict) -> str:
    note = r.get("note") or ""
    if r.get("status") == "confirmed":
        return "Scam"
    if note.startswith(TAG_AGGREGATOR):
        return "Aggregator"
    if note.startswith(TAG_UNCLEAR):
        return "Not enough to tell"
    return "Real job" if r.get("status") == "dismissed" else r.get("status", "")


def _pct(p: float) -> str:
    pct = p * 100
    return "over 99%" if pct >= 99.5 else f"{round(pct)}%"


def _buttons(a: dict, neutral: bool = False) -> str:
    """The likely answer is the primary button: scam when the detector leans that way, real job when it doesn't.
    No answer is pre-selected on close calls or when the rules and the model disagree: the reviewer's call there is
    the label, and an emphasised button would pull it toward the rules."""
    lean = None if neutral else "scam" if a["band"] in ("block", "review") or a["network"] else "real"
    labels = [("scam", "It's a scam"), ("real", "It's a real job"), ("aggregator", "Aggregator"), ("unclear", "Not enough to tell")]
    return "".join(f'<button class="btn {"primary" if k == lean else "ghost"}" name="action" value="{k}">'
                   f'<i style="background:{DOT[k]}"></i>{t}</button>' for k, t in labels)


def _card(r: dict, a: dict, who: dict, token: str, tab: str = "waiting", impact: int = 0) -> str:
    decided = tab == "decided"
    text = r.get("text_masked") or ""
    lg = a.get("lead_gen") or {}
    school = f" · {e(_school_label(r.get('school', '')))}" if not who["school"] else ""
    head = (f'<div class="c-head"><div><span class="r-id">Report #{e(r["id"])} · {e(_day(r.get("received", "")))}{school}</span>'
            f'<h3 class="c-title">{e(_headline(text)) if text else "Text removed after 30 days"}</h3></div>'
            f'{_gauge(a["score"], a["band"])}</div>')
    tags = [_seen_stamp(a)]
    if r.get("outcome") in HARM:
        tags.append(f'<span class="tag harm">Student already {e(HARM[r["outcome"]])}</span>')
    if r.get("kind") == "borderline":
        tags.append('<span class="tag close">Close call: the detector asked for a person</span>')
    if lg.get("flag"):
        tags.append('<span class="tag agg">Looks like an aggregator or lead-gen page</span>')
    tags = "".join(t for t in tags if t)
    body = head + (f'<div class="tags">{tags}</div>' if tags else "")
    if a.get("disagree") and a.get("model"):
        body += (f'<p class="split"><b>The rules and the trained model disagree.</b> Rules: {a["score"]} of 100. '
                 f'Model: {_pct(a["model"]["probability"])} likely a scam. Read this one closely.</p>')
    body += f'<div class="text">{_highlight(text, a["flags"]) if text else "(the text was removed after 30 days)"}</div>'
    items, whys_all = [], []
    for group in _flag_groups(text, a["flags"]):
        lead = group[0]
        sev = "crit" if any(f.get("severity") == "critical" for f in group) else "warn"
        if lead.get("rule_id") == "confirmed_scam_indicator":
            quote = ", ".join(m["value"] for m in a["network"] if m["kind"] == "domain")
            whys = [("", _network_why(a))]
        else:
            quotes = [q for f in group for q in _matched_in(text, f)]
            quote = max(quotes, key=len) if quotes else ""
            whys = [(f.get("title", "") if len(group) > 1 else "", f.get("why", "")) for f in group]
        also = (f'<span class="also">Also: {" · ".join(e(f.get("title", "")) for f in group[1:])}</span>'
                if len(group) > 1 else "")
        whys_all += [(t or lead.get("title", ""), w) for t, w in whys if w]
        items.append(f'<li class="{sev}"><b>{e(lead.get("title", ""))}</b>'
                     f'{f"<q>{e(quote)}</q>" if quote else ""}{also}</li>')
    agg = []
    for rs in (lg.get("reasons") or [])[:3]:
        agg.append(f'<li class="note"><q>{e((rs.get("matched") or [""])[0])}</q><span class="also">{e(rs.get("reason", ""))}</span></li>')
    if items:
        body += f'<ul class="flags">{"".join(items)}</ul>'
    elif not decided:
        body += '<p class="meta">No red flags from the rules. That alone doesn\'t make it real; read it.</p>'
    if whys_all:
        body += ('<details class="whys"><summary>Why these were flagged</summary>'
                 + "".join(f'<p><b>{e(t)}.</b> {e(w)}</p>' for t, w in whys_all) + '</details>')
    if agg:
        body += (f'<p class="agg-h">Aggregator signs <span>· not part of the risk score</span></p>'
                 f'<ul class="flags agg">{"".join(agg)}</ul>')
    ind = r.get("indicators") or {}
    bits = []
    if ind.get("domains"):
        bits.append("Links: " + ", ".join(e(d) for d in ind["domains"][:6]))
    for k, word in (("email_hashes", "email address"), ("phone_hashes", "phone number"), ("wallets", "crypto wallet")):
        n = len(ind.get(k) or [])
        if n:
            bits.append(f"{n} {word}{'es' if word.endswith('ss') and n > 1 else 's' if n > 1 else ''} hidden")
    if a.get("model") and not a.get("disagree"):
        bits.append(f"Trained model: {_pct(a['model']['probability'])} likely a scam")
    if bits:
        body += f'<p class="meta">{" · ".join(bits)}</p>'
    if decided:
        note = (r.get("note") or "").replace(TAG_AGGREGATOR, "").replace(TAG_UNCLEAR, "").strip()
        if note:
            body += f'<p class="meta">Note: {e(note)}</p>'
        if impact:
            body += (f'<p class="impact">Since it was confirmed, this script has flagged {impact:,} later '
                     f'check{"s" if impact != 1 else ""}.</p>')
        v = _verdict(r)
        hits = f' · <em>flagged {impact:,} later check{"s" if impact != 1 else ""}</em>' if impact else ""
        row = (f'<summary class="d-row"><span class="r-id">#{e(r["id"])}</span>'
               f'<span class="d-title">{e(_headline(text)) if text else "Text removed after 30 days"}</span>'
               f'<span class="d-v v-{v.split()[0].lower()}">{e(v)}</span>'
               f'<span class="d-meta">{e(r.get("reviewer", ""))} · {e(_day(r.get("reviewed_at", "")))}{hits}</span></summary>')
        return f'<article class="card done" id="r-{e(r["id"])}"><details>{row}<div class="d-body">{body}</div></details></article>'
    body += (f'<form class="decide" method="post" action="/review/decide"><input type="hidden" name="csrf" '
             f'value="{acct.csrf_for(token)}"><input type="hidden" name="id" value="{e(r["id"])}">'
             f'<input type="hidden" name="tab" value="{e(tab)}">'
             f'<input type="text" name="note" maxlength="500" placeholder="Note (optional)" aria-label="Note">'
             f'{_buttons(a, neutral=bool(a.get("disagree")) or r.get("kind") == "borderline")}</form>')
    return f'<article class="card" id="r-{e(r["id"])}">{body}</article>'


FLASH = {"scam": "Confirmed as a scam. Copies of this script are now flagged on every check, its links and contacts "
                 "are shared with other LureCheck schools, and it's in the next retrain.",
         "real": "Marked as a real job. It's a 'real' example for the next retrain, so look-alikes are less likely to be flagged.",
         "aggregator": "Marked as an aggregator. It's kept out of training in both directions.",
         "unclear": "Closed as not enough to tell. Nothing is learned from it."}


def _stub(n: str, done: str, token: str, tab: str) -> str:
    if done == "undone":
        return f'<div class="card stub" id="decided"><p><b>Report #{e(n)}</b> is back in the queue. Nothing was kept from that decision.</p></div>'
    return (f'<div class="card stub" id="decided"><p><b>Report #{e(n)}.</b> {e(FLASH[done])}</p>'
            f'<form method="post" action="/review/undo"><input type="hidden" name="csrf" value="{acct.csrf_for(token)}">'
            f'<input type="hidden" name="id" value="{e(n)}"><input type="hidden" name="tab" value="{e(tab)}">'
            f'<button class="btn ghost">Undo</button></form></div>')


@router.get("/review/queue", response_class=HTMLResponse)
def queue(request: Request, tab: str = "waiting", done: str = "", n: str = "", at: str = ""):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    tab = tab if tab in TABS else "waiting"
    st = _store()
    g, scored = _ordered(st, who, tab)
    stub = _stub(n, done, token, tab) if (done in FLASH or done == "undone") and n.isdigit() else ""
    impact = {}
    if tab == "decided":
        from . import counts, memory
        keys = {str(r["id"]): memory.text_key(r["text_masked"]) for r, _ in scored
                if r.get("status") == "confirmed" and r.get("text_masked")}
        found = counts.hits(list(keys.values()), st=st)
        impact = {rid: found.get(k, 0) for rid, k in keys.items()}
    cards, placed = [], False
    for r, a in scored:
        if stub and not placed and str(r["id"]) == at:
            cards.append(stub)
            placed = True
        cards.append(_card(r, a, who, token, tab, impact.get(str(r["id"]), 0)))
    if stub and not placed:
        cards.insert(0, stub) if not at else cards.append(stub)
    if not scored:
        from . import counts
        week = counts.totals(who["school"], (dt.date.today() - dt.timedelta(days=6)).isoformat(), st)
        if tab == "decided":
            msg = "Nothing decided yet."
        elif week["checks"]:
            msg = (f"Queue clear. Students checked {week['checks']:,} message{'s' if week['checks'] != 1 else ''} this week "
                   f"without needing you, and {week['flagged']:,} of them were flagged before anyone had to report them.")
        else:
            msg = "Queue clear. New reports show up here as students send them."
        cards.append(f'<div class="card empty">{e(msg)}</div>')
    sub = {"waiting": "Students who already acted come first, then the riskiest. Your answer becomes a training label, "
                      "so 'Not enough to tell' is better than a guess.",
           "acted": "These students already did something. Decide these first; the student was shown what to do next.",
           "close": "The detector couldn't settle these and the student agreed to let a person look. "
                    "These teach the detector the most.",
           "decided": f"The last {QUEUE_MAX} decisions. Open one to see the report. You can undo your own for "
                      f"{UNDO_SECONDS // 60} minutes; after that, ask the operator."}[tab]
    keys = ('<p class="meta kb" id="kb-hint" hidden>Keyboard: <kbd>J</kbd> <kbd>K</kbd> move · <kbd>S</kbd> scam · '
            '<kbd>R</kbd> real job · <kbd>A</kbd> aggregator · <kbd>N</kbd> not enough to tell · <kbd>U</kbd> undo · '
            '<kbd>?</kbd> all keys</p>'
            '<div class="card kb-help" id="kb-help" hidden><h2>Keyboard</h2><ul class="list">'
            '<li><span>Next / previous report</span><b><kbd>J</kbd> <kbd>K</kbd></b></li>'
            '<li><span>It\'s a scam</span><b><kbd>S</kbd></b></li><li><span>It\'s a real job</span><b><kbd>R</kbd></b></li>'
            '<li><span>Aggregator</span><b><kbd>A</kbd></b></li><li><span>Not enough to tell</span><b><kbd>N</kbd></b></li>'
            '<li><span>Write a note</span><b><kbd>E</kbd></b></li><li><span>Undo the last decision</span><b><kbd>U</kbd></b></li>'
            '<li><span>Show or hide this</span><b><kbd>?</kbd></b></li></ul></div>')
    return _page("Reports", f'<p class="kick">{e(_school_label(who["school"]))}</p><h1>Reports from students</h1>'
                            f'{_tabs(g, tab)}<p class="sub">{e(sub)}</p>{keys}{"".join(cards)}', who, token, on="queue")


@router.get("/review", response_class=HTMLResponse)
def home(request: Request):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    from . import trends
    st = _store()
    g = _groups(st.list_reports("", who["school"]))
    month = dt.date.today().strftime("%Y-%m")
    schools = [who["school"]] if who["school"] else sorted(guardrails._config())
    tot = {"confirmed": 0, "confirmed_prev": 0, "caught": 0, "real": 0}
    fam: dict = {}
    for sc in schools:
        try:
            d = trends.monthly(sc, month, st)
        except Exception:                               # noqa: BLE001
            continue
        tot["confirmed"] += d["confirmed"]
        tot["confirmed_prev"] += d["confirmed_prev"]
        tot["caught"] += d["caught"]
        tot["real"] += d["real_jobs_labeled"]
        for name, a, _ in d["families"]:
            fam[name] = fam.get(name, 0) + a
    from . import counts
    used = counts.totals(who["school"], month + "-01", st)
    acted = len(g["acted"])
    tiles = [(f'<a class="stat{" urgent" if acted else ""}" href="/review/queue?tab=acted"><span class="kick">Already acted</span>'
              f'<b>{acted}</b><span>students who sent money or details</span></a>', 0 if acted else 1),
             (f'<a class="stat" href="/review/queue"><span class="kick">Waiting</span><b>{len(g["waiting"])}</b>'
              f'<span>reports to decide</span></a>', 0.5),
             (f'<a class="stat" href="/review/queue?tab=close"><span class="kick">Close calls</span><b>{len(g["close"])}</b>'
              f'<span>the detector asked for a person</span></a>', 2)]
    tiles = "".join(t for t, _ in sorted(tiles, key=lambda x: x[1]))
    stats = (f'<div class="grid">{tiles}<div class="stat static"><span class="kick">This month</span><b>{used["checks"]:,}</b>'
             f'<span>messages students checked, {used["flagged"]:,} flagged · {tot["confirmed"]} scams confirmed</span></div></div>')
    pct = round(tot["caught"] / tot["confirmed"] * 100) if tot["confirmed"] else 0
    reals = f'{tot["real"]} real job{"" if tot["real"] == 1 else "s"} labeled this month, which keeps false alarms down.'
    keep = (f'<div class="card"><h2>Is the detector keeping up?</h2><p class="sub" style="margin-bottom:6px">Of this month\'s '
            f'confirmed scams, today\'s detector flags <b>{tot["caught"]} of {tot["confirmed"]}</b> on its own.</p>'
            + (f'<div class="bar"><i style="width:{pct}%"></i></div><p class="meta">{pct}% · the rest are what the next '
               f'rules and retrain learn from. {reals}</p>' if tot["confirmed"] >= MIN_RATE else
               f'<p class="meta">Too few to call it a rate yet; a percentage shows from {MIN_RATE} confirmed scams. {reals}</p>')
            + '</div>'
            if tot["confirmed"] else
            '<div class="card"><h2>Is the detector keeping up?</h2><p class="sub">No confirmed scams yet this month. '
            'Once reviewers confirm some, this shows how many the detector catches on its own.</p></div>')
    kinds = "".join(f"<li><span>{e(k)}</span><b>{v}</b></li>" for k, v in sorted(fam.items(), key=lambda x: -x[1])[:5] if v)
    kinds = (f'<div class="card"><h2>What\'s hitting students</h2><ul class="list">{kinds}</ul>'
             f'<p class="meta"><a href="/review/trends">Full monthly report</a></p></div>' if kinds else
             '<div class="card"><h2>What\'s hitting students</h2><p class="sub">Scheme types appear here once scams are confirmed.</p></div>')
    recent = sorted(g["decided"], key=lambda r: r.get("reviewed_at") or "", reverse=True)[:5]
    rec = "".join(f'<li><span>#{e(r["id"])} · {e(_headline(r.get("text_masked") or ""))}</span>'
                  f'<b>{e(_verdict(r))}</b></li>'
                  for r in recent)
    rec = f'<div class="card"><h2>Latest decisions</h2><ul class="list">{rec}</ul></div>' if rec else ""
    from . import memory
    mine = [memory.text_key(r["text_masked"]) for r in g["decided"]
            if r.get("status") == "confirmed" and r.get("reviewer") == who["name"] and r.get("text_masked")]
    if mine:
        ever = sum(counts.hits(mine, st=st).values())
        this = sum(counts.hits(mine, since=month + "-01", st=st).values())
        did = (f'<div class="card impact-card"><h2>What your confirmations did</h2><p class="sub" style="margin:0">'
               f'Scripts you confirmed have flagged <b>{ever:,}</b> later check{"s" if ever != 1 else ""}'
               f'{" this month" if this == ever else f", {this:,} of them this month"}. Each one is a student who saw '
               f'the warning before replying.</p></div>' if ever else
               f'<div class="card impact-card"><h2>What your confirmations did</h2><p class="sub" style="margin:0">'
               f'You\'ve confirmed {len(mine)} scam{"s" if len(mine) != 1 else ""}. When a copy reaches another student, '
               f'it\'s flagged on the spot and counted here.</p></div>')
        kinds = did + kinds
    hello = who["name"].split(" ")[0] if who["name"] else ""
    return _page("Home", f'<p class="kick">{e(_school_label(who["school"]))} · <span class="nw">{e(_day(dt.date.today().isoformat()))}</span></p>'
                         f'<h1>Hi {e(hello)}.</h1><p class="sub">Here\'s what needs you and how your students are doing.</p>'
                         f'{stats}<div class="two"><div>{keep}{rec}</div><div>{kinds}</div></div>', who, token, on="home")


@router.post("/review/decide")
async def decide(request: Request):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    f = await _form(request)
    if not acct.csrf_ok(token, f.get("csrf", "")):
        return _expired(who, token)
    action, tab = f.get("action", ""), f.get("tab", "waiting")
    tab = tab if tab in TABS and tab != "decided" else "waiting"
    if action not in FLASH:
        return _to("/review/queue")
    st = _store()
    r = st.get_report(f.get("id", ""))
    if r is None or (who["school"] and r.get("school") != who["school"]):
        return _page("Not found", '<div class="err">That report isn\'t in your queue.</div>', who, token, 404)
    _, order = _ordered(st, who, tab)                   # where the reviewer was, so the page returns them there
    ids = [str(x["id"]) for x, _ in order]
    nxt = ids[ids.index(str(r["id"])) + 1] if str(r["id"]) in ids and ids.index(str(r["id"])) + 1 < len(ids) else ""
    decision, real = ("confirmed", False) if action == "scam" else ("dismissed", action == "real")
    note = f.get("note", "")[:480]
    if action in ("aggregator", "unclear"):
        note = f"{TAG_AGGREGATOR if action == 'aggregator' else TAG_UNCLEAR} {note}".strip()
    try:
        rec = st.decide_report(r["id"], decision, who["name"], note, real=real)
    except ValueError:
        return _page("Already decided", '<div class="err">Someone already decided that report.</div>', who, token, 409)
    try:
        from . import learning
        learning.after_decision(rec, decision, real, st=st)
    except Exception:                                   # noqa: BLE001 - the decision stands; memory catches up next time
        pass
    return _to(f"/review/queue?tab={tab}&done={action}&n={quote(str(r['id']))}&at={quote(nxt)}#decided")


@router.post("/review/undo")
async def undo(request: Request):
    """The same reviewer, within UNDO_SECONDS: the report goes back in the queue and its label and memory go with it."""
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    f = await _form(request)
    if not acct.csrf_ok(token, f.get("csrf", "")):
        return _expired(who, token)
    tab = f.get("tab", "waiting")
    tab = tab if tab in TABS and tab != "decided" else "waiting"
    st = _store()
    r = st.get_report(f.get("id", ""))
    if r is None or (who["school"] and r.get("school") != who["school"]):
        return _page("Not found", '<div class="err">That report isn\'t in your queue.</div>', who, token, 404)
    was = r.get("status")
    try:
        rec = st.undo_decision(r["id"], who["name"], UNDO_SECONDS)
    except ValueError:
        return _page("Too late to undo", f'<div class="err">That decision can only be undone by the person who made it, '
                                         f'within {UNDO_SECONDS // 60} minutes. Ask the operator.</div>', who, token, 409)
    if was == "confirmed" and rec.get("text_masked"):
        try:
            from . import learning
            learning.forget(rec["text_masked"], st)
        except Exception:                               # noqa: BLE001
            pass
    return _to(f"/review/queue?tab={tab}&done=undone&n={quote(str(r['id']))}&at={quote(str(r['id']))}#decided")


# ---------------------------------------------------------------- the school's trusted and blocked domains

def _settings_school(who, asked: str) -> str:
    return who["school"] or (asked if asked in guardrails._config() else "")


def _settings_page(who, token, school: str, msg: str = "", ok: bool = True, status: int = 200) -> HTMLResponse:
    box = f'<div class="{"flash" if ok else "err"}">{e(msg)}</div>' if msg else ""
    picker = ""
    if not who["school"]:
        opts = "".join(f'<option value="{e(k)}"{" selected" if k == school else ""}>{e(_school_label(k))}</option>'
                       for k in sorted(guardrails._config()))
        picker = (f'<form class="inline card" method="get" action="/review/settings"><label for="sc"><b>School</b></label>'
                  f'<select id="sc" name="school">{opts}</select><button class="btn skip">Show</button></form>')
        if not school:
            return _page("School settings", f"<h1>School settings</h1>{picker}", who, token, status, on="settings")
    configured = set()
    for d in (guardrails._config().get(school) or {}).get("employer_domains", []):
        try:
            configured.add(guardrails.clean_domain(d))
        except ValueError:
            pass
    rows = _store().school_rules(school)
    csrf = acct.csrf_for(token)

    def table(kind: str, empty: str) -> str:
        trs = []
        if kind == "trusted_domain":
            trs += [f"<tr><td><b>{e(d)}</b></td><td>Set up with LureCheck</td><td>-</td><td></td></tr>" for d in sorted(configured)]
        for r in rows:
            if r["kind"] != kind:
                continue
            when = dt.datetime.fromtimestamp(r["added_at"]).strftime("%b %d, %Y") if r.get("added_at") else ""
            trs.append(f'<tr><td><b>{e(r["value"])}</b></td><td>{e(r.get("reason") or "")}</td><td>{e(r["added_by"])} · {e(when)}</td>'
                       f'<td><form method="post" action="/review/settings"><input type="hidden" name="csrf" value="{csrf}">'
                       f'<input type="hidden" name="school" value="{e(school)}"><input type="hidden" name="op" value="remove">'
                       f'<input type="hidden" name="kind" value="{kind}"><input type="hidden" name="value" value="{e(r["value"])}">'
                       f'<button class="btn skip">Remove</button></form></td></tr>')
        if not trs:
            return f'<p class="meta">{empty}</p>'
        return ('<table class="rules"><tr><th>Domain</th><th>Why</th><th>Added by</th><th></th></tr>' + "".join(trs) + "</table>")

    add = (f'<form class="inline" method="post" action="/review/settings" style="margin-top:12px"><input type="hidden" name="csrf" '
           f'value="{csrf}"><input type="hidden" name="school" value="{e(school)}"><input type="hidden" name="op" value="add">'
           f'<select name="kind" aria-label="List"><option value="trusted_domain">Trust</option><option value="blocked_domain">Block</option></select>'
           f'<input name="value" placeholder="employer.com or careers.employer.com" aria-label="Domain" required>'
           f'<input name="reason" placeholder="Why (e.g. verified by phone with HR)" maxlength="300" aria-label="Reason">'
           f'<button class="btn dark">Add</button></form>')
    body = (f'{picker}<p class="kick">{e(_school_label(school))}</p><h1>School settings</h1>{box}'
            f'<div class="card"><h2>Trusted employers</h2><p class="sub">Domains your office verified. Warnings about the '
            f'domain itself (new, unregistered, look-alike) stop counting, and sites imitating it get flagged. Scam wording '
            f'and confirmed contacts still count in full, because real accounts get hacked.</p>{table("trusted_domain", "None yet.")}</div>'
            f'<div class="card"><h2>Blocked domains</h2><p class="sub">Any check that uses one of these is marked as a scam '
            f'and names your office. A block always beats a trust.</p>{table("blocked_domain", "None yet.")}</div>'
            f'<div class="card"><h2>Add a domain</h2><p class="sub">An entry covers the domain and its subdomains, never the '
            f'site above it, so one page on a shared host can\'t block the whole host.</p>{add}</div>')
    return _page("School settings", body, who, token, status, on="settings")


@router.get("/review/settings", response_class=HTMLResponse)
def settings(request: Request, school: str = ""):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    return _settings_page(who, token, _settings_school(who, school))


@router.post("/review/settings")
async def settings_change(request: Request):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    f = await _form(request)
    if not acct.csrf_ok(token, f.get("csrf", "")):
        return _expired(who, token)
    school = _settings_school(who, f.get("school", ""))
    if not school:
        return _settings_page(who, token, "", "Pick a school first.", ok=False, status=400)
    kind = f.get("kind", "")
    if kind not in ("trusted_domain", "blocked_domain"):
        return _settings_page(who, token, school, "Pick trust or block.", ok=False, status=400)
    try:
        value = guardrails.clean_domain(f.get("value", ""))
    except ValueError:
        return _settings_page(who, token, school, "That isn't a domain. Use something like employer.com.", ok=False, status=400)
    st = _store()
    word = "trusted" if kind == "trusted_domain" else "blocked"
    if f.get("op") == "remove":
        hit = st.remove_school_rule(school, kind, value, who["name"])
        msg = f"Removed {value} from {word}." if hit else f"{value} wasn't on the {word} list."
    else:
        st.add_school_rule(school, kind, value, who["name"], f.get("reason", "")[:300])
        msg = f"{value} is now {word}. Checks pick it up within a minute."
    guardrails.clear_cache()
    return _settings_page(who, token, school, msg)


# ---------------------------------------------------------------- password and trends

def _password_page(who, token, msg: str = "", ok: bool = False, status: int = 200) -> HTMLResponse:
    box = f'<div class="{"flash" if ok else "err"}">{e(msg)}</div>' if msg else ""
    return _page("Password", f'<div class="login card"><h1>Change password</h1><p class="sub">At least {acct.MIN_PASSWORD} '
                             f'characters. A few unrelated words works well.</p>{box}<form method="post" action="/review/password">'
                             f'<input type="hidden" name="csrf" value="{acct.csrf_for(token)}">'
                             f'<label for="c">Current password</label><input id="c" name="current" type="password" autocomplete="current-password" required>'
                             f'<label for="n">New password</label><input id="n" name="new" type="password" autocomplete="new-password" required>'
                             f'<label for="a">New password again</label><input id="a" name="again" type="password" autocomplete="new-password" required>'
                             f'<button class="btn dark">Change it</button></form></div>', who, token, status, on="password")


@router.get("/review/password", response_class=HTMLResponse)
def password_form(request: Request):
    who, token = _who(request)
    return _password_page(who, token) if who else _to("/review/login")


@router.post("/review/password")
async def password(request: Request):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    f = await _form(request)
    if not acct.csrf_ok(token, f.get("csrf", "")):
        return _password_page(who, token, "That form expired. Try again.", status=403)
    st = _store()
    full = st.reviewer_by_email(who["email"])
    if not full or not acct.verify_password(f.get("current", ""), full["pw_hash"]):
        return _password_page(who, token, "The current password isn't right.", status=400)
    if f.get("new", "") != f.get("again", ""):
        return _password_page(who, token, "The two new passwords don't match.", status=400)
    problems = acct.password_problems(f.get("new", ""), who["email"])
    if problems:
        return _password_page(who, token, "The new password needs " + ", ".join(problems) + ".", status=400)
    st.set_reviewer(who["email"], pw_hash=acct.hash_password(f["new"]))
    st.drop_sessions(who["id"])                         # every other browser is logged out; this one gets a new session
    new, h = acct.new_session()
    st.add_session(h, who["id"], time.time() + acct.SESSION_HOURS * 3600)
    resp = _password_page(who, new, "Password changed. Other browsers were logged out.", ok=True)
    resp.set_cookie(COOKIE, new, max_age=acct.SESSION_HOURS * 3600, path="/review", httponly=True,
                    secure=_secure(), samesite="strict")
    return resp


@router.get("/review/trends", response_class=HTMLResponse)
def trends_page(request: Request, month: str = "", school: str = ""):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    from . import trends
    from .tools.trends import last_full_month
    school = who["school"] or school
    month = month if len(month) == 7 and month[4] == "-" and month.replace("-", "").isdigit() else last_full_month(dt.date.today())
    picker = ""
    if not who["school"]:
        opts = "".join(f'<option value="{e(k)}"{" selected" if k == school else ""}>{e(_school_label(k))}</option>'
                       for k in sorted(guardrails._config()))
        picker = (f'<form class="inline card" method="get" action="/review/trends"><select name="school" aria-label="School">{opts}</select>'
                  f'<input type="hidden" name="month" value="{e(month)}"><button class="btn skip">Show</button></form>')
        if not school:
            return _page("Trends", f"<h1>Trends</h1>{picker}", who, token, on="trends")
    y, m = int(month[:4]), int(month[5:])
    prev = f"{y - 1}-12" if m == 1 else f"{y}-{m - 1:02d}"
    nxt = f"{y + 1}-01" if m == 12 else f"{y}-{m + 1:02d}"
    q = f"&school={quote(school)}" if not who["school"] else ""
    try:
        text = trends.render(trends.monthly(school, month, _store()), _school_label(school))
    except Exception as exc:                            # noqa: BLE001
        text = f"The report couldn't be built: {exc}"
    later = nxt <= dt.date.today().strftime("%Y-%m")
    nav = (f'<div class="doc-bar"><p class="meta"><a href="/review/trends?month={prev}{q}">← {_month_name(prev)}</a>'
           f'{f" · <a href={chr(34)}/review/trends?month={nxt}{q}{chr(34)}>{_month_name(nxt)} →</a>" if later else ""}</p>'
           f'<button class="btn ghost" type="button" data-copy="report-doc" hidden>Copy for email</button></div>')
    return _page("Trends", f'{picker}<p class="kick">Monthly report · ready to forward</p><h1>Trends</h1>{nav}'
                           f'<article class="card doc" id="report-doc">{_md(text)}</article>', who, token, on="trends")


def _month_name(m: str) -> str:
    import calendar
    return f"{calendar.month_name[int(m[5:])]} {m[:4]}"


def _inline(t: str) -> str:
    t = e(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    return re.sub(r"(?<![\w])_(.+?)_(?![\w])", r"<em>\1</em>", t)


def _md(text: str) -> str:
    """The trends report's Markdown (headings, paragraphs, bullets, one kind of table) as HTML for the page and email."""
    out, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        ln = lines[i].rstrip()
        if not ln.strip():
            i += 1
            continue
        if ln.startswith("# "):
            out.append(f"<h2>{_inline(ln[2:])}</h2>")
        elif ln.startswith("## "):
            out.append(f"<h3>{_inline(ln[3:])}</h3>")
        elif ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(set(c) <= set("-: ") for c in cells):
                    rows.append(cells)
                i += 1
            head, body = rows[0], rows[1:]
            out.append('<table><thead><tr>' + "".join(f"<th>{_inline(c)}</th>" for c in head) + "</tr></thead><tbody>"
                       + "".join("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in body) + "</tbody></table>")
            continue
        elif ln.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(f"<li>{_inline(lines[i][2:])}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        else:
            out.append(f"<p>{_inline(ln)}</p>")
        i += 1
    return "".join(out)
