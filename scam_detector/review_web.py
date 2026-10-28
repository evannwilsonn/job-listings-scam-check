"""
The review page: where career-center staff decide what students reported, in a browser.

    GET  /review                 the queue for the reviewer's school (students who already acted first, close calls marked)
    GET  /review?show=decided    the last 50 decisions
    POST /review/decide          it's a scam / it's a real job / not enough to tell
    GET  /review/trends          the monthly trends report (trends.py)
    GET  /review/login, POST /review/login, POST /review/logout, GET|POST /review/password

Every decision goes through store.decide_report and learning.after_decision, exactly like tools/review_queue.py, so the
training label, the template memory and (on Postgres) the confirmed indicators follow from it. The reviewer's name on
the record comes from their account, never from the form.

Security: accounts are made with tools/reviewers.py only. The session cookie is HttpOnly, SameSite=Strict, scoped to
/review and Secure unless REVIEW_COOKIE_SECURE=0 (local http only); the store keeps only its SHA-256. Every form carries
a CSRF token bound to the session. Login is rate limited per IP. Pages send a CSP that allows no scripts at all.
A reviewer sees only their own school's reports; an account with no school (the LureCheck operator) sees every school.
"""

from __future__ import annotations

import datetime as dt
import html
import os
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
HEADERS = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                                      "frame-ancestors 'none'; base-uri 'none'",
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
    return guardrails.school_name(code) or code or "every school"


# ---------------------------------------------------------------- page shell

CSS = """
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:#f5f6f7;color:#1c1f23}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:12px 16px;background:#14213d;color:#fff}
header a,header button{color:#fff}header nav{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
header form{margin:0}header button{background:none;border:1px solid #fff6;border-radius:6px;padding:4px 10px;font:inherit;cursor:pointer}
main{max-width:860px;margin:0 auto;padding:16px}h1{font-size:20px;margin:8px 0 4px}.sub{color:#5a636e;margin:0 0 16px}
.card{background:#fff;border:1px solid #dde1e6;border-radius:10px;padding:14px 16px;margin:0 0 14px}
.meta{display:flex;flex-wrap:wrap;gap:8px;align-items:center;color:#5a636e;font-size:13px;margin-bottom:8px}
.tag{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600}
.close{background:#fff4d6;color:#7a5200}.harm{background:#fde2e1;color:#8a1c17}.ok{background:#e1f3e8;color:#1d6b3a}.gray{background:#eceff2;color:#47505a}
.text{white-space:pre-wrap;word-break:break-word;background:#f8f9fa;border:1px solid #eceff2;border-radius:8px;padding:10px 12px;max-height:340px;overflow:auto;font-size:14px}
.det{font-size:13px;color:#47505a;margin:10px 0 0}.det ul{margin:4px 0 0;padding-left:18px}
form.decide{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px}
form.decide input[type=text]{flex:1 1 220px;min-width:0;padding:8px 10px;border:1px solid #c9ced4;border-radius:7px;font:inherit}
.btn{border:0;border-radius:7px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer}
.scam{background:#b42318;color:#fff}.real{background:#1d6b3a;color:#fff}.skip{background:#eceff2;color:#1c1f23}
.flash{background:#e1f3e8;border:1px solid #b9e2c7;border-radius:8px;padding:10px 12px;margin-bottom:14px}
.err{background:#fde2e1;border:1px solid #f5c2bf;border-radius:8px;padding:10px 12px;margin-bottom:14px}
.login{max-width:380px;margin:48px auto}.login label{display:block;margin:12px 0 4px;font-weight:600}
.login input{width:100%;padding:9px 10px;border:1px solid #c9ced4;border-radius:7px;font:inherit}.login .btn{margin-top:16px;width:100%;background:#14213d;color:#fff}
.report{white-space:pre-wrap;font:13px/1.55 ui-monospace,Menlo,Consolas,monospace}
select{padding:6px 8px;border-radius:6px;border:1px solid #c9ced4;font:inherit}
"""


def _page(title: str, body: str, who=None, token: str = "", status: int = 200) -> HTMLResponse:
    nav = ""
    if who:
        nav = (f'<nav><a href="/review">Queue</a><a href="/review?show=decided">Decided</a><a href="/review/trends">Trends</a>'
               f'<a href="/review/password">Password</a><span>{e(who["name"])} · {e(_school_label(who["school"]))}</span>'
               f'<form method="post" action="/review/logout"><input type="hidden" name="csrf" value="{acct.csrf_for(token)}">'
               f'<button>Log out</button></form></nav>')
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
           f'initial-scale=1"><title>{e(title)} · LureCheck review</title><style>{CSS}</style></head><body>'
           f'<header><strong>LureCheck review</strong>{nav}</header><main>{body}</main></body></html>')
    return HTMLResponse(doc, status_code=status, headers=HEADERS)


def _to(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303, headers=HEADERS)


# ---------------------------------------------------------------- login

def _login_page(error: str = "", status: int = 200) -> HTMLResponse:
    err = f'<div class="err">{e(error)}</div>' if error else ""
    return _page("Log in", f'<div class="login card"><h1>Log in</h1><p class="sub">Career-center reviewers only. Ask the '
                           f'LureCheck operator for an account.</p>{err}<form method="post" action="/review/login">'
                           f'<label for="em">Email</label><input id="em" name="email" type="email" autocomplete="username" required>'
                           f'<label for="pw">Password</label><input id="pw" name="password" type="password" '
                           f'autocomplete="current-password" required><button class="btn">Log in</button></form></div>',
                 status=status)


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

def _detector(text: str) -> str:
    """What today's detector says about the masked text: the band and the reasons that count."""
    from .scorer import score_posting
    try:
        res = score_posting(title="", description=text, company="", run_network=False)
    except Exception:                                   # noqa: BLE001
        return ""
    found = [f for f in res.findings if f.get("weight", 0) > 0][:4]
    band = {"block": "likely scam", "review": "send to a person", "caution": "be careful", "clear": "nothing found"}.get(res.band, res.band)
    items = "".join(f"<li>{e(f['title'])}</li>" for f in found)
    return f'<div class="det">Detector today: <strong>{e(band)}</strong> (score {res.score}){f"<ul>{items}</ul>" if items else ""}</div>'


def _day(iso: str) -> str:
    try:
        d = dt.datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
        return f"{d:%b} {d.day}, {d.year}"
    except ValueError:
        return iso or ""


def _card(r: dict, who: dict, token: str, decided: bool = False) -> str:
    tags = []
    if r.get("kind") == "borderline":
        tags.append('<span class="tag close">Close call: the detector asked</span>')
    if r.get("outcome") in HARM:
        tags.append(f'<span class="tag harm">Student already {e(HARM[r["outcome"]])}</span>')
    if decided:
        label = {"confirmed": ("ok", "Scam"), "dismissed": ("gray", "Dismissed")}.get(r.get("status"), ("gray", r.get("status", "")))
        tags.append(f'<span class="tag {label[0]}">{e(label[1])} · {e(r.get("reviewer", ""))}</span>')
    ind = r.get("indicators") or {}
    bits = []
    if ind.get("domains"):
        bits.append("domains: " + ", ".join(e(d) for d in ind["domains"][:6]))
    for k, word in (("wallets", "wallet"), ("email_hashes", "email address"), ("phone_hashes", "phone number")):
        n = len(ind.get(k) or [])
        if n:
            bits.append(f"{n} {word}{'s' if n > 1 else ''}")
    school = f" · {e(_school_label(r.get('school', '')))}" if not who["school"] else ""
    head = f'<div class="meta">#{e(r["id"])} · {e(_day(r.get("received", "")))}{school} {"".join(tags)}</div>'
    text = r.get("text_masked") or "(the text was purged after 30 days)"
    body = f'{head}<div class="text">{e(text)}</div>'
    if bits:
        body += f'<div class="det">{" · ".join(bits)}</div>'
    if decided:
        if r.get("note"):
            body += f'<div class="det">Note: {e(r["note"])}</div>'
        return f'<div class="card">{body}</div>'
    body += _detector(text)
    body += (f'<form class="decide" method="post" action="/review/decide"><input type="hidden" name="csrf" '
             f'value="{acct.csrf_for(token)}"><input type="hidden" name="id" value="{e(r["id"])}">'
             f'<input type="text" name="note" maxlength="500" placeholder="Note (optional)">'
             f'<button class="btn scam" name="action" value="scam">It\'s a scam</button>'
             f'<button class="btn real" name="action" value="real">It\'s a real job</button>'
             f'<button class="btn skip" name="action" value="unclear">Not enough to tell</button></form>')
    return f'<div class="card">{body}</div>'


FLASH = {"scam": "Marked as a scam. The detector will flag copies of it from now on, and it's in the next retrain.",
         "real": "Marked as a real job. It's a 'real' example for the next retrain, so look-alikes are less likely to be flagged.",
         "unclear": "Dismissed without a label."}


@router.get("/review", response_class=HTMLResponse)
def queue(request: Request, show: str = "", done: str = "", n: str = ""):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    st = _store()
    flash = f'<div class="flash">#{e(n)}: {e(FLASH[done])}</div>' if done in FLASH else ""
    if show == "decided":
        rows = [r for r in st.list_reports("", who["school"]) if r.get("status") != "reported"]
        rows.sort(key=lambda r: r.get("reviewed_at") or "", reverse=True)
        cards = "".join(_card(r, who, token, decided=True) for r in rows[:QUEUE_MAX]) or '<p class="sub">Nothing decided yet.</p>'
        return _page("Decided", f"<h1>Decided</h1><p class=\"sub\">The last {QUEUE_MAX} decisions. They can't be changed "
                                f"here; ask the operator if one was wrong.</p>{cards}", who, token)
    rows = st.list_reports("reported", who["school"])
    rows.sort(key=lambda r: (r.get("outcome") not in HARM, r.get("received", "")))
    total = len(rows)
    cards = "".join(_card(r, who, token) for r in rows[:QUEUE_MAX])
    if not total:
        cards = '<div class="card">Nothing waiting. New reports show up here as students send them.</div>'
    more = f'<p class="sub">Showing the first {QUEUE_MAX} of {total}.</p>' if total > QUEUE_MAX else ""
    sub = (f"{total} waiting. Contact details were hidden before anything was stored. Students who already acted come "
           f"first. Your answer is a training label, so 'Not enough to tell' is better than a guess.")
    return _page("Queue", f"<h1>Reports to review</h1><p class=\"sub\">{e(sub)}</p>{flash}{cards}{more}", who, token)


@router.post("/review/decide")
async def decide(request: Request):
    who, token = _who(request)
    if not who:
        return _to("/review/login")
    f = await _form(request)
    if not acct.csrf_ok(token, f.get("csrf", "")):
        return _page("Expired", '<div class="err">That form expired. Go back to the queue and try again.</div>', who, token, 403)
    action = f.get("action", "")
    if action not in FLASH:
        return _to("/review")
    st = _store()
    r = st.get_report(f.get("id", ""))
    if r is None or (who["school"] and r.get("school") != who["school"]):
        return _page("Not found", '<div class="err">That report isn\'t in your queue.</div>', who, token, 404)
    decision, real = ("confirmed", False) if action == "scam" else ("dismissed", action == "real")
    try:
        rec = st.decide_report(r["id"], decision, who["name"], f.get("note", "")[:500], real=real)
    except ValueError:
        return _page("Already decided", '<div class="err">Someone already decided that report.</div>', who, token, 409)
    try:
        from . import learning
        learning.after_decision(rec, decision, real, st=st)
    except Exception:                                   # noqa: BLE001 - the decision stands; memory catches up next time
        pass
    return _to(f"/review?done={action}&n={quote(str(r['id']))}")


# ---------------------------------------------------------------- password and trends

def _password_page(who, token, msg: str = "", ok: bool = False, status: int = 200) -> HTMLResponse:
    box = f'<div class="{"flash" if ok else "err"}">{e(msg)}</div>' if msg else ""
    return _page("Password", f'<div class="login card"><h1>Change password</h1><p class="sub">At least {acct.MIN_PASSWORD} '
                             f'characters. A few unrelated words works well.</p>{box}<form method="post" action="/review/password">'
                             f'<input type="hidden" name="csrf" value="{acct.csrf_for(token)}">'
                             f'<label for="c">Current password</label><input id="c" name="current" type="password" autocomplete="current-password" required>'
                             f'<label for="n">New password</label><input id="n" name="new" type="password" autocomplete="new-password" required>'
                             f'<label for="a">New password again</label><input id="a" name="again" type="password" autocomplete="new-password" required>'
                             f'<button class="btn">Change it</button></form></div>', who, token, status)


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
        picker = (f'<form method="get" action="/review/trends"><select name="school">{opts}</select> '
                  f'<input type="hidden" name="month" value="{e(month)}"><button class="btn skip">Show</button></form>')
        if not school:
            return _page("Trends", f"<h1>Trends</h1><p class=\"sub\">Pick a school.</p>{picker}", who, token)
    y, m = int(month[:4]), int(month[5:])
    prev = f"{y - 1}-12" if m == 1 else f"{y}-{m - 1:02d}"
    nxt = f"{y + 1}-01" if m == 12 else f"{y}-{m + 1:02d}"
    q = f"&school={quote(school)}" if not who["school"] else ""
    try:
        text = trends.render(trends.monthly(school, month, _store()), _school_label(school))
    except Exception as exc:                            # noqa: BLE001
        text = f"The report couldn't be built: {exc}"
    nav = f'<p class="sub"><a href="/review/trends?month={prev}{q}">← {prev}</a> · <a href="/review/trends?month={nxt}{q}">{nxt} →</a></p>'
    return _page("Trends", f"{picker}{nav}<div class=\"card report\">{e(text)}</div>", who, token)
