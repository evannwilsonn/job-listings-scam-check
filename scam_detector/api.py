"""
HTTP API for the scam detector.

Run locally:
    uvicorn scam_detector.api:app --reload

Then POST a posting:
    curl -X POST http://127.0.0.1:8000/analyze \
      -H 'Content-Type: application/json' \
      -d '{"title":"Remote Data Entry","description":"...","company":"Acme"}'

This is a single service, no Kafka, no GPU, no message broker. At the volumes a
job-scam tool actually sees, one process behind uvicorn handles the load. Add a
worker count and a cache when you have traffic that justifies it, not before.
"""

from __future__ import annotations

import os
from typing import List

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from . import guardrails, learning, ml
from .conversation import analyze_thread
from .attestations import attestation_findings
from .employer import board_finding, check_job_board, screen_employer, verification_script
from .network import lookup as network_lookup, network_findings
from .followup import VERIFIED, follow_up_date, open_case, record_outcome
from .identity import sender_findings
from .intel import intel_findings
from .intel.cache import MemoryCache
from .recovery import HAPPENED, next_step, recovery_plan
from .reports import OUTCOMES, ftc_summary, make_report
from .scorer import _band, score_posting
from .security import RateLimiter, enforce_rate_limit, analyze_limiter, MAX_BODY_BYTES
from .store import get_store

_intel_cache = MemoryCache()
report_limiter = RateLimiter(max_attempts=10, window_seconds=600)

app = FastAPI(title="Job Scam Detector", version="1.0")
learning.configure_serving()      # the active retrained model (or the shipped one), staged releases, and drift recording

# The embeddable checker (web/embed.js) runs on a career center's own site and calls this API from there. Browsers
# only allow that for origins listed here: ALLOWED_ORIGINS="https://career.fsu.edu,https://lurecheck.com". Empty
# (the default) allows no other site. No cookies or credentials are ever accepted cross-origin.
_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if _ORIGINS:
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(CORSMiddleware, allow_origins=_ORIGINS, allow_methods=["POST", "GET"],
                       allow_headers=["Content-Type"], allow_credentials=False, max_age=600)


@app.middleware("http")
async def _limit_body(request: Request, call_next):
    """Refuse oversized bodies before they are read and parsed (the Field caps below only apply after parsing)."""
    from fastapi.responses import JSONResponse
    cl = request.headers.get("content-length", "")
    if (cl and (not cl.isdigit() or int(cl) > MAX_BODY_BYTES)):
        return JSONResponse({"detail": "Request body too large or malformed."}, status_code=413)
    if request.method == "POST":
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "Request body too large."}, status_code=413)
        request._body = body                      # let the route parse what was already read
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(HTTPException)
def _http_exception_handler(request: Request, exc: HTTPException):
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                         headers=exc.headers or {})


class PostingIn(BaseModel):
    # Field caps: this is the DoS-shaped input for this service -- without a
    # limit, a POST body can hold megabytes of text that get pushed through
    # every regex rule in scorer.py on every request. 20k chars is far more
    # than any real job posting or recruiter DM (labeled corpus examples top
    # out well under 2k).
    title: str = Field(default="", max_length=500, description="Job title")
    description: str = Field(..., min_length=1, max_length=20000,
                              description="Full posting or recruiter message text")
    company: str = Field(default="", max_length=300, description="Claimed employer name, if given")
    run_network: bool = Field(default=True, description="Run live domain/MX lookups")
    second_look: bool = Field(default=True, description="Add the learned model's 'worth a second look' finding "
                                                        "(weight 0: it never changes the score or band)")
    sender: str = Field(default="", max_length=320, description="Sender's email address, if it came by email")
    sender_name: str = Field(default="", max_length=200, description="Sender's display name")
    reply_to: str = Field(default="", max_length=320, description="Reply-To address, if different")
    follow_up: bool = Field(default=False, description="Student opted in to a follow-up: returns a case code. Only "
                                                       "the verdict and rule ids are kept, never the text.")
    school: str = Field(default="", max_length=40)


class ThreadIn(BaseModel):
    thread: str = Field(..., min_length=1, max_length=40000, description="The whole conversation, pasted or forwarded")
    me: str = Field(default="", max_length=320, description="The student's own name or address, to tell the sides apart")


class RecoveryIn(BaseModel):
    happened: List[str] = Field(default_factory=list, max_length=12, description="One or more of: " + ", ".join(HAPPENED))


class OutcomeIn(BaseModel):
    case_code: str = Field(..., min_length=6, max_length=40)
    happened: List[str] = Field(..., min_length=1, max_length=12, description="'nothing' or values from /recovery")
    verified: str = Field(default="", max_length=20, description="One of: " + ", ".join(v for v in VERIFIED if v))


class VerifyIn(BaseModel):
    company: str = Field(..., min_length=1, max_length=200)
    title: str = Field(default="", max_length=200)
    recruiter_name: str = Field(default="", max_length=120)
    recruiter_email: str = Field(default="", max_length=320)
    channel: str = Field(default="", max_length=60, description="How they contacted the student, e.g. text, LinkedIn")
    urls: List[str] = Field(default_factory=list, max_length=10)
    check_board: bool = Field(default=True, description="Look the job up on the company's public job board")


class LookupIn(BaseModel):
    value: str = Field(..., min_length=3, max_length=320, description="One phone number, email address, website or wallet")


class ScreenIn(BaseModel):
    company: str = Field(..., min_length=1, max_length=200)
    contact_email: str = Field(default="", max_length=320)
    website: str = Field(default="", max_length=500)
    title: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=20000)
    run_network: bool = Field(default=True)


class ReportIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000, description="The message or posting being reported")
    sender: str = Field(default="", max_length=320)
    school: str = Field(default="", max_length=40)
    outcome: str = Field(default="", max_length=40, description="One of: " + ", ".join(OUTCOMES))


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(posting: PostingIn, request: Request) -> dict:
    enforce_rate_limit(request, analyze_limiter, "analyze")
    result = score_posting(
        title=posting.title,
        description=posting.description,
        company=posting.company,
        run_network=posting.run_network,
    )
    out = result.as_dict()
    # Who sent it, and what the links and addresses are (look-alikes, blocklists, email authentication). The scorer
    # already reports new_domain for domains in the text, so the intel copy is dropped to avoid counting it twice.
    extra = sender_findings(posting.sender, posting.sender_name, posting.reply_to, posting.company, posting.description)
    have = {f["rule_id"] for f in out["findings"]}
    rules = guardrails.rules_for(posting.school)        # the career center's trusted and blocked domains
    intel = intel_findings(posting.description, [], posting.sender, posting.company, cache=_intel_cache,
                           protected_extra=guardrails.protected(rules), network=posting.run_network)
    extra += [f for f in intel if f["rule_id"] not in have and f["rule_id"] != "new_domain"]
    # The network (reviewer-confirmed scam contacts across schools) and what the named employer attested.
    extra += network_findings(posting.description, posting.sender)
    # Template memory: the wording of scams reviewers confirmed, matched on the next check (learning.py, memory.py).
    tm = learning.template_finding("\n".join(x for x in (posting.title, posting.description) if x))
    if tm:
        extra.append(tm)
    _, att = attestation_findings(posting.company, posting.sender, posting.description, out["findings"] + extra)
    extra += att
    if extra or rules["trusted"] or rules["blocked"]:
        out["findings"].extend(extra)
        out["findings"] = guardrails.apply(out["findings"], rules, text=posting.description, sender=posting.sender,
                                           school_name=guardrails.school_name(posting.school))
        out["score"] = min(100, sum(f.get("weight", 0) for f in out["findings"]))
        out["band"], out["verdict"] = _band(out["score"], any(f.get("severity") == "critical" for f in out["findings"]))
    if posting.second_look:
        # The learned layer lives only on the server (the static page has no model). It adds a weight-0 finding when
        # it is confident and the rules weren't; it never changes the score or band, so it stays out of the scorer
        # and out of the Python/JS parity gate.
        extra = ml.second_look(posting.title, posting.description, posting.company,
                               findings=out["findings"], score=out["score"])
        if extra:
            out["findings"].append(extra)
    if posting.follow_up:
        out["case_code"] = open_case(out, posting.school)
        out["follow_up_after"] = follow_up_date()
    return out


@app.post("/analyze-thread")
def analyze_conversation(body: ThreadIn, request: Request) -> dict:
    """A whole conversation: where it is in the scam playbook, the moment it turned, and the likely next ask."""
    enforce_rate_limit(request, analyze_limiter, "analyze")
    return analyze_thread(body.thread, me=body.me or None)


@app.post("/report")
def report(body: ReportIn, request: Request) -> dict:
    """
    One-tap anonymous report. Queues a masked record for a reviewer (see reports.py for what is kept) and returns the
    FTC summary for the student to paste, plus what to do next for what already happened. Nothing reported here
    reaches the network or training until a reviewer confirms it.
    """
    enforce_rate_limit(request, report_limiter, "report")
    record = make_report(body.text, body.sender, body.school, body.outcome)
    try:
        get_store().add_report(record)
        queued = True
    except Exception:                                   # noqa: BLE001 - the student still gets the FTC summary
        queued = False
    return {"queued": queued, "ftc_url": "https://reportfraud.ftc.gov",
            "ftc_summary": ftc_summary(body.text, body.sender, body.outcome),
            "next_step": next_step(record["outcome"])}


@app.post("/recovery")
def recovery(body: RecoveryIn, request: Request) -> dict:
    """'I already responded': ordered steps for what already happened, most urgent first."""
    enforce_rate_limit(request, analyze_limiter, "analyze")
    return recovery_plan(body.happened)


@app.post("/outcome")
def outcome(body: OutcomeIn, request: Request) -> dict:
    """The follow-up answer for a case code: what happened, and whether the job turned out real."""
    enforce_rate_limit(request, report_limiter, "outcome")
    ok = record_outcome(body.case_code, body.happened, body.verified)
    if not ok:
        raise HTTPException(status_code=422, detail="Unknown values in happened or verified.")
    lost = [h for h in body.happened if h != "nothing"]
    return {"recorded": True, "recovery": recovery_plan(lost) if lost else None}


@app.post("/verify-job")
def verify_job(body: VerifyIn, request: Request) -> dict:
    """
    Is the job on the company's own job board, does the recruiter's address fit the company, and the script for
    calling the company to check. A missing listing is a note for a reviewer, never a verdict.
    """
    enforce_rate_limit(request, analyze_limiter, "analyze")
    board = check_job_board(body.company, body.title, body.urls) if body.check_board and body.title else None
    findings = sender_findings(body.recruiter_email, body.recruiter_name, "", body.company)
    att, att_f = attestation_findings(body.company, body.recruiter_email, "", findings, body.channel)
    findings += att_f + network_findings(" ".join(body.urls), body.recruiter_email)
    note = board_finding(board or {}, body.company, body.title)
    if note:
        findings.append(note)
    return {"board": board, "findings": findings, "attested": bool(att),
            "careers_url": (att or {}).get("careers_url"),
            "script": verification_script(body.company, body.title, body.recruiter_name, body.channel)}


@app.post("/lookup")
def lookup(body: LookupIn, request: Request) -> dict:
    """Has this phone number, email, website or wallet been confirmed as a scam at any LureCheck school?"""
    enforce_rate_limit(request, analyze_limiter, "analyze")
    return network_lookup(body.value)


@app.post("/screen-employer")
def screen(body: ScreenIn, request: Request) -> dict:
    """For a career-center reviewer approving an employer (e.g. on Handshake). Recommends; never decides."""
    enforce_rate_limit(request, analyze_limiter, "analyze")
    return screen_employer(body.company, body.contact_email, body.website, body.title, body.description,
                           run_network=body.run_network)
