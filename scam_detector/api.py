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

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from .scorer import score_posting
from .security import enforce_rate_limit, analyze_limiter, MAX_BODY_BYTES

app = FastAPI(title="Job Scam Detector", version="1.0")


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
    return result.as_dict()
