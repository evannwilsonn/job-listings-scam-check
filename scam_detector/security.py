"""
Rate limiting for the standalone scam_detector API.

Mirrors the jobboard's security.py (kept as a separate copy since these two
packages are shipped/deployed independently — see the audit report for why
this isn't a shared library). No login route exists here (there's no admin
surface in the standalone detector), so this covers /analyze against
scripted flooding rather than credential guessing.
"""

from __future__ import annotations

import os
import time
import threading
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > self.window_seconds:
                dq.popleft()
            if len(dq) >= self.max_attempts:
                retry_after = int(self.window_seconds - (now - dq[0])) + 1
                return False, max(retry_after, 1)
            return True, 0

    def hit(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > self.window_seconds:
                dq.popleft()
            dq.append(now)


# 60 analyze calls/minute/IP -- generous for a real integration, enough to
# blunt a naive flood script. Tune per deployment.
analyze_limiter = RateLimiter(max_attempts=60, window_seconds=60)


# X-Forwarded-For is only honored behind a proxy you control (TRUST_PROXY=1), and then only its LAST entry:
# anything to the left was written by the client, so trusting it would let anyone dodge the rate limit.
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"
MAX_BODY_BYTES = 64 * 1024              # /analyze takes at most ~21k characters of text; JSON overhead aside, 64 KB is plenty


def client_key(request: Request, bucket: str) -> str:
    ip = request.client.host if request.client else "unknown"
    if TRUST_PROXY:
        parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if parts:
            ip = parts[-1][:64]
    return f"{bucket}:{ip}"


def enforce_rate_limit(request: Request, limiter: RateLimiter, bucket: str) -> None:
    key = client_key(request, bucket)
    allowed, retry_after = limiter.check(key)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    limiter.hit(key)
