"""
Expand shortened links (bit.ly, tinyurl, t.co, ...) to see where they really go.

Safety rules, because the thing on the other end may be hostile:
  - Only hosts on the SHORTENERS list are ever contacted. As soon as a hop lands on a
    non-shortener host we stop and report it WITHOUT fetching it, so we never touch
    the scam page itself (and a shortener can't bounce us into an internal address).
  - HEAD first; GET only if the shortener rejects HEAD, and the GET body is never read.
  - Nothing is rendered or executed, no cookies are kept or sent (a fresh client per
    hop), redirects are followed by us, one at a time, capped at max_hops.
  - Only http/https Location targets are followed.
  - Any failure returns status "unknown"; this never raises.

Limit: some shorteners show an interstitial page (HTTP 200) instead of redirecting,
or rate-limit unknown clients; then the chain simply stops at the shortener and the
status is "unknown".
"""

from __future__ import annotations

from typing import Callable, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from .domains import normalize_host

TIMEOUT = 4.0
USER_AGENT = "NoleCareerShield-link-check/1.0 (+scam detector; HEAD only)"

SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "j.mp", "tinyurl.com", "tiny.one", "rotf.lol", "t.co", "goo.gl",
    "ow.ly", "is.gd", "v.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "lnkd.in", "t.ly", "bl.ink", "s.id", "qrco.de", "bit.do", "x.co", "tr.im",
    "soo.gd", "clck.ru", "shorte.st", "adf.ly", "forms.gle", "han.gl", "urlz.fr", "v.ht",
    "short.gy", "surl.li", "u.to", "tinu.be", "dub.sh", "linktw.in", "shorturl.gg",
})

# A fetch takes a URL and returns (status_code, location_header_or_None).
Fetch = Callable[[str], Tuple[int, Optional[str]]]


def is_shortener(url_or_host: str) -> bool:
    h = normalize_host(url_or_host)
    if h.startswith("www."):
        h = h[4:]
    return h in SHORTENERS


def _default_fetch(url: str) -> Tuple[int, Optional[str]]:
    import httpx

    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    # New client per hop: no cookie jar survives between requests.
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False, headers=headers) as client:
        r = client.head(url)
        if r.status_code in (400, 403, 404, 405, 501) or (r.status_code < 300 and "location" not in r.headers):
            with client.stream("GET", url) as g:  # body intentionally never read
                return g.status_code, g.headers.get("location")
        return r.status_code, r.headers.get("location")


def expand(url: str, fetch: Optional[Fetch] = None, max_hops: int = 5) -> dict:
    """
    Follow a shortened link's redirects, contacting shortener hosts only.

    Returns {"url", "chain": [url, ...], "final_url", "final_host", "hops",
             "status": "ok"|"not_shortened"|"hop_limit"|"unknown", "detail"}.
    """
    fetch = fetch or _default_fetch
    chain = [url]
    result = {"url": url, "chain": chain, "final_url": url, "final_host": normalize_host(url),
              "hops": 0, "status": "ok", "detail": ""}
    if not is_shortener(url):
        result.update(status="not_shortened", detail="not a known link shortener")
        return result

    current = url
    for _ in range(max(0, int(max_hops))):
        if not is_shortener(current):
            break
        try:
            status, location = fetch(current)
        except Exception as e:  # noqa: BLE001
            result.update(status="unknown", detail=f"could not reach the shortener ({type(e).__name__})")
            return result
        if not (300 <= int(status) < 400 and location):
            result.update(status="unknown", detail=f"shortener answered HTTP {status} without a redirect")
            return result
        nxt = urljoin(current, location.strip())
        if urlsplit(nxt).scheme not in ("http", "https"):
            result.update(status="unknown", detail="redirect to a non-web address was not followed")
            return result
        chain.append(nxt)
        result["hops"] += 1
        result["final_url"], result["final_host"] = nxt, normalize_host(nxt)
        current = nxt
    if is_shortener(current):
        result.update(status="hop_limit", detail=f"still on a shortener after {max_hops} hops; stopped")
    else:
        result["detail"] = f"expanded in {result['hops']} hop(s)"
    return result
