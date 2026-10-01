"""
Domain age lookup via RDAP.

RDAP (Registration Data Access Protocol) is the modern, JSON-based successor to
WHOIS. It is served over HTTPS, returns structured data, and is far more reliable
to parse than free-text WHOIS. We use the IANA bootstrap registry to find the
right RDAP server for each TLD.

Design decisions that matter:
  - A failed lookup returns status="unknown", never "suspicious". A registrar
    timeout is not evidence of fraud. Treating it as such is how the original
    blueprint would have flagged real companies constantly.
  - This is slow (a network round trip, sometimes two) and MUST NOT sit in a
    synchronous scoring path. It belongs in an async enrichment step with a cache.
  - Results are cached in-process for the session. A real deployment would use
    Redis or a DB table with a TTL of a day or so, since registration dates
    do not change.
"""

from __future__ import annotations

import datetime as dt
import functools
import json
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from typing import Optional


IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
LOOKUP_TIMEOUT = 6  # seconds

# Known RDAP base URLs for major TLDs. The IANA bootstrap is authoritative and
# preferred, but some heavily-used TLDs (.com/.net via Verisign) are simplest to
# resolve directly, and this also keeps the tool working if the bootstrap fetch
# is temporarily unavailable. Refresh occasionally from the IANA registry.
RDAP_FALLBACK = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "io": "https://rdap.identitydigital.services/rdap/",
    "co": "https://rdap.nic.co/",
    "biz": "https://rdap.nic.biz/",
    "us": "https://rdap.nic.us/",
}


@dataclass
class DomainAgeResult:
    domain: str
    status: str                    # "ok" | "unknown" | "no_rdap_for_tld"
    age_days: Optional[int] = None
    registration_date: Optional[str] = None
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@functools.lru_cache(maxsize=1)
def _load_bootstrap() -> dict:
    """Fetch and cache IANA's TLD -> RDAP server map. Called once per process."""
    try:
        req = urllib.request.Request(IANA_BOOTSTRAP, headers={"User-Agent": "scam-detector/1.0"})
        with urllib.request.urlopen(req, timeout=LOOKUP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {"services": []}


def _rdap_server_for_tld(tld: str) -> Optional[str]:
    data = _load_bootstrap()
    for service in data.get("services", []):
        tlds, servers = service[0], service[1]
        if tld in tlds and servers:
            base = servers[0]
            return base if base.endswith("/") else base + "/"
    return RDAP_FALLBACK.get(tld)


def _parse_registration_date(rdap: dict) -> Optional[dt.datetime]:
    """RDAP records registration under an 'events' array with action 'registration'."""
    for event in rdap.get("events", []):
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate", "")
            try:
                # RDAP dates are ISO 8601, usually with a Z suffix.
                return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


@functools.lru_cache(maxsize=512)
def lookup_domain_age(domain: str) -> DomainAgeResult:
    """
    Return the age of a registered domain in days, or an honest 'unknown'.
    Cached per-process so repeated lookups of the same domain are free.
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return DomainAgeResult(domain=domain, status="unknown", detail="not a domain")

    tld = domain.rsplit(".", 1)[-1]
    server = _rdap_server_for_tld(tld)
    if not server:
        return DomainAgeResult(
            domain=domain, status="no_rdap_for_tld",
            detail=f"no RDAP server published for .{tld}",
        )

    url = f"{server}domain/{domain}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "scam-detector/1.0"})
        with urllib.request.urlopen(req, timeout=LOOKUP_TIMEOUT) as resp:
            rdap = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # The domain is not registered at all. For a claimed employer link,
            # that is itself worth noting — but it is a fact, not a verdict.
            return DomainAgeResult(domain=domain, status="ok", age_days=None,
                                   detail="domain not found in registry (unregistered)")
        return DomainAgeResult(domain=domain, status="unknown",
                               detail=f"RDAP HTTP {e.code}")
    except (urllib.error.URLError, socket.timeout, TimeoutError):
        return DomainAgeResult(domain=domain, status="unknown", detail="RDAP lookup timed out")
    except Exception as e:
        return DomainAgeResult(domain=domain, status="unknown", detail=f"RDAP error: {type(e).__name__}")

    reg = _parse_registration_date(rdap)
    if reg is None:
        return DomainAgeResult(domain=domain, status="unknown",
                               detail="RDAP record had no registration date")

    now = dt.datetime.now(dt.timezone.utc)
    age = (now - reg).days
    return DomainAgeResult(
        domain=domain, status="ok", age_days=age,
        registration_date=reg.date().isoformat(),
        detail=f"registered {reg.date().isoformat()}",
    )
