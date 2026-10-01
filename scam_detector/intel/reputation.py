"""
Optional third-party reputation lookups. Every one is OFF unless its env var is set.

  urlhaus_host / urlhaus_url   abuse.ch URLhaus (malware-distribution URLs)   URLHAUS_AUTH_KEY
  spamhaus_dbl                 Spamhaus Domain Blocklist via DQS (DNS)        SPAMHAUS_DQS_KEY
  chainabuse_wallet            Chainabuse crypto-wallet scam reports          CHAINABUSE_API_KEY
  twilio_line_type             Twilio Lookup v2 line type intelligence        TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN

Contract for all of them:
  - env var missing          -> {"status": "disabled"}
  - any error or timeout     -> {"status": "unknown", "detail": ...}; nothing ever raises
  - answers are cached through the Cache interface (1 day; phone numbers 30 days).
    "unknown" and "disabled" are not cached.
  - each takes an injectable client (http) or resolver (DNS) so tests never touch the network.

What each result does and doesn't mean:
  - URLhaus tracks MALWARE distribution. A job-scam or phishing page is usually not in
    it, so "clean" there means very little; a hit means a lot.
  - Spamhaus DBL is a strong signal when listed. The free DQS tier requires a
    registered key and is for low-volume/non-commercial use; check the terms before
    scaling up. Codes 127.0.1.1xx mean a legitimate site that has been abused.
  - Chainabuse reports are user-submitted. Unverified reports can be wrong or
    malicious; only "verified" reports justify a critical finding.
  - Twilio "nonFixedVoip" (Google Voice, TextNow...) is weak: plenty of real small
    employers and recruiters use Google Voice. It costs money per lookup.

Deliberately NOT used:
  - OpenPhish community feed: licensed for non-commercial use only.
  - PhishTank: new API registrations have been closed for a long time.
  - Google Safe Browsing Lookup API: non-commercial use only (the commercial
    equivalent is Google Web Risk, which is paid).
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Optional
from urllib.parse import quote

import dns.exception
import dns.resolver

from .cache import DAY, Cache, cached
from .domains import normalize_host

TIMEOUT = 4.0
TTL = DAY
PHONE_TTL = 30 * DAY

URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
CHAINABUSE_API = "https://api.chainabuse.com/v0/reports"
TWILIO_LOOKUP_API = "https://lookups.twilio.com/v2/PhoneNumbers/{}"
DQS_ZONE = "dbl.dq.spamhaus.net"

# Per the Spamhaus DBL return-code documentation (docs.spamhaus.com).
DBL_CODES = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet command-and-control domain",
    "127.0.1.102": "abused legitimate site (spam)",
    "127.0.1.103": "abused legitimate site (spammed redirector)",
    "127.0.1.104": "abused legitimate site (phishing)",
    "127.0.1.105": "abused legitimate site (malware)",
    "127.0.1.106": "abused legitimate site (botnet C&C)",
}
DBL_ERRORS = {
    "127.0.1.255": "IP addresses can't be queried against the DBL",
    "127.255.255.252": "typo in the DNSBL zone name",
    "127.255.255.254": "query refused (public/open resolver)",
    "127.255.255.255": "query refused (rate limit exceeded)",
}

# Twilio line_type_intelligence.type values
TWILIO_LINE_TYPES = {"landline", "mobile", "fixedVoip", "nonFixedVoip", "personal", "tollFree",
                     "premium", "sharedCost", "uan", "voicemail", "pager", "unknown"}


def _unknown(detail: str, **extra) -> dict:
    out = {"status": "unknown", "detail": detail}
    out.update(extra)
    return out


def _http(client):
    """Return (client, owned). A client we create is closed by the caller."""
    if client is not None:
        return client, False
    import httpx
    return httpx.Client(timeout=TIMEOUT, follow_redirects=False), True


def _json(resp):
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

def parse_urlhaus(data, kind: str) -> dict:
    """Interpret a URLhaus /host/ or /url/ JSON body (kind = "host" | "url")."""
    if not isinstance(data, dict):
        return _unknown("URLhaus returned something that isn't JSON")
    qs = str(data.get("query_status", "")).lower()
    if qs in ("no_results", "no_result"):
        return {"status": "clean", "source": "urlhaus", "detail": "not in URLhaus"}
    if qs != "ok":
        return _unknown(f"URLhaus query_status={qs or 'missing'}")
    if kind == "host":
        urls = data.get("urls") or []
        try:
            count = int(data.get("url_count") or len(urls))
        except (TypeError, ValueError):
            count = len(urls)
        online = sum(1 for u in urls if isinstance(u, dict) and u.get("url_status") == "online")
        threats = sorted({u.get("threat") for u in urls if isinstance(u, dict) and u.get("threat")})
        tags = sorted({t for u in urls if isinstance(u, dict) for t in (u.get("tags") or []) if t})
        listed = count > 0
        return {"status": "listed" if listed else "clean", "source": "urlhaus", "url_count": count,
                "online_count": online, "threats": threats, "tags": tags,
                "blacklists": data.get("blacklists") or {},
                "detail": f"{count} malware URL(s) on this host, {online} still online" if listed else "no URLs listed"}
    return {"status": "listed", "source": "urlhaus", "url_status": data.get("url_status"),
            "threat": data.get("threat"), "tags": data.get("tags") or [],
            "detail": f"URLhaus lists this URL ({data.get('threat') or 'malware'}, {data.get('url_status') or 'status unknown'})"}


def _urlhaus(kind: str, value: str, cache: Optional[Cache], client) -> dict:
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        return {"status": "disabled"}

    def compute():
        c, owned = _http(client)
        try:
            api = URLHAUS_HOST_API if kind == "host" else URLHAUS_URL_API
            resp = c.post(api, data={kind: value}, headers={"Auth-Key": key}, timeout=TIMEOUT)
            if resp.status_code != 200:
                return _unknown(f"URLhaus HTTP {resp.status_code}")
            return parse_urlhaus(_json(resp), kind)
        except Exception as e:  # noqa: BLE001
            return _unknown(f"URLhaus lookup failed ({type(e).__name__})")
        finally:
            if owned:
                c.close()

    return cached(cache, f"intel:urlhaus:{kind}:{value}", TTL, compute)


def urlhaus_host(host: str, *, cache: Optional[Cache] = None, client=None) -> dict:
    """URLhaus host lookup: status listed|clean|unknown|disabled."""
    return _urlhaus("host", normalize_host(host), cache, client)


def urlhaus_url(url: str, *, cache: Optional[Cache] = None, client=None) -> dict:
    """URLhaus exact-URL lookup: status listed|clean|unknown|disabled."""
    return _urlhaus("url", (url or "").strip(), cache, client)


# ---------------------------------------------------------------------------
# Spamhaus DBL via DQS
# ---------------------------------------------------------------------------

def interpret_dbl(addresses) -> dict:
    """Map DBL A-record answers to a result. Any 127.0.1.x (except .255) means listed."""
    addrs = sorted({str(a) for a in addresses})
    listed = []
    for a in addrs:
        if a in DBL_ERRORS:
            return _unknown(f"Spamhaus: {DBL_ERRORS[a]}", codes=addrs)
        if a.startswith("127.255.255."):
            return _unknown(f"Spamhaus error code {a}", codes=addrs)
        if a.startswith("127.0.1."):
            listed.append(DBL_CODES.get(a, f"listed (code {a})"))
    if listed:
        return {"status": "listed", "source": "spamhaus_dbl", "codes": addrs, "categories": listed,
                "abused_legit": all(c.startswith("abused") for c in listed),
                "detail": "Spamhaus DBL: " + ", ".join(listed)}
    return _unknown(f"unexpected Spamhaus answer {', '.join(addrs) or '(empty)'}", codes=addrs)


def spamhaus_dbl(domain: str, *, cache: Optional[Cache] = None, resolver=None) -> dict:
    """Spamhaus DBL (DQS) lookup for a domain: status listed|clean|unknown|disabled."""
    key = os.environ.get("SPAMHAUS_DQS_KEY", "").strip()
    if not key:
        return {"status": "disabled"}
    d = normalize_host(domain)
    try:
        ipaddress.ip_address(d)
        return _unknown("the DBL only lists domains, not IP addresses")
    except ValueError:
        pass
    if not d or "." not in d:
        return _unknown("not a domain")

    def compute():
        r = resolver
        if r is None:
            r = dns.resolver.Resolver()
            r.lifetime = r.timeout = TIMEOUT
        try:
            answers = r.resolve(f"{d}.{key}.{DQS_ZONE}", "A")
        except dns.resolver.NXDOMAIN:
            return {"status": "clean", "source": "spamhaus_dbl", "detail": "not listed"}
        except dns.resolver.NoAnswer:
            return {"status": "clean", "source": "spamhaus_dbl", "detail": "not listed"}
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            return _unknown("Spamhaus DNS query timed out")
        except Exception as e:  # noqa: BLE001
            return _unknown(f"Spamhaus DNS error ({type(e).__name__})")
        return interpret_dbl(getattr(a, "address", a) for a in answers)

    # key is deliberately not part of the cache key
    return cached(cache, f"intel:dbl:{d}", TTL, compute)


# ---------------------------------------------------------------------------
# Chainabuse
# ---------------------------------------------------------------------------

def parse_chainabuse(data) -> dict:
    """Defensive parse: accepts a bare list of reports or a dict wrapping one."""
    reports, total = None, None
    if isinstance(data, list):
        reports = data
    elif isinstance(data, dict):
        for k in ("reports", "data", "items", "results"):
            if isinstance(data.get(k), list):
                reports = data[k]
                break
        for k in ("count", "total", "totalCount", "total_count"):
            if isinstance(data.get(k), (int, float)):
                total = int(data[k])
                break
        if reports is None and total is None:
            return _unknown("Chainabuse response had no reports field")
    else:
        return _unknown("Chainabuse returned something that isn't JSON")
    reports = [r for r in (reports or []) if isinstance(r, dict)]
    count = total if total is not None else len(reports)

    def is_verified(r: dict) -> bool:
        for k in ("isVerified", "verified", "is_verified", "trusted", "isTrusted"):
            v = r.get(k)
            if v is True or (isinstance(v, str) and v.lower() in ("true", "yes", "verified")):
                return True
        return str(r.get("status", "")).lower() == "verified"

    verified = any(is_verified(r) for r in reports)
    cats = sorted({str(r.get("scamCategory") or r.get("category")) for r in reports
                   if r.get("scamCategory") or r.get("category")})
    return {"status": "reported" if count > 0 else "clean", "source": "chainabuse",
            "report_count": count, "verified": verified, "categories": cats,
            "detail": f"{count} report(s){', at least one verified' if verified else ''}" if count else "no reports"}


def chainabuse_wallet(address: str, *, cache: Optional[Cache] = None, client=None) -> dict:
    """Chainabuse reports for a crypto address: status reported|clean|unknown|disabled."""
    key = os.environ.get("CHAINABUSE_API_KEY", "").strip()
    if not key:
        return {"status": "disabled"}
    addr = (address or "").strip()
    if not addr:
        return _unknown("empty address")

    def compute():
        c, owned = _http(client)
        try:
            # Chainabuse uses HTTP basic auth with the API key as both user and password.
            resp = c.get(CHAINABUSE_API, params={"address": addr}, auth=(key, key),
                         headers={"Accept": "application/json"}, timeout=TIMEOUT)
            if resp.status_code == 404:
                return {"status": "clean", "source": "chainabuse", "report_count": 0,
                        "verified": False, "categories": [], "detail": "no reports"}
            if resp.status_code != 200:
                return _unknown(f"Chainabuse HTTP {resp.status_code}")
            return parse_chainabuse(_json(resp))
        except Exception as e:  # noqa: BLE001
            return _unknown(f"Chainabuse lookup failed ({type(e).__name__})")
        finally:
            if owned:
                c.close()

    return cached(cache, f"intel:chainabuse:{addr}", TTL, compute)


# ---------------------------------------------------------------------------
# Twilio Lookup v2
# ---------------------------------------------------------------------------

def to_e164(phone: str, default_cc: str = "1") -> Optional[str]:
    """Best-effort E.164 (US default): '(850) 555-0100' -> '+18505550100'."""
    s = (phone or "").strip()
    digits = re.sub(r"\D", "", s)
    if s.startswith("+"):
        return "+" + digits if 8 <= len(digits) <= 15 else None
    if default_cc == "1":
        if len(digits) == 10:
            return "+1" + digits
        if len(digits) == 11 and digits.startswith("1"):
            return "+" + digits
        return None
    return "+" + default_cc + digits if 6 <= len(digits) <= 14 else None


def parse_twilio(data) -> dict:
    if not isinstance(data, dict):
        return _unknown("Twilio returned something that isn't JSON")
    if data.get("valid") is False:
        return {"status": "invalid", "source": "twilio", "type": None,
                "detail": "Twilio says this isn't a valid phone number"}
    lti = data.get("line_type_intelligence") or {}
    if not isinstance(lti, dict):
        return _unknown("Twilio response had no line type data")
    t = lti.get("type")
    if not t:
        return _unknown(f"Twilio gave no line type (error {lti.get('error_code')})")
    return {"status": "ok", "source": "twilio", "type": t, "carrier": lti.get("carrier_name"),
            "known_type": t in TWILIO_LINE_TYPES, "e164": data.get("phone_number"),
            "detail": f"line type {t}" + (f" ({lti.get('carrier_name')})" if lti.get("carrier_name") else "")}


def twilio_line_type(phone: str, *, cache: Optional[Cache] = None, client=None) -> dict:
    """Twilio line type for a phone number: status ok|invalid|unknown|disabled; 'type' e.g. nonFixedVoip."""
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    if not (sid and token):
        return {"status": "disabled"}
    e164 = to_e164(phone)
    if not e164:
        return _unknown("couldn't read that as a phone number")

    def compute():
        c, owned = _http(client)
        try:
            resp = c.get(TWILIO_LOOKUP_API.format(quote(e164, safe="")),
                         params={"Fields": "line_type_intelligence"}, auth=(sid, token), timeout=TIMEOUT)
            if resp.status_code == 404:
                return {"status": "invalid", "source": "twilio", "type": None, "detail": "number not found"}
            if resp.status_code != 200:
                return _unknown(f"Twilio HTTP {resp.status_code}")
            return parse_twilio(_json(resp))
        except Exception as e:  # noqa: BLE001
            return _unknown(f"Twilio lookup failed ({type(e).__name__})")
        finally:
            if owned:
                c.close()

    return cached(cache, f"intel:twilio:{e164}", PHONE_TTL, compute)
