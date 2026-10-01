"""Tests for scam_detector.intel. No network: every HTTP/DNS call goes through a fake."""
import datetime as dt
import json
import sys
from pathlib import Path

import dns.exception
import dns.resolver
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scam_detector.intel import (MemoryCache, chainabuse_wallet, email_auth, expand,  # noqa: E402
                                 find_new_lookalike_certs, intel_findings, lookalike,
                                 registrable_domain, spamhaus_dbl, twilio_line_type,
                                 urlhaus_host, urlhaus_url)
from scam_detector.intel import ct_watch, reputation  # noqa: E402

ENV_VARS = ("URLHAUS_AUTH_KEY", "SPAMHAUS_DQS_KEY", "CHAINABUSE_API_KEY",
            "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN")


# ---------------------------------------------------------------- fakes

class FakeResp:
    def __init__(self, status=200, payload=None, text=None):
        self.status_code = status
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeClient:
    """Records calls; `responder(method, url, kwargs)` returns a FakeResp or raises."""

    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def _do(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.responder(method, url, kw)

    def get(self, url, **kw):
        return self._do("GET", url, **kw)

    def post(self, url, **kw):
        return self._do("POST", url, **kw)

    def close(self):
        pass


class TxtRecord:
    def __init__(self, s):
        self.strings = [s.encode()]


class ARecord:
    def __init__(self, ip):
        self.address = ip


class FakeResolver:
    """answers: {(name, rdtype): list | Exception instance/class}."""

    def __init__(self, answers):
        self.answers = answers
        self.queries = []
        self.lifetime = self.timeout = None

    def resolve(self, name, rdtype):
        self.queries.append((name, rdtype))
        a = self.answers.get((name, rdtype), dns.resolver.NXDOMAIN)
        if isinstance(a, type) and issubclass(a, Exception):
            raise a()
        if isinstance(a, Exception):
            raise a
        return a


def boom(*a, **k):
    raise AssertionError("network must not be used here")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in ENV_VARS:
        monkeypatch.delenv(v, raising=False)
    # Belt and braces: any real DNS resolver construction in these tests is a bug.
    monkeypatch.setattr(dns.resolver, "Resolver", lambda *a, **k: FakeResolver({}))


# ---------------------------------------------------------------- registrable domain

@pytest.mark.parametrize("host,expected", [
    ("fsu.edu", "fsu.edu"),
    ("my.fsu.edu", "fsu.edu"),
    ("a.b.careers.fsu.edu.", "fsu.edu"),
    ("https://WWW.Example.com:8443/path?q=1", "example.com"),
    ("jobs@recruit.acme.co.uk", "acme.co.uk"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("cs.unimelb.edu.au", "unimelb.edu.au"),
    ("ox.ac.uk", "ox.ac.uk"),
    ("fsu.edu.jobs-portal.com", "jobs-portal.com"),
    ("fsu-careers.netlify.app", "fsu-careers.netlify.app"),
    ("192.168.1.10", "192.168.1.10"),
    ("localhost", "localhost"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


# ---------------------------------------------------------------- lookalike

@pytest.mark.parametrize("domain,reason", [
    ("fsu-careers.com", "brand_plus_word"),
    ("fsu-edu.net", "tld_swap"),
    ("fsuu.edu", "typosquat"),
    ("seminoles-hr.com", "brand_plus_word"),
    ("fsu.edu.apply-now.io", "brand_in_subdomain"),
    ("flor1dastate.org", "homoglyph"),
    ("fsu.co", "tld_swap"),
    ("fsuedu.com", "tld_swap"),
    ("fsucareers.com", "brand_plus_word"),
    ("florida-state.com", "hyphen_insert"),
    ("seminoles-jobs.com", "brand_plus_word"),
    ("fsu.jobs-portal.com", "brand_in_subdomain"),
    ("f5u-jobs.com", "homoglyph"),
    ("serninoles-jobs.net", "homoglyph"),       # rn -> m
    ("senninoles.com", "typosquat"),
    ("https://portal.fsu-careers.com/login", "brand_plus_word"),
    ("xn--fu-eoc.com", "homoglyph"),            # Cyrillic "ѕ" in fѕu
])
def test_lookalike_true_positives(domain, reason):
    hits = lookalike(domain)
    assert hits, domain
    assert hits[0]["kind"] == "fsu"
    assert hits[0]["reason"] == reason
    assert hits[0]["brand"] and hits[0]["detail"]


@pytest.mark.parametrize("domain", [
    "fsu.edu", "my.fsu.edu", "careers.fsu.edu", "www.fsu.edu", "https://my.fsu.edu/portal",
    "seminoles.com",                    # FSU athletics, official
    "gmail.com", "foodservices.com", "famu.edu",
    "asu.edu", "usf.edu", "fisu.net", "sfu.ca", "notes.com",   # one letter off, but real/unrelated
    # Decision: "fsuzone.com" is NOT flagged. Brand + an arbitrary word with no hyphen
    # reads as a fan site; only hiring/login bait words (careers, jobs, hr, portal...) count.
    "fsuzone.com",
    "fsucu.org",                        # FSU Credit Union: brand + non-lure word
    "fsu.joinhandshake.com",            # FSU's real Handshake tenant
    "seminolestate.edu", "seminolecountyfl.gov", "seminole-realty.com",  # Seminole the place
    "floridastateparks.org",
    "192.168.0.1", "",
])
def test_lookalike_true_negatives(domain):
    assert lookalike(domain) == []


def test_lookalike_one_fsu_match_even_when_many_brand_words_hit():
    hits = lookalike("fsu.edu.apply-now.io")
    assert len([h for h in hits if h["kind"] == "fsu"]) == 1


def test_lookalike_employer_domains():
    extra = ["lockheedmartin.com"]
    hits = lookalike("lockheedmartln.com", extra=extra)
    assert hits and hits[0]["kind"] == "employer" and hits[0]["reason"] == "typosquat"
    assert lookalike("lockheed-martin-careers.com", extra=extra)[0]["reason"] == "brand_plus_word"
    assert lookalike("lockheedmartin.co", extra=extra)[0]["reason"] == "tld_swap"
    assert lookalike("jobs.lockheedmartin.com", extra=extra) == []
    assert lookalike("lockheedmartln.com") == []   # not protected unless passed in


def test_lookalike_custom_protected_list():
    assert lookalike("acme-careers.com", protected=["acme.com"])[0]["brand"] == "acme.com"
    assert lookalike("fsu-careers.com", protected=["acme.com"]) == []


# ---------------------------------------------------------------- email_auth

def test_email_auth_present_and_policies():
    r = FakeResolver({
        ("acme.com", "TXT"): [TxtRecord("google-site-verification=x"), TxtRecord("v=spf1 include:_spf.google.com ~all")],
        ("_dmarc.acme.com", "TXT"): [TxtRecord("v=DMARC1; p=reject; rua=mailto:d@acme.com")],
    })
    out = email_auth("acme.com", resolver=r)
    assert out["status"] == "ok"
    assert out["spf"]["status"] == "present" and out["spf"]["all"] == "~all"
    assert out["dmarc"]["status"] == "present" and out["dmarc"]["policy"] == "reject"


def test_email_auth_absent():
    r = FakeResolver({("shady.biz", "TXT"): dns.resolver.NoAnswer})
    out = email_auth("shady.biz", resolver=r)
    assert out["spf"]["status"] == "absent" and out["dmarc"]["status"] == "absent"


def test_email_auth_timeout_is_unknown_not_absent(monkeypatch):
    r = FakeResolver({("slow.com", "TXT"): dns.exception.Timeout,
                      ("_dmarc.slow.com", "TXT"): dns.resolver.NoNameservers})
    monkeypatch.setattr(dns.resolver, "Resolver", lambda *a, **k: r)   # default-resolver path
    out = email_auth("slow.com")
    assert out["status"] == "unknown"
    assert out["spf"]["status"] == "unknown" and out["dmarc"]["status"] == "unknown"
    assert ("slow.com", "TXT") in r.queries and ("_dmarc.slow.com", "TXT") in r.queries


# ---------------------------------------------------------------- disabled state

def test_everything_disabled_without_env():
    c = FakeClient(boom)
    res = FakeResolver({})
    assert urlhaus_host("evil.com", client=c) == {"status": "disabled"}
    assert urlhaus_url("http://evil.com/x", client=c) == {"status": "disabled"}
    assert spamhaus_dbl("evil.com", resolver=res) == {"status": "disabled"}
    assert chainabuse_wallet("0x" + "a" * 40, client=c) == {"status": "disabled"}
    assert twilio_line_type("850-555-0100", client=c) == {"status": "disabled"}
    assert c.calls == [] and res.queries == []


def test_twilio_needs_both_env_vars(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC1")
    assert twilio_line_type("8505550100", client=FakeClient(boom)) == {"status": "disabled"}


# ---------------------------------------------------------------- Spamhaus DQS

@pytest.mark.parametrize("code,status,category", [
    ("127.0.1.2", "listed", "spam domain"),
    ("127.0.1.4", "listed", "phishing domain"),
    ("127.0.1.5", "listed", "malware domain"),
    ("127.0.1.6", "listed", "botnet command-and-control domain"),
    ("127.0.1.104", "listed", "abused legitimate site (phishing)"),
    ("127.0.1.77", "listed", "listed (code 127.0.1.77)"),
    ("127.0.1.255", "unknown", None),
    ("127.255.255.252", "unknown", None),
    ("127.255.255.254", "unknown", None),
    ("127.255.255.255", "unknown", None),
    ("10.0.0.1", "unknown", None),
])
def test_dqs_return_codes(monkeypatch, code, status, category):
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "KEY123")
    r = FakeResolver({("evil.com.KEY123.dbl.dq.spamhaus.net", "A"): [ARecord(code)]})
    out = spamhaus_dbl("evil.com", resolver=r)
    assert out["status"] == status
    if category:
        assert out["categories"] == [category]
    else:
        assert out["detail"]


def test_dqs_not_listed_and_timeout(monkeypatch):
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "KEY123")
    assert spamhaus_dbl("fine.com", resolver=FakeResolver({}))["status"] == "clean"
    slow = FakeResolver({("slow.com.KEY123.dbl.dq.spamhaus.net", "A"): dns.exception.Timeout})
    assert spamhaus_dbl("slow.com", resolver=slow)["status"] == "unknown"
    assert spamhaus_dbl("1.2.3.4", resolver=FakeResolver({}))["status"] == "unknown"


# ---------------------------------------------------------------- URLhaus

URLHAUS_HOST_LISTED = {
    "query_status": "ok", "host": "evil.com", "url_count": "2",
    "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
    "urls": [
        {"url": "http://evil.com/a.exe", "url_status": "online", "threat": "malware_download", "tags": ["exe"]},
        {"url": "http://evil.com/b.exe", "url_status": "offline", "threat": "malware_download", "tags": None},
    ],
}


def test_urlhaus_host_listed_and_request_shape(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "AUTH")
    c = FakeClient(lambda m, u, kw: FakeResp(200, URLHAUS_HOST_LISTED))
    out = urlhaus_host("Evil.com", client=c)
    assert out["status"] == "listed" and out["url_count"] == 2 and out["online_count"] == 1
    assert out["threats"] == ["malware_download"] and out["tags"] == ["exe"]
    method, url, kw = c.calls[0]
    assert method == "POST" and url == "https://urlhaus-api.abuse.ch/v1/host/"
    assert kw["headers"]["Auth-Key"] == "AUTH" and kw["data"] == {"host": "evil.com"}


def test_urlhaus_url_and_edge_responses(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "AUTH")
    body = {"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["elf"]}
    c = FakeClient(lambda m, u, kw: FakeResp(200, body))
    out = urlhaus_url("http://evil.com/x", client=c)
    assert out["status"] == "listed" and out["threat"] == "malware_download"
    assert c.calls[0][1] == "https://urlhaus-api.abuse.ch/v1/url/" and c.calls[0][2]["data"] == {"url": "http://evil.com/x"}

    for payload, status in [({"query_status": "no_results"}, "clean"),
                            ({"query_status": "invalid_host"}, "unknown"),
                            (None, "unknown")]:
        c = FakeClient(lambda m, u, kw, p=payload: FakeResp(200, p, text="<html>"))
        assert urlhaus_host("x.com", client=c)["status"] == status
    assert urlhaus_host("x.com", client=FakeClient(lambda m, u, kw: FakeResp(401, {})))["status"] == "unknown"

    def raise_timeout(m, u, kw):
        raise TimeoutError("slow")
    out = urlhaus_host("x.com", client=FakeClient(raise_timeout))
    assert out["status"] == "unknown" and "TimeoutError" in out["detail"]


# ---------------------------------------------------------------- Twilio

@pytest.mark.parametrize("line_type", ["nonFixedVoip", "mobile", "landline", "tollFree", "fixedVoip"])
def test_twilio_line_types(monkeypatch, line_type):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC1")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok")
    body = {"phone_number": "+18505550100", "valid": True,
            "line_type_intelligence": {"type": line_type, "carrier_name": "Carrier X", "error_code": None}}
    c = FakeClient(lambda m, u, kw: FakeResp(200, body))
    out = twilio_line_type("(850) 555-0100", client=c)
    assert out["status"] == "ok" and out["type"] == line_type and out["carrier"] == "Carrier X"
    method, url, kw = c.calls[0]
    assert url == "https://lookups.twilio.com/v2/PhoneNumbers/%2B18505550100"
    assert kw["params"] == {"Fields": "line_type_intelligence"} and kw["auth"] == ("AC1", "tok")


def test_twilio_invalid_and_errors(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC1")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok")
    c = FakeClient(lambda m, u, kw: FakeResp(200, {"valid": False, "line_type_intelligence": None}))
    assert twilio_line_type("8505550100", client=c)["status"] == "invalid"
    c = FakeClient(lambda m, u, kw: FakeResp(200, {"valid": True, "line_type_intelligence": {"type": None, "error_code": 60600}}))
    assert twilio_line_type("8505550101", client=c)["status"] == "unknown"
    assert twilio_line_type("8505550102", client=FakeClient(lambda m, u, kw: FakeResp(500, {})))["status"] == "unknown"
    assert twilio_line_type("12", client=FakeClient(boom))["status"] == "unknown"


# ---------------------------------------------------------------- Chainabuse

WALLET = "0x" + "ab" * 20


@pytest.mark.parametrize("payload,count,verified", [
    ([{"id": 1, "checked": False}, {"id": 2, "isVerified": True}], 2, True),
    ({"reports": [{"id": 1}], "count": 7}, 7, False),
    ({"data": [{"verified": "true"}]}, 1, True),
    ([], 0, False),
])
def test_chainabuse_parsing(monkeypatch, payload, count, verified):
    monkeypatch.setenv("CHAINABUSE_API_KEY", "CK")
    c = FakeClient(lambda m, u, kw: FakeResp(200, payload))
    out = chainabuse_wallet(WALLET, client=c)
    assert out["report_count"] == count and out["verified"] is verified
    assert out["status"] == ("reported" if count else "clean")
    method, url, kw = c.calls[0]
    assert url == "https://api.chainabuse.com/v0/reports" and kw["params"] == {"address": WALLET}
    assert kw["auth"] == ("CK", "CK")


def test_chainabuse_weird_schema_is_unknown(monkeypatch):
    monkeypatch.setenv("CHAINABUSE_API_KEY", "CK")
    assert chainabuse_wallet(WALLET, client=FakeClient(lambda m, u, kw: FakeResp(200, {"x": 1})))["status"] == "unknown"
    assert chainabuse_wallet(WALLET, client=FakeClient(lambda m, u, kw: FakeResp(503, {})))["status"] == "unknown"


# ---------------------------------------------------------------- cache

def test_cache_hit_skips_second_lookup(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "AUTH")
    cache = MemoryCache()
    c = FakeClient(lambda m, u, kw: FakeResp(200, URLHAUS_HOST_LISTED))
    first = urlhaus_host("evil.com", cache=cache, client=c)
    second = urlhaus_host("evil.com", cache=cache, client=c)
    assert len(c.calls) == 1
    assert second["cached"] is True and second["status"] == first["status"] == "listed"


def test_unknown_results_are_not_cached(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "AUTH")
    cache = MemoryCache()
    c = FakeClient(lambda m, u, kw: FakeResp(502, {}))
    urlhaus_host("x.com", cache=cache, client=c)
    urlhaus_host("x.com", cache=cache, client=c)
    assert len(c.calls) == 2 and len(cache) == 0


def test_phone_ttl_is_30_days_and_memory_cache_expires(monkeypatch):
    now = [1000.0]
    cache = MemoryCache(clock=lambda: now[0])
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC1")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok")
    body = {"valid": True, "line_type_intelligence": {"type": "mobile"}}
    c = FakeClient(lambda m, u, kw: FakeResp(200, body))
    twilio_line_type("8505550100", cache=cache, client=c)
    now[0] += 29 * 86400
    twilio_line_type("8505550100", cache=cache, client=c)
    assert len(c.calls) == 1
    now[0] += 2 * 86400
    twilio_line_type("8505550100", cache=cache, client=c)
    assert len(c.calls) == 2
    assert reputation.TTL == 86400 and reputation.PHONE_TTL == 30 * 86400


def test_dqs_cache_hit(monkeypatch):
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "K")
    cache = MemoryCache()
    r = FakeResolver({("evil.com.K.dbl.dq.spamhaus.net", "A"): [ARecord("127.0.1.4")]})
    spamhaus_dbl("evil.com", cache=cache, resolver=r)
    assert spamhaus_dbl("evil.com", cache=cache, resolver=r)["cached"] is True
    assert len(r.queries) == 1


# ---------------------------------------------------------------- shortener

def test_shortener_follows_to_destination_without_fetching_it():
    hops = {"https://bit.ly/abc": (301, "https://tinyurl.com/xyz"),
            "https://tinyurl.com/xyz": (302, "https://fsu-careers.com/apply")}
    seen = []

    def fetch(url):
        seen.append(url)
        return hops[url]
    out = expand("https://bit.ly/abc", fetch=fetch)
    assert out["status"] == "ok" and out["hops"] == 2
    assert out["chain"] == ["https://bit.ly/abc", "https://tinyurl.com/xyz", "https://fsu-careers.com/apply"]
    assert out["final_host"] == "fsu-careers.com"
    assert seen == ["https://bit.ly/abc", "https://tinyurl.com/xyz"]   # destination never contacted


def test_shortener_hop_cap():
    n = [0]

    def loop(url):
        n[0] += 1
        return 301, f"https://bit.ly/{n[0]}"
    out = expand("https://bit.ly/0", fetch=loop, max_hops=3)
    assert out["status"] == "hop_limit" and out["hops"] == 3 and n[0] == 3
    assert len(out["chain"]) == 4


def test_shortener_edge_cases():
    assert expand("https://example.com/x", fetch=boom)["status"] == "not_shortened"
    rel = expand("https://t.co/a", fetch=lambda u: (301, "/b") if u.endswith("/a") else (301, "https://real.example.org/"))
    assert rel["chain"][1] == "https://t.co/b" and rel["final_host"] == "real.example.org"
    assert expand("https://bit.ly/x", fetch=lambda u: (301, "javascript:alert(1)"))["status"] == "unknown"
    assert expand("https://bit.ly/x", fetch=lambda u: (200, None))["status"] == "unknown"

    def err(u):
        raise ConnectionError("reset")
    assert expand("https://www.bit.ly/x", fetch=err)["status"] == "unknown"


# ---------------------------------------------------------------- crt.sh

CRT_ROWS = [
    {"name_value": "fsu-careers.com\nwww.fsu-careers.com", "common_name": "fsu-careers.com",
     "not_before": "2026-09-20T10:00:00", "issuer_name": "C=US, O=Let's Encrypt"},
    {"name_value": "fsu-careers.com", "not_before": "2026-09-25T10:00:00"},
    {"name_value": "*.fsu.edu\nmy.fsu.edu", "not_before": "2026-09-26T00:00:00"},
    {"name_value": "fsuzone.com", "not_before": "2026-09-26T00:00:00"},
    {"name_value": "seminoles-jobs.net", "not_before": "2025-01-01T00:00:00"},     # old
    {"name_value": "fsu.edu.apply-now.io", "not_before": "2026-09-28T08:00:00"},
    {"name_value": "garbage", "not_before": "not a date"},
]


def test_crtsh_parsing_and_filtering():
    urls = []

    def fetch(url):
        urls.append(url)
        return 200, json.dumps(CRT_ROWS)
    since = dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)
    out = find_new_lookalike_certs(["fsu"], since, fetch=fetch)
    assert out["status"] == "ok" and out["errors"] == []
    assert urls == ["https://crt.sh/?q=%25fsu%25&output=json&exclude=expired"]
    by = {d["domain"]: d for d in out["domains"]}
    assert set(by) == {"fsu-careers.com", "apply-now.io"}
    assert by["fsu-careers.com"]["first_seen"].startswith("2026-09-20")
    assert by["fsu-careers.com"]["hostnames"] == ["fsu-careers.com", "www.fsu-careers.com"]
    assert by["apply-now.io"]["reason"] == "brand_in_subdomain"


def test_crtsh_old_domains_are_not_new():
    out = find_new_lookalike_certs(["seminoles"], "2026-01-01", fetch=lambda u: (200, json.dumps(CRT_ROWS)))
    assert "seminoles-jobs.net" not in {d["domain"] for d in out["domains"]}
    out = find_new_lookalike_certs(["seminoles"], 0, fetch=lambda u: (200, json.dumps(CRT_ROWS)))
    assert "seminoles-jobs.net" in {d["domain"] for d in out["domains"]}


def test_crtsh_failures():
    def flaky(url):
        if "fsu" in url:
            return 502, "<html>Bad Gateway</html>"
        if "noles" in url:
            raise TimeoutError("crt.sh is slow")
        return 200, "<html>not json</html>"
    out = find_new_lookalike_certs(["fsu", "noles", "seminole"], 0, fetch=flaky)
    assert out["status"] == "unknown" and out["domains"] == []
    assert [e["term"] for e in out["errors"]] == ["fsu", "noles", "seminole"]
    assert "502" in out["errors"][0]["detail"]

    def half(url):
        return (504, "") if "noles" in url else (200, json.dumps(CRT_ROWS))
    out = find_new_lookalike_certs(["fsu", "noles"], 0, fetch=half)
    assert out["status"] == "partial" and out["domains"]


def test_crtsh_default_fetch_is_not_used_when_injected(monkeypatch):
    monkeypatch.setattr(ct_watch, "_default_fetch", boom)
    assert find_new_lookalike_certs(["fsu"], 0, fetch=lambda u: (200, "[]"))["status"] == "ok"


# ---------------------------------------------------------------- intel_findings

def test_findings_offline_only():
    text = ("Congrats! Apply at https://fsu-careers.com/apply or https://bit.ly/fsujob. "
            "Email hr@fsu-edu.net. Our site is careers.fsu.edu.")
    out = intel_findings(text, [], "recruiter@gmail.com", "FSU", cache=MemoryCache(), network=False,
                         fetch=boom, http_client=FakeClient(boom), age_lookup=boom)
    ids = {f["rule_id"]: f for f in out}
    assert set(ids) == {"lookalike_domain", "shortened_link"}
    lk = ids["lookalike_domain"]
    assert lk["severity"] == "critical" and lk["weight"] == 35
    assert any("fsu-careers.com" in m for m in lk["matched"]) and any("fsu-edu.net" in m for m in lk["matched"])
    assert not any("careers.fsu.edu" in m for m in lk["matched"])
    for f in out:
        assert set(f) == {"rule_id", "severity", "weight", "title", "why", "matched"}


def test_findings_employer_lookalike_is_warning():
    out = intel_findings("Apply: https://acme-careers.net/start", [], "", "Acme", cache=None,
                         protected_extra=["acme.com"], network=False)
    assert out == [out[0]] and out[0]["rule_id"] == "lookalike_domain"
    assert out[0]["severity"] == "warning" and out[0]["weight"] == 22


def test_findings_clean_posting_has_no_findings():
    out = intel_findings("Apply on https://careers.fsu.edu or email jobs@fsu.edu", [], "jobs@fsu.edu", "FSU",
                         cache=MemoryCache(), network=True, fetch=boom, http_client=FakeClient(boom),
                         resolver=FakeResolver({}), age_lookup=boom)
    assert out == []


def test_findings_full_network_path(monkeypatch):
    for v, val in [("URLHAUS_AUTH_KEY", "A"), ("SPAMHAUS_DQS_KEY", "K"), ("CHAINABUSE_API_KEY", "C"),
                   ("TWILIO_ACCOUNT_SID", "AC"), ("TWILIO_AUTH_TOKEN", "T")]:
        monkeypatch.setenv(v, val)

    def http(method, url, kw):
        if "urlhaus" in url:
            if kw["data"].get("host") == "payroll-verify.xyz":
                return FakeResp(200, URLHAUS_HOST_LISTED)
            return FakeResp(200, {"query_status": "no_results"})
        if "chainabuse" in url:
            return FakeResp(200, [{"id": 1, "isVerified": True}])
        if "twilio" in url:
            return FakeResp(200, {"valid": True, "line_type_intelligence": {"type": "nonFixedVoip",
                                                                            "carrier_name": "Google (Grand Central)"}})
        raise AssertionError(url)

    resolver = FakeResolver({
        ("brightfuture-staffing.com", "TXT"): dns.resolver.NoAnswer,
        ("_dmarc.brightfuture-staffing.com", "TXT"): dns.resolver.NXDOMAIN,
        ("payroll-verify.xyz.K.dbl.dq.spamhaus.net", "A"): [ARecord("127.0.1.4")],
    })
    ages = {"payroll-verify.xyz": 12, "brightfuture-staffing.com": 45}

    def age_lookup(d):
        return {"status": "ok", "age_days": ages.get(d, 4000)}

    text = ("Hi! I'm Dana from BrightFuture Staffing. Text me at (850) 555-0142. "
            "Start here: https://bit.ly/brightjob . Buy equipment and send USDT to "
            f"{WALLET}. Questions: dana@brightfuture-staffing.com or dana@gmail.com")
    fetch = lambda u: (301, "https://payroll-verify.xyz/onboard")  # noqa: E731
    cache = MemoryCache()
    out = intel_findings(text, [], "dana@brightfuture-staffing.com", "BrightFuture Staffing", cache=cache,
                         http_client=FakeClient(http), resolver=resolver, fetch=fetch, age_lookup=age_lookup)
    ids = {f["rule_id"]: f for f in out}
    assert set(ids) == {"shortened_link", "new_domain", "blocklisted_domain", "no_email_auth",
                        "reported_wallet", "virtual_number"}
    assert "payroll-verify.xyz" in ids["shortened_link"]["why"]
    assert ids["new_domain"]["weight"] == 18 and ids["new_domain"]["matched"][0].startswith("payroll-verify.xyz")
    assert ids["blocklisted_domain"]["severity"] == "critical" and ids["blocklisted_domain"]["weight"] == 40
    assert len(ids["blocklisted_domain"]["matched"]) == 2          # URLhaus + Spamhaus
    assert ids["no_email_auth"]["matched"] == ["brightfuture-staffing.com"]   # gmail.com skipped
    assert (ids["reported_wallet"]["severity"], ids["reported_wallet"]["weight"]) == ("critical", 35)
    assert (ids["virtual_number"]["severity"], ids["virtual_number"]["weight"]) == ("note", 5)
    # gmail.com never looked up anywhere
    assert not any("gmail.com" in q[0] for q in resolver.queries)


def test_findings_age_band_and_unverified_wallet(monkeypatch):
    monkeypatch.setenv("CHAINABUSE_API_KEY", "C")
    http = FakeClient(lambda m, u, kw: FakeResp(200, {"reports": [{"id": 1}], "count": 3}))
    out = intel_findings(f"Pay the fee to {WALLET} via https://newish-jobs.com", [], "", "",
                         cache=None, http_client=http, resolver=FakeResolver({}), fetch=boom,
                         age_lookup=lambda d: {"status": "ok", "age_days": 60})
    ids = {f["rule_id"]: f for f in out}
    assert ids["new_domain"]["weight"] == 10
    assert (ids["reported_wallet"]["severity"], ids["reported_wallet"]["weight"]) == ("warning", 15)


def test_findings_unknowns_never_become_findings():
    def age_timeout(d):
        return {"status": "unknown", "detail": "RDAP lookup timed out"}
    resolver = FakeResolver({("slowcorp.com", "TXT"): dns.exception.Timeout,
                             ("_dmarc.slowcorp.com", "TXT"): dns.exception.Timeout})
    out = intel_findings("Email jobs@slowcorp.com", [], "jobs@slowcorp.com", "SlowCorp", cache=MemoryCache(),
                         resolver=resolver, fetch=boom, age_lookup=age_timeout, http_client=FakeClient(boom))
    assert out == []
