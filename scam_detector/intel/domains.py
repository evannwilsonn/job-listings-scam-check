"""
Domain intelligence that needs no third-party service.

  registrable_domain(host)      simple eTLD+1 ("careers.fsu.edu" -> "fsu.edu")
  lookalike(domain, protected)  typosquat / impersonation check against FSU and employer brands
  email_auth(domain)            SPF and DMARC presence/policy via DNS TXT

registrable_domain limits
  This is NOT the full Public Suffix List (that would be a new dependency). It knows
  the common two-part country suffixes (co.uk, com.au, ac.uk, edu.au, ...) and a few
  free-hosting suffixes (github.io, netlify.app, ...) where each customer gets their
  own subdomain; everything else is treated as "last two labels". Rare ccTLD
  structures will come out one label too short, which only makes lookalike checks
  slightly less precise, never wrong about fsu.edu itself.

lookalike limits
  - It works on the domain string only. It cannot tell you who owns a domain, and a
    non-match is not a clean bill of health.
  - Edit-distance on very short brands is noisy ("asu", "osu", "fiu" are all one
    letter from "fsu" and are real universities), so the threshold scales with brand
    length: brands of 5 characters or fewer only match a doubled letter or an
    inserted digit (fsuu, fsu1); 6-8 characters allow one edit; 9+ allow two.
  - A brand glued to another word with no hyphen ("fsuzone", "floridastateparks")
    is only flagged when the other word is hiring/login bait (careers, jobs, hr,
    portal, apply, ...). "fsuzone.com" is therefore NOT flagged: it reads as a fan
    site, and flagging every brand-prefixed name would bury real signals.
  - "seminole" is also a Florida county, city, college and tribe, so it only matches
    alongside hiring/login bait words, and a short list of known real Seminole
    organisations is never flagged. .gov and .mil can't be registered by the public,
    so they are skipped.
  - "fsu.joinhandshake.com" style tenant subdomains on known campus SaaS (Handshake,
    Canvas, Zoom, Qualtrics, Workday...) are how FSU really uses those services, so
    brand-as-subdomain is not flagged on those hosts.

email_auth limits
  Missing SPF/DMARC is weak evidence: plenty of small real businesses never set them
  up, and a scammer's own fresh domain can have perfect SPF. DNS timeouts come back
  as "unknown", never as "absent".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

import dns.exception
import dns.resolver


# ---------------------------------------------------------------------------
# registrable domain
# ---------------------------------------------------------------------------

MULTI_PART_SUFFIXES = frozenset({
    # UK
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "sch.uk", "nhs.uk",
    # Australia / NZ
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "org.nz", "ac.nz", "govt.nz", "net.nz",
    # Asia
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in",
    "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn",
    "com.hk", "org.hk", "edu.hk", "com.sg", "edu.sg", "gov.sg", "com.tw", "edu.tw",
    "co.kr", "or.kr", "ac.kr", "com.my", "edu.my", "com.ph", "edu.ph", "com.pk", "edu.pk",
    "co.th", "ac.th", "co.id", "ac.id", "com.vn", "edu.vn",
    # Americas
    "com.br", "net.br", "org.br", "edu.br", "gov.br", "com.mx", "org.mx", "edu.mx", "gob.mx",
    "com.ar", "edu.ar", "com.co", "edu.co", "com.pe", "com.ve", "com.ec",
    # Africa / Middle East / Europe
    "co.za", "org.za", "ac.za", "gov.za", "com.ng", "edu.ng", "co.ke", "ac.ke", "com.gh",
    "co.il", "ac.il", "org.il", "com.tr", "edu.tr", "gov.tr", "com.sa", "edu.sa", "com.eg",
    "com.ua", "com.pl", "com.ru", "com.es", "com.pt", "co.at", "or.at",
})

# Hosting suffixes where every customer gets a subdomain: "fsu-careers.netlify.app"
# is somebody's whole site, so it should be the "registrable" unit.
PRIVATE_SUFFIXES = frozenset({
    "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "herokuapp.com", "web.app", "firebaseapp.com", "glitch.me", "repl.co", "onrender.com",
    "blogspot.com", "wixsite.com", "weebly.com", "square.site", "carrd.co", "webflow.io",
    "azurewebsites.net", "cloudfront.net", "appspot.com", "wordpress.com", "notion.site",
})

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$", re.I)


def normalize_host(value: str) -> str:
    """Accept a host, URL or email address; return a lowercase hostname (no port/dot)."""
    s = (value or "").strip().lower()
    if not s:
        return ""
    if "@" in s and "://" not in s:
        s = s.rsplit("@", 1)[1]
    if "://" in s:
        try:
            s = urlsplit(s).hostname or ""
        except ValueError:
            return ""
    else:
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if s.count(":") == 1:
            s = s.split(":", 1)[0]
    s = s.strip().rstrip(".").strip("[]")
    return s


def split_host(host: str) -> tuple:
    """Return (subdomain, label, suffix) for a host. IPs and single labels give ("", host, "")."""
    h = normalize_host(host)
    if not h or _IP_RE.match(h) or "." not in h:
        return "", h, ""
    parts = h.split(".")
    for suffix_set in (PRIVATE_SUFFIXES, MULTI_PART_SUFFIXES):
        if len(parts) >= 3 and ".".join(parts[-2:]) in suffix_set:
            return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
    if len(parts) == 2 and ".".join(parts) in (MULTI_PART_SUFFIXES | PRIVATE_SUFFIXES):
        return "", h, ""
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def registrable_domain(host: str) -> str:
    """Simple eTLD+1: 'a.b.example.co.uk' -> 'example.co.uk'. IPs are returned unchanged."""
    sub, label, suffix = split_host(host)
    return f"{label}.{suffix}" if suffix else label


def is_subdomain_of(host: str, domain: str) -> bool:
    h, d = normalize_host(host), normalize_host(domain)
    return bool(h and d) and (h == d or h.endswith("." + d))


# ---------------------------------------------------------------------------
# lookalike detection
# ---------------------------------------------------------------------------

DEFAULT_PROTECTED = ("fsu.edu", "fsu", "seminole", "seminoles", "noles", "floridastate")

# Domains that really belong to FSU. Never flagged, nor any subdomain of them.
OFFICIAL_FSU_DOMAINS = frozenset({"fsu.edu", "seminoles.com"})

# Real organisations whose names contain an FSU brand word but are not FSU.
KNOWN_UNRELATED = frozenset({
    "seminolestate.edu", "seminolecountyfl.gov", "seminolehardrock.com", "semtribe.com",
    "floridastateparks.org",
})

# Hosts where "<school>.<service>" is the normal, legitimate tenant URL.
TRUSTED_TENANT_HOSTS = frozenset({
    "joinhandshake.com", "instructure.com", "zoom.us", "qualtrics.com", "symplicity.com",
    "myworkdayjobs.com", "workday.com", "okta.com", "service-now.com", "box.com",
    "sharepoint.com", "12twenty.com", "gradleaders.com", "campusgroups.com", "presence.io",
})

# Words scammers glue onto a brand to make a hiring or login page look official.
LURE_WORDS = frozenset({
    "career", "careers", "job", "jobs", "hr", "hire", "hiring", "recruit", "recruiting",
    "recruiter", "recruitment", "apply", "application", "portal", "edu", "student", "students",
    "payroll", "work", "employment", "employ", "staff", "onboard", "onboarding", "login",
    "signin", "verify", "verification", "secure", "support", "admin", "intern", "interns",
    "internship", "internships", "office", "helpdesk", "it", "mail", "email", "webmail",
    "account", "accounts", "online", "official", "team", "gig", "gigs", "remote", "now",
    "desk", "services", "service", "sso", "auth", "my", "update", "benefits", "pay", "finance",
})

# Brands that are also ordinary Florida place names: only flagged with lure words.
AMBIGUOUS_TOKENS = frozenset({"seminole"})

# Cyrillic/Greek characters that render like Latin letters (used in IDN homograph attacks).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "τ": "t", "ρ": "p",
})
_DIGIT_SWAPS_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
_DIGIT_SWAPS_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
_MULTI_SWAPS = (("rn", "m"), ("vv", "w"), ("cl", "d"))

REASON_TEXT = {
    "brand_in_subdomain": "uses the brand as a subdomain of an unrelated site",
    "tld_swap": "copies the brand but swaps the ending (TLD)",
    "brand_as_domain": "uses the brand name on a domain the brand doesn't own",
    "hyphen_insert": "splits the brand name with hyphens",
    "brand_plus_word": "adds words to the brand name",
    "homoglyph": "swaps letters for look-alike characters",
    "typosquat": "is a near-misspelling of the brand",
}
_REASON_ORDER = list(REASON_TEXT)


@dataclass
class Brand:
    name: str                    # what we report, e.g. "fsu.edu"
    token: str                   # comparable label, e.g. "fsu"
    official: frozenset          # registrable domains that are the real thing
    kind: str                    # "fsu" | "employer"
    suffix: str = ""             # official suffix label for tld_swap ("edu" for fsu.edu)
    ambiguous: bool = False


def _decode_idn(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return label
    return label


def _variants(label: str) -> set:
    """Look-alike normalisations of a label (homoglyph, digit and letter-pair swaps)."""
    base = _decode_idn(label).translate(_CONFUSABLES)
    out = {base}
    for table in (_DIGIT_SWAPS_L, _DIGIT_SWAPS_I):
        v = base.translate(table)
        out.add(v)
        for a, b in _MULTI_SWAPS:
            out.add(v.replace(a, b))
        w = v
        for a, b in _MULTI_SWAPS:
            w = w.replace(a, b)
        out.add(w)
    return out


def _osa_distance(a: str, b: str, cap: int = 3) -> int:
    """Damerau (optimal string alignment) edit distance, capped for speed."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2 = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def _near_miss(candidate: str, token: str) -> bool:
    """Length-scaled typo match (see module docstring). Exact equality is not a near miss."""
    if not candidate or candidate == token:
        return False
    n = len(token)
    if n <= 5:
        if len(candidate) != n + 1:
            return False
        for i, ch in enumerate(candidate):
            if candidate[:i] + candidate[i + 1:] == token:
                doubled = (i > 0 and candidate[i - 1] == ch) or (i + 1 < len(candidate) and candidate[i + 1] == ch)
                if doubled or ch.isdigit():
                    return True
        return False
    if n <= 8:
        return _osa_distance(candidate, token, 1) <= 1
    return len(candidate) >= 6 and _osa_distance(candidate, token, 2) <= 2


def _lure_split(s: str) -> bool:
    """True if s is one or more LURE_WORDS glued together ('jobsportal')."""
    if not s:
        return False
    ok = [True] + [False] * len(s)
    for i in range(1, len(s) + 1):
        for j in range(max(0, i - 14), i):
            if ok[j] and s[j:i] in LURE_WORDS:
                ok[i] = True
                break
    return ok[-1]


def _has_lure(parts: Iterable[str]) -> bool:
    return any(p in LURE_WORDS or _lure_split(p) for p in parts if p)


def build_brands(protected: Optional[Sequence[str]] = None, extra: Sequence[str] = ()) -> List[Brand]:
    """Turn protected strings (domains or bare words) into Brand records. Extras are employers."""
    brands: List[Brand] = []
    seen = set()

    def add(entry: str, kind: str):
        e = normalize_host(entry) if "." in entry else entry.strip().lower()
        if not e:
            return
        if "." in e:
            sub, label, suffix = split_host(e)
            token, official, suf = re.sub(r"[^a-z0-9]", "", label), {f"{label}.{suffix}"}, suffix.split(".")[0]
        else:
            token, official, suf = re.sub(r"[^a-z0-9]", "", e), set(), ""
        if kind == "fsu":
            official |= OFFICIAL_FSU_DOMAINS
            if not suf and token == "fsu":
                suf = "edu"
        if not token or token in seen:
            return
        seen.add(token)
        brands.append(Brand(e, token, frozenset(official), kind, suf, token in AMBIGUOUS_TOKENS))

    for p in (DEFAULT_PROTECTED if protected is None else protected):
        add(p, "fsu")
    for p in extra or ():
        add(p, "employer")
    return brands


def _match_brand(host: str, sub: str, label: str, suffix: str, b: Brand) -> Optional[tuple]:
    """Return (reason, detail) for the strongest way host imitates brand b, or None."""
    reg = f"{label}.{suffix}" if suffix else label
    t = b.token
    parts = [p for p in label.split("-") if p]
    joined = "".join(parts)
    all_host_parts = re.split(r"[.\-]", host)

    # 1. brand as a subdomain of someone else's domain: fsu.edu.jobs-portal.com
    if sub and reg not in TRUSTED_TENANT_HOSTS:
        sub_parts = re.split(r"[.\-]", sub)
        full_official = any(sub == o or sub.endswith("." + o) or sub.startswith(o + ".") or ("." + o + ".") in ("." + sub + ".")
                            for o in b.official)
        token_hit = any(t in _variants(p) for p in sub_parts)
        if full_official or token_hit:
            if not b.ambiguous or _has_lure(all_host_parts):
                what = next((o for o in b.official if o in sub), t)
                return "brand_in_subdomain", f'"{what}" appears before the real site name, which is {reg}'

    # 2. same name, different ending: fsu.co, fsu-edu.net, fsuedu.com
    if b.suffix and joined in (t + b.suffix, t + "-" + b.suffix):
        return "tld_swap", f"{reg} imitates {t}.{b.suffix}"
    if joined == t and "-" not in label:
        if b.ambiguous:
            return None
        if b.official:
            return "tld_swap", f"{reg} is not {', '.join(sorted(b.official))}"
        return "brand_as_domain", f"{reg} is not an official {b.name} site"

    # 3. hyphen inserted inside the brand: florida-state.com
    if "-" in label and joined == t:
        return "hyphen_insert", f"{reg} is the brand name broken up with hyphens"

    # 4. brand plus extra words: fsu-careers, seminoles-hr, fsucareers
    if len(parts) > 1 and t in parts:
        others = [p for p in parts if p != t]
        if not b.ambiguous or _has_lure(others):
            return "brand_plus_word", f'{reg} attaches "{"-".join(others)}" to the brand'
    for p in dict.fromkeys(parts + [joined]):
        if p.startswith(t) and _lure_split(p[len(t):]):
            return "brand_plus_word", f'{reg} glues "{p[len(t):]}" onto the brand'
        if p.endswith(t) and _lure_split(p[: -len(t)]):
            return "brand_plus_word", f'{reg} glues "{p[: -len(t)]}" onto the brand'

    # 5. homoglyphs and typos, on the whole label, the de-hyphenated label and each part
    candidates = {label, joined, *parts}
    for c in candidates:
        variants = _variants(c)
        if c != t and t in variants:
            ok_ctx = not b.ambiguous or _has_lure(parts)
            if ok_ctx:
                return "homoglyph", f'"{c}" reads as "{t}" once look-alike characters are swapped back'
    for c in candidates:
        for v in _variants(c):
            if _near_miss(v, t):
                # "seminole-realty" is a near miss of "seminoles" but is also an ordinary
                # Florida place name, so it needs a lure word too.
                if (b.ambiguous or v in AMBIGUOUS_TOKENS) and not _has_lure([p for p in parts if p != c]):
                    continue
                return "typosquat", f'"{c}" is one or two letters off from "{t}"'
    return None


def lookalike(domain: str, protected: Optional[Sequence[str]] = None, extra: Sequence[str] = ()) -> List[dict]:
    """
    Check whether `domain` (host, URL or email) imitates a protected brand.

    protected: domains or bare words; defaults to DEFAULT_PROTECTED (FSU brands).
    extra:     employer domains (e.g. "lockheedmartin.com") to protect as well; these and
               their subdomains are also treated as genuine.

    Returns a list (one entry per imitated brand) of
      {"domain", "registrable", "brand", "kind": "fsu"|"employer", "reason", "detail"}
    ordered strongest reason first. Empty list = no lookalike pattern found.
    """
    host = normalize_host(domain)
    sub, label, suffix = split_host(host)
    if not host or not suffix:
        return []
    reg = f"{label}.{suffix}"
    if suffix.split(".")[-1] in ("gov", "mil") or reg in KNOWN_UNRELATED:
        return []
    brands = build_brands(protected, extra)
    trusted = set(OFFICIAL_FSU_DOMAINS)
    for b in brands:
        trusted |= set(b.official)
    if reg in trusted:
        return []

    matches = []
    for b in brands:
        hit = _match_brand(host, sub, label, suffix, b)
        if hit:
            reason, detail = hit
            matches.append({"domain": host, "registrable": reg, "brand": b.name, "kind": b.kind,
                            "reason": reason, "detail": f"{host} {REASON_TEXT[reason]} ({detail})"})
    matches.sort(key=lambda m: (m["kind"] != "fsu", _REASON_ORDER.index(m["reason"])))
    # All FSU brand words describe one institution: report only the strongest FSU match.
    out, fsu_seen = [], False
    for m in matches:
        if m["kind"] == "fsu":
            if fsu_seen:
                continue
            fsu_seen = True
        out.append(m)
    return out


# ---------------------------------------------------------------------------
# SPF / DMARC
# ---------------------------------------------------------------------------

def _txt_records(resolver, name: str) -> tuple:
    """Return ("ok", [txt, ...]) | ("absent", []) | ("unknown", [detail])."""
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "absent", []
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return "unknown", ["DNS lookup timed out or no nameserver answered"]
    except Exception as e:  # noqa: BLE001 - DNS errors are never evidence
        return "unknown", [f"DNS error: {type(e).__name__}"]
    out = []
    for r in answers:
        strings = getattr(r, "strings", None)
        if strings is None:
            out.append(str(r).strip('"'))
        else:
            out.append(b"".join(s if isinstance(s, bytes) else s.encode() for s in strings).decode("utf-8", "replace"))
    return "ok", out


def email_auth(domain: str, *, resolver=None, timeout: float = 4.0) -> dict:
    """
    SPF and DMARC for a domain, from TXT on <domain> and _dmarc.<domain>.

    Returns {"domain", "status": "ok"|"unknown",
             "spf":   {"status": "present"|"absent"|"unknown", "record", "all"},
             "dmarc": {"status": "present"|"absent"|"unknown", "record", "policy"}}
    "all" is the SPF catch-all qualifier ("-all", "~all", "?all", "+all" or None);
    "policy" is DMARC p= ("none", "quarantine", "reject"). Timeouts give "unknown".
    """
    d = normalize_host(domain)
    if not d or "." not in d:
        return {"domain": d, "status": "unknown", "detail": "not a domain",
                "spf": {"status": "unknown"}, "dmarc": {"status": "unknown"}}
    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout

    spf: dict = {"status": "unknown", "record": None, "all": None}
    st, recs = _txt_records(resolver, d)
    if st == "unknown":
        spf["detail"] = recs[0]
    else:
        found = [r for r in recs if r.lower().startswith("v=spf1")]
        spf["status"] = "present" if found else "absent"
        if found:
            spf["record"] = found[0]
            m = re.search(r"(?:^|\s)([-~?+]?)all\b", found[0], re.I)
            spf["all"] = ((m.group(1) or "+") + "all") if m else None

    dmarc: dict = {"status": "unknown", "record": None, "policy": None}
    st, recs = _txt_records(resolver, "_dmarc." + d)
    if st == "unknown":
        dmarc["detail"] = recs[0]
    else:
        found = [r for r in recs if r.replace(" ", "").lower().startswith("v=dmarc1")]
        dmarc["status"] = "present" if found else "absent"
        if found:
            dmarc["record"] = found[0]
            m = re.search(r"(?:^|;)\s*p\s*=\s*(\w+)", found[0], re.I)
            dmarc["policy"] = m.group(1).lower() if m else None

    status = "unknown" if "unknown" in (spf["status"], dmarc["status"]) else "ok"
    return {"domain": d, "status": status, "spf": spf, "dmarc": dmarc}
