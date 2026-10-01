"""
Threat-intel helpers for the scam detector: lookalike domains, SPF/DMARC, link
expansion, optional reputation APIs, and a Certificate Transparency watch.

Everything is failure-tolerant: a lookup that can't answer returns "unknown" (or
"disabled" when its API key isn't configured) and never raises. See each module's
docstring for what a result does and doesn't prove.
"""

from .cache import Cache, MemoryCache, NullCache
from .ct_watch import find_new_lookalike_certs
from .domains import DEFAULT_PROTECTED, email_auth, lookalike, registrable_domain
from .findings import intel_findings
from .reputation import chainabuse_wallet, spamhaus_dbl, twilio_line_type, urlhaus_host, urlhaus_url
from .shortener import SHORTENERS, expand, is_shortener

__all__ = [
    "Cache", "MemoryCache", "NullCache", "DEFAULT_PROTECTED", "email_auth", "lookalike",
    "registrable_domain", "expand", "is_shortener", "SHORTENERS", "urlhaus_host", "urlhaus_url",
    "spamhaus_dbl", "chainabuse_wallet", "twilio_line_type", "find_new_lookalike_certs",
    "intel_findings",
]
