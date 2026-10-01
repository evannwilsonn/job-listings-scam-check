"""
MX record check.

A domain that presents itself as a corporate employer but has no mail exchanger
cannot receive email at that domain — mildly suspicious for a "recruiter" address,
but far from conclusive (some orgs route mail through subdomains or third parties
in ways that still resolve). We report the fact and let the scorer weight it lightly.

Like domain age, a lookup failure is 'unknown', never 'suspicious'. DNS resolvers
time out for boring reasons.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List

import dns.resolver
import dns.exception


@dataclass
class MXResult:
    domain: str
    status: str            # "has_mx" | "no_mx" | "nxdomain" | "unknown"
    exchangers: List[str]
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def check_mx(domain: str, timeout: float = 5.0) -> MXResult:
    domain = domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return MXResult(domain=domain, status="unknown", exchangers=[], detail="not a domain")

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        answers = resolver.resolve(domain, "MX")
        hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
        return MXResult(domain=domain, status="has_mx", exchangers=hosts,
                        detail=f"{len(hosts)} mail exchanger(s)")
    except dns.resolver.NoAnswer:
        return MXResult(domain=domain, status="no_mx", exchangers=[],
                        detail="domain resolves but publishes no MX record")
    except dns.resolver.NXDOMAIN:
        return MXResult(domain=domain, status="nxdomain", exchangers=[],
                        detail="domain does not exist")
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return MXResult(domain=domain, status="unknown", exchangers=[], detail="DNS lookup failed")
    except Exception as e:
        return MXResult(domain=domain, status="unknown", exchangers=[],
                        detail=f"DNS error: {type(e).__name__}")
